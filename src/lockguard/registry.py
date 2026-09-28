"""Talking to the npm registry: packuments (metadata) and tarballs.

All HTTP goes through :func:`urlopen_bytes`, a single small function that tests replace
with ``monkeypatch`` so the test-suite never touches the network.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Protocol, cast

from lockguard import __version__

DEFAULT_REGISTRY = "https://registry.npmjs.org"
DEFAULT_ALLOWED_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
USER_AGENT = f"lockguard/{__version__} (+https://github.com/topics/lockguard)"

MAX_TARBALL_BYTES = 256 * 1024 * 1024
MAX_PACKUMENT_BYTES = 256 * 1024 * 1024

# npm package names: optional @scope/, then URL-safe characters. Legacy names may contain
# capitals. Anything else (e.g. "../") is rejected before it is put into a URL.
_NAME_RE = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9._~-][A-Za-z0-9._~-]*$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,256}$")


class RegistryError(Exception):
    """Any failure to obtain data from the registry."""


class NotFoundError(RegistryError):
    """The registry answered 404/410 - the package or version does not exist (any more)."""


class TransientRegistryError(RegistryError):
    """A network error or 5xx/429 response that is worth retrying."""


class RegistryLike(Protocol):
    """What the analysis engine needs from a registry (real or fake)."""

    registry_url: str

    def packument(self, name: str) -> dict[str, Any]:
        """Full packument for `name`, fetched at most once per run."""
        ...

    def tarball(self, url: str) -> bytes:
        """Download a tarball (cached for the rest of the run)."""
        ...


def is_valid_package_name(name: str) -> bool:
    """True if ``name`` looks like an npm package name and is safe to put in a URL."""
    return bool(_NAME_RE.match(name)) and ".." not in name and len(name) <= 214


def is_valid_version(version: str) -> bool:
    """True if ``version`` only contains characters that can appear in a semver string."""
    return bool(_VERSION_RE.match(version))


def registry_from_env() -> str:
    """Registry base URL: ``$LOCKGUARD_REGISTRY`` or the public npm registry."""
    return (os.environ.get("LOCKGUARD_REGISTRY") or DEFAULT_REGISTRY).rstrip("/")


def packument_url(name: str, registry: str = DEFAULT_REGISTRY) -> str:
    """URL of a package's metadata document; scoped names are encoded as ``@scope%2Fname``."""
    return f"{registry.rstrip('/')}/{urllib.parse.quote(name, safe='@')}"


def tarball_url(name: str, version: str, registry: str = DEFAULT_REGISTRY) -> str:
    """Canonical tarball URL, e.g. ``.../@babel/core/-/core-7.24.0.tgz``."""
    basename = name.rsplit("/", 1)[-1]
    return f"{registry.rstrip('/')}/{name}/-/{basename}-{version}.tgz"


def host_of(url: str) -> str:
    """Lower-case host name of a URL (empty string if there is none)."""
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def urlopen_bytes(url: str, *, timeout: float, accept: str, max_bytes: int) -> bytes:
    """Perform one HTTP GET and return the body.

    This is the only function in lockguard that touches the network.

    Raises:
        NotFoundError: on HTTP 404 or 410.
        TransientRegistryError: on connection problems, timeouts, HTTP 429 and 5xx.
        RegistryError: on any other HTTP error or if the body exceeds ``max_bytes``.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise RegistryError(f"{url}: response larger than {max_bytes} bytes")
                chunks.append(chunk)
            return b"".join(chunks)
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            raise NotFoundError(f"{url}: HTTP {exc.code}") from None
        if exc.code == 429 or exc.code >= 500:
            raise TransientRegistryError(f"{url}: HTTP {exc.code}") from None
        raise RegistryError(f"{url}: HTTP {exc.code} {exc.reason}") from None
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TransientRegistryError(f"{url}: {reason}") from None


class RegistryClient:
    """Fetches packuments and tarballs with retries and a per-run on-disk cache.

    Args:
        registry: base URL of the registry (defaults to :func:`registry_from_env`).
        cache_dir: directory for cached downloads; ``None`` disables the disk cache.
        retries: how many times to retry a transient failure (so ``retries + 1`` attempts).
        backoff: seconds to wait before the first retry; doubles on each retry.
        timeout: socket timeout per request in seconds.
    """

    def __init__(
        self,
        registry: str | None = None,
        *,
        cache_dir: Path | None = None,
        retries: int = 2,
        backoff: float = 0.5,
        timeout: float = 60.0,
    ) -> None:
        self.registry_url = (registry or registry_from_env()).rstrip("/")
        self.cache_dir = cache_dir
        self.retries = retries
        self.backoff = backoff
        self.timeout = timeout
        self._packuments: dict[str, dict[str, Any]] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)

    def _lock_for(self, key: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(key, threading.Lock())

    def _cache_path(self, url: str, suffix: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / (hashlib.sha256(url.encode()).hexdigest() + suffix)

    def _get(self, url: str, *, accept: str, max_bytes: int) -> bytes:
        """GET with retries on transient failures."""
        delay = self.backoff
        for attempt in range(self.retries + 1):
            try:
                return urlopen_bytes(url, timeout=self.timeout, accept=accept, max_bytes=max_bytes)
            except TransientRegistryError:
                if attempt >= self.retries:
                    raise
                if delay > 0:
                    time.sleep(delay)
                delay *= 2
        raise AssertionError("unreachable")  # pragma: no cover

    def _cached_get(self, url: str, *, suffix: str, accept: str, max_bytes: int) -> bytes:
        with self._lock_for(url):
            path = self._cache_path(url, suffix)
            if path is not None and path.exists():
                return path.read_bytes()
            data = self._get(url, accept=accept, max_bytes=max_bytes)
            if path is not None:
                tmp = path.with_suffix(path.suffix + ".part")
                tmp.write_bytes(data)
                tmp.replace(path)
            return data

    def packument(self, name: str) -> dict[str, Any]:
        """Return the full packument for ``name`` (fetched at most once per run).

        Raises:
            NotFoundError: if the package does not exist.
            RegistryError: on network failure or invalid JSON.
        """
        if not is_valid_package_name(name):
            raise RegistryError(f"refusing to query invalid package name {name!r}")
        with self._lock_for("packument:" + name):
            cached = self._packuments.get(name)
            if cached is not None:
                return cached
            url = packument_url(name, self.registry_url)
            raw = self._cached_get(
                url, suffix=".json", accept="application/json", max_bytes=MAX_PACKUMENT_BYTES
            )
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise RegistryError(f"{url}: invalid JSON ({exc})") from None
            if not isinstance(data, dict):
                raise RegistryError(f"{url}: packument is not a JSON object")
            packument = cast(dict[str, Any], data)
            self._packuments[name] = packument
            return packument

    def tarball(self, url: str) -> bytes:
        """Download a tarball (cached for the rest of the run).

        Raises:
            NotFoundError: if the tarball is gone (e.g. the version was unpublished).
            RegistryError: on network failure or an oversized download.
        """
        if not url.startswith("https://") and not url.startswith("http://"):
            raise RegistryError(f"refusing to download non-HTTP URL {url!r}")
        return self._cached_get(
            url, suffix=".tgz", accept="application/octet-stream", max_bytes=MAX_TARBALL_BYTES
        )
