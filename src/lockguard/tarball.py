"""In-memory tarball handling: SRI integrity verification and safe extraction.

Nothing is ever written to disk or executed: tarballs are opened from a ``BytesIO`` and
their members are read into a dictionary.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import tarfile
from dataclasses import dataclass, field

MAX_SCAN_BYTES = 2 * 1024 * 1024  # files larger than this are hashed but not scanned
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # refuse tar bombs
MAX_MEMBERS = 50_000

# Strongest first. npm writes sha512; very old lockfiles may still contain sha1.
_SRI_ALGORITHMS = ("sha512", "sha384", "sha256", "sha1")


class TarballError(Exception):
    """The tarball is corrupt, not a tarball, or exceeds safety limits."""


@dataclass(frozen=True)
class LargeFile:
    """A file too large to scan; only its size and hash are kept."""

    size: int
    sha256: str


@dataclass
class TarballContents:
    """Files of an extracted package, keyed by path without the leading ``package/``."""

    files: dict[str, bytes] = field(default_factory=dict)
    large: dict[str, LargeFile] = field(default_factory=dict)


def compute_sri(data: bytes, algorithm: str = "sha512") -> str:
    """Return the Subresource-Integrity string (``sha512-<base64>``) of ``data``."""
    digest = hashlib.new(algorithm, data).digest()
    return f"{algorithm}-{base64.b64encode(digest).decode('ascii')}"


def _parse_sri(integrity: str) -> dict[str, list[bytes]]:
    """Split an SRI string (possibly several space-separated hashes) into digests."""
    parsed: dict[str, list[bytes]] = {}
    for token in integrity.split():
        algorithm, sep, rest = token.partition("-")
        if not sep:
            continue
        algorithm = algorithm.lower()
        if algorithm not in _SRI_ALGORITHMS:
            continue
        b64 = rest.split("?", 1)[0]  # SRI allows "?options" after the digest
        try:
            digest = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            continue
        parsed.setdefault(algorithm, []).append(digest)
    return parsed


def verify_integrity(data: bytes, integrity: str) -> tuple[bool, str]:
    """Check ``data`` against an SRI string using its strongest supported algorithm.

    Returns:
        ``(matches, actual_sri)`` where ``actual_sri`` is the hash of ``data`` computed
        with the algorithm that was compared.

    Raises:
        ValueError: if ``integrity`` contains no hash lockguard can verify.
    """
    parsed = _parse_sri(integrity)
    for algorithm in _SRI_ALGORITHMS:
        expected = parsed.get(algorithm)
        if not expected:
            continue
        actual = hashlib.new(algorithm, data).digest()
        ok = any(hmac.compare_digest(actual, candidate) for candidate in expected)
        return ok, f"{algorithm}-{base64.b64encode(actual).decode('ascii')}"
    raise ValueError(f"no supported hash in integrity string {integrity[:40]!r}")


def _normalise_member_path(name: str) -> str | None:
    """Strip the first path component (``package/``) like npm does; reject traversal."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if len(parts) < 2 or any(p == ".." for p in parts):
        return None
    return "/".join(parts[1:])


def extract_tarball(data: bytes) -> TarballContents:
    """Extract a ``.tgz`` (or plain ``.tar``) entirely in memory.

    Regular files up to :data:`MAX_SCAN_BYTES` are returned in ``files``; bigger ones are
    streamed through SHA-256 and listed in ``large``. Symlinks, devices and paths that
    escape the package directory are ignored.

    Raises:
        TarballError: if the data is not a readable tarball or exceeds safety limits.
    """
    contents = TarballContents()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for count, member in enumerate(archive, start=1):
                if count > MAX_MEMBERS:
                    raise TarballError(f"tarball has more than {MAX_MEMBERS} entries")
                if not member.isfile():
                    continue
                path = _normalise_member_path(member.name)
                if path is None:
                    continue
                total += member.size
                if total > MAX_TOTAL_BYTES:
                    raise TarballError("tarball expands to more than 1 GiB")
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                if member.size > MAX_SCAN_BYTES:
                    hasher = hashlib.sha256()
                    while chunk := handle.read(1 << 20):
                        hasher.update(chunk)
                    contents.large[path] = LargeFile(member.size, hasher.hexdigest())
                    contents.files.pop(path, None)
                else:
                    contents.files[path] = handle.read()
                    contents.large.pop(path, None)
    except TarballError:
        raise
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        raise TarballError(f"cannot read tarball: {exc}") from None
    return contents
