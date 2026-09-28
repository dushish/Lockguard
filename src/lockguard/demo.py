"""The bundled demo: two inert fake packages served by an in-memory fake registry.

* ``fake-logger 1.0.0 → 1.0.1`` imitates the *shape* of the September 2025 npm compromise
  (obfuscated blob, wallet hook, postinstall script, new publisher, dropped provenance).
* ``fake-utils 2.3.0 → 2.3.1`` is a genuine one-line bugfix and must come out clean.

The fixture sources live in ``tests/fixtures`` (shipped in the wheel as
``lockguard/_fixtures``). They are harmless: no network calls, file reads or code
execution ever happen - the suspicious statements are only text for the heuristics.
Tarballs are built in memory at run time; nothing touches the network.
"""

from __future__ import annotations

import copy
import gzip
import io
import json
import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lockguard.lockfile import Lockfile, name_from_path, parse_lockfile
from lockguard.registry import DEFAULT_REGISTRY, NotFoundError, tarball_url
from lockguard.tarball import compute_sri

FIXTURES_ENV = "LOCKGUARD_FIXTURES"
_NPM_EPOCH = 499162500  # npm normalizes tarball mtimes to 1985-10-26


def fixtures_dir() -> Path:
    """Locate the fixture directory (installed wheel, source checkout, or ``$LOCKGUARD_FIXTURES``)."""
    candidates = []
    if os.environ.get(FIXTURES_ENV):
        candidates.append(Path(os.environ[FIXTURES_ENV]))
    here = Path(__file__).resolve().parent
    candidates += [here / "_fixtures", here.parents[1] / "tests" / "fixtures"]
    for candidate in candidates:
        if (candidate / "packages").is_dir():
            return candidate
    raise FileNotFoundError(
        "lockguard demo fixtures not found; reinstall lockguard or set $LOCKGUARD_FIXTURES"
    )


def build_tarball(files: dict[str, bytes], prefix: str = "package") -> bytes:
    """Build a deterministic npm-style ``.tgz`` (all paths under ``package/``) in memory."""
    buffer = io.BytesIO()
    with (
        gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for path in sorted(files):
            data = files[path]
            info = tarfile.TarInfo(f"{prefix}/{path}")
            info.size = len(data)
            info.mtime = _NPM_EPOCH
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def read_tree(directory: Path) -> dict[str, bytes]:
    """Read every file below ``directory`` into ``{relative/posix/path: bytes}``."""
    return {
        p.relative_to(directory).as_posix(): p.read_bytes()
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


class FakeRegistry:
    """An in-memory stand-in for the npm registry (implements ``RegistryLike``)."""

    def __init__(
        self,
        packuments: dict[str, dict[str, Any]],
        tarballs: dict[str, bytes],
        registry_url: str = DEFAULT_REGISTRY,
    ) -> None:
        self.registry_url = registry_url
        self.packuments = packuments
        self.tarballs = tarballs

    def packument(self, name: str) -> dict[str, Any]:
        """Return a deep copy of the stored packument."""
        try:
            return copy.deepcopy(self.packuments[name])
        except KeyError:
            raise NotFoundError(f"{name}: not in fake registry") from None

    def tarball(self, url: str) -> bytes:
        """Return stored tarball bytes."""
        try:
            return self.tarballs[url]
        except KeyError:
            raise NotFoundError(f"{url}: not in fake registry") from None


@dataclass
class DemoSetup:
    """Everything needed to run the demo pipeline."""

    old_lockfile_data: dict[str, Any]
    new_lockfile_data: dict[str, Any]
    registry: FakeRegistry
    integrity: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def old_lockfile(self) -> Lockfile:
        """Parsed base lockfile."""
        return parse_lockfile(self.old_lockfile_data, "demo base package-lock.json")

    @property
    def new_lockfile(self) -> Lockfile:
        """Parsed PR lockfile."""
        return parse_lockfile(self.new_lockfile_data, "demo PR package-lock.json")


def _fill_lockfile(data: dict[str, Any], integrity: dict[tuple[str, str], str]) -> dict[str, Any]:
    """Insert real ``resolved``/``integrity`` values for fixture packages."""
    filled = copy.deepcopy(data)
    for key, entry in filled.get("packages", {}).items():
        if not isinstance(entry, dict) or not key:
            continue
        name = entry.get("name") or name_from_path(key)
        version = entry.get("version")
        if isinstance(name, str) and isinstance(version, str) and (name, version) in integrity:
            entry["resolved"] = tarball_url(name, version)
            entry["integrity"] = integrity[(name, version)]
    return filled


def build_demo(fixtures: Path | None = None) -> DemoSetup:
    """Build fake tarballs, packuments and lockfiles from the fixture directory."""
    root = fixtures or fixtures_dir()
    packuments: dict[str, dict[str, Any]] = {}
    tarballs: dict[str, bytes] = {}
    integrity: dict[tuple[str, str], str] = {}

    for package_dir in sorted(p for p in (root / "packages").iterdir() if p.is_dir()):
        packument = json.loads((package_dir / "packument.json").read_text(encoding="utf-8"))
        name = packument["name"]
        for version_dir in sorted(p for p in package_dir.iterdir() if p.is_dir()):
            version = version_dir.name
            data = build_tarball(read_tree(version_dir))
            url = tarball_url(name, version)
            sri = compute_sri(data)
            tarballs[url] = data
            integrity[(name, version)] = sri
            dist = packument["versions"][version].setdefault("dist", {})
            dist["tarball"] = url
            dist["integrity"] = sri
        packuments[name] = packument

    lockfiles = root / "lockfiles"
    old = json.loads((lockfiles / "base-package-lock.json").read_text(encoding="utf-8"))
    new = json.loads((lockfiles / "pr-package-lock.json").read_text(encoding="utf-8"))
    return DemoSetup(
        old_lockfile_data=_fill_lockfile(old, integrity),
        new_lockfile_data=_fill_lockfile(new, integrity),
        registry=FakeRegistry(packuments, tarballs),
        integrity=integrity,
    )


def write_demo_lockfiles(directory: Path, setup: DemoSetup | None = None) -> tuple[Path, Path]:
    """Write the demo base/PR lockfiles into ``directory`` and return their paths."""
    setup = setup or build_demo()
    directory.mkdir(parents=True, exist_ok=True)
    old_path = directory / "base-package-lock.json"
    new_path = directory / "package-lock.json"
    old_path.write_text(json.dumps(setup.old_lockfile_data, indent=2) + "\n", encoding="utf-8")
    new_path.write_text(json.dumps(setup.new_lockfile_data, indent=2) + "\n", encoding="utf-8")
    return old_path, new_path
