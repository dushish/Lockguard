"""Reading npm ``package-lock.json`` files (lockfileVersion 2 and 3) and diffing two of them.

Both formats contain a flat ``packages`` map whose keys are install paths::

    "node_modules/debug"                       -> top-level dependency
    "node_modules/debug/node_modules/ms"       -> nested (transitive) copy
    "node_modules/@babel/core"                 -> scoped package
    "packages/app"                             -> workspace source folder

lockguard compares the *set of versions per package name* between the two files, so a
package that is merely re-hoisted to another path is not reported as a change.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from lockguard.models import ChangeKind, PackageChange, SkippedEntry

NODE_MODULES = "node_modules/"

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

# Version / resolved prefixes that mean "this did not come from a registry tarball".
_NON_REGISTRY_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("git", ("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:")),
    ("file", ("file:",)),
    ("link", ("link:",)),
)


class LockfileError(Exception):
    """Raised when a lockfile cannot be read or uses an unsupported format."""


@dataclass(frozen=True)
class Version:
    """A parsed semantic version (build metadata is ignored, as semver requires)."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    def sort_key(self) -> tuple[Any, ...]:
        """Key implementing semver precedence (a release sorts after its prereleases)."""
        if not self.prerelease:
            pre: tuple[Any, ...] = (1,)
        else:
            idents = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.prerelease)
            pre = (0, idents)
        return (self.major, self.minor, self.patch, pre)


def parse_version(value: str) -> Version | None:
    """Parse a semver string such as ``1.2.3-beta.1``; return ``None`` if it is not semver."""
    match = _SEMVER_RE.match(value.strip())
    if not match:
        return None
    pre = tuple(match.group(4).split(".")) if match.group(4) else ()
    return Version(int(match.group(1)), int(match.group(2)), int(match.group(3)), pre)


def version_sort_key(value: str) -> tuple[Any, ...]:
    """Sort key that orders semver versions correctly and puts non-semver strings first."""
    parsed = parse_version(value)
    if parsed is None:
        return (0, (), value)
    return (1, parsed.sort_key(), value)


def compare_versions(a: str, b: str) -> int | None:
    """Return -1/0/1 comparing two semver strings, or ``None`` if either is not semver."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    ka, kb = pa.sort_key(), pb.sort_key()
    return (ka > kb) - (ka < kb)


def bump_level(old: str, new: str) -> str | None:
    """Classify an update as ``major``, ``minor``, ``patch``, ``prerelease`` or ``downgrade``.

    For ``0.x`` versions a minor bump is treated as ``major`` (semver allows breaking
    changes there). Returns ``None`` when either version is not semver or they are equal.
    """
    po, pn = parse_version(old), parse_version(new)
    if po is None or pn is None or po.sort_key() == pn.sort_key():
        return None
    if pn.sort_key() < po.sort_key():
        return "downgrade"
    if pn.major != po.major:
        return "major"
    if pn.minor != po.minor:
        return "major" if pn.major == 0 else "minor"
    if pn.patch != po.patch:
        return "patch"
    return "prerelease"


@dataclass(frozen=True)
class LockEntry:
    """One entry of the lockfile ``packages`` map."""

    path: str
    name: str
    version: str | None
    resolved: str | None
    integrity: str | None
    source: str  # registry | git | file | link | workspace | unknown

    @property
    def depth(self) -> int:
        """Nesting depth: 1 for ``node_modules/a``, 2 for ``node_modules/a/node_modules/b``."""
        return self.path.count(NODE_MODULES)


@dataclass
class Lockfile:
    """A parsed lockfile."""

    lockfile_version: int
    entries: list[LockEntry] = field(default_factory=list)

    @property
    def registry_entries(self) -> list[LockEntry]:
        """Entries whose code comes from a registry tarball."""
        return [e for e in self.entries if e.source == "registry"]

    @property
    def non_registry_entries(self) -> list[LockEntry]:
        """Entries lockguard cannot download (git, file:, link:, workspaces ...)."""
        return [e for e in self.entries if e.source != "registry"]


def name_from_path(path: str) -> str | None:
    """Return the package name for an install path, or ``None`` for non-``node_modules`` keys.

    >>> name_from_path("node_modules/a/node_modules/@scope/b")
    '@scope/b'
    """
    idx = path.rfind(NODE_MODULES)
    if idx == -1:
        return None
    name = path[idx + len(NODE_MODULES) :]
    return name or None


def _classify(path: str, raw: dict[str, Any]) -> str:
    """Decide where an entry's code comes from."""
    if raw.get("link") is True:
        return "link"
    if NODE_MODULES not in path:
        return "workspace"
    resolved = raw.get("resolved")
    version = raw.get("version")
    for ref in (resolved, version):
        if isinstance(ref, str):
            for kind, prefixes in _NON_REGISTRY_PREFIXES:
                if ref.startswith(prefixes):
                    return kind
    if not isinstance(version, str) or parse_version(version) is None:
        return "unknown"
    if resolved is None or (
        isinstance(resolved, str) and resolved.startswith(("https://", "http://"))
    ):
        # A tarball URL. Whether its host is trustworthy is checked by the
        # `unexpected_source` rule, so an attacker cannot hide a package from analysis
        # simply by pointing `resolved` somewhere else.
        return "registry"
    return "unknown"


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def parse_lockfile(data: Any, source: str = "package-lock.json") -> Lockfile:
    """Parse the decoded JSON of a lockfile.

    Raises:
        LockfileError: for lockfile v1, unknown versions or malformed structure.
    """
    if not isinstance(data, dict):
        raise LockfileError(f"{source}: expected a JSON object at the top level")
    version = data.get("lockfileVersion")
    if version == 1 or ("packages" not in data and "dependencies" in data):
        raise LockfileError(
            f"{source}: lockfileVersion 1 is not supported. Regenerate the lockfile with "
            "npm 7 or newer, e.g. `npm install --package-lock-only --lockfile-version 3`."
        )
    if version not in (2, 3):
        raise LockfileError(f"{source}: unsupported lockfileVersion {version!r} (expected 2 or 3)")
    packages = data.get("packages")
    if not isinstance(packages, dict):
        raise LockfileError(f"{source}: missing or invalid 'packages' map")

    lockfile = Lockfile(lockfile_version=int(version))
    for path, raw in packages.items():
        if not isinstance(path, str) or path == "" or not isinstance(raw, dict):
            continue  # "" is the root project itself
        if raw.get("inBundle"):
            continue  # bundled deps ship inside the parent's tarball and are diffed with it
        source_kind = _classify(path, raw)
        declared_name = _opt_str(raw.get("name"))
        if source_kind == "workspace":
            name = declared_name or path
        else:
            # `name` is only present for aliases ("foo": "npm:bar@1") - it is the real name.
            name = declared_name or name_from_path(path) or path
        lockfile.entries.append(
            LockEntry(
                path=path,
                name=name,
                version=_opt_str(raw.get("version")),
                resolved=_opt_str(raw.get("resolved")),
                integrity=_opt_str(raw.get("integrity")),
                source=source_kind,
            )
        )
    return lockfile


def parse_lockfile_text(text: str, source: str = "package-lock.json") -> Lockfile:
    """Parse lockfile JSON text (raises LockfileError)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockfileError(f"{source}: invalid JSON ({exc})") from None
    return parse_lockfile(data, source)


def load_lockfile(path: str | Path) -> Lockfile:
    """Read and parse a lockfile from disk (raises LockfileError)."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise LockfileError(f"{p}: file not found") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise LockfileError(f"{p}: cannot read file ({exc})") from None
    return parse_lockfile_text(text, str(p))


def empty_lockfile() -> Lockfile:
    """A lockfile with no packages (used when the base branch has no lockfile yet)."""
    return Lockfile(lockfile_version=3)


def _index(lockfile: Lockfile) -> dict[str, dict[str, list[LockEntry]]]:
    """Map ``name -> version -> entries`` (shallowest install path first)."""
    index: dict[str, dict[str, list[LockEntry]]] = defaultdict(dict)
    for entry in sorted(lockfile.registry_entries, key=lambda e: (e.depth, e.path)):
        if entry.version is None:
            continue
        index[entry.name].setdefault(entry.version, []).append(entry)
    return index


def _pair_cost(old: str, new: str) -> tuple[int, ...]:
    """Lower is a more plausible "old was upgraded to new" pairing."""
    po, pn = parse_version(old), parse_version(new)
    if po is None or pn is None:
        return (2, 0, 0, 0, 0)
    below = 0 if po.sort_key() <= pn.sort_key() else 1
    return (
        0 if po.major == pn.major else 1,
        below,
        abs(po.major - pn.major),
        abs(po.minor - pn.minor),
        abs(po.patch - pn.patch),
    )


def _pair_versions(removed: list[str], added: list[str]) -> list[tuple[str | None, str | None]]:
    """Pair disappeared versions with new versions so each bump is diffed sensibly."""
    remaining = sorted(removed, key=version_sort_key)
    pairs: list[tuple[str | None, str | None]] = []
    for new in sorted(added, key=version_sort_key, reverse=True):
        if not remaining:
            pairs.append((None, new))
            continue
        best = min(remaining, key=partial(_pair_cost, new=new))
        remaining.remove(best)
        pairs.append((best, new))
    pairs.extend((old, None) for old in remaining)
    return pairs


def _kind(old: str | None, new: str | None) -> ChangeKind:
    if old is None:
        return ChangeKind.ADDED
    if new is None:
        return ChangeKind.REMOVED
    cmp = compare_versions(old, new)
    if cmp is None:
        return ChangeKind.REPLACED
    if cmp == 0:
        return ChangeKind.SOURCE_CHANGED
    return ChangeKind.UPGRADED if cmp < 0 else ChangeKind.DOWNGRADED


def compute_changes(old: Lockfile, new: Lockfile) -> tuple[list[PackageChange], list[SkippedEntry]]:
    """Compute every registry package that was added, removed, upgraded or downgraded.

    Also reports versions that stayed the same but whose ``resolved`` URL or ``integrity``
    hash changed - a classic lockfile-injection trick. Non-registry entries that are new or
    changed are returned separately as "not analyzed".
    """
    old_idx, new_idx = _index(old), _index(new)
    changes: list[PackageChange] = []

    for name in sorted(set(old_idx) | set(new_idx)):
        old_versions = old_idx.get(name, {})
        new_versions = new_idx.get(name, {})
        removed = [v for v in old_versions if v not in new_versions]
        added = [v for v in new_versions if v not in old_versions]

        for old_v, new_v in _pair_versions(removed, added):
            old_e = old_versions[old_v][0] if old_v is not None else None
            new_e = new_versions[new_v][0] if new_v is not None else None
            paths_src = new_versions[new_v] if new_v is not None else old_versions.get(old_v or "")
            changes.append(
                PackageChange(
                    name=name,
                    old_version=old_v,
                    new_version=new_v,
                    kind=_kind(old_v, new_v),
                    old_resolved=old_e.resolved if old_e else None,
                    old_integrity=old_e.integrity if old_e else None,
                    new_resolved=new_e.resolved if new_e else None,
                    new_integrity=new_e.integrity if new_e else None,
                    paths=tuple(e.path for e in (paths_src or [])),
                )
            )

        # Same version on both sides, but the tarball source or hash was edited.
        for version in sorted(set(old_versions) & set(new_versions), key=version_sort_key):
            old_sources = {(e.resolved, e.integrity) for e in old_versions[version]}
            for entry in new_versions[version]:
                if (entry.resolved, entry.integrity) in old_sources:
                    continue
                reference = old_versions[version][0]
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=version,
                        new_version=version,
                        kind=ChangeKind.SOURCE_CHANGED,
                        old_resolved=reference.resolved,
                        old_integrity=reference.integrity,
                        new_resolved=entry.resolved,
                        new_integrity=entry.integrity,
                        paths=(entry.path,),
                    )
                )
                break

    old_by_path = {e.path: e for e in old.entries}
    skipped: list[SkippedEntry] = []
    for entry in new.non_registry_entries:
        previous = old_by_path.get(entry.path)
        if previous is not None and (previous.version, previous.resolved, previous.source) == (
            entry.version,
            entry.resolved,
            entry.source,
        ):
            continue
        reason = {
            "git": "git dependency",
            "file": "local file: dependency",
            "link": "symlinked (link:) package",
            "workspace": "workspace package",
        }.get(entry.source, "unrecognised source")
        skipped.append(SkippedEntry(entry.name, entry.path, entry.version, reason))
    skipped.sort(key=lambda s: (s.name, s.path))
    return changes, skipped
