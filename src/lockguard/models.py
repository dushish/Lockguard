"""Core data structures shared by every part of lockguard."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lockguard.diffing import PackageDiff


class Severity(enum.IntEnum):
    """How dangerous a finding is. Ordered, so severities can be compared with ``>=``."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Lower-case display name; ``NONE`` is shown as ``clean``."""
        return "clean" if self is Severity.NONE else self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse "low", "HIGH", "clean" etc. Raises ValueError for unknown names."""
        key = value.strip().upper()
        if key in ("CLEAN", "NONE"):
            return cls.NONE
        try:
            return cls[key]
        except KeyError:
            choices = ", ".join(s.label for s in cls if s is not cls.NONE)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from None


@dataclass(frozen=True)
class Finding:
    """One suspicious thing a rule noticed, with the evidence that triggered it."""

    rule: str
    severity: Severity
    message: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None

    @property
    def location(self) -> str:
        """``file:line``, ``file`` or an empty string when the finding is package-wide."""
        if self.file is None:
            return ""
        return f"{self.file}:{self.line}" if self.line is not None else self.file

    def sort_key(self) -> tuple[int, str, str, int]:
        """Most severe first, then by rule and location for stable output."""
        return (-int(self.severity), self.rule, self.file or "", self.line or 0)


class ChangeKind(enum.Enum):
    """How a package differs between the base and the new lockfile."""

    ADDED = "added"
    REMOVED = "removed"
    UPGRADED = "upgraded"
    DOWNGRADED = "downgraded"
    REPLACED = "replaced"  # versions that cannot be ordered with semver
    SOURCE_CHANGED = "source-changed"  # same version, different resolved URL or integrity


@dataclass(frozen=True)
class PackageChange:
    """A single ``name: old_version → new_version`` transition found in the lockfiles."""

    name: str
    old_version: str | None
    new_version: str | None
    kind: ChangeKind
    old_resolved: str | None = None
    old_integrity: str | None = None
    new_resolved: str | None = None
    new_integrity: str | None = None
    paths: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        """Human readable description of the change, e.g. ``1.0.0 → 1.0.1``."""
        if self.kind is ChangeKind.ADDED:
            return f"added {self.new_version}"
        if self.kind is ChangeKind.REMOVED:
            return f"removed {self.old_version}"
        if self.kind is ChangeKind.SOURCE_CHANGED:
            return f"{self.new_version} (source changed)"
        return f"{self.old_version} → {self.new_version}"

    @property
    def display_version(self) -> str:
        """The version that is analyzed: the new one, or the old one for removals."""
        return self.new_version or self.old_version or "?"


@dataclass(frozen=True)
class SkippedEntry:
    """A lockfile entry lockguard cannot analyze (git, file:, link:, workspace ...)."""

    name: str
    path: str
    version: str | None
    reason: str


@dataclass
class PackageReport:
    """All findings for one :class:`PackageChange`."""

    change: PackageChange
    findings: list[Finding] = field(default_factory=list)
    ignored: int = 0

    @property
    def risk(self) -> Severity:
        """Highest severity among the findings (``NONE`` when clean)."""
        return max((f.severity for f in self.findings), default=Severity.NONE)

    def rule_ids(self) -> list[str]:
        """Distinct rule ids in severity order, for compact summaries."""
        seen: list[str] = []
        for finding in sorted(self.findings, key=Finding.sort_key):
            if finding.rule not in seen:
                seen.append(finding.rule)
        return seen


@dataclass
class RunReport:
    """The result of one lockguard run: every analyzed package plus skipped entries."""

    packages: list[PackageReport]
    skipped: list[SkippedEntry] = field(default_factory=list)

    @property
    def verdict(self) -> Severity:
        """Highest risk across all packages."""
        return max((p.risk for p in self.packages), default=Severity.NONE)

    def sorted_packages(self) -> list[PackageReport]:
        """Riskiest packages first, then alphabetical."""
        return sorted(self.packages, key=lambda p: (-int(p.risk), p.change.name, p.change.label))

    def risk_counts(self) -> dict[Severity, int]:
        """Number of packages per risk level (only levels that occur)."""
        counts: dict[Severity, int] = {}
        for pkg in self.packages:
            counts[pkg.risk] = counts.get(pkg.risk, 0) + 1
        return counts

    def headline(self) -> str:
        """Short summary such as ``12 packages changed, 1 CRITICAL, 2 HIGH``."""
        total = len(self.packages)
        noun = "package" if total == 1 else "packages"
        counts = self.risk_counts()
        parts = [
            f"{counts[sev]} {sev.name}"
            for sev in sorted(counts, reverse=True)
            if sev is not Severity.NONE
        ]
        return f"{total} {noun} changed, " + (", ".join(parts) if parts else "all clean")


@dataclass(frozen=True)
class IntegrityFailure:
    """A downloaded tarball whose hash does not match the expected SRI integrity."""

    which: str  # "old" or "new"
    version: str
    expected: str
    actual: str
    source: str  # "lockfile" or "registry"


@dataclass
class RuleContext:
    """Everything a rule may look at for one package change.

    ``old_files`` / ``new_files`` map paths inside the tarball (without the leading
    ``package/``) to raw bytes; files over the scan limit are absent and only described in
    ``diff``. ``old_meta`` / ``new_meta`` are the per-version objects from the registry
    packument (``packument["versions"][version]``).
    """

    name: str
    old_version: str | None
    new_version: str | None
    old_files: dict[str, bytes]
    new_files: dict[str, bytes]
    diff: PackageDiff
    old_meta: dict[str, Any] | None
    new_meta: dict[str, Any] | None
    packument: dict[str, Any] | None = None
    integrity_failures: list[IntegrityFailure] = field(default_factory=list)
    new_resolved: str | None = None
    allowed_hosts: frozenset[str] = frozenset()
    now: datetime | None = None
    cache: dict[str, Any] = field(default_factory=dict, repr=False)  # shared by rules

    @property
    def has_baseline(self) -> bool:
        """True when an old version was downloaded, so "added" really means added."""
        return bool(self.old_files) or bool(self.diff.old_paths)
