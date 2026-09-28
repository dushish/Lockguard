"""The analysis pipeline: fetch → verify → extract → diff → run rules → filter.

:func:`analyze_changes` is the main entry point; it analyzes package changes concurrently
(at most :data:`MAX_WORKERS` downloads at a time) and never raises for problems with an
individual package - those become findings instead.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from lockguard.config import Config
from lockguard.diffing import compute_diff
from lockguard.models import (
    ChangeKind,
    Finding,
    IntegrityFailure,
    PackageChange,
    PackageReport,
    RuleContext,
    Severity,
)
from lockguard.registry import (
    DEFAULT_ALLOWED_HOSTS,
    NotFoundError,
    RegistryError,
    RegistryLike,
    host_of,
    is_valid_package_name,
    is_valid_version,
    tarball_url,
)
from lockguard.rules import run_rules
from lockguard.rules.unexpected_source import expected_tarball_suffixes
from lockguard.tarball import TarballContents, TarballError, extract_tarball, verify_integrity

MAX_WORKERS = 6
MAX_FINDINGS_PER_RULE = 8

Progress = Callable[[str], None]


def allowed_hosts(registry: RegistryLike, config: Config) -> frozenset[str]:
    """Hosts tarballs may be downloaded from: npm, yarn's mirror, the configured registry
    and any ``allowedHosts`` from the config."""
    return DEFAULT_ALLOWED_HOSTS | {host_of(registry.registry_url)} | set(config.allowed_hosts)


def select_tarball_url(
    name: str, version: str, resolved: str | None, registry_url: str, hosts: frozenset[str]
) -> str | None:
    """Decide where to download ``name@version`` from.

    The lockfile's ``resolved`` URL is used only if it is HTTPS, on an allowed host and
    points at this exact package; otherwise the canonical registry URL is used. Returns
    ``None`` when ``resolved`` names a host that is not allowed - lockguard will not fetch
    attacker-chosen URLs (the ``unexpected_source`` rule reports it).
    """
    if resolved and resolved.startswith(("http://", "https://")):
        if host_of(resolved) not in hosts:
            return None
        path = urllib.parse.unquote(urllib.parse.urlsplit(resolved).path)
        if resolved.startswith("https://") and path.endswith(
            expected_tarball_suffixes(name, version)
        ):
            return resolved
    return tarball_url(name, version, registry_url)


@dataclass
class _Fetched:
    contents: TarballContents | None = None
    findings: list[Finding] = field(default_factory=list)
    integrity_failure: IntegrityFailure | None = None


def _dist_integrity(meta: dict[str, Any] | None) -> str | None:
    dist = meta.get("dist") if meta else None
    value = dist.get("integrity") if isinstance(dist, dict) else None
    return value if isinstance(value, str) and value else None


def _fetch_version(
    change: PackageChange,
    which: str,
    registry: RegistryLike,
    meta: dict[str, Any] | None,
    hosts: frozenset[str],
) -> _Fetched:
    """Download, verify and extract one side (old or new) of a change."""
    version = change.new_version if which == "new" else change.old_version
    resolved = change.new_resolved if which == "new" else change.old_resolved
    lock_integrity = change.new_integrity if which == "new" else change.old_integrity
    result = _Fetched()
    assert version is not None
    # Problems with the old side only reduce precision; problems with the new side hide code.
    miss = Severity.HIGH if which == "new" else Severity.LOW
    fail = Severity.MEDIUM if which == "new" else Severity.LOW

    if not is_valid_version(version):
        result.findings.append(
            Finding(
                "registry_unavailable", fail, f"{which} version {version!r} is not a valid version"
            )
        )
        return result
    url = select_tarball_url(change.name, version, resolved, registry.registry_url, hosts)
    if url is None:
        return result  # reported by the unexpected_source rule
    try:
        data = registry.tarball(url)
    except NotFoundError:
        result.findings.append(
            Finding(
                "registry_unavailable",
                miss,
                f"{which} tarball {change.name}@{version} is not available on the registry"
                + (
                    " - it may have been unpublished (npm removes malicious versions)"
                    if which == "new"
                    else "; the new version was analyzed without a baseline"
                ),
            )
        )
        return result
    except RegistryError as exc:
        result.findings.append(
            Finding("registry_unavailable", fail, f"could not download {which} tarball: {exc}")
        )
        return result

    expected, source = (
        (lock_integrity, "lockfile") if lock_integrity else (_dist_integrity(meta), "registry")
    )
    if expected:
        try:
            ok, actual = verify_integrity(data, expected)
        except ValueError:
            result.findings.append(
                Finding(
                    "integrity_mismatch",
                    Severity.LOW,
                    f"{which} integrity value uses no supported hash algorithm",
                )
            )
        else:
            if not ok:
                result.integrity_failure = IntegrityFailure(
                    which, version, expected, actual, source
                )

    try:
        result.contents = extract_tarball(data)
    except TarballError as exc:
        result.findings.append(
            Finding(
                "tarball_error",
                Severity.HIGH if which == "new" else Severity.LOW,
                f"{which} tarball could not be read: {exc}",
            )
        )
    return result


def _cap(findings: list[Finding]) -> list[Finding]:
    """Keep the report readable: at most MAX_FINDINGS_PER_RULE findings per rule.

    Findings are ordered by severity; a rule's suppressed findings are summarized in one
    extra entry placed right after that rule's last shown finding.
    """
    by_rule: dict[str, list[Finding]] = {}
    for finding in sorted(findings, key=Finding.sort_key):
        by_rule.setdefault(finding.rule, []).append(finding)
    shown: list[Finding] = []
    summaries: dict[str, Finding] = {}
    for rule, items in by_rule.items():
        shown.extend(items[:MAX_FINDINGS_PER_RULE])
        rest = items[MAX_FINDINGS_PER_RULE:]
        if rest:
            summaries[rule] = Finding(
                rule, max(f.severity for f in rest), f"... and {len(rest)} more similar finding(s)"
            )
    ordered: list[Finding] = []
    remaining = {rule: sum(1 for f in shown if f.rule == rule) for rule in by_rule}
    for finding in sorted(shown, key=Finding.sort_key):
        ordered.append(finding)
        remaining[finding.rule] -= 1
        if remaining[finding.rule] == 0 and finding.rule in summaries:
            ordered.append(summaries[finding.rule])
    return ordered


def analyze_change(
    change: PackageChange,
    registry: RegistryLike,
    config: Config,
    *,
    now: datetime | None = None,
) -> PackageReport:
    """Analyze a single package change and return its report (never raises).

    An unexpected internal error becomes a medium finding, so a package that could not be
    analyzed never silently shows up as clean.
    """
    try:
        return _analyze_change(change, registry, config, now=now)
    except Exception as exc:
        return PackageReport(
            change,
            [
                Finding(
                    "analysis_error",
                    Severity.MEDIUM,
                    f"lockguard could not analyze this package ({type(exc).__name__}: {exc})",
                )
            ],
        )


def _analyze_change(
    change: PackageChange,
    registry: RegistryLike,
    config: Config,
    *,
    now: datetime | None = None,
) -> PackageReport:
    report = PackageReport(change)
    if change.kind is ChangeKind.REMOVED or change.new_version is None:
        return report
    if not is_valid_package_name(change.name):
        report.findings.append(
            Finding(
                "registry_unavailable",
                Severity.HIGH,
                f"lockfile contains an invalid package name {change.name!r}",
            )
        )
        return report

    hosts = allowed_hosts(registry, config)
    findings: list[Finding] = []
    packument: dict[str, Any] | None = None
    try:
        packument = registry.packument(change.name)
    except NotFoundError:
        findings.append(
            Finding(
                "registry_unavailable",
                Severity.HIGH,
                f"{change.name} does not exist on the registry (it may have been removed)",
            )
        )
    except RegistryError as exc:
        findings.append(
            Finding("registry_unavailable", Severity.MEDIUM, f"could not fetch metadata: {exc}")
        )

    versions = packument.get("versions") if packument else None
    versions = versions if isinstance(versions, dict) else {}
    old_meta = versions.get(change.old_version) if change.old_version else None
    new_meta = versions.get(change.new_version)
    unlisted = packument is not None and not isinstance(new_meta, dict)
    if unlisted:
        findings.append(
            Finding(
                "registry_unavailable",
                Severity.HIGH,
                f"{change.new_version} is not listed in the registry metadata - it may have "
                "been unpublished (npm removes malicious versions)",
            )
        )
        new_meta = None
    old_meta = old_meta if isinstance(old_meta, dict) else None

    new = _fetch_version(change, "new", registry, new_meta, hosts)
    if unlisted:  # the missing tarball is the same problem; report it once
        new.findings = [f for f in new.findings if "not available on the registry" not in f.message]
    findings.extend(new.findings)
    old = _Fetched()
    if change.old_version is not None:
        old = _fetch_version(change, "old", registry, old_meta, hosts)
        findings.extend(old.findings)

    old_contents = old.contents or TarballContents()
    new_contents = new.contents or TarballContents()
    ctx = RuleContext(
        name=change.name,
        old_version=change.old_version,
        new_version=change.new_version,
        old_files=old_contents.files,
        new_files=new_contents.files,
        diff=compute_diff(
            old_contents.files, new_contents.files, old_contents.large, new_contents.large
        ),
        old_meta=old_meta,
        new_meta=new_meta,
        packument=packument,
        integrity_failures=[f for f in (new.integrity_failure, old.integrity_failure) if f],
        new_resolved=change.new_resolved,
        allowed_hosts=hosts,
        now=now,
    )
    findings.extend(run_rules(ctx))

    kept: list[Finding] = []
    for finding in findings:
        if config.is_ignored(change.name, change.new_version, finding):
            report.ignored += 1
        else:
            kept.append(finding)
    report.findings = _cap(kept)
    return report


def analyze_changes(
    changes: Iterable[PackageChange],
    registry: RegistryLike,
    config: Config,
    *,
    now: datetime | None = None,
    progress: Progress | None = None,
    max_workers: int = MAX_WORKERS,
) -> list[PackageReport]:
    """Analyze many changes concurrently; results are returned in input order."""
    items = list(changes)
    if not items:
        return []

    def work(change: PackageChange) -> PackageReport:
        if progress is not None and change.kind is not ChangeKind.REMOVED:
            progress(f"analyzing {change.name} {change.label}")
        return analyze_change(change, registry, config, now=now)

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        return list(pool.map(work, items))
