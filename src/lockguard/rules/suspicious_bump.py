"""Small version bumps that change a suspicious amount of code, and very fresh releases.

Genuine patch releases are usually small. Malware injected into an existing package tends
to add a lot of code, or new files in places the package never used before. Brand-new
releases are also the riskiest: most malicious versions are detected and removed within
hours to days.
"""

from __future__ import annotations

import posixpath
from datetime import datetime, timezone

from lockguard.lockfile import bump_level
from lockguard.models import Finding, RuleContext, Severity
from lockguard.rules._common import added_code_lines, is_code_file

RULE_ID = "suspicious_bump"
DESCRIPTION = (
    "patch/minor bump adding > 30% new code or files outside the previous structure; "
    "versions published < 24 hours ago"
)
SEVERITY = "medium"

GROWTH_RATIO = 0.30
MIN_ADDED_LINES = 30
FRESH_HOURS = 24


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _ancestors(path: str) -> set[str]:
    dirs: set[str] = set()
    current = posixpath.dirname(path)
    while True:
        dirs.add(current)
        if not current:
            return dirs
        current = posixpath.dirname(current)


def _fresh_release(ctx: RuleContext) -> list[Finding]:
    if ctx.packument is None or ctx.new_version is None:
        return []
    times = ctx.packument.get("time")
    published = _parse_time(times.get(ctx.new_version)) if isinstance(times, dict) else None
    if published is None:
        return []
    now = ctx.now or datetime.now(timezone.utc)
    age_hours = (now - published).total_seconds() / 3600
    if not 0 <= age_hours < FRESH_HOURS:
        return []
    age = f"{age_hours * 60:.0f} minutes" if age_hours < 1 else f"{age_hours:.0f} hours"
    return [
        Finding(
            RULE_ID,
            Severity.MEDIUM,
            f"{ctx.new_version} was published {age} ago - most malicious releases are caught "
            "and removed within the first days; consider waiting",
        )
    ]


def check(ctx: RuleContext) -> list[Finding]:
    """Flag oversized small bumps, new directories in small bumps, and fresh releases."""
    findings = _fresh_release(ctx)
    if not ctx.has_baseline or ctx.old_version is None or ctx.new_version is None:
        return findings
    level = bump_level(ctx.old_version, ctx.new_version)
    if level not in ("patch", "minor", "prerelease"):
        return findings

    old_code_lines = sum(n for p, n in ctx.diff.old_line_counts.items() if is_code_file(p))
    added = len({(line.path, line.lineno) for line in added_code_lines(ctx)})
    if added >= MIN_ADDED_LINES and added > GROWTH_RATIO * max(old_code_lines, 1):
        pct = 100 * added / max(old_code_lines, 1)
        findings.append(
            Finding(
                RULE_ID,
                Severity.MEDIUM,
                f"{level} bump adds {added:,} new lines of code "
                f"(+{pct:.0f}% of the previous {old_code_lines:,})",
            )
        )

    known_dirs: set[str] = set()
    for path in ctx.diff.old_paths:
        known_dirs |= _ancestors(path)
    new_dirs: dict[str, int] = {}
    for fd in ctx.diff.by_status("added"):
        directory = posixpath.dirname(fd.path)
        if directory not in known_dirs:
            new_dirs[directory] = new_dirs.get(directory, 0) + 1
    if new_dirs:
        shown = ", ".join(
            f"{d}/ ({n} file{'s' if n != 1 else ''})" for d, n in sorted(new_dirs.items())[:5]
        )
        more = f" and {len(new_dirs) - 5} more" if len(new_dirs) > 5 else ""
        findings.append(
            Finding(
                RULE_ID,
                Severity.MEDIUM,
                f"{level} bump adds files outside the previous structure: {shown}{more}",
            )
        )
    return findings
