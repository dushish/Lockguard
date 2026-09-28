"""Machine-readable JSON report."""

from __future__ import annotations

import json
from typing import Any

from lockguard import __version__
from lockguard.models import RunReport, Severity


def report_to_dict(report: RunReport, *, fail_on: Severity | None = None) -> dict[str, Any]:
    """Convert a :class:`RunReport` into plain JSON-serializable data."""
    verdict = report.verdict
    data: dict[str, Any] = {
        "tool": "lockguard",
        "version": __version__,
        "verdict": verdict.label,
        "summary": {
            "packagesChanged": len(report.packages),
            "byRisk": {
                sev.label: n for sev, n in sorted(report.risk_counts().items(), reverse=True)
            },
        },
        "packages": [
            {
                "name": pkg.change.name,
                "change": pkg.change.kind.value,
                "oldVersion": pkg.change.old_version,
                "newVersion": pkg.change.new_version,
                "paths": list(pkg.change.paths),
                "risk": pkg.risk.label,
                "ignoredFindings": pkg.ignored,
                "findings": [
                    {
                        "rule": f.rule,
                        "severity": f.severity.label,
                        "message": f.message,
                        "file": f.file,
                        "line": f.line,
                        "snippet": f.snippet,
                    }
                    for f in pkg.findings
                ],
            }
            for pkg in report.sorted_packages()
        ],
        "notAnalyzed": [
            {"name": s.name, "path": s.path, "version": s.version, "reason": s.reason}
            for s in report.skipped
        ],
    }
    if fail_on is not None:
        data["failOn"] = fail_on.label
        data["failed"] = verdict >= fail_on and verdict is not Severity.NONE
    return data


def render_json(report: RunReport, *, fail_on: Severity | None = None) -> str:
    """Render the report as indented JSON text (with a trailing newline)."""
    return json.dumps(report_to_dict(report, fail_on=fail_on), indent=2, ensure_ascii=False) + "\n"
