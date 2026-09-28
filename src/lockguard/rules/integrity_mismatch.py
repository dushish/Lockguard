"""Downloaded tarball does not match the SRI hash we expected.

npm itself refuses such a tarball, so a mismatch means the lockfile was edited to point at
different content, or something between you and the registry altered the download.
"""

from __future__ import annotations

from lockguard.models import Finding, RuleContext, Severity

RULE_ID = "integrity_mismatch"
DESCRIPTION = "tarball hash does not match the lockfile's integrity field"
SEVERITY = "critical"


def _short(sri: str) -> str:
    return sri if len(sri) <= 30 else sri[:27] + "..."


def check(ctx: RuleContext) -> list[Finding]:
    """Report every integrity failure recorded by the engine while downloading."""
    return [
        Finding(
            RULE_ID,
            Severity.CRITICAL,
            f"{failure.which} tarball ({failure.version}) does not match the {failure.source} "
            f"integrity: expected {_short(failure.expected)}, got {_short(failure.actual)}",
        )
        for failure in ctx.integrity_failures
    ]
