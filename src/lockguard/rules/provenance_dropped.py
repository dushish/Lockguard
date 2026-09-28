"""Old version had npm provenance attestations, new one does not.

Packages published from CI with ``npm publish --provenance`` (or trusted publishing) carry
signed build attestations. An attacker publishing with a stolen token from their own
machine cannot produce them, so their sudden absence is a strong signal.
"""

from __future__ import annotations

from typing import Any

from lockguard.models import Finding, RuleContext, Severity

RULE_ID = "provenance_dropped"
DESCRIPTION = "the previous version had dist.attestations (provenance) and the new one does not"
SEVERITY = "high"


def has_attestations(meta: dict[str, Any] | None) -> bool:
    """True if a packument version object carries provenance attestations."""
    if not meta:
        return False
    dist = meta.get("dist")
    return isinstance(dist, dict) and bool(dist.get("attestations"))


def check(ctx: RuleContext) -> list[Finding]:
    """Flag a version that lost the provenance its predecessor had."""
    if ctx.new_meta is None or not has_attestations(ctx.old_meta):
        return []
    if has_attestations(ctx.new_meta):
        return []
    return [
        Finding(
            RULE_ID,
            Severity.HIGH,
            f"{ctx.old_version} was published with provenance attestations, "
            f"{ctx.new_version} has none - it may not have been built by the usual CI pipeline",
        )
    ]
