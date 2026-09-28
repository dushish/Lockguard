"""Rule registry.

Every module in this package whose name does not start with ``_`` and which defines a
``check(ctx: RuleContext) -> list[Finding]`` function is a rule. Modules are discovered
automatically, so adding a rule means dropping a new file here - nothing else to edit.

Each rule module should also define:

* ``RULE_ID`` - the identifier used in reports and in ``.lockguardrc.json`` ignore entries;
* ``DESCRIPTION`` - one sentence for ``lockguard rules`` and the README;
* ``SEVERITY`` - the severity range, for documentation.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass

from lockguard.models import Finding, RuleContext, Severity

RuleCheck = Callable[[RuleContext], list[Finding]]


@dataclass(frozen=True)
class Rule:
    """A registered rule."""

    id: str
    description: str
    severity: str
    check: RuleCheck


def _discover() -> dict[str, Rule]:
    """Import every rule module in this package and collect its ``check`` function."""
    found: dict[str, Rule] = {}
    for info in pkgutil.iter_modules(__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        check = getattr(module, "check", None)
        if not callable(check):
            continue
        rule_id = str(getattr(module, "RULE_ID", info.name))
        found[rule_id] = Rule(
            id=rule_id,
            description=str(getattr(module, "DESCRIPTION", "")),
            severity=str(getattr(module, "SEVERITY", "")),
            check=check,
        )
    return dict(sorted(found.items()))


RULES: dict[str, Rule] = _discover()


def run_rules(ctx: RuleContext, rules: dict[str, Rule] | None = None) -> list[Finding]:
    """Run every rule against ``ctx``.

    A rule that raises is reported as a low-severity finding instead of aborting the run,
    so one buggy heuristic cannot hide the results of the others.
    """
    findings: list[Finding] = []
    for rule in (rules or RULES).values():
        try:
            findings.extend(rule.check(ctx))
        except Exception as exc:
            findings.append(
                Finding(rule.id, Severity.LOW, f"rule failed with {type(exc).__name__}: {exc}")
            )
    return findings


__all__ = ["RULES", "Rule", "RuleCheck", "run_rules"]
