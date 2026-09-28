"""New code that spawns other programs."""

from __future__ import annotations

import re

from lockguard.models import Finding, RuleContext, Severity
from lockguard.rules._common import (
    Hit,
    added_code_lines,
    capability_severity,
    downgrade_if_existing,
    existing_capabilities,
    merge_hits,
)

RULE_ID = "process_exec"
DESCRIPTION = "new child_process usage, exec()/spawn()/execSync() calls"
SEVERITY = "high (low if the previous version already did the same)"

PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b(?:require|import)\s*\(\s*['\"`](?:node:)?child_process['\"`]\s*\)"),
        "loads child_process",
    ),
    (re.compile(r"\bfrom\s+['\"](?:node:)?child_process['\"]"), "imports child_process"),
    (re.compile(r"\bchild_process\b"), "references child_process"),
    (re.compile(r"\b(?:execSync|execFileSync|spawnSync|execFile)\s*\("), "synchronous/exec call"),
    # A bare exec( / spawn( - but not regex.exec(...) or a function definition.
    (re.compile(r"(?<![\w$.])(?<!function )exec\s*\("), "exec() call"),
    (re.compile(r"(?<![\w$.])(?<!function )spawn\s*\("), "spawn() call"),
    (
        re.compile(r"\b(?:cp|childProcess|child_process)\s*\.\s*(?:exec|spawn|fork)\w*\s*\("),
        "child_process method call",
    ),
    (
        re.compile(r"\bprocess\s*\.\s*binding\s*\(\s*['\"]spawn_sync"),
        "process.binding('spawn_sync')",
    ),
    (
        re.compile(r"\bBun\s*\.\s*spawn(?:Sync)?\s*\(|\bDeno\s*\.\s*(?:run|Command)\b"),
        "Bun/Deno spawn",
    ),
    (
        re.compile(
            r"\bsubprocess\s*\.\s*(?:run|Popen|call|check_output)\s*\(|\bos\s*\.\s*system\s*\("
        ),
        "Python subprocess",
    ),
)


def check(ctx: RuleContext) -> list[Finding]:
    """Flag process-spawning APIs in added code.

    Spawning processes is treated as one capability: if the previous version already
    spawned processes in any way, new spawning code is reported as low.
    """
    labels = {label for _, label in PATTERNS}
    existing = labels if existing_capabilities(ctx, PATTERNS) else set()
    hits: list[Hit] = []
    for line in added_code_lines(ctx):
        for pattern, label in PATTERNS:
            match = pattern.search(line.text)
            if match:
                severity, message = downgrade_if_existing(
                    capability_severity(ctx, Severity.HIGH), label, existing
                )
                hits.append(
                    Hit(line.path, line.lineno, line.text, match.start(), severity, message)
                )
    return merge_hits(RULE_ID, hits)
