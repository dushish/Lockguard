"""Checks for new or changed install-time scripts in package.json.

``preinstall``/``install``/``postinstall`` run on every ``npm install`` of the package, which
is how worms such as Shai-Hulud executed. ``prepare`` runs for git and local installs.
"""

from __future__ import annotations

import posixpath
import re

from lockguard.models import Finding, RuleContext, Severity
from lockguard.rules._common import excerpt, package_json

RULE_ID = "install_scripts"
DESCRIPTION = "preinstall/install/postinstall/prepare scripts added or changed in package.json"
SEVERITY = "high, critical if the script runs changed code or downloads something (prepare: medium)"

LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare")

_DOWNLOADER_RE = re.compile(
    r"\b(?:curl|wget|powershell|pwsh|Invoke-WebRequest|Invoke-Expression|iwr|iex|certutil"
    r"|bitsadmin)\b|\|\s*(?:ba|z)?sh\b|\bnode\s+(?:-e|--eval)\b|\b(?:ba)?sh\s+-c\b",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"[^\s'\"&|;<>()=]+")


def _scripts(files: dict[str, bytes]) -> dict[str, str]:
    scripts = package_json(files).get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {k: v for k, v in scripts.items() if isinstance(k, str) and isinstance(v, str)}


def referenced_changed_files(script: str, changed: set[str]) -> list[str]:
    """Paths mentioned in ``script`` that were added or modified in this release."""
    refs: list[str] = []
    for token in _TOKEN_RE.findall(script):
        candidate = token
        while candidate.startswith("./"):
            candidate = candidate[2:]
        candidate = posixpath.normpath(candidate)
        for option in (candidate, candidate + ".js", candidate + "/index.js"):
            if option in changed and option not in refs:
                refs.append(option)
                break
    return refs


def _line_of(text: str | None, needle: str) -> tuple[int | None, str | None]:
    if text is None:
        return None, None
    for number, line in enumerate(text.split("\n"), start=1):
        if needle in line:
            return number, excerpt(line)
    return None, None


def check(ctx: RuleContext) -> list[Finding]:
    """Flag new or changed lifecycle scripts and newly added ``binding.gyp`` files."""
    old_scripts = _scripts(ctx.old_files)
    new_scripts = _scripts(ctx.new_files)
    changed = {fd.path for fd in ctx.diff.changed_files()}
    raw_pkg = ctx.new_files.get("package.json")
    pkg_text = raw_pkg.decode("utf-8", errors="replace") if raw_pkg is not None else None
    findings: list[Finding] = []

    for hook in LIFECYCLE_HOOKS:
        script = new_scripts.get(hook)
        if script is None or old_scripts.get(hook) == script:
            continue
        verb = "changed" if hook in old_scripts else "new"
        severity = Severity.HIGH
        reasons: list[str] = []
        if _DOWNLOADER_RE.search(script):
            severity = Severity.CRITICAL
            reasons.append("downloads or pipes remote content")
        if ctx.has_baseline:
            # For a brand-new dependency every file is "added", so this escalation would
            # fire for every legitimate native module; only apply it to real updates.
            refs = referenced_changed_files(script, changed)
            if refs:
                severity = Severity.CRITICAL
                reasons.append(
                    f"runs {', '.join(refs)}, which was added or changed in this release"
                )
        if hook == "prepare":
            # npm does not run `prepare` when installing a registry tarball.
            severity = min(severity, Severity.MEDIUM)
            reasons.append("only runs for git and local installs, not registry installs")
        message = f'{verb} "{hook}" script: {script}'
        if reasons:
            message += " - " + "; ".join(reasons)
        line, snippet = _line_of(pkg_text, f'"{hook}"')
        findings.append(Finding(RULE_ID, severity, message, "package.json", line, snippet))

    added_gyp = [fd.path for fd in ctx.diff.by_status("added") if fd.path == "binding.gyp"]
    if added_gyp and not any(h in new_scripts for h in ("install", "preinstall")):
        findings.append(
            Finding(
                RULE_ID,
                Severity.HIGH,
                "binding.gyp added: npm will run `node-gyp rebuild` on install "
                "(an implicit install script)",
                "binding.gyp",
            )
        )
    return findings
