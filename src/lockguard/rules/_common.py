"""Shared helpers for the rules. (Leading underscore = not picked up as a rule.)"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from lockguard.diffing import split_lines
from lockguard.models import Finding, RuleContext, Severity

# Files whose added lines are scanned as code. Type declarations are never executed.
CODE_EXTENSIONS = frozenset(
    ".js .mjs .cjs .jsx .ts .mts .cts .tsx .sh .bash .zsh .ps1 .psm1 .bat .cmd .vbs .py".split()
)
_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
_HASH_COMMENT_EXTENSIONS = frozenset({".sh", ".bash", ".zsh", ".py", ".ps1", ".psm1"})

SNIPPET_WIDTH = 160

# Network primitives, shared by network_access, secret_access and obfuscation.
NETWORK_API_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w$.])fetch\s*\("), "fetch() call"),
    (re.compile(r"\bhttps?\s*\.\s*(?:request|get)\s*\("), "http(s).request/get call"),
    (
        re.compile(r"\b(?:net|tls)\s*\.\s*(?:connect|createConnection)\s*\("),
        "raw socket connection",
    ),
    (re.compile(r"\bdns\s*\.\s*(?:promises\s*\.\s*)?(?:lookup|resolve\w*|reverse)\b"), "DNS query"),
    (re.compile(r"\bXMLHttpRequest\b"), "XMLHttpRequest"),
    (re.compile(r"\bWebSocket\b"), "WebSocket"),
    (re.compile(r"\bnavigator\s*\.\s*sendBeacon\s*\("), "navigator.sendBeacon()"),
    (
        re.compile(
            r"\b(?:require|import)\s*\(\s*['\"`](?:node:)?(?:http|https|http2|net|tls|dgram|dns)"
            r"['\"`]\s*\)"
        ),
        "loads a networking module",
    ),
    (
        re.compile(r"\bfrom\s+['\"](?:node:)?(?:http|https|http2|net|tls|dgram|dns)['\"]"),
        "imports a networking module",
    ),
    (re.compile(r"\b(?:Invoke-WebRequest|Invoke-RestMethod|curl|wget)\b"), "command-line download"),
)


@dataclass(frozen=True)
class AddedLine:
    """One added line of code."""

    path: str
    lineno: int
    text: str


@dataclass(frozen=True)
class Hit:
    """A pattern match on an added line, before hits on the same line are merged."""

    path: str
    lineno: int
    text: str
    start: int
    severity: Severity
    message: str


def is_code_file(path: str) -> bool:
    """True if the file is JavaScript/TypeScript or a script that can be executed."""
    lower = path.lower()
    if lower.endswith(_DECLARATION_SUFFIXES):
        return False
    ext = posixpath.splitext(lower)[1]
    if ext in CODE_EXTENSIONS:
        return True
    # Extension-less executables such as bin/cli
    return ext == "" and (lower.startswith("bin/") or "/bin/" in lower)


def is_comment_line(path: str, text: str) -> bool:
    """True for lines that are only a comment (documentation mentioning ``fetch()`` etc.)."""
    stripped = text.lstrip()
    if stripped.startswith(("//", "#!")):
        return True
    if stripped.startswith(("/*", "*")) and len(stripped) < 400:
        return True
    ext = posixpath.splitext(path.lower())[1]
    return ext in _HASH_COMMENT_EXTENSIONS and stripped.startswith("#")


def added_code_lines(ctx: RuleContext) -> Iterator[AddedLine]:
    """Yield every added, non-comment line of every code file in the new version.

    For long lines the diff yields individual new statements; whether the line is a
    comment (e.g. an inline ``//# sourceMappingURL=data:...`` map) is decided on the full line.
    """
    for fd in ctx.diff.changed_files():
        if fd.is_binary or not is_code_file(fd.path):
            continue
        full_lines = new_file_lines(ctx, fd.path)
        for lineno, text in fd.added_lines:
            full = full_lines[lineno - 1] if 0 < lineno <= len(full_lines) else text
            if not is_comment_line(fd.path, full):
                yield AddedLine(fd.path, lineno, text)


def lines_by_file(ctx: RuleContext) -> dict[str, list[AddedLine]]:
    """Group :func:`added_code_lines` by file path."""
    grouped: dict[str, list[AddedLine]] = {}
    for line in added_code_lines(ctx):
        grouped.setdefault(line.path, []).append(line)
    return grouped


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def sanitize(text: str) -> str:
    """Replace control and bidi-override characters so snippets cannot mess up terminals."""
    return _CONTROL_RE.sub("\ufffd", text.replace("\t", " "))


def excerpt(text: str, start: int = 0, width: int = SNIPPET_WIDTH) -> str:
    """A readable window of ``text`` around ``start``, at most ``width`` characters."""
    stripped = text.strip()
    offset = max(0, start - (len(text) - len(text.lstrip())))
    if len(stripped) <= width:
        return sanitize(stripped)
    begin = max(0, min(offset - 40, len(stripped) - width))
    window = stripped[begin : begin + width - 2]
    prefix = "..." if begin > 0 else ""
    suffix = "..." if begin + width - 2 < len(stripped) else ""
    return sanitize(prefix + window + suffix)


def merge_hits(rule_id: str, hits: Iterable[Hit]) -> list[Finding]:
    """Combine hits on the same line into one finding with the highest severity."""
    grouped: dict[tuple[str, int], list[Hit]] = {}
    for hit in hits:
        grouped.setdefault((hit.path, hit.lineno), []).append(hit)
    findings: list[Finding] = []
    for (path, lineno), line_hits in grouped.items():
        messages: list[str] = []
        for hit in line_hits:
            if hit.message not in messages:
                messages.append(hit.message)
        first = min(line_hits, key=lambda h: h.start)
        findings.append(
            Finding(
                rule=rule_id,
                severity=max(h.severity for h in line_hits),
                message="; ".join(messages),
                file=path,
                line=lineno,
                snippet=excerpt(first.text, first.start),
            )
        )
    return findings


def package_json(files: dict[str, bytes]) -> dict[str, Any]:
    """Parse ``package.json`` from extracted files (empty dict if missing or invalid)."""
    raw = files.get("package.json")
    if raw is None:
        return {}
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def new_file_lines(ctx: RuleContext, path: str) -> list[str]:
    """Full lines of a file in the new version (cached per context)."""
    key = "new_lines:" + path
    cached = ctx.cache.get(key)
    if isinstance(cached, list):
        return cached
    data = ctx.new_files.get(path, b"")
    lines = split_lines(data.decode("utf-8", errors="replace")) if b"\x00" not in data else []
    ctx.cache[key] = lines
    return lines


def old_code_text(ctx: RuleContext) -> str:
    """All code of the *old* version joined into one string (cached per context)."""
    cached = ctx.cache.get("old_code_text")
    if isinstance(cached, str):
        return cached
    parts = [
        data.decode("utf-8", errors="replace")
        for path, data in sorted(ctx.old_files.items())
        if is_code_file(path) and b"\x00" not in data
    ]
    text = "\n".join(parts)
    ctx.cache["old_code_text"] = text
    return text


def existing_capabilities(
    ctx: RuleContext, patterns: Iterable[tuple[re.Pattern[str], str]]
) -> set[str]:
    """Labels of the patterns that already match somewhere in the old version's code.

    A capability the package already had (an HTTP client using ``fetch``, a bundler using
    ``child_process``) is far less alarming than one that appears for the first time.
    """
    text = old_code_text(ctx)
    if not text:
        return set()
    return {label for pattern, label in patterns if pattern.search(text)}


def capability_severity(ctx: RuleContext, severity: Severity) -> Severity:
    """Cap "capability" findings at medium for brand-new dependencies.

    Without a previous version every line is new, so using the network or spawning a
    process is simply what the package does - worth a look, not an alarm. Strong signals
    (obfuscated payloads, wallet hooks, raw IPs, install scripts) are not capped.
    """
    return min(severity, Severity.MEDIUM) if not ctx.has_baseline else severity


def downgrade_if_existing(
    severity: Severity, label: str, existing: set[str]
) -> tuple[Severity, str]:
    """Return ``(LOW, label + note)`` when the capability existed before, else unchanged."""
    if label in existing:
        return Severity.LOW, f"{label} (already used by the previous version)"
    return severity, label


def file_has_network_api(lines: Iterable[AddedLine]) -> bool:
    """True if any of the lines uses a networking primitive."""
    return any(pattern.search(line.text) for line in lines for pattern, _ in NETWORK_API_PATTERNS)
