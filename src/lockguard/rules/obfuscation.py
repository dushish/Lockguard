"""Heuristics for code that is trying not to be read.

Covers dynamic evaluation, decode-and-execute, escape-sequence soup, obfuscator.io-style
``_0x1a2b`` identifiers, base64 blobs, very long lines in previously readable files, and
long high-entropy string literals.
"""

from __future__ import annotations

import re

from lockguard.diffing import SEGMENT_THRESHOLD
from lockguard.entropy import iter_string_literals, shannon_entropy
from lockguard.models import Finding, RuleContext, Severity
from lockguard.rules._common import (
    AddedLine,
    Hit,
    capability_severity,
    downgrade_if_existing,
    existing_capabilities,
    lines_by_file,
    merge_hits,
    new_file_lines,
)

RULE_ID = "obfuscation"
DESCRIPTION = (
    "new eval/new Function/vm, decode-then-execute, hex/unicode escape soup, invisible Unicode, "
    "_0x identifiers, "
    "base64 blobs > 200 chars, lines > 1000 chars, high-entropy strings"
)
SEVERITY = "high (medium for long lines; low for escapes/entropy in already-minified files)"

ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_LENGTH = 100
MAX_WHITESPACE_RATIO = 0.05  # prose has lots of spaces; encoded payloads have none
BASE64_MIN_LENGTH = 200
LONG_LINE = 1000
HEX_ESCAPE_MIN = 20
UNICODE_ESCAPE_MIN = 40
OBFUSCATOR_IDENT_MIN = 5
INVISIBLE_MIN = 20

EVAL_LABEL = "eval() call"
FUNCTION_LABEL = "Function constructor (runs a string as code)"
VM_LABEL = "vm module executes a string as code"

EVAL_RE = re.compile(r"(?<![\w$.])eval\s*\(|\b(?:window|globalThis|global|self)\s*\.\s*eval\s*\(")
NEW_FUNCTION_RE = re.compile(r"\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(\s*['\"`]")
# `Function('return this')()` is the classic, harmless global-object polyfill.
_GLOBAL_THIS_POLYFILL_RE = re.compile(r"Function\s*\(\s*['\"`]return this['\"`]\s*\)")
VM_RE = re.compile(
    r"\bvm\s*\.\s*(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\("
    r"|\bnew\s+vm\s*\.\s*Script\s*\("
)
DYNAMIC_PATTERNS = ((EVAL_RE, EVAL_LABEL), (NEW_FUNCTION_RE, FUNCTION_LABEL), (VM_RE, VM_LABEL))

DECODE_RE = re.compile(r"\batob\s*\(|\bBuffer\s*\.\s*from\s*\([^;]*?['\"](?:base64|hex)['\"]")
EXEC_CONTEXT_RE = re.compile(
    r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*\w+|\bchild_process\b"
    r"|\brequire\s*\(\s*[^'\"`\s)]"
)
# Zero-width characters, word joiner, BOM and variation selectors (used to smuggle code
# that editors and diff views do not display).
INVISIBLE_RE = re.compile("[\u200b-\u200d\u2060\ufeff\ufe00-\ufe0f\U000e0100-\U000e01ef]")
HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}")
OBFUSCATOR_IDENT_RE = re.compile(r"\b_0x[0-9a-fA-F]{3,8}\b")
BASE64_RE = re.compile(
    rf"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{{{BASE64_MIN_LENGTH},}}={{0,2}}(?![A-Za-z0-9+/=])"
)
_MEDIA_DATA_URI_RE = re.compile(r"data:(?:image|font|audio|video)/[\w.+-]+;base64,")
_DATA_URI_RE = re.compile(
    r"data:(?:image|font|audio|video)/[\w.+-]+;base64,$|application/(?:x-)?font[\w-]*;base64,$"
)


def _looks_random(blob: str) -> bool:
    """Base64 payloads mix upper, lower and digits; long runs like ``AAAA...`` do not count."""
    return (
        any(c.isupper() for c in blob)
        and any(c.islower() for c in blob)
        and any(c.isdigit() for c in blob)
    )


def _minified_context(ctx: RuleContext, path: str) -> bool:
    """True if long lines in ``path`` are expected (the old code was already minified)."""
    if ".min." in path.lower():
        return True
    if not ctx.has_baseline:
        # A brand-new dependency: judge the file by itself.
        return any(len(line) > LONG_LINE for line in new_file_lines(ctx, path))
    fd = ctx.diff.files.get(path)
    if fd is not None and fd.status == "modified":
        return fd.old_max_line_length > LONG_LINE
    return ctx.diff.old_has_minified


def _file_hits(
    ctx: RuleContext, path: str, lines: list[AddedLine], existing: set[str]
) -> list[Hit]:
    hits: list[Hit] = []
    executes = any(EXEC_CONTEXT_RE.search(line.text) for line in lines)
    minified = _minified_context(ctx, path)
    # Escape-heavy tables are normal in bundles that were already minified.
    escape_high, escape_medium = (
        (Severity.LOW, Severity.LOW) if minified else (Severity.HIGH, Severity.MEDIUM)
    )
    blob_lines: set[int] = set()
    full_lines = new_file_lines(ctx, path)

    obf = [(line, m) for line in lines for m in OBFUSCATOR_IDENT_RE.finditer(line.text)]
    names = {m.group(0) for _, m in obf}
    if len(names) >= OBFUSCATOR_IDENT_MIN:
        first_line, first_match = obf[0]
        hits.append(
            Hit(
                path,
                first_line.lineno,
                first_line.text,
                first_match.start(),
                Severity.HIGH,
                f"obfuscator-style identifiers (_0x...): {len(obf)} occurrences of {len(names)} names",
            )
        )

    for line in lines:
        text = line.text

        def add(start: int, severity: Severity, message: str, _line: AddedLine = line) -> None:
            hits.append(Hit(path, _line.lineno, _line.text, start, severity, message))

        for pattern, label in DYNAMIC_PATTERNS:
            match = pattern.search(text)
            if match and not (label == FUNCTION_LABEL and _GLOBAL_THIS_POLYFILL_RE.search(text)):
                base = capability_severity(ctx, Severity.HIGH)
                add(match.start(), *downgrade_if_existing(base, label, existing))
        if (match := DECODE_RE.search(text)) and executes:
            add(
                match.start(),
                Severity.LOW if minified else capability_severity(ctx, Severity.HIGH),
                "decodes base64/hex in a file that also executes dynamic code",
            )

        hex_count = len(HEX_ESCAPE_RE.findall(text))
        if hex_count >= HEX_ESCAPE_MIN:
            add(0, escape_high, f"{hex_count} hex escape sequences (\\xNN) on one line")
        uni_count = len(UNICODE_ESCAPE_RE.findall(text))
        if uni_count >= UNICODE_ESCAPE_MIN:
            add(0, escape_medium, f"{uni_count} unicode escape sequences on one line")

        invisible = len(INVISIBLE_RE.findall(text))
        if invisible >= INVISIBLE_MIN:
            add(
                0,
                Severity.HIGH,
                f"{invisible} invisible Unicode characters (zero-width / variation selectors) "
                "- can hide code from reviewers",
            )

        blob_spans: list[tuple[int, int]] = []
        for match in BASE64_RE.finditer(text):
            blob = match.group(0)
            # Look at the full line: long lines arrive here split into statements.
            full = full_lines[line.lineno - 1] if line.lineno <= len(full_lines) else text
            at = full.find(blob)
            prefix = full[max(0, at - 80) : at] if at >= 0 else text[: match.start()][-80:]
            if not _looks_random(blob) or _DATA_URI_RE.search(prefix):
                continue
            blob_spans.append((match.start(), match.end()))
            add(
                match.start(),
                Severity.HIGH,
                f"base64 string of {len(blob):,} chars, entropy {shannon_entropy(blob):.1f}",
            )

        if blob_spans:
            blob_lines.add(line.lineno)

    hits.extend(_entropy_hits(ctx, path, lines, blob_lines, minified))
    return hits


def _new_spans(full: str, fragments: list[str]) -> list[tuple[int, int]]:
    """Character spans of the new fragments of a (long) line inside the full line."""
    spans: list[tuple[int, int]] = []
    pos = 0
    for fragment in fragments:
        idx = full.find(fragment, pos)
        if idx == -1:
            idx = full.find(fragment)
        if idx == -1:
            continue
        spans.append((idx, idx + len(fragment)))
        pos = idx + len(fragment)
    return spans


def _entropy_hits(
    ctx: RuleContext, path: str, lines: list[AddedLine], skip: set[int], minified: bool
) -> list[Hit]:
    """Long, space-free, high-entropy string literals in added code.

    Literals are tokenised on the *full* line so that minified code between two strings is
    never mistaken for a string; on long lines only literals overlapping new statements count.
    """
    hits: list[Hit] = []
    fragments: dict[int, list[str]] = {}
    for line in lines:
        fragments.setdefault(line.lineno, []).append(line.text)
    full_lines = new_file_lines(ctx, path)
    for lineno, pieces in fragments.items():
        if lineno in skip or lineno > len(full_lines):
            continue
        full = full_lines[lineno - 1]
        spans = [(0, len(full))] if len(full) <= SEGMENT_THRESHOLD else _new_spans(full, pieces)
        for start, literal in iter_string_literals(full, MIN_ENTROPY_LENGTH):
            begin, end = start + 1, start + 1 + len(literal)
            if not any(s < end and e > begin for s, e in spans):
                continue  # this string existed before
            if "${" in literal:
                continue  # template literal with interpolation: code, not data
            if _MEDIA_DATA_URI_RE.match(literal):
                continue  # an embedded image or font (but not data:text/javascript!)
            if sum(1 for c in literal if ord(c) > 126) > 0.1 * len(literal):
                continue  # character tables and translations, not encoded payloads
            spaces = sum(1 for c in literal if c.isspace())
            if spaces > MAX_WHITESPACE_RATIO * len(literal):
                continue  # prose and messages
            entropy = shannon_entropy(literal)
            if entropy > ENTROPY_THRESHOLD:
                hits.append(
                    Hit(
                        path,
                        lineno,
                        full,
                        start,
                        Severity.LOW if minified else Severity.HIGH,
                        f"high-entropy string of {len(literal):,} chars, entropy {entropy:.1f}",
                    )
                )
    return hits


def _long_line_hits(ctx: RuleContext, lines_by_path: dict[str, list[AddedLine]]) -> list[Hit]:
    """Very long added lines in files whose previous version was readable (one per file)."""
    hits: list[Hit] = []
    for path, lines in lines_by_path.items():
        fd = ctx.diff.files.get(path)
        if fd is None or _minified_context(ctx, path):
            continue
        present = {line.lineno for line in lines}
        lengths = dict(fd.long_added_lines)
        lengths.update(
            {line.lineno: len(line.text) for line in lines if len(line.text) > LONG_LINE}
        )
        long_lines = sorted(
            (n, size) for n, size in lengths.items() if size > LONG_LINE and n in present
        )
        if not long_lines:
            continue
        first, _ = long_lines[0]
        longest = max(size for _, size in long_lines)
        full_lines = new_file_lines(ctx, path)
        text = full_lines[first - 1] if first <= len(full_lines) else ""
        what = (
            f"line of {longest:,} chars"
            if len(long_lines) == 1
            else f"{len(long_lines)} lines over {LONG_LINE:,} chars (longest {longest:,})"
        )
        hits.append(
            Hit(
                path,
                first,
                text,
                0,
                Severity.MEDIUM,
                f"{what} in a file that was not minified before",
            )
        )
    return hits


def check(ctx: RuleContext) -> list[Finding]:
    """Flag obfuscation techniques in added code."""
    existing = existing_capabilities(ctx, DYNAMIC_PATTERNS)
    grouped = lines_by_file(ctx)
    hits: list[Hit] = []
    for path, lines in grouped.items():
        hits.extend(_file_hits(ctx, path, lines, existing))
    hits.extend(_long_line_hits(ctx, grouped))
    return merge_hits(RULE_ID, hits)
