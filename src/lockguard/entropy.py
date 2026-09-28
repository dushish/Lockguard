"""Shannon entropy and string-literal extraction used by the obfuscation rule.

English text sits around 4.0-4.4 bits per character, hex around 4.0, while base64 or
encrypted payloads approach 6.0. Long literals above ~4.5 bits/char are therefore unusual
in hand-written source code.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator

_QUOTES = "'\"`"
# A "/" after one of these characters (or keywords) starts a regex literal, not a division.
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORD_RE = re.compile(
    r"(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await)\s*$"
)


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of ``text`` in bits per character (0.0 for empty input)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _skip_regex(line: str, start: int) -> int:
    """Return the index just after a regex literal starting at ``start`` (the ``/``)."""
    j, in_class = start + 1, False
    while j < len(line):
        char = line[j]
        if char == "\\":
            j += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            return j + 1
        j += 1
    return j


def iter_string_literals(line: str, min_length: int = 100) -> Iterator[tuple[int, str]]:
    """Yield ``(offset_of_opening_quote, content)`` for string literals on a line of code.

    A small left-to-right scanner that understands quotes, escapes, comments and regex
    literals well enough that code *between* two strings (common in minified bundles) is
    never mistaken for a string. Only literals of at least ``min_length`` characters are
    yielded; unterminated literals run to the end of the line.
    """
    i, n, prev = 0, len(line), ""
    while i < n:
        char = line[i]
        if char in _QUOTES:
            j = i + 1
            while j < n and line[j] != char:
                j += 2 if line[j] == "\\" else 1
            content = line[i + 1 : min(j, n)]
            if len(content) >= min_length:
                yield i, content
            i, prev = j + 1, char
            continue
        if char == "/" and i + 1 < n:
            nxt = line[i + 1]
            if nxt == "/":
                return  # line comment
            if nxt == "*":
                end = line.find("*/", i + 2)
                if end == -1:
                    return
                i = end + 2
                continue
            if (
                prev == ""
                or prev in _REGEX_PRECEDERS
                or _REGEX_KEYWORD_RE.search(line[max(0, i - 12) : i])
            ):
                i, prev = _skip_regex(line, i), "/"
                continue
        if not char.isspace():
            prev = char
        i += 1
