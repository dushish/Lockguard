"""Computing what was added or changed between two versions of a package.

The key guarantee for low false positives: a line only counts as *added* if its
(whitespace-stripped) text did not exist **anywhere** in the old version. Code that was
merely moved, re-indented or copied between files is therefore never reported.
"""

from __future__ import annotations

import difflib
import hashlib
import posixpath
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from lockguard.tarball import LargeFile

# Above this many lines difflib gets slow; the set-based filter alone is then used,
# which yields the same result because of the "text existed anywhere" rule.
_DIFFLIB_MAX_LINES = 20_000

# Minified bundles put thousands of statements on one line, so a one-character change
# would make the whole line "added". Lines longer than this are compared statement by
# statement instead, and only the statements that are new are reported.
SEGMENT_THRESHOLD = 500
_SEGMENT_SPLIT_RE = re.compile(r"(?<=[;{}])")
_SUBSEGMENT_SPLIT_RE = re.compile(r"(?<=,)")
_MAX_SEGMENT = 1000


@dataclass
class FileDiff:
    """How one file differs between the old and new version."""

    path: str
    status: str  # "added" | "modified" | "removed"
    is_binary: bool = False
    too_large: bool = False
    size: int = 0
    # (1-based line number, text). For long lines the text is one new statement of that
    # line, so a line number can appear several times.
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    long_added_lines: list[tuple[int, int]] = field(default_factory=list)  # (line, length)
    new_line_count: int = 0
    old_max_line_length: int = 0

    @property
    def extension(self) -> str:
        """Lower-case extension including the dot (``.js``), or empty string."""
        return posixpath.splitext(self.path.lower())[1]


@dataclass
class PackageDiff:
    """All file-level differences between two versions of a package."""

    files: dict[str, FileDiff] = field(default_factory=dict)
    old_paths: frozenset[str] = frozenset()
    new_paths: frozenset[str] = frozenset()
    old_line_counts: dict[str, int] = field(default_factory=dict)
    old_has_minified: bool = False

    def by_status(self, status: str) -> list[FileDiff]:
        """Files with the given status, sorted by path."""
        return [f for _, f in sorted(self.files.items()) if f.status == status]

    def changed_files(self) -> list[FileDiff]:
        """Added and modified files, sorted by path."""
        return [f for _, f in sorted(self.files.items()) if f.status in ("added", "modified")]

    def iter_added_lines(self) -> Iterator[tuple[str, int, str]]:
        """Yield ``(path, line_number, text)`` for every added line of every text file."""
        for fd in self.changed_files():
            for lineno, text in fd.added_lines:
                yield fd.path, lineno, text


def decode_text(data: bytes) -> str | None:
    """Decode file content as UTF-8 text, or return ``None`` if it looks binary."""
    if b"\x00" in data:
        return None
    return data.decode("utf-8", errors="replace")


def split_lines(text: str) -> list[str]:
    """Split on ``\\n`` (keeping editor-compatible line numbers) and drop ``\\r``."""
    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def split_segments(line: str) -> list[str]:
    """Split a long (minified) line into statement-sized pieces.

    Splits after ``;``, ``{`` and ``}``; pieces still longer than 1000 characters are
    split after commas as well. Joining the result gives back the original line.
    """
    pieces: list[str] = []
    for piece in _SEGMENT_SPLIT_RE.split(line):
        if len(piece) > _MAX_SEGMENT:
            pieces.extend(p for p in _SUBSEGMENT_SPLIT_RE.split(piece) if p)
        elif piece:
            pieces.append(piece)
    return pieces


def _added_line_numbers(old_lines: list[str], new_lines: list[str]) -> list[int]:
    """0-based indices of new lines that fall in insert/replace regions of the diff."""
    if len(old_lines) > _DIFFLIB_MAX_LINES or len(new_lines) > _DIFFLIB_MAX_LINES:
        return list(range(len(new_lines)))
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    indices: list[int] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            indices.extend(range(j1, j2))
    return indices


def compute_diff(
    old_files: Mapping[str, bytes],
    new_files: Mapping[str, bytes],
    old_large: Mapping[str, LargeFile] | None = None,
    new_large: Mapping[str, LargeFile] | None = None,
) -> PackageDiff:
    """Diff two extracted packages. `*_large` hold files too big to scan (path -> size/hash)."""
    old_large = old_large or {}
    new_large = new_large or {}
    diff = PackageDiff(
        old_paths=frozenset(old_files) | frozenset(old_large),
        new_paths=frozenset(new_files) | frozenset(new_large),
    )

    old_texts: dict[str, list[str]] = {}
    known_lines: set[str] = set()
    known_segments: set[str] = set()
    for path, data in old_files.items():
        text = decode_text(data)
        if text is None:
            continue
        lines = split_lines(text)
        old_texts[path] = lines
        diff.old_line_counts[path] = len(lines)
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            known_lines.add(stripped)
            if len(line) > SEGMENT_THRESHOLD:
                known_segments.update(seg for p in split_segments(line) if (seg := p.strip()))
        if any(len(line) > 1000 for line in lines):
            diff.old_has_minified = True

    old_hashes = {p: hashlib.sha256(d).hexdigest() for p, d in old_files.items()}
    old_hashes.update({p: lf.sha256 for p, lf in old_large.items()})

    for path, info in new_large.items():
        if old_hashes.get(path) == info.sha256:
            continue
        status = "modified" if path in diff.old_paths else "added"
        diff.files[path] = FileDiff(path, status, too_large=True, size=info.size)

    for path, data in new_files.items():
        if old_hashes.get(path) == hashlib.sha256(data).hexdigest():
            continue  # unchanged
        status = "modified" if path in diff.old_paths else "added"
        text = decode_text(data)
        fd = FileDiff(path, status, is_binary=text is None, size=len(data))
        if text is not None:
            new_lines = split_lines(text)
            fd.new_line_count = len(new_lines)
            old_lines = old_texts.get(path)
            if old_lines is not None:
                fd.old_max_line_length = max((len(line) for line in old_lines), default=0)
                candidates = _added_line_numbers(old_lines, new_lines)
            else:
                candidates = list(range(len(new_lines)))
            for idx in candidates:
                line = new_lines[idx]
                stripped = line.strip()
                if not stripped or stripped in known_lines:
                    continue
                if len(line) <= SEGMENT_THRESHOLD:
                    fd.added_lines.append((idx + 1, line))
                    continue
                new_segments = [
                    piece
                    for piece in split_segments(line)
                    if (seg := piece.strip())
                    and seg not in known_segments
                    and seg not in known_lines
                ]
                if new_segments:
                    fd.long_added_lines.append((idx + 1, len(line)))
                    fd.added_lines.extend((idx + 1, piece) for piece in new_segments)
        diff.files[path] = fd

    for path in diff.old_paths - diff.new_paths:
        diff.files[path] = FileDiff(path, "removed")
    return diff
