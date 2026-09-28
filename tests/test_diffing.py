from __future__ import annotations

from lockguard.diffing import compute_diff, split_segments
from lockguard.tarball import LargeFile


def diff(old: dict[str, str], new: dict[str, str]):  # type: ignore[no-untyped-def]
    return compute_diff(
        {k: v.encode() for k, v in old.items()}, {k: v.encode() for k, v in new.items()}
    )


def test_added_and_changed_lines_with_line_numbers() -> None:
    d = diff({"a.js": "one\ntwo\nthree\n"}, {"a.js": "one\nTWO\nthree\nfour\n", "b.js": "x\n"})
    assert d.files["a.js"].status == "modified"
    assert d.files["a.js"].added_lines == [(2, "TWO"), (4, "four")]
    assert d.files["b.js"].status == "added"
    assert d.files["b.js"].added_lines == [(1, "x")]


def test_unchanged_and_removed_files() -> None:
    d = diff({"a.js": "same", "gone.js": "x"}, {"a.js": "same"})
    assert "a.js" not in d.files
    assert d.files["gone.js"].status == "removed"


def test_moved_or_reindented_code_is_not_added() -> None:
    d = diff({"a.js": "evil();\nok();\n"}, {"a.js": "ok();\n", "lib/b.js": "    evil();\n"})
    assert d.files["lib/b.js"].added_lines == []


def test_minified_lines_are_diffed_per_statement() -> None:
    statements = [f"var v{i}=f({i});" for i in range(100)]
    old_line = "".join(statements)
    new_line = "".join([*statements[:50], "steal(document.cookie);", *statements[50:]])
    d = diff({"m.js": old_line}, {"m.js": new_line})
    fd = d.files["m.js"]
    assert [text for _, text in fd.added_lines] == ["steal(document.cookie);"]
    assert fd.long_added_lines == [(1, len(new_line))]


def test_split_segments_round_trips() -> None:
    line = "a();b(){c,d};" + "x," * 600
    assert "".join(split_segments(line)) == line


def test_binary_and_large_files() -> None:
    d = compute_diff(
        {},
        {"bin.dat": b"\x00\x01"},
        old_large={"big.js": LargeFile(3_000_000, "aaa")},
        new_large={"big.js": LargeFile(3_100_000, "bbb"), "new.js": LargeFile(3_000_000, "c")},
    )
    assert d.files["bin.dat"].is_binary and d.files["bin.dat"].added_lines == []
    assert d.files["big.js"].status == "modified" and d.files["big.js"].too_large
    assert d.files["new.js"].status == "added"
