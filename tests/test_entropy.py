from __future__ import annotations

import base64
import random

import pytest

from lockguard.entropy import iter_string_literals, shannon_entropy


@pytest.mark.parametrize(
    "text, expected",
    [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("abcd", 2.0), ("".join(map(chr, range(256))), 8.0)],
)
def test_known_values(text: str, expected: float) -> None:
    assert shannon_entropy(text) == pytest.approx(expected)


def test_base64_payload_is_high_and_prose_is_low() -> None:
    blob = base64.b64encode(random.Random(1).randbytes(600)).decode()
    prose = "The quick brown fox jumps over the lazy dog while the logger writes a line. " * 3
    assert shannon_entropy(blob) > 5.5
    assert shannon_entropy(prose) < 4.5


def test_finds_long_literals() -> None:
    literal = "x" * 120
    line = f"const a = '{literal}'; const b = \"short\";"
    assert list(iter_string_literals(line)) == [(10, literal)]


def test_code_between_strings_is_not_a_literal() -> None:
    # In minified code the text between a closing and the next opening quote is code.
    code = "+".join(f"f{i}(e)" for i in range(60))
    line = f'"a"==typeof e&&{code}||"b"'
    assert list(iter_string_literals(line, 50)) == []


def test_escapes_regexes_and_comments() -> None:
    long = "y" * 110
    assert [c for _, c in iter_string_literals(f"s = 'it\\'s {long}'")] == [f"it\\'s {long}"]
    # A quote inside a regex literal must not start a string.
    regex_line = "x = /[\"']/g.test(v) ? " + "a" * 150 + ' : "z"'
    assert list(iter_string_literals(regex_line)) == []
    assert list(iter_string_literals("// '" + "c" * 150 + "'")) == []
    assert list(iter_string_literals("/* '" + "c" * 150 + "' */")) == []


def test_min_length_filter() -> None:
    assert list(iter_string_literals("'" + "z" * 150 + "'", min_length=200)) == []
