from __future__ import annotations

import pytest

from helpers import make_tarball, sri
from lockguard.tarball import (
    MAX_SCAN_BYTES,
    TarballError,
    compute_sri,
    extract_tarball,
    verify_integrity,
)

DATA = b"hello lockguard"


def test_compute_sri_matches_reference_helper() -> None:
    assert compute_sri(DATA) == sri(DATA)
    assert compute_sri(DATA).startswith("sha512-")


def test_verify_matching_sha512() -> None:
    ok, actual = verify_integrity(DATA, sri(DATA))
    assert ok and actual == sri(DATA)


def test_verify_mismatch_reports_actual_hash() -> None:
    ok, actual = verify_integrity(b"tampered", sri(DATA))
    assert not ok
    assert actual == sri(b"tampered")


def test_strongest_algorithm_wins() -> None:
    # A correct sha1 must not rescue a wrong sha512.
    integrity = f"{sri(DATA, 'sha1')} {sri(b'other')}"
    ok, actual = verify_integrity(DATA, integrity)
    assert not ok and actual.startswith("sha512-")


def test_legacy_sha1_and_options_suffix() -> None:
    assert verify_integrity(DATA, sri(DATA, "sha1"))[0]
    assert verify_integrity(DATA, sri(DATA) + "?foo")[0]


def test_any_of_multiple_hashes_of_same_algorithm() -> None:
    assert verify_integrity(DATA, f"{sri(b'x')} {sri(DATA)}")[0]


@pytest.mark.parametrize("bad", ["", "md5-abc", "sha512-!!!notbase64!!!", "garbage"])
def test_unsupported_integrity_raises(bad: str) -> None:
    with pytest.raises(ValueError):
        verify_integrity(DATA, bad)


def test_extract_strips_package_prefix_and_ignores_traversal() -> None:
    blob = make_tarball({"index.js": "x", "lib/a.js": "y", "../evil.js": "z"})
    contents = extract_tarball(blob)
    assert set(contents.files) == {"index.js", "lib/a.js"}


def test_extract_handles_non_standard_prefix() -> None:
    contents = extract_tarball(make_tarball({"index.d.ts": "x"}, prefix="node"))
    assert set(contents.files) == {"index.d.ts"}


def test_large_files_are_hashed_not_kept() -> None:
    big = b"a" * (MAX_SCAN_BYTES + 1)
    contents = extract_tarball(make_tarball({"big.js": big, "small.js": "ok"}))
    assert "big.js" not in contents.files
    assert contents.large["big.js"].size == len(big)
    assert contents.files["small.js"] == b"ok"


def test_corrupt_tarball_raises() -> None:
    with pytest.raises(TarballError):
        extract_tarball(b"definitely not a tarball")
