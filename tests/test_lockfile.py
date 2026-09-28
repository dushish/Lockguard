from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import lockfile_data, lockfile_text
from lockguard.lockfile import (
    LockfileError,
    bump_level,
    compare_versions,
    compute_changes,
    load_lockfile,
    name_from_path,
    parse_lockfile,
    parse_lockfile_text,
    parse_version,
)
from lockguard.models import ChangeKind

REG = "https://registry.npmjs.org"


def entry(name: str, version: str, **extra: object) -> dict[str, object]:
    basename = name.rsplit("/", 1)[-1]
    return {
        "version": version,
        "resolved": f"{REG}/{name}/-/{basename}-{version}.tgz",
        "integrity": f"sha512-{name}-{version}",
        **extra,
    }


@pytest.mark.parametrize("version", [2, 3])
def test_parses_v2_and_v3(version: int) -> None:
    lock = parse_lockfile(lockfile_data({"node_modules/a": entry("a", "1.0.0")}, version))
    assert lock.lockfile_version == version
    [a] = lock.registry_entries
    assert (a.name, a.version, a.source) == ("a", "1.0.0", "registry")
    assert a.integrity == "sha512-a-1.0.0"


def test_v2_legacy_dependencies_section_is_ignored() -> None:
    data = lockfile_data({"node_modules/a": entry("a", "1.0.0")}, 2)
    data["dependencies"] = {"a": {"version": "1.0.0"}}
    assert [e.name for e in parse_lockfile(data).entries] == ["a"]


def test_nested_and_scoped_packages() -> None:
    lock = parse_lockfile(
        lockfile_data(
            {
                "node_modules/a": entry("a", "1.0.0"),
                "node_modules/a/node_modules/b": entry("b", "2.0.0"),
                "node_modules/@scope/c": entry("@scope/c", "3.0.0"),
                "node_modules/a/node_modules/@scope/d": entry("@scope/d", "4.0.0"),
            }
        )
    )
    names = {(e.name, e.depth) for e in lock.entries}
    assert names == {("a", 1), ("b", 2), ("@scope/c", 1), ("@scope/d", 2)}


def test_name_from_path() -> None:
    assert name_from_path("node_modules/@s/n") == "@s/n"
    assert name_from_path("node_modules/a/node_modules/b") == "b"
    assert name_from_path("packages/app") is None


def test_alias_uses_real_package_name() -> None:
    lock = parse_lockfile(
        lockfile_data(
            {
                "node_modules/string-width-cjs": {
                    **entry("string-width", "4.2.3"),
                    "name": "string-width",
                }
            }
        )
    )
    assert lock.entries[0].name == "string-width"


def test_non_registry_entries_are_classified() -> None:
    lock = parse_lockfile(
        lockfile_data(
            {
                "node_modules/g": {
                    "version": "1.0.0",
                    "resolved": "git+ssh://git@github.com/x/g.git#abc",
                },
                "node_modules/f": {"version": "file:../f", "resolved": "file:../f"},
                "node_modules/l": {"resolved": "packages/l", "link": True},
                "packages/l": {"name": "l", "version": "0.1.0"},
                "node_modules/r": entry("r", "1.0.0"),
            }
        )
    )
    sources = {e.path: e.source for e in lock.entries}
    assert sources == {
        "node_modules/g": "git",
        "node_modules/f": "file",
        "node_modules/l": "link",
        "packages/l": "workspace",
        "node_modules/r": "registry",
    }


def test_bundled_dependencies_are_skipped() -> None:
    lock = parse_lockfile(
        lockfile_data(
            {
                "node_modules/a": entry("a", "1.0.0"),
                "node_modules/a/node_modules/x": {"version": "1.0.0", "inBundle": True},
            }
        )
    )
    assert [e.name for e in lock.entries] == ["a"]


def test_missing_resolved_with_semver_is_registry() -> None:
    lock = parse_lockfile(lockfile_data({"node_modules/a": {"version": "1.2.3"}}))
    assert lock.entries[0].source == "registry"


def test_lockfile_v1_is_rejected_clearly() -> None:
    with pytest.raises(LockfileError, match="lockfileVersion 1"):
        parse_lockfile({"lockfileVersion": 1, "dependencies": {}})


@pytest.mark.parametrize(
    "text, message",
    [
        ("not json", "invalid JSON"),
        ("[]", "JSON object"),
        ('{"lockfileVersion": 9, "packages": {}}', "unsupported"),
        ('{"lockfileVersion": 3}', "packages"),
    ],
)
def test_invalid_lockfiles(text: str, message: str) -> None:
    with pytest.raises(LockfileError, match=message):
        parse_lockfile_text(text)


def test_load_lockfile_missing_file(tmp_path: Path) -> None:
    with pytest.raises(LockfileError, match="not found"):
        load_lockfile(tmp_path / "nope.json")


def test_load_lockfile_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "package-lock.json"
    path.write_text(lockfile_text({"node_modules/a": entry("a", "1.0.0")}))
    assert load_lockfile(path).entries[0].name == "a"


def test_semver_parsing_and_ordering() -> None:
    assert parse_version("1.2.3-beta.1+build.5") is not None
    assert parse_version("latest") is None
    assert compare_versions("1.0.0-alpha", "1.0.0") == -1
    assert compare_versions("1.0.0-alpha.2", "1.0.0-alpha.10") == -1
    assert compare_versions("2.0.0", "10.0.0") == -1
    assert compare_versions("1.0.0", "x") is None


@pytest.mark.parametrize(
    "old, new, level",
    [
        ("1.0.0", "1.0.1", "patch"),
        ("1.0.0", "1.1.0", "minor"),
        ("1.0.0", "2.0.0", "major"),
        ("0.3.0", "0.4.0", "major"),
        ("1.0.0-rc.1", "1.0.0", "prerelease"),
        ("1.0.1", "1.0.0", "downgrade"),
        ("1.0.0", "1.0.0", None),
    ],
)
def test_bump_level(old: str, new: str, level: str | None) -> None:
    assert bump_level(old, new) == level


def changes_between(old: dict[str, dict[str, object]], new: dict[str, dict[str, object]]):  # type: ignore[no-untyped-def]
    return compute_changes(parse_lockfile(lockfile_data(old)), parse_lockfile(lockfile_data(new)))


def test_upgrade_downgrade_added_removed() -> None:
    changes, skipped = changes_between(
        {
            "node_modules/up": entry("up", "1.0.0"),
            "node_modules/down": entry("down", "2.0.0"),
            "node_modules/gone": entry("gone", "1.0.0"),
        },
        {
            "node_modules/up": entry("up", "1.0.1"),
            "node_modules/down": entry("down", "1.9.0"),
            "node_modules/new": entry("new", "0.1.0"),
        },
    )
    kinds = {c.name: (c.kind, c.old_version, c.new_version) for c in changes}
    assert kinds == {
        "up": (ChangeKind.UPGRADED, "1.0.0", "1.0.1"),
        "down": (ChangeKind.DOWNGRADED, "2.0.0", "1.9.0"),
        "gone": (ChangeKind.REMOVED, "1.0.0", None),
        "new": (ChangeKind.ADDED, None, "0.1.0"),
    }
    assert skipped == []
    up = next(c for c in changes if c.name == "up")
    assert up.new_integrity == "sha512-up-1.0.1"
    assert up.paths == ("node_modules/up",)


def test_transitive_and_scoped_changes() -> None:
    changes, _ = changes_between(
        {"node_modules/a/node_modules/@s/b": entry("@s/b", "1.0.0")},
        {"node_modules/a/node_modules/@s/b": entry("@s/b", "1.1.0")},
    )
    assert [(c.name, c.label) for c in changes] == [("@s/b", "1.0.0 → 1.1.0")]


def test_rehoisting_is_not_a_change() -> None:
    changes, _ = changes_between(
        {"node_modules/a/node_modules/b": entry("b", "1.0.0")},
        {"node_modules/b": entry("b", "1.0.0")},
    )
    assert changes == []


def test_multiple_versions_are_paired_sensibly() -> None:
    changes, _ = changes_between(
        {
            "node_modules/x": entry("x", "1.0.0"),
            "node_modules/y/node_modules/x": entry("x", "2.0.0"),
        },
        {
            "node_modules/x": entry("x", "1.0.1"),
            "node_modules/y/node_modules/x": entry("x", "2.1.0"),
        },
    )
    pairs = sorted((c.old_version, c.new_version) for c in changes)
    assert pairs == [("1.0.0", "1.0.1"), ("2.0.0", "2.1.0")]


def test_same_version_with_edited_source_is_reported() -> None:
    evil = {
        **entry("a", "1.0.0"),
        "resolved": "https://evil.example/a-1.0.0.tgz",
        "integrity": "sha512-x",
    }
    changes, _ = changes_between({"node_modules/a": entry("a", "1.0.0")}, {"node_modules/a": evil})
    [change] = changes
    assert change.kind is ChangeKind.SOURCE_CHANGED
    assert change.new_resolved == "https://evil.example/a-1.0.0.tgz"
    assert change.old_resolved.startswith(REG)  # type: ignore[union-attr]


def test_changed_non_registry_entries_are_listed_as_skipped() -> None:
    git = {"version": "1.0.0", "resolved": "git+https://github.com/x/g.git#aaa"}
    git2 = {"version": "1.0.0", "resolved": "git+https://github.com/x/g.git#bbb"}
    same = {"version": "1.0.0", "resolved": "git+https://github.com/x/s.git#ccc"}
    changes, skipped = changes_between(
        {"node_modules/g": git, "node_modules/s": same},
        {
            "node_modules/g": git2,
            "node_modules/s": same,
            "node_modules/w": {"resolved": "w", "link": True},
        },
    )
    assert changes == []
    assert [(s.name, s.reason) for s in skipped] == [
        ("g", "git dependency"),
        ("w", "symlinked (link:) package"),
    ]


def test_demo_lockfiles_parse(demo_setup) -> None:  # type: ignore[no-untyped-def]
    changes, skipped = compute_changes(demo_setup.old_lockfile, demo_setup.new_lockfile)
    assert sorted(c.name for c in changes) == ["fake-logger", "fake-utils"]
    assert [s.name for s in skipped] == ["internal-tool"]
    assert json.dumps(demo_setup.new_lockfile_data)  # serializable
