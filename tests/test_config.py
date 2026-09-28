from __future__ import annotations

import json
from pathlib import Path

import pytest

from lockguard.config import (
    Config,
    ConfigError,
    IgnoreRule,
    load_config,
    parse_config,
    parse_config_text,
)
from lockguard.engine import analyze_change
from lockguard.models import ChangeKind, Finding, PackageChange, Severity


def test_defaults_when_no_file(tmp_path: Path) -> None:
    config = load_config(search_dir=tmp_path)
    assert config == Config()
    assert config.fail_on is Severity.HIGH


def test_loads_file_from_search_dir(tmp_path: Path) -> None:
    (tmp_path / ".lockguardrc.json").write_text(
        json.dumps({"failOn": "medium", "ignore": [{"package": "a", "rule": "network_access"}]})
    )
    config = load_config(search_dir=tmp_path)
    assert config.fail_on is Severity.MEDIUM
    assert config.ignore == (IgnoreRule(package="a", rule="network_access"),)


def test_explicit_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.json")


@pytest.mark.parametrize(
    "data, message",
    [
        ({"failon": "high"}, "unknown key"),
        ({"failOn": "extreme"}, "unknown severity"),
        ({"failOn": "clean"}, "must be low"),
        ({"ignore": {}}, "must be a list"),
        ({"ignore": [{}]}, "at least"),
        ({"ignore": [{"package": "a", "rulez": "x"}]}, "unknown key"),
        ({"ignore": [{"package": 3}]}, "non-empty string"),
        ({"allowedHosts": "x"}, "allowedHosts"),
    ],
)
def test_invalid_configs(data: object, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config(data)


def test_invalid_json() -> None:
    with pytest.raises(ConfigError, match="invalid JSON"):
        parse_config_text("{")


def test_wildcards_and_version_matching() -> None:
    finding = Finding("network_access", Severity.MEDIUM, "x")
    assert IgnoreRule(package="@types/*").matches("@types/node", "1.0.0", finding)
    assert IgnoreRule(rule="network_*").matches("x", "1.0.0", finding)
    assert IgnoreRule(package="x", version="1.*").matches("x", "1.2.0", finding)
    assert not IgnoreRule(package="x", version="1.*").matches("x", "2.0.0", finding)
    assert not IgnoreRule(package="x", rule="obfuscation").matches("x", "1.0.0", finding)


def test_ignore_list_is_applied_by_the_engine(demo_setup) -> None:  # type: ignore[no-untyped-def]
    change = PackageChange(
        "fake-logger",
        "1.0.0",
        "1.0.1",
        ChangeKind.UPGRADED,
        new_integrity=demo_setup.integrity[("fake-logger", "1.0.1")],
        old_integrity=demo_setup.integrity[("fake-logger", "1.0.0")],
    )
    full = analyze_change(change, demo_setup.registry, Config())
    config = parse_config({"ignore": [{"package": "fake-logger", "rule": "secret_access"}]})
    filtered = analyze_change(change, demo_setup.registry, config)
    assert "secret_access" in full.rule_ids()
    assert "secret_access" not in filtered.rule_ids()
    assert filtered.ignored == sum(1 for f in full.findings if f.rule == "secret_access")
    assert filtered.risk is Severity.CRITICAL  # other rules still apply

    everything = parse_config({"ignore": [{"package": "fake-*"}]})
    assert analyze_change(change, demo_setup.registry, everything).risk is Severity.NONE
