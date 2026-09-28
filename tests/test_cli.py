"""End-to-end tests of the command line (no network: the HTTP layer is faked)."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conftest import FakeHTTP
from lockguard.cli import main
from lockguard.demo import DemoSetup, write_demo_lockfiles
from lockguard.registry import TransientRegistryError, packument_url


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def json_run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    code, out, _ = run(capsys, *argv, "--format", "json")
    return code, json.loads(out)


def by_name(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {p["name"]: p for p in report["packages"]}


def test_demo_pretty_output_and_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "demo", "--no-color")
    assert code == 1
    assert "lockguard report - 2 packages changed, 1 CRITICAL" in out
    assert "fake-logger" in out and "fake-utils" in out
    assert "Not analyzed (1)" in out and "internal-tool" in out


def test_demo_meets_acceptance_criteria(capsys: pytest.CaptureFixture[str]) -> None:
    code, report = json_run(capsys, "demo")
    assert code == 1
    packages = by_name(report)
    logger = packages["fake-logger"]
    assert logger["risk"] == "critical"
    assert len({f["rule"] for f in logger["findings"]}) >= 4
    assert packages["fake-utils"]["risk"] == "clean"
    assert packages["fake-utils"]["findings"] == []
    assert report["verdict"] == "critical" and report["failed"] is True


@pytest.fixture
def demo_files(tmp_path: Path, demo_setup: DemoSetup, fake_http: FakeHTTP) -> tuple[Path, Path]:
    fake_http.serve_demo(demo_setup)
    return write_demo_lockfiles(tmp_path, demo_setup)


def test_diff_flags_the_malicious_bump(
    capsys: pytest.CaptureFixture[str], demo_files: tuple[Path, Path], fake_http: FakeHTTP
) -> None:
    old, new = demo_files
    code, report = json_run(capsys, "diff", str(old), str(new))
    assert code == 1
    assert by_name(report)["fake-logger"]["risk"] == "critical"
    assert any(url.endswith("fake-logger-1.0.1.tgz") for url in fake_http.calls)


def test_diff_clean_bump_passes(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, demo_setup: DemoSetup, fake_http: FakeHTTP
) -> None:
    fake_http.serve_demo(demo_setup)
    new_data = copy.deepcopy(demo_setup.new_lockfile_data)
    new_data["packages"]["node_modules/fake-logger"] = copy.deepcopy(
        demo_setup.old_lockfile_data["packages"]["node_modules/fake-logger"]
    )
    (tmp_path / "old.json").write_text(json.dumps(demo_setup.old_lockfile_data))
    (tmp_path / "new.json").write_text(json.dumps(new_data))
    code, report = json_run(capsys, "diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"))
    assert code == 0
    assert [p["name"] for p in report["packages"]] == ["fake-utils"]
    assert report["verdict"] == "clean"


def test_fail_on_threshold_and_config_ignore(
    capsys: pytest.CaptureFixture[str], demo_files: tuple[Path, Path], tmp_path: Path
) -> None:
    old, new = demo_files
    assert run(capsys, "diff", str(old), str(new), "--fail-on", "critical")[0] == 1
    config = tmp_path / "rc.json"
    config.write_text(json.dumps({"ignore": [{"package": "fake-logger"}]}))
    code, report = json_run(capsys, "diff", str(old), str(new), "--config", str(config))
    assert code == 0
    assert by_name(report)["fake-logger"]["ignoredFindings"] > 0


def test_integrity_mismatch_is_critical(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, demo_setup: DemoSetup, fake_http: FakeHTTP
) -> None:
    fake_http.serve_demo(demo_setup)
    new_data = copy.deepcopy(demo_setup.new_lockfile_data)
    utils = new_data["packages"]["node_modules/fake-utils"]
    utils["integrity"] = demo_setup.integrity[("fake-logger", "1.0.0")]  # wrong hash
    (tmp_path / "old.json").write_text(json.dumps(demo_setup.old_lockfile_data))
    (tmp_path / "new.json").write_text(json.dumps(new_data))
    code, report = json_run(capsys, "diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"))
    assert code == 1
    rules = {f["rule"]: f["severity"] for f in by_name(report)["fake-utils"]["findings"]}
    assert rules["integrity_mismatch"] == "critical"


def test_untrusted_resolved_host_is_never_fetched(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, demo_setup: DemoSetup, fake_http: FakeHTTP
) -> None:
    fake_http.serve_demo(demo_setup)
    new_data = copy.deepcopy(demo_setup.new_lockfile_data)
    new_data["packages"]["node_modules/fake-utils"]["resolved"] = "https://evil.example/u.tgz"
    (tmp_path / "old.json").write_text(json.dumps(demo_setup.old_lockfile_data))
    (tmp_path / "new.json").write_text(json.dumps(new_data))
    code, report = json_run(capsys, "diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"))
    assert code == 1
    assert not any("evil.example" in url for url in fake_http.calls)
    assert "unexpected_source" in {f["rule"] for f in by_name(report)["fake-utils"]["findings"]}


def test_unpublished_version_is_reported_not_crashed(
    capsys: pytest.CaptureFixture[str], demo_files: tuple[Path, Path], fake_http: FakeHTTP
) -> None:
    old, new = demo_files
    del fake_http.routes["https://registry.npmjs.org/fake-utils/-/fake-utils-2.3.1.tgz"]
    code, report = json_run(capsys, "diff", str(old), str(new))
    utils = by_name(report)["fake-utils"]
    assert utils["risk"] == "high"
    assert "registry_unavailable" in {f["rule"] for f in utils["findings"]}
    assert code == 1


def test_network_errors_are_retried(
    capsys: pytest.CaptureFixture[str],
    demo_files: tuple[Path, Path],
    fake_http: FakeHTTP,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lockguard.registry.time.sleep", lambda _s: None)
    old, new = demo_files
    url = packument_url("fake-utils")
    body = fake_http.routes[url]
    attempts: list[int] = []
    real_call = fake_http.__call__

    def flaky(u: str, **kw: Any) -> bytes:
        if u == url and len(attempts) < 2:
            attempts.append(1)
            raise TransientRegistryError("connection reset")
        return real_call(u, **kw)

    monkeypatch.setattr("lockguard.registry.urlopen_bytes", flaky)
    code, report = json_run(capsys, "diff", str(old), str(new))
    assert len(attempts) == 2 and body
    assert by_name(report)["fake-utils"]["risk"] == "clean"
    assert code == 1  # fake-logger is still critical


def test_pkg_command(
    capsys: pytest.CaptureFixture[str], demo_setup: DemoSetup, fake_http: FakeHTTP
) -> None:
    fake_http.serve_demo(demo_setup)
    assert json_run(capsys, "pkg", "fake-utils", "2.3.0", "2.3.1")[0] == 0
    code, report = json_run(capsys, "pkg", "fake-logger", "1.0.0", "1.0.1")
    assert code == 1 and report["verdict"] == "critical"


def test_pkg_rejects_bad_input(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "pkg", "../etc", "1.0.0", "1.0.1")[0] == 2
    assert run(capsys, "pkg", "a", "1.0.0", "1.0.0")[0] == 2


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_command_reads_base_lockfile_and_base_config(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    demo_setup: DemoSetup,
    fake_http: FakeHTTP,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_http.serve_demo(demo_setup)
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
            check=True,
            capture_output=True,
        )

    git("init", "-q")
    (repo / "package-lock.json").write_text(json.dumps(demo_setup.old_lockfile_data))
    git("add", "package-lock.json")
    git("commit", "-q", "-m", "base")
    (repo / "package-lock.json").write_text(json.dumps(demo_setup.new_lockfile_data))
    # A config added by the PR itself must not be trusted.
    (repo / ".lockguardrc.json").write_text(json.dumps({"ignore": [{"package": "*"}]}))

    code, report = json_run(capsys, "git", "--base", "HEAD")
    assert code == 1
    assert by_name(report)["fake-logger"]["risk"] == "critical"

    git("add", ".lockguardrc.json")
    git("commit", "-q", "-m", "trusted config")
    code, report = json_run(capsys, "git", "--base", "HEAD")
    assert code == 0 and report["verdict"] == "clean"


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_command_errors(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    code, _, err = run(capsys, "git", "--base", "HEAD")
    assert code == 2 and "git show" in err
    assert run(capsys, "git", "--base", "--upload-pack=x")[0] == 2


def test_tool_errors_exit_2(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    v1 = tmp_path / "v1.json"
    v1.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    code, _, err = run(capsys, "diff", str(v1), str(v1))
    assert code == 2 and "lockfileVersion 1" in err
    assert run(capsys, "diff", str(tmp_path / "missing.json"), str(v1))[0] == 2
    bad_config = tmp_path / "bad.json"
    bad_config.write_text("{")
    assert run(capsys, "demo", "--config", str(bad_config))[0] == 2
    assert run(capsys, "no-such-command")[0] == 2
    assert run(capsys, "demo", "--fail-on", "extreme")[0] == 2


def test_version_and_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "--version")
    assert code == 0 and out.startswith("lockguard ")
    code, out, _ = run(capsys, "rules")
    assert code == 0 and "install_scripts" in out and "integrity_mismatch" in out


def test_markdown_format_is_valid(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "demo", "--format", "markdown")
    assert code == 1
    assert out.startswith("<!-- lockguard-report -->")
    assert out.count("```") % 2 == 0
