"""Snapshot of the Markdown PR comment for the demo.

If the report format changes on purpose, regenerate the snapshot with::

    LOCKGUARD_UPDATE_SNAPSHOTS=1 pytest tests/test_markdown_snapshot.py
"""

from __future__ import annotations

import os
from pathlib import Path

from lockguard.config import Config
from lockguard.demo import DemoSetup
from lockguard.engine import analyze_changes
from lockguard.lockfile import compute_changes
from lockguard.models import (
    ChangeKind,
    Finding,
    PackageChange,
    PackageReport,
    RunReport,
    Severity,
    SkippedEntry,
)
from lockguard.report.markdown import MARKER, render_markdown

SNAPSHOT = Path(__file__).parent / "snapshots" / "demo-report.md"


def demo_markdown(setup: DemoSetup) -> str:
    changes, skipped = compute_changes(setup.old_lockfile, setup.new_lockfile)
    reports = analyze_changes(changes, setup.registry, Config())
    return render_markdown(RunReport(reports, skipped), fail_on=Severity.HIGH)


def test_demo_markdown_matches_snapshot(demo_setup: DemoSetup) -> None:
    rendered = demo_markdown(demo_setup)
    if os.environ.get("LOCKGUARD_UPDATE_SNAPSHOTS"):
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(rendered, encoding="utf-8")
    assert rendered == SNAPSHOT.read_text(encoding="utf-8")


def test_untrusted_text_is_escaped() -> None:
    change = PackageChange("evil|<img src=x>", "1.0.0", "1.0.1", ChangeKind.UPGRADED)
    finding = Finding(
        "obfuscation",
        Severity.HIGH,
        "msg",
        "a.js",
        1,
        snippet="```\n## fake heading\x1b[31m",
    )
    report = RunReport(
        [PackageReport(change, [finding])],
        [SkippedEntry("x|y", "node_modules/x", None, "git dependency")],
    )
    text = render_markdown(report)
    assert text.startswith(MARKER)
    assert "evil\\|\\<img src=x\\>" in text
    assert "\x1b" not in text
    assert text.count("```") == 2  # the snippet cannot close the code block
    assert "x\\|y" in text


def test_many_clean_packages_are_collapsed() -> None:
    reports = [
        PackageReport(PackageChange(f"p{i:02}", "1.0.0", "1.0.1", ChangeKind.UPGRADED))
        for i in range(40)
    ]
    text = render_markdown(RunReport(reports))
    assert "more clean packages" in text
    assert "40 packages changed, all clean" in text
