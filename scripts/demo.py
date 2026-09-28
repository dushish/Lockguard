#!/usr/bin/env python3
"""Run the lockguard demo, optionally saving a screenshot for the README.

    python scripts/demo.py                 # same as `lockguard demo`
    python scripts/demo.py --format markdown
    python scripts/demo.py --svg docs/demo.svg   # regenerate the README screenshot

The demo analyzes the bundled, inert fixtures (tests/fixtures) with an in-memory fake
registry, so it needs no network access.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lockguard.cli import main  # noqa: E402


def save_svg(path: Path) -> int:
    """Render the pretty demo report to an SVG terminal screenshot."""
    from rich.console import Console

    from lockguard.config import Config
    from lockguard.demo import build_demo
    from lockguard.engine import analyze_changes
    from lockguard.lockfile import compute_changes
    from lockguard.models import RunReport, Severity
    from lockguard.report.pretty import render_pretty

    setup = build_demo()
    changes, skipped = compute_changes(setup.old_lockfile, setup.new_lockfile)
    reports = analyze_changes(changes, setup.registry, Config())
    console = Console(record=True, width=110, force_terminal=True, highlight=False)
    console.print("$ lockguard demo", style="bold green")
    render_pretty(RunReport(reports, skipped), console, fail_on=Severity.HIGH)
    path.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(path), title="lockguard demo")
    print(f"wrote {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--svg", type=Path)
    known, rest = parser.parse_known_args()
    if known.svg:
        raise SystemExit(save_svg(known.svg))
    raise SystemExit(main(["demo", *rest]))
