"""Report renderers: pretty terminal output, Markdown for PR comments, and JSON."""

from __future__ import annotations

from lockguard.report.json_report import render_json
from lockguard.report.markdown import MARKER, render_markdown
from lockguard.report.pretty import make_console, render_pretty

__all__ = ["MARKER", "make_console", "render_json", "render_markdown", "render_pretty"]
