"""Colored terminal report built with rich.

All text coming from packages (names, snippets, messages) is wrapped in :class:`rich.text.Text`
objects, never interpreted as rich markup, so a malicious package cannot restyle or fake
the report.
"""

from __future__ import annotations

from typing import TextIO

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from lockguard.models import RunReport, Severity
from lockguard.rules._common import sanitize

SNIPPET_LIMIT = 160

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.NONE: "bold green",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "bold yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def make_console(*, no_color: bool = False, file: TextIO | None = None) -> Console:
    """Create the console used for pretty output (honors ``NO_COLOR`` too)."""
    return Console(file=file, no_color=no_color, highlight=False, emoji=False)


def badge(severity: Severity) -> Text:
    """A colored severity label such as `` CRITICAL ``."""
    label = severity.label if severity is Severity.NONE else severity.name
    return Text(f" {label} ", style=SEVERITY_STYLES[severity])


def truncate(text: str, limit: int = SNIPPET_LIMIT) -> str:
    """Shorten ``text`` to ``limit`` characters with an ellipsis."""
    text = sanitize(text)
    return text if len(text) <= limit else text[: limit - 1] + "..."


def render_pretty(report: RunReport, console: Console, *, fail_on: Severity | None = None) -> None:
    """Print the summary table followed by per-package details."""
    verdict = report.verdict
    header = Text("lockguard report - ", style="bold")
    header.append(report.headline(), style=SEVERITY_STYLES[verdict])
    console.print(header)

    if not report.packages:
        console.print(Text("No registry packages changed.", style="dim"))
    else:
        table = Table(box=box.SIMPLE_HEAVY, show_edge=False, pad_edge=False)
        table.add_column("Package", overflow="fold")
        table.add_column("Change", overflow="fold")
        table.add_column("Risk", no_wrap=True)
        table.add_column("Findings", overflow="fold")
        for pkg in report.sorted_packages():
            rules = ", ".join(pkg.rule_ids()) or "-"
            table.add_row(
                Text(sanitize(pkg.change.name)),
                Text(sanitize(pkg.change.label)),
                badge(pkg.risk),
                Text(rules, style="dim" if not pkg.findings else ""),
            )
        console.print(table)

    for pkg in report.sorted_packages():
        if not pkg.findings:
            continue
        console.print()
        title = Text(sanitize(f"{pkg.change.name}@{pkg.change.display_version}"), style="bold")
        title.append(f"  ({pkg.change.label})", style="dim")
        console.print(title)
        for finding in pkg.findings:
            line = Text("  ")
            line.append(
                f"[{finding.severity.label}]".ljust(11), style=SEVERITY_STYLES[finding.severity]
            )
            line.append(finding.rule.ljust(21), style="bold")
            if finding.location:
                line.append(sanitize(finding.location) + "  ", style="cyan")
            line.append(sanitize(finding.message))
            console.print(line)
            if finding.snippet:
                console.print(Text("      > " + truncate(finding.snippet), style="dim"))
        if pkg.ignored:
            console.print(Text(f"  ({pkg.ignored} finding(s) ignored by config)", style="dim"))

    if report.skipped:
        console.print()
        console.print(Text(f"Not analyzed ({len(report.skipped)}):", style="bold"))
        for entry in report.skipped:
            version = f"@{entry.version}" if entry.version else ""
            console.print(Text(sanitize(f"  - {entry.name}{version}  {entry.reason}"), style="dim"))

    console.print()
    footer = Text("Verdict: ", style="bold")
    footer.append_text(badge(verdict))
    if fail_on is not None:
        failed = verdict >= fail_on and verdict is not Severity.NONE
        footer.append(
            f"  ({'fails' if failed else 'passes'} threshold {fail_on.label})",
            style="bold red" if failed else "green",
        )
    console.print(footer)
