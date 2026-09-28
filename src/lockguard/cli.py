"""Command-line interface.

Exit codes: 0 = pass, 1 = findings at or above the ``--fail-on`` threshold, 2 = tool error.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

from lockguard import __version__
from lockguard.config import (
    DEFAULT_CONFIG_NAME,
    Config,
    ConfigError,
    load_config,
    parse_config_text,
)
from lockguard.engine import analyze_changes
from lockguard.lockfile import (
    Lockfile,
    LockfileError,
    compare_versions,
    compute_changes,
    empty_lockfile,
    load_lockfile,
    parse_lockfile_text,
)
from lockguard.models import ChangeKind, PackageChange, RunReport, Severity
from lockguard.registry import RegistryClient, RegistryLike, is_valid_package_name
from lockguard.report import make_console, render_json, render_markdown, render_pretty
from lockguard.rules import RULES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class GitError(Exception):
    """Running ``git`` failed."""


class UsageError(Exception):
    """Invalid command-line input that argparse cannot catch."""


def _err(message: str) -> None:
    print(f"lockguard: error: {message}", file=sys.stderr)


def _log(args: argparse.Namespace, message: str) -> None:
    if getattr(args, "verbose", False):
        print(f"lockguard: {message}", file=sys.stderr)


def git_show(ref: str, path: str, *, cwd: Path | None = None) -> str | None:
    """Return the content of ``path`` at ``ref`` (``None`` if the file does not exist there).

    ``path`` is interpreted relative to the current directory, like ``git show ref:./path``.

    Raises:
        GitError: if git is missing, the ref is unknown, or the command fails otherwise.
    """
    if not ref or ref.startswith("-"):
        raise GitError(f"invalid git ref {ref!r}")
    rel = path if not os.path.isabs(path) else os.path.relpath(path, cwd or Path.cwd())
    spec = f"{ref}:./{Path(rel).as_posix().removeprefix('./')}"
    try:
        proc = subprocess.run(
            ["git", "show", spec], cwd=cwd, capture_output=True, check=False, timeout=120
        )
    except FileNotFoundError:
        raise GitError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise GitError(f"git show {spec} timed out") from None
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        if "does not exist in" in stderr or "exists on disk, but not in" in stderr:
            return None
        raise GitError(f"git show {spec} failed: {stderr or f'exit {proc.returncode}'}")
    return proc.stdout.decode("utf-8", errors="replace")


def _resolve_fail_on(args: argparse.Namespace, config: Config) -> Severity:
    return Severity.parse(args.fail_on) if args.fail_on else config.fail_on


def _emit(report: RunReport, args: argparse.Namespace, fail_on: Severity) -> None:
    if args.format == "json":
        sys.stdout.write(render_json(report, fail_on=fail_on))
    elif args.format == "markdown":
        sys.stdout.write(render_markdown(report, fail_on=fail_on))
    else:
        console = make_console(no_color=args.no_color, file=sys.stdout)
        render_pretty(report, console, fail_on=fail_on)
    sys.stdout.flush()


def _exit_code(report: RunReport, fail_on: Severity) -> int:
    verdict = report.verdict
    return EXIT_FINDINGS if verdict is not Severity.NONE and verdict >= fail_on else EXIT_OK


def _registry_client(tmp: str) -> RegistryClient:
    return RegistryClient(cache_dir=Path(tmp) / "cache")


def run_lockfiles(
    old: Lockfile,
    new: Lockfile,
    registry: RegistryLike,
    config: Config,
    args: argparse.Namespace,
) -> int:
    """Diff two parsed lockfiles, analyze the changes, print the report, return exit code."""
    changes, skipped = compute_changes(old, new)
    _log(args, f"{len(changes)} package change(s), {len(skipped)} entr(y/ies) not analysable")
    reports = analyze_changes(
        changes, registry, config, progress=(lambda m: _log(args, m)) if args.verbose else None
    )
    report = RunReport(packages=reports, skipped=skipped)
    fail_on = _resolve_fail_on(args, config)
    _emit(report, args, fail_on)
    return _exit_code(report, fail_on)


def cmd_diff(args: argparse.Namespace) -> int:
    """``lockguard diff OLD NEW``"""
    config = load_config(args.config)
    old = load_lockfile(args.old_lockfile)
    new = load_lockfile(args.new_lockfile)
    with tempfile.TemporaryDirectory(prefix="lockguard-") as tmp:
        return run_lockfiles(old, new, _registry_client(tmp), config, args)


def cmd_git(args: argparse.Namespace) -> int:
    """``lockguard git [--base REF]``: base lockfile from git, new one from the working tree."""
    base_text = git_show(args.base, args.lockfile)
    if base_text is None:
        _log(args, f"{args.lockfile} does not exist at {args.base}; treating every package as new")
        old = empty_lockfile()
    else:
        old = parse_lockfile_text(base_text, f"{args.base}:{args.lockfile}")
    new = load_lockfile(args.lockfile)

    if args.config:
        config = load_config(args.config)
    else:
        # Read the config from the *base* revision: in CI the working tree is the pull
        # request, and a malicious PR must not be able to add ignore rules for itself.
        config_path = str(Path(args.lockfile).parent / DEFAULT_CONFIG_NAME)
        config_text = git_show(args.base, config_path)
        config = (
            parse_config_text(config_text, f"{args.base}:{config_path}")
            if config_text is not None
            else Config()
        )
        if config_text is None and Path(config_path).is_file():
            _log(args, f"ignoring {config_path} from the working tree (not present at {args.base})")
    with tempfile.TemporaryDirectory(prefix="lockguard-") as tmp:
        return run_lockfiles(old, new, _registry_client(tmp), config, args)


def cmd_pkg(args: argparse.Namespace) -> int:
    """``lockguard pkg NAME OLD NEW``: analyze one version bump straight from the registry."""
    if not is_valid_package_name(args.name):
        raise UsageError(f"invalid package name {args.name!r}")
    if args.old_version == args.new_version:
        raise UsageError("old and new version are identical")
    cmp = compare_versions(args.old_version, args.new_version)
    kind = (
        ChangeKind.REPLACED
        if cmp is None
        else ChangeKind.UPGRADED
        if cmp < 0
        else ChangeKind.DOWNGRADED
    )
    change = PackageChange(args.name, args.old_version, args.new_version, kind)
    config = load_config(args.config)
    with tempfile.TemporaryDirectory(prefix="lockguard-") as tmp:
        reports = analyze_changes(
            [change],
            _registry_client(tmp),
            config,
            progress=(lambda m: _log(args, m)) if args.verbose else None,
        )
    report = RunReport(packages=reports)
    fail_on = _resolve_fail_on(args, config)
    _emit(report, args, fail_on)
    return _exit_code(report, fail_on)


def cmd_demo(args: argparse.Namespace) -> int:
    """``lockguard demo``: run the full pipeline against the bundled inert fixtures."""
    from lockguard.demo import build_demo

    setup = build_demo()
    config = load_config(args.config) if args.config else Config()
    return run_lockfiles(setup.old_lockfile, setup.new_lockfile, setup.registry, config, args)


def cmd_rules(args: argparse.Namespace) -> int:
    """``lockguard rules``: list the available rules."""
    width = max(len(rule_id) for rule_id in RULES)
    for rule in RULES.values():
        print(f"{rule.id.ljust(width)}  [{rule.severity}]\n{' ' * width}  {rule.description}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format", choices=("pretty", "markdown", "json"), default="pretty", help="output format"
    )
    common.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default=None,
        help="exit 1 if any finding is at least this severe (default: config or 'high')",
    )
    common.add_argument(
        "--config", metavar="PATH", help=f"config file (default: {DEFAULT_CONFIG_NAME})"
    )
    common.add_argument("--no-color", action="store_true", help="disable colors")
    common.add_argument("--verbose", "-v", action="store_true", help="log progress to stderr")

    parser = argparse.ArgumentParser(
        prog="lockguard",
        description="Inspect npm dependency updates for malicious-looking code before you merge.",
        epilog="Exit codes: 0 = pass, 1 = findings at or above threshold, 2 = tool error.",
    )
    parser.add_argument("--version", action="version", version=f"lockguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_diff = sub.add_parser("diff", parents=[common], help="compare two lockfiles")
    p_diff.add_argument("old_lockfile", help="base package-lock.json")
    p_diff.add_argument("new_lockfile", help="updated package-lock.json")
    p_diff.set_defaults(func=cmd_diff)

    p_git = sub.add_parser(
        "git", parents=[common], help="compare the lockfile at a git ref with the working tree"
    )
    p_git.add_argument("--base", default="origin/main", help="base ref (default: origin/main)")
    p_git.add_argument(
        "--lockfile", default="package-lock.json", help="lockfile path (default: package-lock.json)"
    )
    p_git.set_defaults(func=cmd_git)

    p_pkg = sub.add_parser("pkg", parents=[common], help="analyze one version bump directly")
    p_pkg.add_argument("name")
    p_pkg.add_argument("old_version")
    p_pkg.add_argument("new_version")
    p_pkg.set_defaults(func=cmd_pkg)

    p_demo = sub.add_parser("demo", parents=[common], help="run against the bundled test fixtures")
    p_demo.set_defaults(func=cmd_demo)

    p_rules = sub.add_parser("rules", help="list the detection rules")
    p_rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``lockguard`` console script. Returns the exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse: --help/--version exit 0, usage errors exit 2
        return int(exc.code) if isinstance(exc.code, int) else EXIT_ERROR
    try:
        return int(args.func(args))
    except (LockfileError, ConfigError, GitError, UsageError, FileNotFoundError) as exc:
        _err(str(exc))
    except KeyboardInterrupt:
        _err("interrupted")
    except Exception as exc:
        if getattr(args, "verbose", False):
            traceback.print_exc()
        _err(f"unexpected {type(exc).__name__}: {exc}")
    return EXIT_ERROR
