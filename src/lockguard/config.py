"""Loading ``.lockguardrc.json``.

Example::

    {
      "failOn": "high",
      "ignore": [
        { "package": "some-pkg", "rule": "network_access" },
        { "package": "@types/*" },
        { "package": "esbuild", "rule": "install_scripts", "version": "0.2*" }
      ],
      "allowedHosts": ["npm.internal.example.com"]
    }

``package``, ``rule`` and ``version`` accept shell-style wildcards. An entry needs at least
``package`` or ``rule``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from lockguard.models import Finding, Severity

DEFAULT_CONFIG_NAME = ".lockguardrc.json"
_TOP_LEVEL_KEYS = frozenset({"$schema", "failOn", "ignore", "allowedHosts"})
_IGNORE_KEYS = frozenset({"package", "rule", "version", "reason"})


class ConfigError(Exception):
    """The configuration file is missing, unreadable or invalid."""


@dataclass(frozen=True)
class IgnoreRule:
    """Suppress findings matching all of the given (wildcard) fields."""

    package: str | None = None
    rule: str | None = None
    version: str | None = None

    def matches(self, package: str, version: str | None, finding: Finding) -> bool:
        """True if this entry suppresses ``finding`` for ``package@version``."""
        if self.package is not None and not fnmatchcase(package, self.package):
            return False
        if self.rule is not None and not fnmatchcase(finding.rule, self.rule):
            return False
        return self.version is None or (version is not None and fnmatchcase(version, self.version))


@dataclass(frozen=True)
class Config:
    """Effective lockguard configuration."""

    fail_on: Severity = Severity.HIGH
    ignore: tuple[IgnoreRule, ...] = ()
    allowed_hosts: tuple[str, ...] = ()

    def is_ignored(self, package: str, version: str | None, finding: Finding) -> bool:
        """True if any ignore entry matches the finding."""
        return any(rule.matches(package, version, finding) for rule in self.ignore)


def _optional_str(entry: dict[str, Any], key: str, where: str) -> str | None:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where}: '{key}' must be a non-empty string")
    return value


def parse_config(data: Any, source: str = DEFAULT_CONFIG_NAME) -> Config:
    """Validate decoded JSON and build a :class:`Config`.

    Raises:
        ConfigError: on unknown keys or wrongly typed values (typos should not silently
            disable protection).
    """
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a JSON object")
    unknown = sorted(set(data) - _TOP_LEVEL_KEYS)
    if unknown:
        raise ConfigError(f"{source}: unknown key(s): {', '.join(unknown)}")

    fail_on = Severity.HIGH
    if "failOn" in data:
        raw = data["failOn"]
        if not isinstance(raw, str):
            raise ConfigError(f"{source}: 'failOn' must be a string")
        try:
            fail_on = Severity.parse(raw)
        except ValueError as exc:
            raise ConfigError(f"{source}: {exc}") from None
        if fail_on is Severity.NONE:
            raise ConfigError(f"{source}: 'failOn' must be low, medium, high or critical")

    ignore: list[IgnoreRule] = []
    raw_ignore = data.get("ignore", [])
    if not isinstance(raw_ignore, list):
        raise ConfigError(f"{source}: 'ignore' must be a list")
    for index, entry in enumerate(raw_ignore):
        where = f"{source}: ignore[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: must be an object")
        bad = sorted(set(entry) - _IGNORE_KEYS)
        if bad:
            raise ConfigError(f"{where}: unknown key(s): {', '.join(bad)}")
        rule = IgnoreRule(
            package=_optional_str(entry, "package", where),
            rule=_optional_str(entry, "rule", where),
            version=_optional_str(entry, "version", where),
        )
        if rule.package is None and rule.rule is None:
            raise ConfigError(f"{where}: needs at least 'package' or 'rule'")
        ignore.append(rule)

    raw_hosts = data.get("allowedHosts", [])
    if not isinstance(raw_hosts, list) or not all(isinstance(h, str) and h for h in raw_hosts):
        raise ConfigError(f"{source}: 'allowedHosts' must be a list of host names")
    hosts = tuple(h.strip().lower() for h in raw_hosts)

    return Config(fail_on=fail_on, ignore=tuple(ignore), allowed_hosts=hosts)


def parse_config_text(text: str, source: str = DEFAULT_CONFIG_NAME) -> Config:
    """Parse config JSON text; raises ConfigError on bad JSON or settings."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{source}: invalid JSON ({exc})") from None
    return parse_config(data, source)


def load_config(path: str | Path | None = None, *, search_dir: Path | None = None) -> Config:
    """Load configuration.

    Args:
        path: explicit config file; it must exist.
        search_dir: directory in which to look for ``.lockguardrc.json`` when ``path`` is
            not given (defaults to the current directory). A missing file means defaults.

    Raises:
        ConfigError: if an explicit file is missing or any file is invalid.
    """
    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"{p}: config file not found")
    else:
        p = (search_dir or Path.cwd()) / DEFAULT_CONFIG_NAME
        if not p.is_file():
            return Config()
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{p}: cannot read file ({exc})") from None
    return parse_config_text(text, str(p))
