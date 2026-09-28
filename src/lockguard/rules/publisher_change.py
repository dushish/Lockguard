"""Was the new version published by a different npm account?

Account takeovers (phished maintainers, stolen tokens) publish from the victim's account,
but hostile takeovers of abandoned packages and many worm infections show up as a new
or rarely seen publisher.
"""

from __future__ import annotations

import re
from typing import Any

from lockguard.models import Finding, RuleContext, Severity

RULE_ID = "publisher_change"
DESCRIPTION = "_npmUser of the new version differs from the previous version's publisher"
SEVERITY = "high for a first-time publisher who was not a maintainer; medium/low otherwise"

_NAME_EMAIL_RE = re.compile(r"^\s*([^<]+?)\s*(?:<[^>]*>)?\s*$")


def publisher_of(meta: dict[str, Any] | None) -> str | None:
    """Return the ``_npmUser`` name of a packument version object."""
    if not meta:
        return None
    user = meta.get("_npmUser")
    if isinstance(user, dict):
        name = user.get("name")
        return name if isinstance(name, str) and name else None
    if isinstance(user, str):
        match = _NAME_EMAIL_RE.match(user)
        return match.group(1) if match else None
    return None


def previous_publishers(packument: dict[str, Any] | None, new_version: str) -> list[str]:
    """Publishers of all versions released before ``new_version``, most recent first."""
    if not packument:
        return []
    versions = packument.get("versions")
    times = packument.get("time")
    if not isinstance(versions, dict):
        return []
    times = times if isinstance(times, dict) else {}
    cutoff = times.get(new_version)
    ordered: list[tuple[str, str]] = []
    for version, meta in versions.items():
        if version == new_version or not isinstance(meta, dict):
            continue
        published = times.get(version)
        stamp = published if isinstance(published, str) else ""
        if isinstance(cutoff, str) and stamp and stamp > cutoff:
            continue  # released after the version we are looking at
        user = publisher_of(meta)
        if user:
            ordered.append((stamp, user))
    ordered.sort(reverse=True)
    result: list[str] = []
    for _, user in ordered:
        if user not in result:
            result.append(user)
    return result


def maintainers_of(meta: dict[str, Any] | None) -> set[str]:
    """Names in a version object's ``maintainers`` list."""
    people = meta.get("maintainers") if meta else None
    if not isinstance(people, list):
        return set()
    names: set[str] = set()
    for person in people:
        if isinstance(person, dict) and isinstance(person.get("name"), str):
            names.add(person["name"])
        elif isinstance(person, str) and (match := _NAME_EMAIL_RE.match(person)):
            names.add(match.group(1))
    return names


def check(ctx: RuleContext) -> list[Finding]:
    """Compare the publisher of the old and new version.

    * first release by an account that was not even a maintainer of the previous
      version: high;
    * first release by an account that was already listed as a maintainer: medium;
    * an account that has published this package before: low.
    """
    old_user = publisher_of(ctx.old_meta)
    new_user = publisher_of(ctx.new_meta)
    if not old_user or not new_user or old_user == new_user or ctx.new_version is None:
        return []
    history = previous_publishers(ctx.packument, ctx.new_version) or [old_user]
    if new_user not in history:
        others = ", ".join(f'"{u}"' for u in history[:3])
        message = f'published by "{new_user}", previous versions by {others} - first release from this account'
        if new_user in maintainers_of(ctx.old_meta):
            return [
                Finding(
                    RULE_ID,
                    Severity.MEDIUM,
                    message + f" (already a listed maintainer of {ctx.old_version})",
                )
            ]
        return [Finding(RULE_ID, Severity.HIGH, message)]
    return [
        Finding(
            RULE_ID,
            Severity.LOW,
            f'published by "{new_user}", previous version by "{old_user}" '
            "(this account has published the package before)",
        )
    ]
