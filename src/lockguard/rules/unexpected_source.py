"""Checks where the lockfile says a tarball comes from.

Editing ``resolved`` in a lockfile is a known way to smuggle code into a project: the PR
diff shows an innocent-looking URL change, and ``npm ci`` installs whatever is there.
lockguard never downloads from an unapproved host; it reports it instead.
"""

from __future__ import annotations

import urllib.parse

from lockguard.models import Finding, RuleContext, Severity
from lockguard.registry import host_of

RULE_ID = "unexpected_source"
DESCRIPTION = "resolved URL on a non-registry host, over plain http, or pointing at another package"
SEVERITY = "high (medium for plain http)"


def expected_tarball_suffixes(name: str, version: str) -> tuple[str, ...]:
    """Path endings a registry tarball URL for ``name@version`` may have."""
    basename = name.rsplit("/", 1)[-1]
    return (f"/{name}/-/{basename}-{version}.tgz", f"/{name}/-/{name}-{version}.tgz")


def check(ctx: RuleContext) -> list[Finding]:
    """Validate the host, scheme and path of the new version's ``resolved`` URL."""
    url = ctx.new_resolved
    if not url or ctx.new_version is None:
        return []
    parts = urllib.parse.urlsplit(url)
    host = host_of(url)
    if host not in ctx.allowed_hosts:
        return [
            Finding(
                RULE_ID,
                Severity.HIGH,
                f"lockfile resolves {ctx.name}@{ctx.new_version} to non-registry host "
                f'"{host or url}" - not downloaded; add it to "allowedHosts" if it is your '
                "private registry",
                snippet=url,
            )
        ]
    findings: list[Finding] = []
    if parts.scheme != "https":
        findings.append(
            Finding(RULE_ID, Severity.MEDIUM, "resolved URL uses plain http", snippet=url)
        )
    path = urllib.parse.unquote(parts.path)
    if not path.endswith(expected_tarball_suffixes(ctx.name, ctx.new_version)):
        findings.append(
            Finding(
                RULE_ID,
                Severity.HIGH,
                f"resolved URL does not point at {ctx.name}@{ctx.new_version}'s tarball - "
                "the canonical tarball was analyzed instead",
                snippet=url,
            )
        )
    return findings
