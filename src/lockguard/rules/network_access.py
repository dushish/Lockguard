"""New code that talks to the network, or hardcodes somewhere to talk to."""

from __future__ import annotations

import ipaddress
import re

from lockguard.models import Finding, RuleContext, Severity
from lockguard.rules._common import (
    NETWORK_API_PATTERNS,
    Hit,
    capability_severity,
    downgrade_if_existing,
    existing_capabilities,
    lines_by_file,
    merge_hits,
    old_code_text,
)

RULE_ID = "network_access"
DESCRIPTION = "new fetch/http/net/dns/XMLHttpRequest/WebSocket usage, hardcoded URLs or raw IPs"
SEVERITY = "medium; high with a new hardcoded destination; low if the old version did the same"

URL_RE = re.compile(r"\b(?:https?|wss?)://([A-Za-z0-9.-]+)(?::\d+)?")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
# An IPv4 address directly after a quote, slash or @ - avoids matching version numbers.
IP_RE = re.compile(rf"(?<=['\"`/@])({_OCTET}(?:\.{_OCTET}){{3}})(?=[:/'\"`]|$)")

# Hosts that appear in code as documentation links, XML namespaces and the like.
BENIGN_HOSTS = frozenset(
    {
        "github.com",
        "www.github.com",
        "gist.github.com",
        "docs.github.com",
        "npmjs.com",
        "www.npmjs.com",
        "npmjs.org",
        "docs.npmjs.com",
        "npm.im",
        "nodejs.org",
        "developer.mozilla.org",
        "mdn.io",
        "tc39.es",
        "w3.org",
        "www.w3.org",
        "whatwg.org",
        "html.spec.whatwg.org",
        "fetch.spec.whatwg.org",
        "json-schema.org",
        "opensource.org",
        "spdx.org",
        "semver.org",
        "tools.ietf.org",
        "datatracker.ietf.org",
        "www.ietf.org",
        "www.rfc-editor.org",
        "example.com",
        "www.example.com",
        "example.org",
        "example.net",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "unpkg.com",
        "jsr.io",
        "mths.be",
        "git.io",
        "bit.ly",
        "babeljs.io",
        "eslint.org",
        "typescriptlang.org",
        "www.typescriptlang.org",
        "react.dev",
        "reactjs.org",
        "fb.me",
        "vuejs.org",
        "stackoverflow.com",
        "en.wikipedia.org",
        "www.apache.org",
        "creativecommons.org",
        "schema.org",
        "purl.org",
        "ns.adobe.com",
        "www.gnu.org",
        "gnu.org",
    }
)


def _is_public_ip(value: str) -> bool:
    """Private, loopback, link-local, documentation and reserved ranges are not C2 servers."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _destinations(text: str) -> list[tuple[int, str, str]]:
    """``(offset, kind, value)`` for non-benign URLs and raw IPs on a line."""
    found: list[tuple[int, str, str]] = []
    for match in URL_RE.finditer(text):
        host = match.group(1).lower().rstrip(".")
        if host in BENIGN_HOSTS or host.endswith((".github.io", ".mozilla.org")):
            continue
        if re.fullmatch(r"[\d.]+", host):
            continue  # numeric hosts are reported by the IP check below
        found.append((match.start(), "url", host))
    for match in IP_RE.finditer(text):
        if _is_public_ip(match.group(1)):
            found.append((match.start(), "ip", match.group(1)))
    return found


def check(ctx: RuleContext) -> list[Finding]:
    """Flag networking primitives and hardcoded destinations in added code.

    * a networking API the old version never used: medium, high if the file also gains a
      new destination; an API the old version already used: low;
    * a new hardcoded URL: medium, high on the same line as a network call or in a file
      that gains a new networking capability;
    * a raw IP address: high.
    """
    existing = existing_capabilities(ctx, NETWORK_API_PATTERNS)
    old_text = old_code_text(ctx)
    old_hosts = {value for _, _, value in _destinations(old_text)} if old_text else set()
    hits: list[Hit] = []
    for path, lines in lines_by_file(ctx).items():
        api_lines: list[tuple[int, str, int, str]] = []
        dest_lines: list[tuple[int, str, int, str, str]] = []
        for line in lines:
            for pattern, label in NETWORK_API_PATTERNS:
                match = pattern.search(line.text)
                if match:
                    api_lines.append((line.lineno, line.text, match.start(), label))
            for offset, kind, value in _destinations(line.text):
                if value not in old_hosts:
                    dest_lines.append((line.lineno, line.text, offset, kind, value))

        new_capability = any(label not in existing for _, _, _, label in api_lines)
        api_line_numbers = {lineno for lineno, _, _, _ in api_lines}
        for lineno, text, start, label in api_lines:
            severity = capability_severity(ctx, Severity.HIGH if dest_lines else Severity.MEDIUM)
            severity, message = downgrade_if_existing(severity, label, existing)
            hits.append(Hit(path, lineno, text, start, severity, message))
        for lineno, text, start, kind, value in dest_lines:
            if kind == "ip":
                hits.append(
                    Hit(path, lineno, text, start, Severity.HIGH, f"hardcoded IP address {value}")
                )
            else:
                severity = capability_severity(
                    ctx,
                    Severity.HIGH
                    if lineno in api_line_numbers or new_capability
                    else Severity.MEDIUM,
                )
                hits.append(Hit(path, lineno, text, start, severity, f"hardcoded URL to {value}"))
    return merge_hits(RULE_ID, hits)
