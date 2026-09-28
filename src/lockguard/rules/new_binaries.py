"""Native binaries, archives and other opaque files showing up in a package."""

from __future__ import annotations

import re

from lockguard.models import Finding, RuleContext, Severity

RULE_ID = "new_binaries"
DESCRIPTION = "added or changed .node/.exe/.dll/.so/.dylib/.wasm files, archives, binary or unscanned large files"
SEVERITY = "medium (low for an existing large file that changed)"

NATIVE_RE = re.compile(r"\.(?:node|exe|dll|so(?:\.\d+)*|dylib|wasm|bin|elf|scr|com|msi)$", re.I)
ARCHIVE_RE = re.compile(r"\.(?:zip|gz|tgz|tar|7z|rar|xz|bz2|zst|jar)$", re.I)
# Binary formats that are routinely shipped and carry little execution risk.
MEDIA_RE = re.compile(
    r"\.(?:png|jpe?g|gif|ico|icns|webp|avif|bmp|tiff?|woff2?|ttf|otf|eot|mp3|mp4|m4a|wav|ogg"
    r"|webm|flac|pdf|psd|cur|pbf|mvt)$",
    re.I,
)


def check(ctx: RuleContext) -> list[Finding]:
    """Flag added or modified binary-ish files."""
    findings: list[Finding] = []
    for fd in ctx.diff.changed_files():
        if fd.path.lower().endswith(".map"):
            continue  # source maps are never executed
        verb = "added" if fd.status == "added" else "changed"
        severity = Severity.MEDIUM
        if NATIVE_RE.search(fd.path):
            message = f"native binary / executable {verb} ({fd.size:,} bytes)"
        elif ARCHIVE_RE.search(fd.path):
            message = f"archive {verb} inside the package ({fd.size:,} bytes)"
        elif fd.too_large:
            message = f"large file {verb} ({fd.size / 1_048_576:.1f} MB) - content not scanned"
            if fd.status == "modified":
                severity = Severity.LOW  # an existing bundle that grew; still unscanned
        elif fd.is_binary and not MEDIA_RE.search(fd.path):
            message = f"binary file (contains NUL bytes) {verb} ({fd.size:,} bytes)"
        else:
            continue
        findings.append(Finding(RULE_ID, severity, message, fd.path))
    return findings
