"""Test helpers: in-memory tarballs, SRI hashes, lockfile builders and rule contexts.

Nothing here touches the network or the file system (except where a test passes a
``tmp_path``).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from typing import Any

from lockguard.diffing import compute_diff
from lockguard.models import Finding, RuleContext
from lockguard.registry import DEFAULT_ALLOWED_HOSTS

FileMap = dict[str, "str | bytes"]


def _to_bytes(content: str | bytes) -> bytes:
    return content.encode("utf-8") if isinstance(content, str) else content


def make_tarball(files: FileMap, prefix: str = "package") -> bytes:
    """Build a gzipped npm-style tarball in memory with ``tarfile`` + ``io.BytesIO``."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, content in sorted(files.items()):
            data = _to_bytes(content)
            info = tarfile.TarInfo(f"{prefix}/{path}" if prefix else path)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def sri(data: bytes, algorithm: str = "sha512") -> str:
    """Subresource-Integrity string for ``data``."""
    return f"{algorithm}-{base64.b64encode(hashlib.new(algorithm, data).digest()).decode()}"


def lockfile_data(packages: dict[str, dict[str, Any]], version: int = 3) -> dict[str, Any]:
    """A lockfile dict with a root entry plus ``packages``."""
    return {
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": version,
        "requires": True,
        "packages": {"": {"name": "app", "version": "1.0.0"}, **packages},
    }


def lockfile_text(packages: dict[str, dict[str, Any]], version: int = 3) -> str:
    """Same as :func:`lockfile_data`, serialized."""
    return json.dumps(lockfile_data(packages, version))


def package_json(**fields: Any) -> str:
    """A package.json document."""
    data = {"name": "pkg", "version": "1.0.0", **fields}
    return json.dumps(data, indent=2)


def make_ctx(
    old: FileMap | None,
    new: FileMap,
    *,
    name: str = "pkg",
    old_version: str | None = "1.0.0",
    new_version: str = "1.0.1",
    old_meta: dict[str, Any] | None = None,
    new_meta: dict[str, Any] | None = None,
    packument: dict[str, Any] | None = None,
    **extra: Any,
) -> RuleContext:
    """Build a :class:`RuleContext` from old/new file maps (``old=None`` = new package)."""
    old_files = {k: _to_bytes(v) for k, v in (old or {}).items()}
    new_files = {k: _to_bytes(v) for k, v in new.items()}
    return RuleContext(
        name=name,
        old_version=old_version if old is not None else None,
        new_version=new_version,
        old_files=old_files,
        new_files=new_files,
        diff=compute_diff(old_files, new_files),
        old_meta=old_meta,
        new_meta=new_meta,
        packument=packument,
        allowed_hosts=extra.pop("allowed_hosts", DEFAULT_ALLOWED_HOSTS),
        **extra,
    )


def rules_of(findings: list[Finding]) -> set[str]:
    """Distinct rule ids in a list of findings."""
    return {f.rule for f in findings}
