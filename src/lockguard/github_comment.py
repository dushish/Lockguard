"""Post or update the single lockguard comment on a GitHub pull request.

Used by ``action.yml``::

    python -m lockguard.github_comment --repo owner/name --pr 42 --body-file report.md

The token is read from ``$GITHUB_TOKEN``; the API base from ``$GITHUB_API_URL`` (so GitHub
Enterprise works). An existing comment containing the report marker is edited in place,
so repeated pushes to a PR do not pile up comments.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from lockguard import __version__
from lockguard.report.markdown import MARKER

DEFAULT_API = "https://api.github.com"


class GitHubError(Exception):
    """A GitHub API request failed."""


def _request(method: str, url: str, token: str, payload: dict[str, Any] | None = None) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"lockguard/{__version__}",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise GitHubError(f"{method} {url}: HTTP {exc.code} {detail}") from None
    except urllib.error.URLError as exc:
        raise GitHubError(f"{method} {url}: {exc.reason}") from None
    return json.loads(raw) if raw else None


def find_existing_comment(api: str, repo: str, pr: int, token: str) -> int | None:
    """Return the id of the existing lockguard comment on the PR, if any."""
    page = 1
    while True:
        url = f"{api}/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}"
        comments = _request("GET", url, token)
        if not isinstance(comments, list):
            return None
        for comment in comments:
            if isinstance(comment, dict) and MARKER in str(comment.get("body", "")):
                comment_id = comment.get("id")
                if isinstance(comment_id, int):
                    return comment_id
        if len(comments) < 100:
            return None
        page += 1


def upsert_comment(body: str, *, repo: str, pr: int, token: str, api: str = DEFAULT_API) -> str:
    """Create or update the lockguard comment. Returns ``"created"`` or ``"updated"``."""
    if MARKER not in body:
        body = f"{MARKER}\n{body}"
    api = api.rstrip("/")
    existing = find_existing_comment(api, repo, pr, token)
    if existing is not None:
        _request("PATCH", f"{api}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
        return "updated"
    _request("POST", f"{api}/repos/{repo}/issues/{pr}/comments", token, {"body": body})
    return "created"


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point; returns a process exit code."""
    parser = argparse.ArgumentParser(prog="python -m lockguard.github_comment")
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--pr", required=True, type=int, help="pull request number")
    parser.add_argument("--body-file", required=True, type=Path)
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("lockguard: GITHUB_TOKEN is not set", file=sys.stderr)
        return 2
    try:
        body = args.body_file.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"lockguard: cannot read {args.body_file}: {exc}", file=sys.stderr)
        return 2
    try:
        action = upsert_comment(
            body,
            repo=args.repo,
            pr=args.pr,
            token=token,
            api=os.environ.get("GITHUB_API_URL", DEFAULT_API),
        )
    except GitHubError as exc:
        print(f"lockguard: {exc}", file=sys.stderr)
        return 1
    print(f"lockguard: PR comment {action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
