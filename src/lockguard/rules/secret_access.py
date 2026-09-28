"""New code that reads tokens, credential files or crypto wallet data."""

from __future__ import annotations

import re

from lockguard.models import Finding, RuleContext, Severity
from lockguard.rules._common import (
    AddedLine,
    Hit,
    capability_severity,
    downgrade_if_existing,
    existing_capabilities,
    file_has_network_api,
    lines_by_file,
    merge_hits,
    old_code_text,
)

RULE_ID = "secret_access"
DESCRIPTION = (
    "new reads of process.env tokens, ~/.npmrc, ~/.ssh, ~/.aws, ~/.gitconfig, "
    "home-directory files, or crypto-wallet APIs and address patterns"
)
SEVERITY = "high (medium for a bare process.env read; low if the old version did the same)"

_TOKEN_KEY = (
    r"(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH"
    r"|CREDENTIAL|SESSION)[A-Z0-9_]*|NPM_[A-Z0-9_]+|AWS_[A-Z0-9_]+|GITHUB_[A-Z0-9_]+"
    r"|GH_[A-Z0-9_]+|GITLAB_[A-Z0-9_]+|AZURE_[A-Z0-9_]+|GOOGLE_[A-Z0-9_]+)"
)
ENV_TOKEN_RE = re.compile(
    rf"\bprocess\s*\.\s*env\s*(?:\??\.\s*({_TOKEN_KEY})\b|\[\s*['\"`]({_TOKEN_KEY})['\"`]\s*\])"
)
ENV_WHOLE_RE = re.compile(
    r"\bprocess\s*\.\s*env\b(?!\s*(?:\.|\[|\?\.))|\bDeno\s*\.\s*env\s*\.\s*toObject\b"
)
_ENV_EXFIL_RE = re.compile(
    r"JSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env|Object\s*\.\s*(?:keys|entries|values|assign)"
    r"\s*\(\s*process\s*\.\s*env|Deno\s*\.\s*env\s*\.\s*toObject"
)

CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\.npmrc\b"), "npm credentials file (.npmrc)"),
    (re.compile(r"(?:^|[\\/'\"`~])\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b"), "SSH keys (~/.ssh)"),
    (re.compile(r"(?:^|[\\/'\"`~])\.aws\b"), "AWS credentials (~/.aws)"),
    (re.compile(r"\.gitconfig\b|\.git-credentials\b"), "git credentials"),
    (
        re.compile(r"\.docker[\\/]config\.json|\.kube[\\/]config|\.config[\\/]gcloud"),
        "cloud/container credentials",
    ),
    (
        re.compile(r"\bwallet\.dat\b|\bnkbihfbeogaeaoehlefnkodbefgpgknn\b"),
        "crypto wallet files (wallet.dat / MetaMask extension id)",
    ),
)

WALLET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bwindow\s*\.\s*ethereum\b"), "reads window.ethereum"),
    (re.compile(r"\bethereum\s*\.\s*request\s*\("), "calls ethereum.request()"),
    (
        re.compile(r"\beth_(?:sendTransaction|signTransaction|sign|accounts|requestAccounts)\b"),
        "Ethereum wallet RPC method",
    ),
    (
        re.compile(r"\bwindow\s*\.\s*(?:solana|phantom|tronWeb|tronLink)\b"),
        "reads a wallet provider",
    ),
    (
        re.compile(r"0x\[(?:a-fA-F0-9|0-9a-fA-F|A-Fa-f0-9|0-9A-Fa-f|a-f0-9|0-9a-f)\]\{40\}"),
        "Ethereum address regex",
    ),
    (re.compile(r"a-km-zA-HJ-NP-Z1-9\]\{\d"), "Bitcoin address regex"),
    (re.compile(r"1-9A-HJ-NP-Za-km-z\]\{\d"), "Solana/base58 address regex"),
    (
        re.compile(r"\bbc1\[(?:a-z0-9|ac-hj-np-z02-9|a-zA-HJ-NP-Z0-9)\]"),
        "Bitcoin bech32 address regex",
    ),
    (re.compile(r"['\"`]0x[a-fA-F0-9]{40}['\"`]"), "hardcoded Ethereum address"),
    (
        re.compile(r"['\"`](?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})['\"`]"),
        "hardcoded Bitcoin address",
    ),
)

HOMEDIR_RE = re.compile(
    r"\bos\s*\.\s*homedir\s*\(\s*\)|(?<![\w$.])homedir\s*\(\s*\)"
    r"|\bprocess\s*\.\s*env\s*\.\s*(?:HOME|USERPROFILE)\b"
)
_WHOLE_ENV = "reads the whole process.env object"
_HOMEDIR = "reads files from the user's home directory"
FILE_READ_RE = re.compile(
    r"\b(?:readFileSync|readFile|createReadStream|readdirSync|readdir|opendirSync)\s*\("
)


def check(ctx: RuleContext) -> list[Finding]:
    """Flag secret, credential and wallet access in added code.

    Accesses the previous version already performed (a wallet library that always read
    ``window.ethereum``, a CLI that always read ``NPM_TOKEN``) are reported as low.
    """
    old_text = old_code_text(ctx)
    existing = existing_capabilities(ctx, (*CREDENTIAL_PATTERNS, *WALLET_PATTERNS))
    old_env_keys = {m.group(1) or m.group(2) for m in ENV_TOKEN_RE.finditer(old_text)}
    if ENV_WHOLE_RE.search(old_text):
        existing.add(_WHOLE_ENV)
    if HOMEDIR_RE.search(old_text) and FILE_READ_RE.search(old_text):
        existing.add(_HOMEDIR)

    hits: list[Hit] = []
    for path, lines in lines_by_file(ctx).items():
        networked = file_has_network_api(lines)
        reads_files = any(FILE_READ_RE.search(line.text) for line in lines)
        for line in lines:
            text = line.text

            def add(
                start: int,
                severity: Severity,
                label: str,
                note: str = "",
                _line: AddedLine = line,
                _path: str = path,
            ) -> None:
                severity, message = downgrade_if_existing(severity, label, existing)
                hits.append(Hit(_path, _line.lineno, _line.text, start, severity, message + note))

            for env_match in ENV_TOKEN_RE.finditer(text):
                key = env_match.group(1) or env_match.group(2)
                label = f"reads secret-looking environment variable {key}"
                if key in old_env_keys:
                    existing.add(label)
                add(env_match.start(), capability_severity(ctx, Severity.HIGH), label)

            match = ENV_WHOLE_RE.search(text)
            if match:
                exfil = networked or bool(_ENV_EXFIL_RE.search(text))
                add(
                    match.start(),
                    capability_severity(ctx, Severity.HIGH if exfil else Severity.MEDIUM),
                    _WHOLE_ENV,
                    " (serialized or sent over the network)" if exfil else "",
                )

            for pattern, label in (*CREDENTIAL_PATTERNS, *WALLET_PATTERNS):
                match = pattern.search(text)
                if match:
                    add(match.start(), Severity.HIGH, label)

            match = HOMEDIR_RE.search(text)
            if match and reads_files:
                add(match.start(), capability_severity(ctx, Severity.HIGH), _HOMEDIR)
    return merge_hits(RULE_ID, hits)
