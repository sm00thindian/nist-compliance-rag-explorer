"""
Tests for local STIG checks: format, engine, evidence collection, generator, rollup.

    pytest test/test_checks.py
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from checks.engine import evaluate_check  # noqa: E402
from checks.evidence import EvidenceBundle, collection_script, normalize_command  # noqa: E402
from checks.generator import (  # noqa: E402
    CheckStore, PublicRequirement, build_prompt, generate_check, parse_model_output, stale_checks,
)
from checks.spec import CheckSpecError, evidence_needed, source_hash, validate_check  # noqa: E402

KNOWLEDGE = os.path.join(ROOT, "knowledge")
real = pytest.mark.skipif(not os.path.exists(os.path.join(KNOWLEDGE, "nist_800_53-rev5_catalog_json.json")),
                          reason="real NIST data not in knowledge/")


def check(*conditions, logic="all", **extra):
    return dict({"rule": "V-1", "automatable": True, "logic": logic, "conditions": list(conditions)}, **extra)


def setting(**kw):
    return dict({"type": "setting", "path": "/etc/app.conf", "key": "deny", "separator": "=", "op": "le", "value": 3}, **kw)


@pytest.fixture
def evidence(tmp_path):
    def make(files=None, commands=None):
        root = tmp_path / "evidence"
        for path, text in (files or {}).items():
            p = root / "files" / path.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        if commands is not None:
            (root / "commands").mkdir(parents=True, exist_ok=True)
            for i, (cmd, out) in enumerate(commands.items(), 1):
                (root / "commands" / f"{i:03d}.txt").write_text(f"$ {cmd}\n{out}")
        root.mkdir(exist_ok=True)
        return EvidenceBundle(str(root))
    return make


# ----------------------------------------------------------------------
#  Format
# ----------------------------------------------------------------------
@pytest.mark.parametrize("bad, message", [
    (check(dict(setting(), extra=1)), "unknown fields"),
    (check(setting(path="etc/app.conf")), "absolute"),
    (check(setting(path="/etc/../root/x")), ".."),
    (check(setting(op="le", value="3")), "numeric"),
    (check(setting(op="in", value=[])), "non-empty list"),
    (check({"type": "line", "path": "/x", "pattern": "(", "expect": "present"}), "invalid regex"),
    (check({"type": "shell", "command": "rm -rf /"}), "type must be"),
    ({"rule": "V-1", "automatable": False, "conditions": []}, "manual_reason"),
    (check(), "at least one condition"),
    (dict(check(setting()), reviewed=True, surprise=1), "unknown check fields"),
])
def test_invalid_checks_rejected(bad, message):
    with pytest.raises(CheckSpecError, match=message):
        validate_check(bad)


def test_evidence_needed():
    c = check(setting(), {"type": "command", "command": "rpm -qa", "pattern": "x", "expect": "present"})
    assert evidence_needed(c) == {"files": ["/etc/app.conf"], "commands": ["rpm -qa"]}


# ----------------------------------------------------------------------
#  Engine
# ----------------------------------------------------------------------
@pytest.mark.parametrize("text, cond, expected", [
    ("deny = 3\n", setting(), "pass"),
    ("deny = 5\n", setting(), "fail"),
    ("# deny = 3\n", setting(), "fail"),                              # commented out counts as missing
    ("", setting(), "fail"),                                          # missing fails by default
    ("", setting(missing="pass"), "pass"),
    ("deny = 3\ndeny = 9\n", setting(), "fail"),                      # last occurrence wins by default
    ("deny = 3\ndeny = 9\n", setting(occurrence="first"), "pass"),
    ("deny = 3\ndeny = 9\n", setting(occurrence="all"), "fail"),
    ("deny = 3   # site default\n", setting(), "pass"),               # inline comment stripped
    ("DENY = 3\n", setting(), "pass"),                                # keys case-insensitive by default
    ("DENY = 3\n", setting(case_sensitive=True), "fail"),
    ("PermitRootLogin no\n", setting(key="PermitRootLogin", separator=None, op="eq", value="no"), "pass"),
    ("PermitRootLogin yes\n", setting(key="PermitRootLogin", separator=None, op="in", value=["no", "prohibit-password"]), "fail"),
    ("Ciphers aes256-ctr,aes128-ctr\n", setting(key="Ciphers", separator=None, op="regex", value=r"^aes256"), "pass"),
    ("deny = 0\n", setting(op="ne", value=0), "fail"),
    ("deny = abc\n", setting(), "fail"),                              # non-numeric value for numeric op
])
def test_setting_conditions(evidence, text, cond, expected):
    bundle = evidence({"/etc/app.conf": text})
    assert evaluate_check(check(cond), bundle)["status"] == expected


def test_result_cites_the_deciding_line(evidence):
    bundle = evidence({"/etc/app.conf": "# comment\ndeny = 5\n"})
    r = evaluate_check(check(setting()), bundle)
    assert r["status"] == "fail"
    assert r["conditions"][0]["evidence"] == [{"source": "/etc/app.conf", "line": 2, "text": "deny = 5"}]


def test_missing_file_is_not_evaluated_not_failed(evidence):
    assert evaluate_check(check(setting()), evidence({"/etc/other": "x"}))["status"] == "not_evaluated"


def test_line_and_wildcards(evidence):
    bundle = evidence({"/etc/ssh/sshd_config.d/10-a.conf": "Ciphers aes256-ctr\n",
                       "/etc/ssh/sshd_config.d/20-b.conf": "PermitRootLogin no\n"})
    any_file = {"type": "line", "path": "/etc/ssh/sshd_config.d/*.conf", "pattern": r"^Ciphers\s", "expect": "present"}
    assert evaluate_check(check(any_file), bundle)["status"] == "pass"
    assert evaluate_check(check(dict(any_file, files="all")), bundle)["status"] == "fail"
    absent = {"type": "line", "path": "/etc/ssh/sshd_config.d/*.conf", "pattern": r"^PermitEmptyPasswords\s+yes", "expect": "absent", "files": "all"}
    assert evaluate_check(check(absent), bundle)["status"] == "pass"


def test_file_exists(evidence):
    bundle = evidence({"/etc/a": "x"})
    assert evaluate_check(check({"type": "file_exists", "path": "/etc/a", "expect": "present"}), bundle)["status"] == "pass"
    assert evaluate_check(check({"type": "file_exists", "path": "/etc/b", "expect": "present"}), bundle)["status"] == "fail"
    assert evaluate_check(check({"type": "file_exists", "path": "/etc/b", "expect": "absent"}), bundle)["status"] == "pass"


def test_command_output_and_sudo_normalization(evidence):
    bundle = evidence(commands={"systemctl is-active auditd": "active\n"})
    cond = {"type": "command", "command": "sudo  systemctl is-active auditd", "pattern": r"^active$", "expect": "present"}
    r = evaluate_check(check(cond), bundle)
    assert r["status"] == "pass" and r["conditions"][0]["evidence"][0]["text"] == "active"
    missing = dict(cond, command="systemctl is-enabled auditd")
    assert evaluate_check(check(missing), bundle)["status"] == "not_evaluated"


def test_logic_any_and_all(evidence):
    bundle = evidence({"/etc/app.conf": "deny = 5\n"})
    passing, failing = setting(op="ge", value=5), setting()
    missing = setting(path="/etc/none.conf")
    assert evaluate_check(check(passing, failing, logic="any"), bundle)["status"] == "pass"
    assert evaluate_check(check(passing, failing), bundle)["status"] == "fail"
    assert evaluate_check(check(passing, missing), bundle)["status"] == "not_evaluated"
    assert evaluate_check(check(failing, missing), bundle)["status"] == "fail"


def test_manual_and_invalid_checks(evidence):
    bundle = evidence({})
    manual = {"rule": "V-2", "automatable": False, "conditions": [], "manual_reason": "Needs ISSO review"}
    assert evaluate_check(manual, bundle)["status"] == "manual"
    assert evaluate_check(check(setting(path="relative")), bundle)["status"] == "error"


def test_evidence_paths_cannot_escape(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "secret").write_text("x")
    os.symlink(str(tmp_path / "secret"), str(tmp_path / "files" / "link"))
    with pytest.raises(ValueError):
        EvidenceBundle(str(tmp_path)).files("/link")


def test_commands_json_index(tmp_path):
    (tmp_path / "commands.json").write_text(json.dumps({"rpm -qa": "audit-3.1\n"}))
    assert EvidenceBundle(str(tmp_path)).command_output("sudo rpm -qa") == "audit-3.1\n"
    assert normalize_command(" sudo   rpm  -qa ") == "rpm -qa"


# ----------------------------------------------------------------------
#  Collection script: run it for real against a stand-in "target"
# ----------------------------------------------------------------------
def test_collection_script_builds_a_usable_evidence_folder(tmp_path):
    target = tmp_path / "target"
    (target / "etc").mkdir(parents=True)
    (target / "etc" / "app.conf").write_text("deny = 3\n")
    conf = str(target / "etc" / "app.conf")
    script = collection_script([conf, str(target / "etc" / "*.conf"), str(target / "missing.conf")],
                               ["echo auditd active"], unreviewed=["V-9"])
    assert "WARNING" in script and "V-9" in script
    path = tmp_path / "collect.sh"
    path.write_text(script)
    out = tmp_path / "evidence"
    subprocess.run(["sh", str(path), str(out)], check=True, capture_output=True)
    bundle = EvidenceBundle(str(out))
    assert evaluate_check(check(setting(path=conf)), bundle)["status"] == "pass"
    cmd = {"type": "command", "command": "echo auditd active", "pattern": "auditd active", "expect": "present"}
    assert evaluate_check(check(cmd), bundle)["status"] == "pass"


# ----------------------------------------------------------------------
#  Generator (fake model; nothing leaves the machine in tests)
# ----------------------------------------------------------------------
RULE = {"vuln_id": "V-258054", "rule_id": "SV-258054r1", "stig_id": "RHEL-09-411075", "severity": "medium",
        "title": "RHEL 9 must lock an account after three unsuccessful logon attempts.",
        "check": 'If the "deny" option is not set to "3" or less (but not "0"), this is a finding.',
        "fix": "Set deny = 3", "discussion": "Brute force protection.", "ccis": ["CCI-000044"]}
GOOD = {"automatable": True, "logic": "all", "notes": "deny <= 3 and != 0",
        "conditions": [setting(path="/etc/security/faillock.conf"),
                       setting(path="/etc/security/faillock.conf", op="ne", value=0)]}


class FakeClient:
    name = "fake:model"

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts = []

    def complete(self, system, user, max_tokens=2000):
        self.prompts.append((system, user))
        return self.replies.pop(0)


def test_prompt_contains_only_public_stig_fields():
    req = PublicRequirement.from_rule(RULE, "Red Hat Enterprise Linux 9")
    prompt = build_prompt(req)
    assert RULE["check"] in prompt and RULE["title"] in prompt
    assert "CCI-000044" not in prompt  # only the listed public fields are used
    assert set(PublicRequirement.__dataclass_fields__) == {
        "technology", "vuln_id", "rule_id", "stig_id", "title", "severity", "check", "fix", "discussion"}


def test_generator_never_loads_evidence_code():
    code = ("import sys; sys.path.insert(0, 'src'); import checks.generator, checks.llm; "
            "print('checks.evidence' in sys.modules, 'checks.engine' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False False"


def test_generate_check_sets_metadata_itself():
    client = FakeClient("Here you go:\n```json\n" + json.dumps(GOOD) + "\n```")
    c = generate_check(PublicRequirement.from_rule(RULE, "Red Hat Enterprise Linux 9"), client)
    assert c["rule"] == "V-258054" and c["stig_id"] == "RHEL-09-411075"
    assert c["reviewed"] is False and c["generated_by"] == "fake:model"
    assert c["source_sha256"] == source_hash(RULE["check"])


def test_generate_check_rejects_model_setting_reviewed_then_retries():
    sneaky = dict(GOOD, reviewed=True)
    bad_regex = dict(GOOD, conditions=[{"type": "line", "path": "/x", "pattern": "(", "expect": "present"}])
    client = FakeClient(json.dumps(sneaky), json.dumps(GOOD))
    assert generate_check(PublicRequirement.from_rule(RULE, "RHEL"), client)["reviewed"] is False
    assert "rejected" in client.prompts[1][1]
    with pytest.raises(CheckSpecError):
        generate_check(PublicRequirement.from_rule(RULE, "RHEL"), FakeClient(json.dumps(bad_regex), "not json"))


def test_parse_model_output_variants():
    assert parse_model_output('{"a": 1}') == {"a": 1}
    assert parse_model_output('text before {"a": 1} after') == {"a": 1}
    with pytest.raises(CheckSpecError):
        parse_model_output("no json here")


def test_store_protects_reviewed_checks(tmp_path):
    store = CheckStore(str(tmp_path))
    c = generate_check(PublicRequirement.from_rule(RULE, "RHEL 9"), FakeClient(json.dumps(GOOD)))
    store.save(c)
    store.save(dict(c, notes="regenerated"))       # unreviewed: overwrite allowed
    store.save(dict(c, reviewed=True), overwrite_reviewed=True)
    with pytest.raises(FileExistsError):
        store.save(dict(c, notes="clobber"))
    assert store.load_all("RHEL 9")["V-258054"]["reviewed"] is True
    assert stale_checks(store.load_all("RHEL 9"), [dict(RULE, check="new text")]) == ["V-258054"]
    assert stale_checks(store.load_all("RHEL 9"), [RULE]) == []


# ----------------------------------------------------------------------
#  Shipped checks and rollup against real data
# ----------------------------------------------------------------------
def test_shipped_checks_are_valid_and_current():
    from parsers import parse_stig_file
    _, rules = parse_stig_file(os.path.join(ROOT, "stigs", "U_RHEL_9_STIG_V2R3_Manual-xccdf.xml"))
    shipped = CheckStore(os.path.join(ROOT, "checks")).load_all("Red Hat Enterprise Linux 9")
    assert len(shipped) >= 4
    for c in shipped.values():
        validate_check(c)
    assert stale_checks(shipped, rules) == []


@real
def test_rollup_traces_a_failure_to_800_53a(evidence):
    from checks.rollup import load_context, rollup
    ctx = load_context(KNOWLEDGE, os.path.join(ROOT, "stigs"))
    if not ctx["cci_to_nist"]:
        pytest.skip("no CCI mapping in knowledge/")
    tech = "Red Hat Enterprise Linux 9"
    shipped = CheckStore(os.path.join(ROOT, "checks")).load_all(tech)
    bundle = evidence({"/etc/security/faillock.conf": "deny = 5\n"})
    results = {v: evaluate_check(c, bundle) for v, c in shipped.items()}
    assert results["V-258054"]["status"] == "fail"
    report = {c["control"]: c for c in rollup(tech, results, ctx)}
    ac7 = {s["label"]: s for s in report["AC-7"]["statements"]}
    assert ac7["AC-07a."]["status"] == "fail" and ac7["AC-07a."]["rules"]["V-258054"] == "fail"
