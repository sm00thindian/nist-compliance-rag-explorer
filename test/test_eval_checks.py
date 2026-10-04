"""
Tests for the check-generation eval harness (scripts/eval_checks.py).

The scenarios are the ground truth for measuring generated checks, so they are
tested against the hand-written reviewed checks, and the #27 regressions are
pinned: a pattern that matches audit-libs, and an sshd check that reads only
sshd_config, must both fail their scenarios.

    pytest test/test_eval_checks.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import eval_checks as ev  # noqa: E402
from checks.generator import SYSTEM_PROMPT, CheckStore  # noqa: E402

REFERENCE = CheckStore(os.path.join(ROOT, "checks"))


def check(conditions, logic="all"):
    return {"schema": 1, "rule": "V-0", "stig_id": "X", "title": "t", "technology": ev.TECH, "source_sha256": "0",
            "automatable": True, "logic": logic, "conditions": conditions, "notes": "", "manual_reason": None,
            "generated_by": "test", "reviewed": False}


def wrong(results):
    return [name for name, expected, verdict in results if verdict != expected]


def test_reference_checks_pass_their_scenarios():
    for vuln in ("V-258054", "V-257987", "V-258151", "V-258152"):
        ref = REFERENCE.load(ev.TECH, vuln)
        assert ref and ref["reviewed"], vuln
        assert wrong(ev.run_scenarios(ref, vuln)) == [], vuln


def test_audit_libs_regression_is_caught():
    loose = check([{"type": "command", "command": "dnf list --installed audit",
                    "pattern": "^audit\\.\\S+|^audit-\\S+", "expect": "present"}])
    assert wrong(ev.run_scenarios(loose, "V-258151")) == ["only audit-libs"]


def test_sshd_file_only_regression_is_caught():
    # The defective first-run check: main file only, last value.
    file_only = check([{"type": "setting", "path": "/etc/ssh/sshd_config", "key": "PermitRootLogin",
                        "separator": None, "op": "eq", "value": "no", "occurrence": "last", "missing": "fail",
                        "files": "any"}])
    assert set(wrong(ev.run_scenarios(file_only, "V-257985"))) == {"drop-in yes, main no", "only a drop-in sets no"}


def test_sshd_effective_config_check_passes_all_scenarios():
    effective = check([{"type": "command", "command": "sshd -T", "pattern": "^permitrootlogin\\s+no\\s*$",
                        "expect": "present"}])
    assert wrong(ev.run_scenarios(effective, "V-257985")) == []


def test_prompt_carries_the_27_guidance():
    assert "anchor the pattern so a similarly named package cannot match" in SYSTEM_PROMPT
    assert "sshd -T" in SYSTEM_PROMPT and "FIRST value" in SYSTEM_PROMPT
    # The guidance uses a different package than the regression scenario, so the eval measures generalization.
    assert "audit-libs" not in SYSTEM_PROMPT


def test_fake_run_writes_a_report(tmp_path):
    assert ev.main(["--fake", "--rules", "V-258151,V-257985", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "report-fake.json").exists()
