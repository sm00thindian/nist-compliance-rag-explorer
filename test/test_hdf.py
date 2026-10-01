"""
Tests for importing CINC Auditor / InSpec (HDF) results.

The fixture is synthetic, built on real RHEL 9 V2R3 rule IDs, with one control
per status path, a rule revision mismatch, a rule not in the STIG, an
attestation, and a hostname/IP in passthrough that must never be returned.

    pytest test/test_hdf.py
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from checks.hdf import HDFError, _controls, control_status, import_hdf, rollup_summary  # noqa: E402
from parsers import parse_stig_file  # noqa: E402

FIXTURE = os.path.join(ROOT, "test", "fixtures", "hdf_rhel9_sample.json")
RHEL9 = os.path.join(ROOT, "stigs", "U_RHEL_9_STIG_V2R3_Manual-xccdf.xml")
KNOWLEDGE = os.environ.get("NIST_DATA_DIR", os.path.join(ROOT, "knowledge"))
real = pytest.mark.skipif(not os.path.exists(os.path.join(KNOWLEDGE, "nist_800_53-rev5_catalog_json.json")),
                          reason="real catalog not found in knowledge/")
SECRETS = ("secret-host.example", "10.2.3.4", "SECRET_CODE_DESC")


@pytest.fixture(scope="module")
def rules():
    return parse_stig_file(RHEL9)[1]


@pytest.mark.parametrize("control, expected", [
    ({"impact": 0.5, "results": [{"status": "passed"}]}, "pass"),
    ({"impact": 0.5, "results": [{"status": "passed"}, {"status": "failed"}]}, "fail"),
    ({"impact": 0.5, "results": [{"status": "passed"}, {"status": "skipped"}]}, "pass"),   # Heimdall's rule
    ({"impact": 0.5, "results": [{"status": "skipped"}]}, "not_reviewed"),
    ({"impact": 0.0, "results": [{"status": "failed"}]}, "not_applicable"),
    ({"impact": 0.5, "results": [], "waiver_data": {"skipped_due_to_waiver": True}}, "not_applicable"),
    ({"impact": 0.5, "results": [], "waiver_data": {"skipped_due_to_waiver": False}}, "error"),
    ({"impact": 0.5, "results": []}, "error"),
    ({"impact": 0.0, "results": [{"status": "error"}]}, "error"),                          # error beats N/A
    ({"impact": 0.5, "results": [{"status": "passed", "backtrace": ["x"]}]}, "error"),
    ({"impact": 0.5, "results": [{"code_desc": "no status"}]}, "error"),
])
def test_control_status_follows_heimdall(control, expected):
    assert control_status(control) == expected


def test_import_matches_by_gid_and_flags_problems(rules):
    out = import_hdf(FIXTURE, rules)
    statuses = {v: r["status"] for v, r in out["results"].items()}
    assert statuses == {
        "V-258054": "pass", "V-257779": "fail", "V-257777": "not_applicable", "V-257782": "not_applicable",
        "V-257784": "not_reviewed", "V-257785": "error", "V-257786": "error", "V-257787": "pass",
    }
    assert [m["vuln_id"] for m in out["rid_mismatches"]] == ["V-257779"]
    assert out["rid_mismatches"][0]["stig_rid"] == "SV-257779r958390_rule"
    assert out["not_in_stig"] == ["V-999999"]
    assert out["attested"] == ["V-257787"]
    assert out["profiles"] == [{"name": "redhat-enterprise-linux-9-stig-baseline", "version": "2.3.0"}]
    assert "failures" not in out


def test_import_returns_no_raw_result_text(rules):
    dumped = json.dumps(import_hdf(FIXTURE, rules))
    assert not any(s in dumped for s in SECRETS)


def test_keep_details_is_for_local_reports(rules):
    out = import_hdf(FIXTURE, rules, keep_details=True)
    assert out["failures"] == {"V-257779": ["SECRET_CODE_DESC failed"]}


def test_wrong_stig_and_bad_files_are_refused(rules, tmp_path):
    windows = parse_stig_file(os.path.join(ROOT, "stigs", "U_MS_Windows_10_STIG_V3R3_Manual-xccdf.xml"))[1]
    with pytest.raises(HDFError, match="None of the 9 controls"):
        import_hdf(FIXTURE, windows)
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    with pytest.raises(HDFError, match="no 'profiles'"):
        import_hdf(str(bad), rules)
    bad.write_text("not json")
    with pytest.raises(HDFError, match="not JSON"):
        import_hdf(str(bad), rules)


def test_overlay_prefers_the_copy_with_results():
    hdf = {"profiles": [
        {"name": "wrapper", "controls": [{"id": "V-1", "tags": {"gid": "V-1"}, "results": [{"status": "failed"}]}]},
        {"name": "base", "parent_profile": "wrapper",
         "controls": [{"id": "V-1", "tags": {"gid": "V-1"}, "results": []},
                      {"id": "V-2", "tags": {"gid": "V-2"}, "results": [{"status": "passed"}]}]},
    ]}
    by_id = {c["id"]: c for c in _controls(hdf)}
    assert by_id["V-1"]["results"] == [{"status": "failed"}] and "V-2" in by_id


@real
def test_rollup_of_imported_results(rules):
    from checks.rollup import load_context, rollup
    ctx = load_context(KNOWLEDGE, os.path.join(ROOT, "stigs"))
    tech = "Red Hat Enterprise Linux 9"
    imported = import_hdf(FIXTURE, ctx["rules"][tech])
    report = rollup(tech, imported["results"], ctx)
    ac7 = {s["label"]: s for c in report if c["control"] == "AC-7" for s in c["statements"]}
    assert ac7["AC-07a."]["rules"]["V-258054"] == "pass"
    summary = rollup_summary(report, imported)
    assert summary["rid_mismatches"] == 1 and summary["results_not_in_stig"] == 1
    assert summary["attestations_not_applied"] == 1
    assert not any(s in json.dumps(summary) for s in SECRETS)
    assert all("text" not in s for c in summary["controls"] for s in c["statements"])


def test_rollup_not_applicable_rules():
    from checks.rollup import rollup
    rules = [{"vuln_id": "V-1", "ccis": ["CCI-1"]}, {"vuln_id": "V-2", "ccis": ["CCI-1"]}]
    ctx = {"recommendations": {"T": {"XX-1": rules}}, "cci_to_nist": {"CCI-1": "XX-1"}, "cci_parts": {"CCI-1": ""},
           "assessment": {"XX-1": {"objectives": [{"label": "XX-01", "text": "t", "part": "", "leaf": True}]}},
           "controls": {"XX-1": {"title": "X"}}}

    def status(results):
        return rollup("T", results, ctx)[0]["statements"][0]["status"]
    assert status({"V-1": {"status": "not_applicable"}, "V-2": {"status": "not_applicable"}}) == "not_applicable"
    assert status({"V-1": {"status": "not_applicable"}, "V-2": {"status": "pass"}}) == "pass"
    assert status({"V-1": {"status": "not_applicable"}, "V-2": {"status": "fail"}}) == "fail"
    assert status({"V-1": {"status": "not_applicable"}}) == "unchecked"
