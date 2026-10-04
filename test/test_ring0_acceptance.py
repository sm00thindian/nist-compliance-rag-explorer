"""
Ring 0 acceptance tests (stories R0-2 #36, R0-3 #37, R0-4 #38), run against the
real public data through ``mcp_server.data.Explorer``. Skipped when the NIST
catalog is not in knowledge/ (or $NIST_DATA_DIR).

    NIST_DATA_DIR=/path/to/knowledge pytest test/test_ring0_acceptance.py
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from mcp_server.data import NO_STIG_EVIDENCE, Explorer  # noqa: E402

KNOWLEDGE = os.environ.get("NIST_DATA_DIR", os.path.join(ROOT, "knowledge"))
STIGS = os.path.join(ROOT, "stigs")
pytestmark = pytest.mark.skipif(
    not os.path.exists(os.path.join(KNOWLEDGE, "nist_800_53-rev5_catalog_json.json")),
    reason="real catalog not found in knowledge/")


@pytest.fixture(scope="module")
def explorer():
    return Explorer.load(KNOWLEDGE, STIGS)


def cci_source(explorer):
    return os.path.basename(explorer.ctx["cci_source"])


# ----------------------------------------------------------------------
#  R0-2: control lookups by any common spelling
# ----------------------------------------------------------------------
def test_r0_2_spellings_resolve_to_one_canonical_control(explorer):
    answers = [explorer.get_control(ref) for ref in ("AC-02(01)", "ac-2.1", "AC-2(1)")]
    assert {a["control_id"] for a in answers} == {"AC-2(1)"}
    assert len({a["statement"] for a in answers}) == 1
    assert answers[0]["statement"] and answers[0]["parent"] == "AC-2"


def test_r0_2_withdrawn_control_names_its_replacement(explorer):
    c = explorer.get_control("AC-2(10)")
    assert c["withdrawn"] is True
    assert c["withdrawn_to"] == ["AC-2"]
    with pytest.raises(LookupError, match=r"withdrawn.*AC-2"):
        explorer.statement_coverage("AC-2(10)", "rhel")


# ----------------------------------------------------------------------
#  R0-3: statement -> STIG rules, traceable through CCIs
# ----------------------------------------------------------------------
def test_r0_3_statement_coverage_rules_are_traceable(explorer):
    r = explorer.statement_coverage("AU-03a", "rhel")
    assert r["control_id"] == "AU-3"
    assert [s["part"] for s in r["statements"]] == ["a"]
    rules = r["statements"][0]["stig_rules"]
    assert rules
    for rule in rules:
        assert rule["vuln_id"].startswith("V-")
        assert rule["stig_id"].startswith("RHEL-09-")
        assert rule["severity"] in {"low", "medium", "high"}

    traced = []
    for rule in rules:
        mappings = explorer.get_stig_rule(rule["vuln_id"])["cci_mappings"]
        if any(m.get("control") == "AU-3" and m.get("part") == "a" for m in mappings):
            traced.append(rule["vuln_id"])
    assert traced, "no AU-3 a rule traces back through a CCI mapped to AU-3 part a"


def test_r0_3_control_level_rules_are_reported_separately(explorer):
    r = explorer.statement_coverage("AU-03a", "rhel")
    assert "control_level_rules" in r and "control_level_note" in r

    # With the DISA list no bundled-STIG rule cites a control-level CCI; if one
    # does (other CCI sources), it must sit apart from every statement.
    found = None
    for tech, by_control in explorer.ctx["recommendations"].items():
        for cid in by_control:
            cov = explorer.statement_coverage(cid, tech)
            if cov["control_level_rules"]:
                found = cov
                break
        if found:
            break
    if found is None:
        assert r["control_level_rules"] == [] and r["control_level_note"] == ""
        return
    assert found["control_level_note"]
    in_statements = {rule["vuln_id"] for s in found["statements"] for rule in s.get("stig_rules", [])}
    assert not in_statements & {rule["vuln_id"] for rule in found["control_level_rules"]}


# ----------------------------------------------------------------------
#  R0-4: gaps for a STIG within a baseline
# ----------------------------------------------------------------------
# (all RHEL 9 gaps, RHEL 9 gaps in the moderate baseline) per CCI source
EXPECTED_GAPS = {
    "U_CCI_List.xml": (38, 26),  # DISA 2026-07-14: 175 statements - 137 covered = 38
}


def test_r0_4_gaps_in_moderate_baseline(explorer):
    source = cci_source(explorer)
    if source not in EXPECTED_GAPS:
        pytest.skip(f"no expected gap numbers for CCI source {source}")
    total, moderate = EXPECTED_GAPS[source]

    assert explorer.list_gaps("rhel", limit=500)["total"] == total
    g = explorer.list_gaps("rhel", baseline="moderate", limit=500)
    assert g["baseline"] == "MODERATE"
    assert g["total"] == moderate == len(g["statements"])
    assert g["note"] == NO_STIG_EVIDENCE
    moderate_ids = explorer.baselines["MODERATE"]
    assert all(s["control_id"] in moderate_ids and s["label"] and s["text"] for s in g["statements"])

    without = g["baseline_controls_without_stig_rules"]
    assert without and set(without) <= moderate_ids
    touched = set(explorer.ctx["recommendations"]["Red Hat Enterprise Linux 9"])
    assert not touched & set(without)
