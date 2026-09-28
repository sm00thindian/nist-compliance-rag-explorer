"""
Parser tests.

Offline tests use the bundled STIGs and a small CCI sample in DISA's format.
Tests marked "real data" run against the actual NIST files in knowledge/ (or
NIST_DATA_DIR) and are skipped if those files are not present.

    pytest test/test_parsers.py
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from parsers import (  # noqa: E402
    apply_baselines,
    extract_assessment_details,
    extract_assessment_procedures,
    extract_baseline_control_ids,
    extract_controls_from_json,
    load_cci_mapping,
    load_cci_mapping_from_heimdall,
    load_cci_parts,
    load_cci_parts_from_heimdall,
    load_cci_records,
    link_objectives_to_rules,
    part_key,
    parts_overlap,
    reconcile_cci_mapping,
    load_stig_data,
    normalize_control_id,
    parse_control_ref,
)

FIXTURES = os.path.join(ROOT, "test", "fixtures")
STIGS = os.path.join(ROOT, "stigs")
DATA_DIR = os.environ.get("NIST_DATA_DIR", os.path.join(ROOT, "knowledge"))
CATALOG = os.path.join(DATA_DIR, "nist_800_53-rev5_catalog_json.json")
BASELINE = os.path.join(DATA_DIR, "nist_800_53-rev5_{}-baseline_json.json")


# ----------------------------------------------------------------------
#  Control ID normalization
# ----------------------------------------------------------------------
@pytest.mark.parametrize("raw, expected", [
    ("ac-2", "AC-2"),
    ("AC-02", "AC-2"),
    ("ac-2.1", "AC-2(1)"),        # OSCAL catalog
    ("AC-2(1)", "AC-2(1)"),       # user query
    ("AC-2 (1)", "AC-2(1)"),      # CCI list
    ("AC-02(01)", "AC-2(1)"),     # zero-padded 800-53A label
    ("AC-2 a", "AC-2"),           # CCI statement part
    ("AC-2 (4) (a)", "AC-2(4)"),  # enhancement statement part
    ("si-4.24", "SI-4(24)"),
    ("ac-2_smt.a", "AC-2"),
    ("", ""),
    ("not a control", ""),
])
def test_normalize_control_id(raw, expected):
    assert normalize_control_id(raw) == expected


@pytest.mark.parametrize("raw, expected", [
    ("a", "a"), ("a 1 (a)", "a.1.a"), ("(c)", "c"), ("d.01", "d.1"), ("", ""), (", SC-37 (1)", ""),
])
def test_part_key(raw, expected):
    assert part_key(raw) == expected


def test_parts_overlap():
    assert parts_overlap("d", "d.1") and parts_overlap("d.1", "d") and parts_overlap("a", "a")
    assert not parts_overlap("a", "b") and not parts_overlap("d.1", "d.2") and not parts_overlap("", "a")
    assert not parts_overlap("a", "ab")


def test_parse_control_ref_keeps_part():
    assert parse_control_ref("AC-2 a.1") == ("AC-2", "a.1")
    assert parse_control_ref("IA-5 (1) (d)") == ("IA-5(1)", "(d)")


# ----------------------------------------------------------------------
#  CCI list (DISA format)
# ----------------------------------------------------------------------
CCI_SAMPLE = os.path.join(FIXTURES, "cci_sample.xml")


def test_cci_records_read_reference_attributes():
    recs = {r["cci_id"]: r for r in load_cci_records(CCI_SAMPLE)}
    assert set(recs) == {"CCI-000048", "CCI-000130", "CCI-000196", "CCI-000366", "CCI-001453", "CCI-999999"}
    refs = recs["CCI-000048"]["references"]
    # 800-53A references are not control mappings
    assert all("800-53A" not in r["title"] for r in refs)
    assert [r["version"] for r in refs] == ["3", "4", "5"]


def test_cci_mapping_uses_rev5_only():
    mapping = load_cci_mapping(CCI_SAMPLE)
    assert mapping == {
        "CCI-000048": "AC-8",
        "CCI-000130": "AU-3",
        "CCI-000196": "IA-5(1)",
        "CCI-000366": "CM-6",
        "CCI-001453": "AC-17(2)",
    }
    assert "CCI-999999" not in mapping  # Rev 4 only


def test_cci_parts_use_rev5_reference():
    parts = load_cci_parts(CCI_SAMPLE)
    assert parts["CCI-000048"] == "a"        # AC-8 a
    assert parts["CCI-000196"] == "d"        # Rev 5 IA-5 (1) (d), not Rev 4's (c)
    assert parts["CCI-001453"] == ""         # AC-17 (2), whole enhancement
    assert "CCI-999999" not in parts


def test_cci_mapping_missing_file_is_empty():
    assert load_cci_mapping(os.path.join(FIXTURES, "does-not-exist.xml")) == {}


# ----------------------------------------------------------------------
#  Heimdall fallback and Rev 5 reconciliation
# ----------------------------------------------------------------------
HEIMDALL_SAMPLE = os.path.join(FIXTURES, "heimdall_cci_sample.ts")

# Just enough catalog to reconcile against, mirroring real Rev 5 status.
REV5 = {
    "AU-3": {"withdrawn": False},
    "CM-6": {"withdrawn": False},
    "AC-17(2)": {"withdrawn": False},
    "AC-2": {"withdrawn": False},
    "AC-2(10)": {"withdrawn": True, "withdrawn_to": ["AC-2"], "withdrawn_to_parts": {"AC-2": "k"}},
    "AC-3(6)": {"withdrawn": True, "withdrawn_to": ["MP-4", "SC-28"]},
    "MP-4": {"withdrawn": False},
    "SC-28": {"withdrawn": False},
    "IA-5(1)": {"withdrawn": False},
    "AT-2": {"withdrawn": False},
}


def test_heimdall_mapping_parses_both_quote_styles():
    m = load_cci_mapping_from_heimdall(HEIMDALL_SAMPLE)
    assert len(m) == 8
    assert m["CCI-000130"] == "AU-3"
    assert m["CCI-003002"] == "IA-5(1)"
    assert m["CCI-005147"] == "AT-2"
    assert m["CCI-003001"] == "AR-1"  # Rev 4 privacy family; reconciliation drops it


def test_reconcile_redirects_drops_and_keeps():
    clean, report = reconcile_cci_mapping(load_cci_mapping_from_heimdall(HEIMDALL_SAMPLE), REV5)
    assert clean["CCI-000130"] == "AU-3"
    assert clean["CCI-002150"] == "AC-2"                       # withdrawn, one replacement
    assert report["redirected"]["CCI-002150"] == ("AC-2(10)", "AC-2")
    assert "CCI-003000" not in clean                           # withdrawn, two replacements
    assert report["dropped_ambiguous"]["CCI-003000"][0] == "AC-3(6)"
    assert report["dropped_not_in_rev5"] == {"CCI-003001": "AR-1"}
    assert all(not REV5[c]["withdrawn"] for c in clean.values())
    assert report["kept"] + len(report["redirected"]) == len(clean)


def test_reconcile_carries_statement_parts():
    path = HEIMDALL_SAMPLE
    clean, report = reconcile_cci_mapping(load_cci_mapping_from_heimdall(path), REV5, load_cci_parts_from_heimdall(path))
    assert report["parts"]["CCI-000130"] == "a"       # AU-3 a
    assert report["parts"]["CCI-005147"] == "a.1"     # AT-2 a 1
    assert report["parts"]["CCI-001453"] == ""        # AC-17 (2)
    assert report["parts"]["CCI-002150"] == "k"       # AC-2(10) -> AC-2 k
    assert set(report["parts"]) == set(clean)


def test_reconcile_leaves_clean_rev5_mapping_alone():
    clean, report = reconcile_cci_mapping(load_cci_mapping(CCI_SAMPLE), {**REV5, "AC-8": {"withdrawn": False}})
    assert clean == load_cci_mapping(CCI_SAMPLE)
    assert not report["redirected"] and not report["dropped_ambiguous"] and not report["dropped_not_in_rev5"]


# ----------------------------------------------------------------------
#  800-53A objectives <-> STIG rules
# ----------------------------------------------------------------------
def _obj(label, part):
    return {"id": label, "label": label, "text": label, "part": part, "leaf": True}


def _rule(vid, *ccis):
    return {"vuln_id": vid, "rule_id": f"S{vid}", "ccis": list(ccis)}


def test_link_objectives_by_statement_part():
    assessment = {"objectives": [_obj("X-01a.", "a"), _obj("X-01b.01", "b.1"), _obj("X-01b.02", "b.2"),
                                 {"id": "top", "label": "X-01", "text": "", "part": "", "leaf": False}]}
    cci_to_nist = {"CCI-1": "X-1", "CCI-2": "X-1", "CCI-3": "X-1", "CCI-9": "Y-1"}
    cci_parts = {"CCI-1": "a", "CCI-2": "b", "CCI-3": "", "CCI-9": "a"}
    rules = [_rule("V-1", "CCI-1"), _rule("V-2", "CCI-2"), _rule("V-3", "CCI-3"), _rule("V-9", "CCI-9")]
    link = link_objectives_to_rules("X-1", rules, cci_to_nist, cci_parts, assessment)
    got = {o["label"]: [r["vuln_id"] for r in o["rules"]] for o in link["objectives"]}
    assert got == {"X-01a.": ["V-1"], "X-01b.01": ["V-2"], "X-01b.02": ["V-2"]}  # b covers b.1 and b.2
    assert [r["vuln_id"] for r in link["control_level_rules"]] == ["V-3"]       # whole-control CCI, 3 objectives
    assert (link["covered"], link["total"]) == (3, 3)                           # V-9 maps to another control


def test_link_whole_control_cci_counts_for_single_or_whole_statement_objectives():
    rules = [_rule("V-1", "CCI-1")]
    m, parts = {"CCI-1": "X-1"}, {"CCI-1": ""}
    single = link_objectives_to_rules("X-1", rules, m, parts, {"objectives": [_obj("X-01", "")]})
    assert single["covered"] == 1
    whole = link_objectives_to_rules("X-1", rules, m, parts,
                                     {"objectives": [_obj("X-01[01]", ""), _obj("X-01[02]", ""), _obj("X-01a.", "a")]})
    assert [o["label"] for o in whole["objectives"] if o["rules"]] == ["X-01[01]", "X-01[02]"]
    assert whole["control_level_rules"] == []


def test_link_without_assessment_data_is_empty():
    link = link_objectives_to_rules("X-1", [_rule("V-1", "CCI-1")], {"CCI-1": "X-1"}, {}, None)
    assert link == {"objectives": [], "control_level_rules": [_rule("V-1", "CCI-1")], "covered": 0, "total": 0}


# ----------------------------------------------------------------------
#  STIGs joined through CCIs
# ----------------------------------------------------------------------
def test_stig_rules_have_check_and_fix():
    _, stigs = load_stig_data(STIGS, {})
    assert {s["technology"] for s in stigs} == {
        "Microsoft Windows 10", "Red Hat Enterprise Linux 9",
    }
    assert all(s["rule_count"] > 200 for s in stigs)
    # with no CCI list nothing maps, and that is reported rather than hidden
    assert all(s["unmapped_rules"] == s["rule_count"] for s in stigs)


def test_stig_rules_join_to_controls_through_cci():
    recs, stigs = load_stig_data(STIGS, load_cci_mapping(CCI_SAMPLE))
    rhel = recs["Red Hat Enterprise Linux 9"]
    assert set(rhel) >= {"CM-6", "AU-3", "AC-8", "AC-17(2)", "IA-5(1)"}
    rule = rhel["AU-3"][0]
    assert rule["rule_id"].startswith("SV-")
    assert rule["vuln_id"].startswith("V-")
    assert rule["check"] and rule["fix"]
    assert "CCI-000130" in rule["ccis"]
    # every rule filed under a control really cites a CCI for that control
    mapping = load_cci_mapping(CCI_SAMPLE)
    for control, rules in rhel.items():
        for r in rules:
            assert control in {mapping.get(c) for c in r["ccis"]}


# ----------------------------------------------------------------------
#  Minimal OSCAL shapes (offline)
# ----------------------------------------------------------------------
MINI_CATALOG = {
    "catalog": {
        "uuid": "x",
        "metadata": {"title": "mini", "version": "0"},
        "groups": [{
            "id": "au", "class": "family", "title": "Audit and Accountability",
            "controls": [{
                "id": "au-2", "class": "SP800-53", "title": "Event Logging",
                "params": [
                    {"id": "au-2_prm_1", "label": "event types"},
                    {"id": "au-2_prm_2", "select": {"how-many": "one-or-more", "choice": ["daily", "weekly"]}},
                ],
                "parts": [
                    {"id": "au-2_smt", "name": "statement", "parts": [
                        {"id": "au-2_smt.a", "name": "item", "props": [{"name": "label", "value": "a."}],
                         "prose": "Identify {{ insert: param, au-2_prm_1 }}, reviewed {{ insert: param, au-2_prm_2 }};"},
                    ]},
                    {"id": "au-2_gdn", "name": "guidance", "prose": "Events matter. More text."},
                    {"id": "au-2_obj", "name": "assessment-objective", "parts": [
                        {"id": "au-2_obj.a", "name": "assessment-objective",
                         "props": [{"name": "label", "value": "AU-02a.", "class": "sp800-53a"}],
                         "links": [{"href": "#au-2_smt.a", "rel": "assessment-for"}],
                         "prose": "{{ insert: param, au-2_prm_1 }} are identified;"},
                    ]},
                    {"id": "au-2_asm-examine", "name": "assessment-method",
                     "props": [{"name": "method", "ns": "http://csrc.nist.gov/ns/rmf", "value": "EXAMINE"}],
                     "parts": [{"name": "assessment-objects", "prose": "audit policy\n\nsystem security plan"}]},
                ],
                "controls": [{
                    "id": "au-2.1", "class": "SP800-53-enhancement", "title": "Compilation",
                    "props": [{"name": "status", "value": "withdrawn"}],
                    "links": [{"href": "#au-12", "rel": "incorporated-into"}],
                }],
            }],
        }],
    }
}


def test_catalog_walks_groups_and_enhancements():
    ctrls = {c["control_id"]: c for c in extract_controls_from_json(MINI_CATALOG)}
    assert set(ctrls) == {"AU-2", "AU-2(1)"}
    au2 = ctrls["AU-2"]
    assert au2["family"] == "AU" and au2["family_title"] == "Audit and Accountability"
    assert au2["description"] == (
        "a. Identify [Assignment: organization-defined event types], "
        "reviewed [Selection (one or more): daily; weekly];"
    )
    assert au2["guidance"].startswith("Events matter")
    enh = ctrls["AU-2(1)"]
    assert enh["parent"] == "AU-2" and enh["withdrawn"] and enh["withdrawn_to"] == ["AU-12"]
    assert enh["description"] == "Withdrawn: incorporated into AU-12."


def test_assessment_procedures_from_catalog():
    details = extract_assessment_details(MINI_CATALOG)["AU-2"]
    assert details["objectives"] == [{
        "id": "au-2_obj.a", "label": "AU-02a.", "part": "a", "leaf": True,
        "text": "[Assignment: organization-defined event types] are identified;",
    }]
    assert details["methods"] == {"EXAMINE": ["audit policy", "system security plan"]}
    steps = extract_assessment_procedures(MINI_CATALOG)["AU-2"]
    assert steps[0].startswith("AU-02a. Determine if")
    assert steps[-1] == "Examine: audit policy; system security plan"


def test_rejects_non_oscal_catalog():
    with pytest.raises(ValueError):
        extract_controls_from_json({"controls_list": []})


def test_baseline_profile():
    profile = {"profile": {"imports": [{"href": "#x", "include-controls": [{"with-ids": ["ac-1", "ac-2.1"]}]}]}}
    assert extract_baseline_control_ids(profile) == {"AC-1", "AC-2(1)"}


# ----------------------------------------------------------------------
#  Real NIST data (skipped when knowledge/ is empty)
# ----------------------------------------------------------------------
real = pytest.mark.skipif(not os.path.exists(CATALOG), reason=f"real catalog not found at {CATALOG}")


@pytest.fixture(scope="module")
def catalog_json():
    with open(CATALOG, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def controls(catalog_json):
    return {c["control_id"]: c for c in extract_controls_from_json(catalog_json)}


@real
def test_real_catalog_counts(controls):
    assert len(controls) > 1000
    assert {"AC-2", "AC-2(1)", "AU-3", "SR-12"} <= set(controls)
    assert not any("{{" in c["description"] for c in controls.values())
    assert all(c["description"] for c in controls.values())


@real
def test_real_catalog_text_is_rev5(controls):
    # Rev 5 wording, not Rev 4 ("The information system generates...")
    assert controls["AU-3"]["description"].startswith("Ensure that audit records contain")
    assert controls["AC-2(10)"]["withdrawn"]


@real
def test_real_assessment_procedures(catalog_json, controls):
    details = extract_assessment_details(catalog_json)
    active = [c for c in controls.values() if not c["withdrawn"]]
    assert all(c["control_id"] in details for c in active)
    assert len(details["AU-3"]["objectives"]) == 6
    assert set(details["AU-3"]["methods"]) == {"EXAMINE", "INTERVIEW", "TEST"}


HEIMDALL_REAL = os.path.join(DATA_DIR, "CciNistMappingData.ts")


@real
@pytest.mark.skipif(not os.path.exists(HEIMDALL_REAL), reason="Heimdall CCI mapping not downloaded")
def test_real_heimdall_fallback_links_every_stig_rule(controls):
    clean, report = reconcile_cci_mapping(load_cci_mapping_from_heimdall(HEIMDALL_REAL), controls)
    assert len(clean) > 4000
    assert all(c in controls and not controls[c]["withdrawn"] for c in clean.values())
    _, stigs = load_stig_data(STIGS, clean)
    for s in stigs:
        assert s["unmapped_rules"] / s["rule_count"] <= 0.05, s


@real
@pytest.mark.skipif(not os.path.exists(HEIMDALL_REAL), reason="Heimdall CCI mapping not downloaded")
def test_real_objective_evidence(catalog_json, controls):
    path = HEIMDALL_REAL
    clean, report = reconcile_cci_mapping(load_cci_mapping_from_heimdall(path), controls, load_cci_parts_from_heimdall(path))
    recs, _ = load_stig_data(STIGS, clean)
    rhel = recs["Red Hat Enterprise Linux 9"]
    details = extract_assessment_details(catalog_json)

    au3 = link_objectives_to_rules("AU-3", rhel["AU-3"], clean, report["parts"], details["AU-3"])
    assert (au3["covered"], au3["total"]) == (6, 6)

    # STIGs show settings are implemented (CM-6 b), not that they are documented or monitored.
    cm6 = link_objectives_to_rules("CM-6", rhel["CM-6"], clean, report["parts"], details["CM-6"])
    assert [o["label"] for o in cm6["objectives"] if o["rules"]] == ["CM-06b."]


@real
def test_real_baselines(controls):
    levels = {}
    for level in ("low", "moderate", "high"):
        path = BASELINE.format(level)
        if not os.path.exists(path):
            pytest.skip(f"{path} not found")
        with open(path, encoding="utf-8") as f:
            levels[level] = extract_baseline_control_ids(json.load(f))
    assert levels["low"] <= levels["moderate"] <= levels["high"]
    for ids in levels.values():
        assert ids and all(i in controls and not controls[i]["withdrawn"] for i in ids)
    apply_baselines(controls, {k.upper(): v for k, v in levels.items()})
    assert controls["AC-2"]["baseline_levels"] == ["LOW", "MODERATE", "HIGH"]
