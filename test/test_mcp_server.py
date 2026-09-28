"""
MCP server tests.

The tool-surface tests check the read-only contract. Tests marked "real" run
against the NIST files in knowledge/ and are skipped if they are not present.

    pytest test/test_mcp_server.py
"""
import asyncio
import inspect
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

pytest.importorskip("mcp")

from mcp.server.mcpserver.exceptions import ToolError  # noqa: E402

from mcp_server.data import NO_STIG_EVIDENCE, Explorer  # noqa: E402
from mcp_server.server import build_server  # noqa: E402

KNOWLEDGE = os.environ.get("NIST_DATA_DIR", os.path.join(ROOT, "knowledge"))
STIGS = os.path.join(ROOT, "stigs")
real = pytest.mark.skipif(not os.path.exists(os.path.join(KNOWLEDGE, "nist_800_53-rev5_catalog_json.json")),
                          reason="real catalog not found in knowledge/")

EXPECTED_TOOLS = {
    "get_control", "search_controls", "get_assessment_procedure", "list_stigs", "get_stig_rule",
    "search_stig_rules", "lookup_cci", "statement_coverage", "stig_coverage", "list_gaps",
}


def empty_explorer():
    ctx = {"controls": {}, "assessment": {}, "cci_to_nist": {}, "cci_parts": {}, "cci_report": {},
           "cci_source": "none", "recommendations": {}, "stigs": [], "rules": {}}
    return Explorer(ctx, {})


# ----------------------------------------------------------------------
#  Read-only contract (offline)
# ----------------------------------------------------------------------
def test_tool_surface_is_read_only():
    tools = asyncio.run(build_server(empty_explorer()).list_tools())
    assert {t.name for t in tools} == EXPECTED_TOOLS
    for t in tools:
        a = t.annotations
        assert a.read_only_hint and not a.destructive_hint and not a.open_world_hint, t.name


def test_no_tool_takes_a_path_or_results():
    tools = asyncio.run(build_server(empty_explorer()).list_tools())
    for t in tools:
        for arg in t.input_schema.get("properties", {}):
            assert not any(w in arg.lower() for w in ("path", "file", "dir", "evidence", "result", "url")), (t.name, arg)


def test_data_layer_does_not_import_evidence_or_llm_code():
    import mcp_server.data as data
    import mcp_server.server as server
    for mod in (data, server):
        src = inspect.getsource(mod)
        for forbidden in ("checks.engine", "checks.evidence", "checks.llm", "checks.generator", "subprocess", "requests"):
            assert forbidden not in src, (mod.__name__, forbidden)


def test_bad_input_becomes_a_tool_error():
    server = build_server(empty_explorer())
    with pytest.raises(ToolError, match="not a control ID"):
        asyncio.run(server.call_tool("get_control", {"control_id": "nonsense"}))
    with pytest.raises(ToolError, match="matched 0"):
        asyncio.run(server.call_tool("stig_coverage", {"stig": "rhel"}))


# ----------------------------------------------------------------------
#  Real data
# ----------------------------------------------------------------------
@pytest.fixture(scope="module")
def explorer():
    return Explorer.load(KNOWLEDGE, STIGS)


# (covered, total, controls) per STIG, as printed by validate_data.py for each CCI source
EXPECTED_COVERAGE = {
    "U_CCI_List.xml": {"rhel": (137, 175, 81), "windows 10": (76, 113, 44)},        # DISA 2026-07-14
    "CciNistMappingData.ts": {"rhel": (139, 179, 82), "windows 10": (77, 117, 45)},  # Heimdall fallback
}


def expected(explorer):
    source = os.path.basename(explorer.ctx["cci_source"])
    if source not in EXPECTED_COVERAGE:
        pytest.skip(f"no expected numbers for CCI source {source}")
    return EXPECTED_COVERAGE[source]


@real
def test_stig_coverage_matches_validate_data(explorer):
    for stig, numbers in expected(explorer).items():
        r = explorer.stig_coverage(stig)
        assert (r["statements_covered"], r["statements_total"], r["controls"]) == numbers, stig


@real
def test_statement_coverage_narrows_to_a_statement(explorer):
    r = explorer.statement_coverage("AU-03a", "rhel")
    assert [s["label"] for s in r["statements"]] == ["AU-03a."]
    assert r["statements"][0]["stig_rules"]
    assert all(rule["stig"] == "Red Hat Enterprise Linux 9" for rule in r["statements"][0]["stig_rules"])


@real
def test_statement_coverage_without_rules_says_so(explorer):
    r = explorer.statement_coverage("AC-2", "rhel")
    assert r["covered"] == 0 and r["total"] > 20
    assert all(s["evidence"] == NO_STIG_EVIDENCE for s in r["statements"])
    assert "AC-2(1)" in r["enhancements_with_stig_rules"]
    assert r["methods"]["INTERVIEW"]


@real
def test_controls_and_baselines(explorer):
    c = explorer.get_control("ac-07")
    assert c["control_id"] == "AC-7" and c["baselines"] == ["LOW", "MODERATE", "HIGH"]
    assert "{{" not in c["statement"]
    w = explorer.get_control("AC-2(10)")
    assert w["withdrawn"] and w["withdrawn_to"] == ["AC-2"]
    assert explorer.search_controls(baseline="moderate", limit=500)["total"] == 287


@real
def test_cci_and_rule_lookups(explorer):
    rule = explorer.get_stig_rule("V-258054")
    assert {m["control"] for m in rule["cci_mappings"]} == {"AC-7"}
    assert explorer.lookup_cci("130")["cci"] == "CCI-000130"
    # Unmapped CCIs are reported, not guessed: ambiguous Heimdall redirects, or DISA CCIs with no Rev 5 reference.
    dropped = next(iter(explorer.cci_report["dropped_ambiguous"]), None)
    if dropped:
        assert "not guessed" in explorer.lookup_cci(dropped)["dropped"]
    unmapped = next((c for c in explorer.cci_rules if c not in explorer.cci_to_nist), None)
    if unmapped:
        assert "control" not in explorer.lookup_cci(unmapped) and explorer.lookup_cci(unmapped)["dropped"]


@real
def test_gaps_are_the_uncovered_statements(explorer):
    covered, total, _ = expected(explorer)["rhel"]
    assert explorer.list_gaps("rhel", limit=500)["total"] == total - covered


@real
def test_end_to_end_through_mcp(explorer):
    result = asyncio.run(build_server(explorer).call_tool("statement_coverage", {"control": "AU-3 a", "stig": "rhel"}))
    assert not result.is_error
    assert json.loads(result.content[0].text)["covered"] == 1
