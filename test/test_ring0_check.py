"""
Ring 0 setup check tests (scripts/ring0_check.py).

Tests marked "real" use the NIST files in knowledge/ (or NIST_DATA_DIR) and
are skipped when they are not present.

    pytest test/test_ring0_check.py
"""
import importlib.util
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from parsers import cci_list_metadata  # noqa: E402

pytest.importorskip("mcp")

_spec = importlib.util.spec_from_file_location("ring0_check", os.path.join(ROOT, "scripts", "ring0_check.py"))
ring0 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ring0)

KNOWLEDGE = os.environ.get("NIST_DATA_DIR", os.path.join(ROOT, "knowledge"))
STIGS = os.path.join(ROOT, "stigs")
CCI_SAMPLE = os.path.join(ROOT, "test", "fixtures", "cci_sample.xml")
real = pytest.mark.skipif(not os.path.exists(os.path.join(KNOWLEDGE, "nist_800_53-rev5_catalog_json.json")),
                          reason="real catalog not found in knowledge/")


@pytest.fixture(scope="module")
def explorer():
    exp, err = ring0.load_explorer(KNOWLEDGE, STIGS)
    assert err is None, err
    return exp


# ----------------------------------------------------------------------
#  CCI list metadata helper
# ----------------------------------------------------------------------
def test_cci_list_metadata_sample():
    assert cci_list_metadata(CCI_SAMPLE) == {"version": "sample", "publishdate": "2024-01-01"}


def test_cci_list_metadata_ignores_item_dates(tmp_path):
    p = tmp_path / "U_CCI_List.xml"
    p.write_text('<?xml version="1.0"?><cci_list xmlns="http://iase.disa.mil/cci"><cci_items>'
                 '<cci_item id="CCI-000001"><publishdate>2009-05-13</publishdate></cci_item>'
                 '</cci_items></cci_list>', encoding="utf-8")
    assert cci_list_metadata(str(p)) == {"version": "", "publishdate": ""}


@real
def test_cci_list_metadata_real():
    path = os.path.join(KNOWLEDGE, "U_CCI_List.xml")
    if not os.path.exists(path):
        pytest.skip("U_CCI_List.xml not in knowledge/")
    assert cci_list_metadata(path)["publishdate"][:2] == "20"


# ----------------------------------------------------------------------
#  CCI source
# ----------------------------------------------------------------------
def test_cci_source_disa_pass(tmp_path):
    p = tmp_path / "U_CCI_List.xml"
    p.write_bytes(open(CCI_SAMPLE, "rb").read())
    r = ring0.check_cci_source(str(p))
    assert r["status"] == ring0.PASS and "2024-01-01" in r["detail"]


def test_cci_source_old_disa_list_warns(tmp_path):
    p = tmp_path / "U_CCI_List.xml"
    p.write_text('<cci_list xmlns="http://iase.disa.mil/cci"><metadata><version>2016-06-27</version>'
                 '<publishdate>2016-06-27</publishdate></metadata></cci_list>', encoding="utf-8")
    assert ring0.check_cci_source(str(p))["status"] == ring0.WARN


def test_cci_source_heimdall_warns():
    assert ring0.check_cci_source("knowledge/CciNistMappingData.ts")["status"] == ring0.WARN


def test_cci_source_none_fails():
    assert ring0.check_cci_source("none")["status"] == ring0.FAIL


# ----------------------------------------------------------------------
#  Reference data
# ----------------------------------------------------------------------
def test_data_load_failure_is_fail(tmp_path):
    exp, err = ring0.load_explorer(str(tmp_path), STIGS)
    assert exp is None and err
    results = ring0.check_data(exp, STIGS, err)
    assert [r["status"] for r in results] == [ring0.FAIL]


@real
def test_data_checks_pass(explorer):
    results = ring0.check_data(explorer, STIGS)
    assert all(r["status"] == ring0.PASS for r in results), results
    stig_lines = [r for r in results if r["check"] == "data.stig"]
    assert len(stig_lines) == 2  # both bundled STIGs


@real
def test_data_unmapped_rule_fails(explorer):
    stigs = explorer.ctx["stigs"]
    saved = stigs[0]["unmapped_rules"]
    try:
        stigs[0]["unmapped_rules"] = 1
        results = ring0.check_data(explorer, STIGS)
    finally:
        stigs[0]["unmapped_rules"] = saved
    assert any(r["check"] == "data.stig" and r["status"] == ring0.FAIL for r in results)


@real
def test_real_cci_source(explorer):
    assert ring0.check_cci_source(explorer.ctx["cci_source"])["status"] in (ring0.PASS, ring0.WARN)


# ----------------------------------------------------------------------
#  MCP surface and guardrail
# ----------------------------------------------------------------------
def test_mcp_surface_offline():
    r = ring0.check_mcp_surface()
    assert r["status"] == ring0.PASS, r


def test_mcp_surface_ignores_caller_env(monkeypatch):
    monkeypatch.setenv(ring0.ROLLUP_ENV, "1")
    r = ring0.check_mcp_surface()
    assert r["status"] == ring0.PASS, r
    assert os.environ[ring0.ROLLUP_ENV] == "1"  # restored afterwards


def test_mcp_surface_detects_rollup_tool(monkeypatch):
    import mcp_server.server as srv
    monkeypatch.setattr(srv, "rollup_allowed", lambda: True)
    r = ring0.check_mcp_surface()
    assert r["status"] == ring0.FAIL and "results_rollup" in r["detail"]


@real
def test_mcp_surface_real(explorer):
    assert ring0.check_mcp_surface(explorer)["status"] == ring0.PASS


@pytest.mark.parametrize("value", ["1", "true", "YES", " True "])
def test_rollup_env_true_fails(monkeypatch, value):
    monkeypatch.setenv(ring0.ROLLUP_ENV, value)
    assert ring0.check_rollup_env()["status"] == ring0.FAIL


@pytest.mark.parametrize("value", [None, "", "0", "false", "no"])
def test_rollup_env_off_passes(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(ring0.ROLLUP_ENV, raising=False)
    else:
        monkeypatch.setenv(ring0.ROLLUP_ENV, value)
    assert ring0.check_rollup_env()["status"] == ring0.PASS


# ----------------------------------------------------------------------
#  Claude Code registration
# ----------------------------------------------------------------------
def test_claude_cli_absent_warns(monkeypatch):
    monkeypatch.setattr(ring0.shutil, "which", lambda name: None)
    assert ring0.check_claude_registration()["status"] == ring0.WARN


def _fake_run(stdout):
    def run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout=stdout, stderr="")
    return run


def test_claude_registered_prints_status_only(monkeypatch):
    monkeypatch.setattr(ring0.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(ring0.subprocess, "run", _fake_run(
        "Checking MCP server health...\n\nnist-explorer: /secret/venv/bin/python /secret/scripts/mcp_server.py - Connected\n"))
    r = ring0.check_claude_registration()
    assert r["status"] == ring0.PASS and "Connected" in r["detail"] and "/secret" not in r["detail"]


def test_claude_not_registered_warns(monkeypatch):
    monkeypatch.setattr(ring0.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(ring0.subprocess, "run", _fake_run("other: cmd - Connected\n"))
    assert ring0.check_claude_registration()["status"] == ring0.WARN


def test_claude_timeout_warns(monkeypatch):
    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout"))
    monkeypatch.setattr(ring0.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(ring0.subprocess, "run", run)
    assert ring0.check_claude_registration()["status"] == ring0.WARN


# ----------------------------------------------------------------------
#  End to end
# ----------------------------------------------------------------------
@real
def test_main_json_exit_code(monkeypatch, capsys):
    import json
    monkeypatch.delenv(ring0.ROLLUP_ENV, raising=False)
    code = ring0.main(["--knowledge", KNOWLEDGE, "--stigs", STIGS, "--json", "--no-claude"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["ok"]
    monkeypatch.setenv(ring0.ROLLUP_ENV, "1")
    assert ring0.main(["--knowledge", KNOWLEDGE, "--stigs", STIGS, "--no-claude"]) == 1
