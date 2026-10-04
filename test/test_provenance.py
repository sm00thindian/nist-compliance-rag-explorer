"""Tests for src/provenance.py (data-source records and warnings)."""
import datetime as dt
import hashlib
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from provenance import (  # noqa: E402
    describe_cci_list,
    describe_heimdall,
    describe_oscal,
    describe_sources,
    describe_stig,
    format_record,
    provenance_document,
    sha256_file,
    source_warnings,
)

KNOWLEDGE = os.environ.get("NIST_DATA_DIR", os.path.join(ROOT, "knowledge"))
STIGS = os.path.join(ROOT, "stigs")
RHEL = os.path.join(STIGS, "U_RHEL_9_STIG_V2R3_Manual-xccdf.xml")
WIN10 = os.path.join(STIGS, "U_MS_Windows_10_STIG_V3R3_Manual-xccdf.xml")

CCI_XML = (
    '﻿<?xml version="1.0" encoding="utf-8"?>'
    '<cci_list xmlns="http://iase.disa.mil/cci"><metadata><version>{v}</version>'
    "<publishdate>{d}</publishdate></metadata><cci_items>"
    '<cci_item id="CCI-000001"><status>draft</status><publishdate>2009-05-13</publishdate>'
    "<definition>x</definition></cci_item></cci_items></cci_list>"
)


def write_oscal(path, kind="catalog", version="5.2.0", modified="2026-05-11T16:01:09.00000-00:00"):
    doc = {kind: {"uuid": "u", "metadata": {"title": "T", "version": version, "last-modified": modified}}}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def write_cci(path, version="2026-07-14", date="2026-07-14"):
    path.write_text(CCI_XML.format(v=version, d=date), encoding="utf-8")
    return str(path)


def make_knowledge(tmp_path, cci=True, heimdall=False, catalog_version="5.2.0", cci_date="2026-07-14"):
    k = tmp_path / "knowledge"
    k.mkdir()
    write_oscal(k / "nist_800_53-rev5_catalog_json.json", version=catalog_version)
    for level in ("low", "moderate", "high"):
        write_oscal(k / f"nist_800_53-rev5_{level}-baseline_json.json", kind="profile")
    if cci:
        write_cci(k / "U_CCI_List.xml", cci_date, cci_date)
    if heimdall:
        (k / "CciNistMappingData.ts").write_text("export const data = [];\n", encoding="utf-8")
    return str(k)


def test_sha256_and_size(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello world")
    assert sha256_file(str(p)) == hashlib.sha256(b"hello world").hexdigest()
    rec = describe_heimdall(str(p))
    assert rec["sha256"] == hashlib.sha256(b"hello world").hexdigest()
    assert rec["size"] == 11
    assert rec["version"] is None and "no version" in rec["note"]


def test_oscal_metadata(tmp_path):
    rec = describe_oscal(write_oscal(tmp_path / "c.json"), "catalog")
    assert rec["version"] == "5.2.0"
    assert rec["last_modified"] == "2026-05-11T16:01:09.00000-00:00"
    assert "oscal-content" in rec["source"]
    rec = describe_oscal(write_oscal(tmp_path / "p.json", kind="profile", version="9.9"), "baseline")
    assert rec["version"] == "9.9"


def test_cci_metadata_with_bom(tmp_path):
    rec = describe_cci_list(write_cci(tmp_path / "U_CCI_List.xml", "2026-07-14", "2026-07-14"))
    assert rec["version"] == "2026-07-14"
    assert rec["publishdate"] == "2026-07-14"
    assert "CCI List" in rec["source"]


def test_bundled_stigs():
    rhel = describe_stig(RHEL)
    assert rhel["title"] == "Red Hat Enterprise Linux 9 Security Technical Implementation Guide"
    assert rhel["version"] == "2"
    assert rhel["release_info"] == "Release: 3 Benchmark Date: 30 Jan 2025"
    assert rhel["benchmark_id"] == "RHEL_9_STIG"
    win = describe_stig(WIN10)
    assert win["version"] == "3"
    assert win["release_info"].startswith("Release: 3")
    assert win["sha256"] == sha256_file(WIN10)


def test_describe_sources_order_and_kinds(tmp_path):
    k = make_knowledge(tmp_path, heimdall=True)
    recs = describe_sources(k, STIGS)
    kinds = [r["kind"] for r in recs]
    assert kinds == ["catalog", "baseline", "baseline", "baseline", "cci_list", "stig", "stig"]
    assert [r.get("level") for r in recs if r["kind"] == "baseline"] == ["LOW", "MODERATE", "HIGH"]
    assert source_warnings(recs, today=dt.date(2026, 10, 4)) == []
    doc = provenance_document(recs, [])
    assert json.loads(json.dumps(doc))["sources"][0]["kind"] == "catalog"
    assert all(format_record(r) for r in recs)


def test_stale_cci_warning(tmp_path):
    k = make_knowledge(tmp_path, cci_date="2025-01-01")
    recs = describe_sources(k, str(tmp_path / "no-stigs"))
    fresh = source_warnings(recs, today=dt.date(2025, 12, 31))
    assert fresh == []
    stale = source_warnings(recs, today=dt.date(2026, 1, 2))
    assert len(stale) == 1 and "366 days old" in stale[0]
    assert source_warnings(recs, today=dt.date(2025, 2, 1), max_cci_age_days=30) != []


def test_catalog_version_warning(tmp_path):
    k = make_knowledge(tmp_path, catalog_version="5.1.1")
    recs = describe_sources(k, STIGS)
    w = source_warnings(recs, today=dt.date(2026, 10, 4))
    assert len(w) == 1 and "5.1.1" in w[0] and "5.2.0" in w[0]
    assert source_warnings(recs, today=dt.date(2026, 10, 4), expect_catalog_version="5.1.1") == []


def test_heimdall_fallback(tmp_path):
    k = make_knowledge(tmp_path, cci=False, heimdall=True)
    recs = describe_sources(k, STIGS)
    cci = [r for r in recs if r["kind"].startswith("cci")]
    assert [r["kind"] for r in cci] == ["cci_heimdall"]
    assert cci[0]["version"] is None and len(cci[0]["sha256"]) == 64
    w = source_warnings(recs, today=dt.date(2026, 10, 4))
    assert len(w) == 1 and "Heimdall fallback" in w[0]


def test_explicit_cci_path_wins(tmp_path):
    k = make_knowledge(tmp_path, cci=False, heimdall=True)
    other = write_cci(tmp_path / "elsewhere.xml", "2026-01-01", "2026-01-01")
    recs = describe_sources(k, STIGS, cci_path=other)
    assert [r["path"] for r in recs if r["kind"].startswith("cci")] == [other]


def test_no_sources(tmp_path):
    w = source_warnings([], today=dt.date(2026, 10, 4))
    assert any("no CCI source" in x for x in w) and any("no OSCAL catalog" in x for x in w)


CATALOG = os.path.join(KNOWLEDGE, "nist_800_53-rev5_catalog_json.json")
CCI_LIST = os.path.join(KNOWLEDGE, "U_CCI_List.xml")


@pytest.mark.skipif(not os.path.exists(CATALOG), reason="catalog not in knowledge/")
def test_real_data_versions():
    recs = describe_sources(KNOWLEDGE, STIGS)
    catalog = next(r for r in recs if r["kind"] == "catalog")
    assert catalog["version"] == "5.2.0"
    if os.path.exists(CCI_LIST):
        cci = next(r for r in recs if r["kind"] == "cci_list")
        assert cci["publishdate"] == "2026-07-14"
        assert cci["version"] == "2026-07-14"
