"""
Provenance of the data files: where each one comes from, its version and its
SHA-256, so a result can be traced to the exact inputs that produced it.

Only public source files are described here (OSCAL catalog and baselines, the
CCI list, STIG XCCDF). Nothing is sent anywhere.

    records = describe_sources("knowledge", "stigs")
    warnings = source_warnings(records)
"""
import datetime as _dt
import hashlib
import json
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from parsers import cci_list_metadata

DEFAULT_MAX_CCI_AGE_DAYS = 365
DEFAULT_EXPECT_CATALOG_VERSION = "5.2.0"

CATALOG_FILE = "nist_800_53-rev5_catalog_json.json"
BASELINE_FILES = {
    level: f"nist_800_53-rev5_{level.lower()}-baseline_json.json" for level in ("LOW", "MODERATE", "HIGH")
}
CCI_FILE = "U_CCI_List.xml"
HEIMDALL_FILE = "CciNistMappingData.ts"

OSCAL_SOURCE = "NIST oscal-content (github.com/usnistgov/oscal-content)"
CCI_SOURCE = 'DISA "CCI List" (www.cyber.mil/stigs/downloads)'
HEIMDALL_SOURCE = "MITRE heimdall2 (libs/hdf-converters/src/mappings/CciNistMappingData.ts)"
STIG_SOURCE = "bundled in stigs/ (DISA STIG XCCDF, public.cyber.mil)"


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _base_record(kind: str, path: str, source: str) -> dict:
    return {
        "kind": kind,
        "path": path,
        "sha256": sha256_file(path),
        "size": os.path.getsize(path),
        "source": source,
        "version": None,
    }


def describe_oscal(path: str, kind: str) -> dict:
    """Catalog or profile JSON: metadata.version and metadata.last-modified."""
    rec = _base_record(kind, path, OSCAL_SOURCE)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    root = next(iter(doc.values()), {}) if isinstance(doc, dict) and len(doc) == 1 else doc
    meta = root.get("metadata", {}) if isinstance(root, dict) else {}
    rec["version"] = meta.get("version")
    rec["last_modified"] = meta.get("last-modified")
    rec["title"] = meta.get("title")
    return rec


def describe_cci_list(path: str) -> dict:
    """DISA U_CCI_List.xml: <metadata><version> and <publishdate>."""
    rec = _base_record("cci_list", path, CCI_SOURCE)
    meta = cci_list_metadata(path)
    rec["version"] = meta["version"] or None
    rec["publishdate"] = meta["publishdate"] or None
    return rec


def describe_heimdall(path: str) -> dict:
    rec = _base_record("cci_heimdall", path, HEIMDALL_SOURCE)
    rec["note"] = "no version available in this file; identified by SHA-256 only"
    return rec


def describe_stig(path: str) -> dict:
    """STIG XCCDF: benchmark title, version and the release-info plain text."""
    rec = _base_record("stig", path, STIG_SOURCE)
    title = version = release = bench_id = None
    depth = 0
    for event, elem in ET.iterparse(path, events=("start", "end")):
        name = elem.tag.split("}", 1)[-1]
        if event == "start":
            depth += 1
            if depth == 1 and name == "Benchmark":
                bench_id = elem.get("id")
            if depth == 2 and name == "Group":
                break  # benchmark metadata precedes the groups
            continue
        if depth == 2:
            text = (elem.text or "").strip() or None
            if name == "title":
                title = text
            elif name == "version":
                version = text
            elif name == "plain-text" and elem.get("id") == "release-info":
                release = text
        depth -= 1
    rec["benchmark_id"] = bench_id
    rec["title"] = title
    rec["version"] = version
    rec["release_info"] = release
    return rec


def find_cci_list(knowledge_dir: str, cci_path: Optional[str] = None) -> Optional[str]:
    """Same lookup order as validate_data.py: explicit path, knowledge/, then ./"""
    if cci_path:
        return cci_path
    for p in (os.path.join(knowledge_dir, CCI_FILE), CCI_FILE):
        if os.path.exists(p):
            return p
    return None


def describe_sources(knowledge_dir: str, stig_folder: str, cci_path: Optional[str] = None,
                     catalog_path: Optional[str] = None, cci_fallback: Optional[str] = None) -> List[dict]:
    """One record per data file: catalog, baselines, CCI source, each STIG.

    The Heimdall fallback is described only when no DISA CCI list is found,
    matching the order the loaders use. Missing files are skipped.
    """
    records: List[dict] = []
    catalog = catalog_path or os.path.join(knowledge_dir, CATALOG_FILE)
    if os.path.exists(catalog):
        records.append(describe_oscal(catalog, "catalog"))
    for level, name in BASELINE_FILES.items():
        p = os.path.join(knowledge_dir, name)
        if os.path.exists(p):
            rec = describe_oscal(p, "baseline")
            rec["level"] = level
            records.append(rec)
    cci = find_cci_list(knowledge_dir, cci_path)
    if cci and os.path.exists(cci):
        records.append(describe_cci_list(cci))
    else:
        fallback = cci_fallback or os.path.join(knowledge_dir, HEIMDALL_FILE)
        if os.path.exists(fallback):
            records.append(describe_heimdall(fallback))
    if os.path.isdir(stig_folder):
        for name in sorted(os.listdir(stig_folder)):
            if name.lower().endswith(".xml"):
                try:
                    records.append(describe_stig(os.path.join(stig_folder, name)))
                except ET.ParseError:
                    continue
    return records


def _parse_date(value: Optional[str]) -> Optional[_dt.date]:
    if not value:
        return None
    try:
        return _dt.date.fromisoformat(value[:10])
    except ValueError:
        return None


def source_warnings(records: List[dict], today: Optional[_dt.date] = None,
                    max_cci_age_days: int = DEFAULT_MAX_CCI_AGE_DAYS,
                    expect_catalog_version: Optional[str] = DEFAULT_EXPECT_CATALOG_VERSION) -> List[str]:
    """Warnings about the sources (stale CCI list, fallback only, unexpected catalog version)."""
    today = today or _dt.date.today()
    warnings: List[str] = []
    kinds = {r["kind"] for r in records}
    for r in records:
        if r["kind"] == "catalog" and expect_catalog_version and r.get("version") != expect_catalog_version:
            warnings.append(f"catalog version {r.get('version')!r} differs from the expected "
                            f"{expect_catalog_version!r} ({r['path']})")
        if r["kind"] == "cci_list":
            published = _parse_date(r.get("publishdate"))
            if published is None:
                warnings.append(f"CCI list has no readable publishdate ({r['path']})")
            else:
                age = (today - published).days
                if age > max_cci_age_days:
                    warnings.append(f"CCI list published {published.isoformat()} is {age} days old "
                                    f"(more than {max_cci_age_days}); get the current list from "
                                    "www.cyber.mil/stigs/downloads (\"CCI List\")")
    if "cci_list" not in kinds:
        if "cci_heimdall" in kinds:
            warnings.append("no DISA CCI list found; only the MITRE Heimdall fallback is available "
                            "(unversioned, mixes Rev 4 and Rev 5 targets)")
        else:
            warnings.append("no CCI source found")
    if "catalog" not in kinds:
        warnings.append("no OSCAL catalog found")
    return warnings


def format_record(r: dict) -> List[str]:
    """Human-readable lines for one record."""
    label = {"catalog": "Catalog", "baseline": f"Baseline {r.get('level', '')}".strip(),
             "cci_list": "CCI list", "cci_heimdall": "CCI fallback", "stig": "STIG"}.get(r["kind"], r["kind"])
    lines = [f"  {label}: {r['path']}"]
    if r["kind"] in ("catalog", "baseline"):
        lines.append(f"    version {r.get('version')}, last-modified {r.get('last_modified')}")
    elif r["kind"] == "cci_list":
        lines.append(f"    version {r.get('version')}, publishdate {r.get('publishdate')}")
    elif r["kind"] == "cci_heimdall":
        lines.append(f"    {r['note']}")
    elif r["kind"] == "stig":
        lines.append(f"    {r.get('title')}, version {r.get('version')}, {r.get('release_info')}")
    lines.append(f"    sha256 {r['sha256']}, {r['size']:,} bytes")
    lines.append(f"    source: {r['source']}")
    return lines


def provenance_document(records: List[dict], warnings: List[str],
                        generated: Optional[_dt.datetime] = None) -> Dict:
    generated = generated or _dt.datetime.now(_dt.timezone.utc)
    return {"generated": generated.isoformat(timespec="seconds"), "sources": records, "warnings": warnings}
