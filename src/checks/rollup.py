"""
Roll local check results up to SP 800-53A determination statements.

Statuses per statement:
  fail        a linked STIG rule failed
  pass        every linked STIG rule was checked and passed
  partial     some linked rules passed; others have no check yet, need manual review, or lack evidence
  unchecked   linked rules exist but none was evaluated
  no_stig     no STIG rule provides evidence; use Examine/Interview
"""
import json
import os
import re
from typing import Dict, List, Optional

from parsers import (
    extract_assessment_details,
    extract_controls_from_json,
    link_objectives_to_rules,
    load_cci_mapping,
    load_cci_mapping_from_heimdall,
    load_cci_parts,
    load_cci_parts_from_heimdall,
    load_stig_data,
    parse_stig_file,
    reconcile_cci_mapping,
)


def load_context(knowledge_dir: str = "knowledge", stig_folder: str = "stigs") -> dict:
    """Load the catalog, 800-53A data, CCI mapping and STIGs (no models, no network)."""
    with open(os.path.join(knowledge_dir, "nist_800_53-rev5_catalog_json.json"), encoding="utf-8") as f:
        catalog_json = json.load(f)
    controls = {c["control_id"]: c for c in extract_controls_from_json(catalog_json)}
    raw, parts, source = {}, {}, "none"
    disa = next((p for p in (os.path.join(knowledge_dir, "U_CCI_List.xml"), "U_CCI_List.xml") if os.path.exists(p)), None)
    if disa:
        raw, parts, source = load_cci_mapping(disa), load_cci_parts(disa), disa
    heimdall = os.path.join(knowledge_dir, "CciNistMappingData.ts")
    if not raw and os.path.exists(heimdall):
        raw, parts, source = load_cci_mapping_from_heimdall(heimdall), load_cci_parts_from_heimdall(heimdall), heimdall
    cci_to_nist, report = reconcile_cci_mapping(raw, controls, parts)
    recs, stigs = load_stig_data(stig_folder, cci_to_nist)
    rules = {}
    for s in stigs:
        _, rs = parse_stig_file(os.path.join(stig_folder, s["file"]))
        rules[s["technology"]] = rs
    return {
        "controls": controls,
        "assessment": extract_assessment_details(catalog_json),
        "cci_to_nist": cci_to_nist,
        "cci_parts": report["parts"],
        "cci_source": source,
        "recommendations": recs,
        "stigs": stigs,
        "rules": rules,
    }


def _statement_status(rule_statuses: List[Optional[str]]) -> str:
    if not rule_statuses:
        return "no_stig"
    if "fail" in rule_statuses:
        return "fail"
    if all(s == "pass" for s in rule_statuses):
        return "pass"
    if "pass" in rule_statuses:
        return "partial"
    return "unchecked"


def rollup(technology: str, results: Dict[str, dict], ctx: dict) -> List[dict]:
    """Per control touched by the STIG: each determination statement with its rule results."""
    out = []
    by_control = ctx["recommendations"].get(technology, {})
    for cid in sorted(by_control, key=lambda c: (c.split("-")[0], *map(int, re.findall(r"\d+", c)))):
        link = link_objectives_to_rules(cid, by_control[cid], ctx["cci_to_nist"], ctx["cci_parts"],
                                        ctx["assessment"].get(cid))
        if not link["total"]:
            continue
        statements = []
        for obj in link["objectives"]:
            vulns = list(dict.fromkeys(r["vuln_id"] for r in obj["rules"]))
            per_rule = {v: (results.get(v) or {}).get("status", "no_check") for v in vulns}
            status = _statement_status([per_rule[v] if per_rule[v] in ("pass", "fail") else None for v in vulns]
                                       if vulns else [])
            statements.append({"label": obj["label"], "text": obj["text"], "status": status, "rules": per_rule})
        out.append({"control": cid, "title": ctx["controls"].get(cid, {}).get("title", ""), "statements": statements})
    return out
