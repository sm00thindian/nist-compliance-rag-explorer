"""
Import CINC Auditor / InSpec results (HDF or InSpec JSON) for rollup.

Scans run outside this tool; this module only reads the result file. Each
control is matched to the loaded STIG by its ``gid`` tag (the Vuln ID), and
its status is computed with Heimdall's rules (inspecjs compute_status), so
counts match what Heimdall shows:

    any result errored (or has a backtrace)   -> error
    waived (skipped_due_to_waiver) or impact 0 -> not_applicable
    no results                                -> error
    any failed                                -> fail
    any passed                                -> pass
    all skipped                               -> not_reviewed

Attestations (``attestation_data``) are not applied; attested controls are
listed so they can be reviewed by hand.

The returned results hold statuses and IDs only. Test descriptions, messages,
platform, target and passthrough data (hostnames, IPs) stay in the file and
are never copied into what this module returns, except ``failures`` in
``import_hdf(..., keep_details=True)``, which is for local reports only.
"""
import json
from typing import Dict, List, Optional

PASS, FAIL, NOT_APPLICABLE, NOT_REVIEWED, ERROR = "pass", "fail", "not_applicable", "not_reviewed", "error"


class HDFError(ValueError):
    pass


def control_status(control: dict) -> str:
    """Status of one HDF control, following Heimdall's precedence."""
    segments = ["error" if r.get("backtrace") else (r.get("status") or "no_status")
                for r in control.get("results") or []]
    waived = bool((control.get("waiver_data") or {}).get("skipped_due_to_waiver"))
    if "error" in segments:
        return ERROR
    if waived or control.get("impact") == 0:
        return NOT_APPLICABLE
    if not segments:
        return ERROR
    if "failed" in segments:
        return FAIL
    if "passed" in segments:
        return PASS
    if "skipped" in segments:
        return NOT_REVIEWED
    return ERROR


def _controls(hdf: dict) -> List[dict]:
    """Controls with results, one per ID.

    Overlaid profiles repeat a control in the wrapper and the base profile;
    the copy that carries results wins, and the wrapper (a profile with no
    parent) wins a tie.
    """
    profiles = hdf.get("profiles")
    if not isinstance(profiles, list):
        raise HDFError("Not an HDF / InSpec results file: no 'profiles' list.")
    chosen: Dict[str, dict] = {}
    rank: Dict[str, tuple] = {}
    for profile in profiles:
        for c in profile.get("controls") or []:
            key = (c.get("tags") or {}).get("gid") or c.get("id")
            r = (bool(c.get("results")), not profile.get("parent_profile"))
            if key and (key not in rank or r > rank[key]):
                chosen[key], rank[key] = c, r
    if not chosen:
        raise HDFError("The results file has no controls.")
    return list(chosen.values())


def import_hdf(path: str, rules: List[dict], keep_details: bool = False) -> dict:
    """Read a results file and match it to a loaded STIG's rules.

    Returns {
      "results": {vuln_id: {"status", "rid", "rid_mismatch"}},   # rollup input
      "counts": {status: n},
      "rid_mismatches": [{"vuln_id", "result_rid", "stig_rid"}],
      "not_in_stig": [gid, ...],            # results for rules the loaded STIG doesn't have
      "attested": [vuln_id, ...],           # attestations present but not applied
      "profiles": [{"name", "version"}],
      "failures": {vuln_id: [code_desc, ...]}   # only with keep_details; local use only
    }
    """
    with open(path, encoding="utf-8") as f:
        try:
            hdf = json.load(f)
        except json.JSONDecodeError as e:
            raise HDFError(f"{path} is not JSON: {e}") from e
    by_vuln = {r["vuln_id"]: r for r in rules}
    out = {"results": {}, "counts": {}, "rid_mismatches": [], "not_in_stig": [], "attested": [],
           "profiles": [{"name": p.get("name", ""), "version": p.get("version", "")}
                        for p in hdf.get("profiles") or [] if not p.get("parent_profile")]}
    if keep_details:
        out["failures"] = {}
    for c in _controls(hdf):
        tags = c.get("tags") or {}
        gid = tags.get("gid") or c.get("id", "")
        rule = by_vuln.get(gid)
        if rule is None:
            out["not_in_stig"].append(gid)
            continue
        status = control_status(c)
        rid = tags.get("rid", "")
        mismatch = bool(rid) and rid != rule["rule_id"]
        out["results"][gid] = {"status": status, "rid": rid, "rid_mismatch": mismatch}
        out["counts"][status] = out["counts"].get(status, 0) + 1
        if mismatch:
            out["rid_mismatches"].append({"vuln_id": gid, "result_rid": rid, "stig_rid": rule["rule_id"]})
        if c.get("attestation_data"):
            out["attested"].append(gid)
        if keep_details and status == FAIL:
            out["failures"][gid] = [r.get("code_desc", "") for r in c.get("results") or []
                                    if r.get("status") == "failed"]
    if not out["results"]:
        raise HDFError(f"None of the {len(out['not_in_stig'])} controls in {path} match a rule in the loaded STIG "
                       "(matched on the gid tag / Vuln ID). Is --stig the right one?")
    return out


def rollup_summary(report: List[dict], imported: Optional[dict] = None) -> dict:
    """Statement-level view of a rollup with statuses and IDs only (safe to show a model when allowed)."""
    totals: Dict[str, int] = {}
    controls = []
    for c in report:
        statements = []
        for s in c["statements"]:
            totals[s["status"]] = totals.get(s["status"], 0) + 1
            statements.append({"label": s["label"], "status": s["status"], "rules": s["rules"]})
        controls.append({"control": c["control"], "title": c["title"], "statements": statements})
    out = {"statement_totals": totals, "controls": controls}
    if imported:
        out["rule_counts"] = imported["counts"]
        out["rid_mismatches"] = len(imported["rid_mismatches"])
        out["results_not_in_stig"] = len(imported["not_in_stig"])
        out["attestations_not_applied"] = len(imported["attested"])
    return out
