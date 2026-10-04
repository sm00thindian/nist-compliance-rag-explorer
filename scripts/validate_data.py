#!/usr/bin/env python3
"""
Validate the data plumbing against the real source files.

Loads the OSCAL catalog, baselines, CCI list and STIGs the same way the app
does, prints what was parsed, and exits non-zero if any check fails.

    python scripts/validate_data.py                     # uses knowledge/ and stigs/
    python scripts/validate_data.py --cci ~/Downloads/U_CCI_List.xml
    python scripts/validate_data.py --json sources.json  # also write the data-source records

It first prints a "Data sources" section (path, SHA-256, size, version and
origin of every file used). WARN lines there never change the exit code.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from parsers import (  # noqa: E402
    apply_baselines,
    extract_assessment_details,
    extract_baseline_control_ids,
    extract_controls_from_json,
    load_cci_mapping,
    load_cci_mapping_from_heimdall,
    load_cci_parts,
    load_cci_parts_from_heimdall,
    link_objectives_to_rules,
    reconcile_cci_mapping,
    load_cci_records,
    load_stig_data,
)
from provenance import (  # noqa: E402
    DEFAULT_EXPECT_CATALOG_VERSION,
    DEFAULT_MAX_CCI_AGE_DAYS,
    describe_sources,
    format_record,
    provenance_document,
    source_warnings,
)

failures = []


def check(ok, message):
    print(("  PASS  " if ok else "  FAIL  ") + message)
    if not ok:
        failures.append(message)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knowledge", default="knowledge")
    ap.add_argument("--catalog", default=None)
    ap.add_argument("--cci", default=None, help="path to U_CCI_List.xml (default: knowledge/ then ./)")
    ap.add_argument("--cci-fallback", default=None,
                    help="path to MITRE Heimdall CciNistMappingData.ts, used when no DISA list is found "
                         "(default: knowledge/CciNistMappingData.ts)")
    ap.add_argument("--stigs", default="stigs")
    ap.add_argument("--max-cci-age-days", type=int, default=DEFAULT_MAX_CCI_AGE_DAYS,
                    help="WARN when the DISA CCI list's publishdate is older than this (default %(default)s)")
    ap.add_argument("--expect-catalog-version", default=DEFAULT_EXPECT_CATALOG_VERSION,
                    help="WARN when the catalog's metadata.version differs (default %(default)s)")
    ap.add_argument("--json", default=None, metavar="PATH",
                    help="also write the data-source records and warnings as JSON to PATH")
    args = ap.parse_args()

    k = args.knowledge
    catalog_path = args.catalog or os.path.join(k, "nist_800_53-rev5_catalog_json.json")

    # Provenance of every input file (informational; warnings never fail the run)
    records = describe_sources(k, args.stigs, cci_path=args.cci, catalog_path=catalog_path,
                               cci_fallback=args.cci_fallback)
    warnings = source_warnings(records, max_cci_age_days=args.max_cci_age_days,
                               expect_catalog_version=args.expect_catalog_version)
    print("Data sources:")
    for r in records:
        for line in format_record(r):
            print(line)
    for w in warnings:
        print(f"  WARN  {w}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(provenance_document(records, warnings), f, indent=2)
        print(f"  wrote data-source records to {args.json}")
    print()

    print(f"Catalog: {catalog_path}")
    with open(catalog_path, encoding="utf-8") as f:
        catalog_json = json.load(f)
    version = catalog_json.get("catalog", {}).get("metadata", {}).get("version", "?")
    controls = {c["control_id"]: c for c in extract_controls_from_json(catalog_json)}
    active = [c for c in controls.values() if not c["withdrawn"]]
    print(f"  catalog version {version}: {len(controls)} controls, {len(active)} active, "
          f"{len(controls) - len(active)} withdrawn")
    check(len(controls) > 1000, "catalog parses to more than 1,000 controls and enhancements")
    check(all(c["description"] for c in controls.values()), "every control has statement text (or a withdrawn note)")
    check(not any("{{" in c["description"] for c in controls.values()), "no unresolved parameter inserts")
    check(all(c["family_title"] for c in controls.values()), "every control has a family")

    # Baselines
    baselines = {}
    for level in ("LOW", "MODERATE", "HIGH"):
        path = os.path.join(k, f"nist_800_53-rev5_{level.lower()}-baseline_json.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                baselines[level] = extract_baseline_control_ids(json.load(f))
    print(f"Baselines: { {lvl: len(ids) for lvl, ids in baselines.items()} }")
    for level, ids in baselines.items():
        missing = sorted(i for i in ids if i not in controls)
        check(not missing, f"{level} baseline: all {len(ids)} IDs exist in the catalog" + (f" (missing {missing[:5]})" if missing else ""))
        withdrawn = sorted(i for i in ids if i in controls and controls[i]["withdrawn"])
        check(not withdrawn, f"{level} baseline: no withdrawn controls" + (f" ({withdrawn[:5]})" if withdrawn else ""))
    if {"LOW", "MODERATE", "HIGH"} <= baselines.keys():
        check(baselines["LOW"] <= baselines["MODERATE"] <= baselines["HIGH"], "LOW ⊆ MODERATE ⊆ HIGH")
    apply_baselines(controls, baselines)

    # 800-53A
    assessment = extract_assessment_details(catalog_json)
    no_obj = sorted(c["control_id"] for c in active if c["control_id"] not in assessment)
    print(f"800-53A: objectives/methods for {len(assessment)} controls")
    check(not no_obj, "every active control has 800-53A objectives" + (f" (missing {no_obj[:5]})" if no_obj else ""))

    # CCI: the DISA list first, then the Heimdall fallback
    cci_path = args.cci or next((p for p in (os.path.join(k, "U_CCI_List.xml"), "U_CCI_List.xml") if os.path.exists(p)), None)
    fallback = args.cci_fallback or os.path.join(k, "CciNistMappingData.ts")
    raw, raw_parts = {}, {}
    if cci_path:
        records = load_cci_records(cci_path)
        raw = load_cci_mapping(cci_path)
        raw_parts = load_cci_parts(cci_path)
        rev5 = [r for r in records if any(x["version"] == "5" for x in r["references"])]
        print(f"CCI: DISA list {cci_path}: {len(records)} CCIs, {len(rev5)} with a Rev 5 reference, {len(raw)} mapped")
        check(len(records) > 1000, "CCI list parses to more than 1,000 CCIs")
        if not rev5:
            newest = max((x["version"] for r in records for x in r["references"]), default="none")
            print(f"  NOTE  newest SP 800-53 revision referenced in this file: {newest}. "
                  "Use a CCI list published after DISA added Rev 5 mappings (2022 or later).")
        check(len(raw) == len(rev5), "every CCI with a Rev 5 reference maps to a parseable control")
    if not raw and os.path.exists(fallback):
        raw = load_cci_mapping_from_heimdall(fallback)
        raw_parts = load_cci_parts_from_heimdall(fallback)
        print(f"CCI: no usable DISA list; using MITRE Heimdall fallback {fallback}: {len(raw)} CCIs")
    if not raw:
        print("CCI: no usable Rev 5 CCI mapping (pass --cci or --cci-fallback)")
        failures.append("no usable CCI mapping source")

    cci_to_nist, report = reconcile_cci_mapping(raw, controls, raw_parts)
    if raw:
        print(f"  reconciled against Rev 5: {report['kept']} kept, {len(report['redirected'])} redirected "
              f"from withdrawn controls, {len(report['dropped_not_in_rev5'])} dropped (not in Rev 5), "
              f"{len(report['dropped_ambiguous'])} dropped (withdrawn, ambiguous replacement)")
        check(len(cci_to_nist) > 1000, "more than 1,000 CCIs map to an active Rev 5 control")
        check(all(c in controls and not controls[c]["withdrawn"] for c in cci_to_nist.values()),
              "every mapped CCI points at an active Rev 5 control")

    # STIGs
    recs, stigs = load_stig_data(args.stigs, cci_to_nist)
    print(f"STIGs: {len(stigs)} in {args.stigs}")
    for s in stigs:
        mapped = s["rule_count"] - s["unmapped_rules"]
        n_controls = len(recs.get(s["technology"], {}))
        print(f"  {s['technology']} ({s['release']}): {mapped}/{s['rule_count']} rules mapped to {n_controls} controls")
        if raw:
            by_control = recs.get(s["technology"], {})
            links = [link_objectives_to_rules(c, rules, cci_to_nist, report["parts"], assessment.get(c))
                     for c, rules in by_control.items()]
            covered, total = sum(x["covered"] for x in links), sum(x["total"] for x in links)
            if total:
                print(f"    800-53A: {covered}/{total} determination statements in those controls have STIG evidence "
                      f"({covered * 100 // total}%)")
            check(mapped / max(s["rule_count"], 1) >= 0.95, f"{s['technology']}: at least 95% of rules map to a control")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed.")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()
