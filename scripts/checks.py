#!/usr/bin/env python3
"""
Local STIG checks: generate from public STIG text, collect evidence, evaluate locally.

  python scripts/checks.py status   --stig rhel
  python scripts/checks.py generate --stig rhel --control AU-3            # calls the configured LLM
  python scripts/checks.py generate --stig rhel --rules V-258054 --dry-run  # show exactly what would be sent
  python scripts/checks.py review   --stig rhel V-258054 [--approve]
  python scripts/checks.py plan     --stig rhel --out collect.sh          # evidence collection script
  python scripts/checks.py evaluate --stig rhel --evidence ./evidence [--json out.json] [--csv out.csv]
  python scripts/checks.py import-results --stig rhel --hdf scan.json [--json out.json] [--csv out.csv]

Only `generate` talks to a model, and it only sends published STIG text.
Evidence and scan results are read locally and never sent anywhere.
"""
import argparse
import csv
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from checks.engine import evaluate_check  # noqa: E402
from checks.evidence import EvidenceBundle, collection_script  # noqa: E402
from checks.hdf import HDFError, import_hdf  # noqa: E402
from checks.generator import (  # noqa: E402
    SYSTEM_PROMPT, CheckStore, PublicRequirement, build_prompt, generate_check, stale_checks,
)
from checks.rollup import load_context, rollup  # noqa: E402
from checks.spec import CheckSpecError, evidence_needed  # noqa: E402
from parsers import normalize_control_id  # noqa: E402


def pick_stig(ctx, name):
    name = name.lower()
    matches = [s for s in ctx["stigs"] if name in s["technology"].lower() or name in s["file"].lower()
               or (name == "rhel" and "red hat" in s["technology"].lower())]
    if len(matches) != 1:
        options = ", ".join(s["technology"] for s in ctx["stigs"])
        sys.exit(f"--stig {name!r} matched {len(matches)} STIGs. Available: {options}")
    return matches[0]["technology"]


def select_rules(ctx, tech, args):
    rules = ctx["rules"][tech]
    if getattr(args, "rules", None):
        wanted = {r.strip().upper() for r in args.rules.split(",")}
        rules = [r for r in rules if r["vuln_id"].upper() in wanted or r["stig_id"].upper() in wanted]
    if getattr(args, "control", None):
        cid = normalize_control_id(args.control)
        linked = {r["vuln_id"] for r in ctx["recommendations"].get(tech, {}).get(cid, [])}
        rules = [r for r in rules if r["vuln_id"] in linked]
    if getattr(args, "limit", None):
        rules = rules[: args.limit]
    return rules


def cmd_status(ctx, tech, store, args):
    rules = ctx["rules"][tech]
    checks = store.load_all(tech)
    auto = sum(1 for c in checks.values() if c.get("automatable"))
    reviewed = sum(1 for c in checks.values() if c.get("reviewed"))
    print(f"{tech}: {len(rules)} rules; {len(checks)} checks written ({auto} automatable, "
          f"{len(checks) - auto} manual), {reviewed} reviewed")
    stale = stale_checks(checks, rules)
    if stale:
        print(f"  {len(stale)} checks were written against older STIG text and need regenerating: {', '.join(stale[:10])}")
    print(f"  CCI mapping: {ctx['cci_source']}")


def cmd_generate(ctx, tech, store, args):
    rules = select_rules(ctx, tech, args)
    if not rules:
        sys.exit("No rules selected.")
    if args.dry_run:
        print("=== system prompt ===\n" + SYSTEM_PROMPT)
        for r in rules:
            print(f"=== user prompt for {r['vuln_id']} ===\n" + build_prompt(PublicRequirement.from_rule(r, tech)))
        return
    from checks.llm import make_client
    client = make_client(args.provider)
    print(f"Generating {len(rules)} checks with {client.name} (public STIG text only)")
    done = skipped = failed = 0
    for r in rules:
        existing = store.load(tech, r["vuln_id"])
        if existing and (existing.get("reviewed") or not args.force):
            skipped += 1
            continue
        try:
            check = generate_check(PublicRequirement.from_rule(r, tech), client)
            store.save(check)
            done += 1
            kind = f"{len(check['conditions'])} condition(s)" if check["automatable"] else "manual"
            print(f"  {r['vuln_id']}: {kind}")
        except (CheckSpecError, Exception) as e:  # keep going; report at the end
            failed += 1
            print(f"  {r['vuln_id']}: FAILED: {e}")
    print(f"{done} written, {skipped} skipped (already present), {failed} failed. "
          f"Review them with: python scripts/checks.py review --stig ... <Vuln-ID>")


def cmd_review(ctx, tech, store, args):
    check = store.load(tech, args.vuln)
    if not check:
        sys.exit(f"No check for {args.vuln}. Generate it first.")
    rule = next((r for r in ctx["rules"][tech] if r["vuln_id"] == args.vuln), None)
    if rule:
        print(f"=== STIG check text ({args.vuln}) ===\n{rule['check']}\n")
    print("=== structured check ===")
    print(json.dumps(check, indent=2))
    if args.approve:
        check["reviewed"] = True
        store.save(check, overwrite_reviewed=True)
        print(f"\nMarked {args.vuln} reviewed.")


def cmd_plan(ctx, tech, store, args):
    checks = store.load_all(tech)
    files, commands, unreviewed = [], [], []
    for c in checks.values():
        if not c.get("automatable"):
            continue
        need = evidence_needed(c)
        files += need["files"]
        commands += need["commands"]
        if need["commands"] and not c.get("reviewed"):
            unreviewed.append(c["rule"])
    script = collection_script(files, commands, unreviewed)
    if args.out:
        with open(args.out, "w") as f:
            f.write(script)
        print(f"Wrote {args.out}: {len(set(files))} files, {len(set(commands))} commands. Review it, then run it on the target.")
    else:
        print(script)


def cmd_evaluate(ctx, tech, store, args):
    checks = store.load_all(tech)
    if not checks:
        sys.exit(f"No checks for {tech}. Generate some first.")
    bundle = EvidenceBundle(args.evidence)
    results = {v: evaluate_check(c, bundle) for v, c in checks.items()}
    counts = {}
    for r in results.values():
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f"{tech}: {len(results)} checks evaluated locally: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    unreviewed = sum(1 for c in checks.values() if not c.get("reviewed"))
    if unreviewed:
        print(f"  Note: {unreviewed} checks are model-generated and not yet reviewed.")
    for v, r in sorted(results.items()):
        if r["status"] == "fail":
            print(f"  FAIL {v} {r['title']}")
            for cond in r["conditions"]:
                if cond["status"] == "fail":
                    print(f"       {cond['detail']}")
                    for e in cond["evidence"][:3]:
                        print(f"       {e['source']}:{e['line']}: {e['text']}")

    report_rollup(ctx, tech, results, args,
                  lambda v: "; ".join(f"[{x['status']}] {x['detail']}" for x in (results.get(v) or {}).get("conditions", [])))


def report_rollup(ctx, tech, results, args, detail, extra=None):
    """Print the 800-53A rollup and write --json / --csv. detail(vuln_id) gives the CSV Detail column."""
    report = rollup(tech, results, ctx)
    totals = {}
    for c in report:
        for s in c["statements"]:
            totals[s["status"]] = totals.get(s["status"], 0) + 1
    print("\n800-53A determination statements: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
    for c in report:
        flagged = [s for s in c["statements"] if s["status"] in ("fail", "partial")]
        for s in flagged:
            bad = [v for v, st in s["rules"].items() if st == "fail"]
            print(f"  {s['status'].upper():<8} {s['label']:<16} {c['title']}" + (f"  (failing: {', '.join(bad)})" if bad else ""))

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"technology": tech, "results": results, "statements": report, **(extra or {})}, f, indent=2)
        print(f"Wrote {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Control", "800-53A statement", "Statement status", "STIG rule", "Rule status", "Detail"])
            for c in report:
                for s in c["statements"]:
                    if not s["rules"]:
                        w.writerow([c["control"], s["label"], s["status"], "", "", "Examine/Interview"])
                    for v, st in s["rules"].items():
                        w.writerow([c["control"], s["label"], s["status"], v, st, detail(v)])
        print(f"Wrote {args.csv}")


def cmd_import_results(ctx, tech, store, args):
    try:
        imported = import_hdf(args.hdf, ctx["rules"][tech], keep_details=True)
    except HDFError as e:
        sys.exit(str(e))
    results = imported["results"]
    names = ", ".join(f"{p['name']} {p['version']}".strip() for p in imported["profiles"])
    print(f"{tech}: {len(results)} results imported from {os.path.basename(args.hdf)} ({names}): "
          + ", ".join(f"{k} {v}" for k, v in sorted(imported["counts"].items())))
    if imported["rid_mismatches"]:
        print(f"  {len(imported['rid_mismatches'])} results were run against a different rule revision than the "
              f"loaded STIG ({', '.join(m['vuln_id'] for m in imported['rid_mismatches'][:8])}"
              f"{', ...' if len(imported['rid_mismatches']) > 8 else ''}). Check the profile matches the STIG release.")
    if imported["not_in_stig"]:
        print(f"  {len(imported['not_in_stig'])} results are for rules not in the loaded STIG and were skipped: "
              + ", ".join(imported["not_in_stig"][:8]))
    if imported["attested"]:
        print(f"  {len(imported['attested'])} controls carry attestations, which are not applied: "
              + ", ".join(imported["attested"][:8]))
    missing = len(ctx["rules"][tech]) - len(results)
    if missing:
        print(f"  {missing} STIG rules have no result in this file.")
    for v in sorted(imported["failures"]):
        print(f"  FAIL {v}")
    failures = imported["failures"]
    report_rollup(ctx, tech, results, args,
                  lambda v: ("rid mismatch; " if (results.get(v) or {}).get("rid_mismatch") else "")
                  + "; ".join(failures.get(v, [])),
                  extra={"rid_mismatches": imported["rid_mismatches"], "not_in_stig": imported["not_in_stig"]})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knowledge", default="knowledge")
    ap.add_argument("--stigs", default="stigs")
    ap.add_argument("--checks", default="checks", help="folder for generated checks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("status", "generate", "review", "plan", "evaluate", "import-results"):
        p = sub.add_parser(name)
        p.add_argument("--stig", required=True, help="e.g. rhel, windows")
        if name == "generate":
            p.add_argument("--rules", help="comma-separated Vuln IDs or STIG IDs")
            p.add_argument("--control", help="only rules linked to this control, e.g. AU-3")
            p.add_argument("--limit", type=int)
            p.add_argument("--provider", help="anthropic, bedrock, openai or xai (default: $LLM_PROVIDER)")
            p.add_argument("--force", action="store_true", help="regenerate unreviewed checks")
            p.add_argument("--dry-run", action="store_true", help="print the prompts; call nothing")
        if name == "review":
            p.add_argument("vuln")
            p.add_argument("--approve", action="store_true")
        if name == "plan":
            p.add_argument("--out")
        if name == "evaluate":
            p.add_argument("--evidence", required=True)
        if name == "import-results":
            p.add_argument("--hdf", required=True, help="CINC Auditor / InSpec JSON or HDF results file")
        if name in ("evaluate", "import-results"):
            p.add_argument("--json")
            p.add_argument("--csv")
    args = ap.parse_args()
    ctx = load_context(args.knowledge, args.stigs)
    tech = pick_stig(ctx, args.stig)
    store = CheckStore(args.checks)
    {"status": cmd_status, "generate": cmd_generate, "review": cmd_review, "plan": cmd_plan,
     "evaluate": cmd_evaluate, "import-results": cmd_import_results}[args.cmd](ctx, tech, store, args)


if __name__ == "__main__":
    main()
