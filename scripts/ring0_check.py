#!/usr/bin/env python3
"""
Ring 0 setup check: confirm the read-only setup is in place.

Prints one PASS / WARN / FAIL line per check and exits non-zero on any FAIL.
It only reads the public reference data (knowledge/, stigs/) and the local
environment; it reads no results or evidence, makes no network calls and
starts nothing beyond an optional `claude mcp list`.

    python scripts/ring0_check.py [--knowledge knowledge] [--stigs stigs] [--json]

Checks:
  data      catalog, 800-53A, baselines and CCI mapping load; every bundled STIG maps all rules
  cci       which CCI source is in use (DISA U_CCI_List.xml = PASS, Heimdall fallback = WARN)
  mcp       the MCP server exposes exactly the read-only tools and no results_rollup
  env       ALLOW_ROLLUP_TO_LLM is not set to a true value
  claude    nist-explorer is registered in Claude Code (WARN only; skipped without the CLI)
"""
import argparse
import asyncio
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from mcp_server.server import PUBLIC_TOOLS as EXPECTED_TOOLS  # noqa: E402
from parsers import cci_list_metadata  # noqa: E402

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
ROLLUP_ENV = "ALLOW_ROLLUP_TO_LLM"
SERVER_NAME = "nist-explorer"
BASELINE_LEVELS = ("LOW", "MODERATE", "HIGH")


def result(check: str, status: str, detail: str) -> dict:
    return {"check": check, "status": status, "detail": detail}


# ----------------------------------------------------------------------
#  1. Reference data
# ----------------------------------------------------------------------
def load_explorer(knowledge: str, stigs: str):
    """Load the data the way the MCP server does. Returns (explorer, error message or None)."""
    from mcp_server.data import Explorer
    try:
        return Explorer.load(knowledge, stigs), None
    except Exception as e:  # missing or unparsable files
        return None, f"{type(e).__name__}: {e}"


def check_data(explorer, stigs_dir: str, load_error=None) -> list:
    if explorer is None:
        return [result("data", FAIL, f"reference data did not load ({load_error})")]
    out = []
    controls = explorer.controls
    active = [c for c in controls.values() if not c["withdrawn"]]
    out.append(result("data.catalog", PASS if len(controls) > 1000 else FAIL,
                      f"{len(controls)} controls, {len(active)} active, {len(controls) - len(active)} withdrawn"))

    without = [c["control_id"] for c in active if not explorer.assessment.get(c["control_id"], {}).get("objectives")]
    out.append(result("data.800-53A", PASS if active and not without else FAIL,
                      f"objectives for {len(active) - len(without)}/{len(active)} active controls"
                      + (f" (missing e.g. {', '.join(without[:5])})" if without else "")))

    sizes = {lvl: len(explorer.baselines.get(lvl, ())) for lvl in BASELINE_LEVELS}
    missing = [lvl for lvl, n in sizes.items() if not n]
    out.append(result("data.baselines", FAIL if missing else PASS,
                      " / ".join(f"{lvl} {n}" for lvl, n in sizes.items())
                      + (f" (missing {', '.join(missing)})" if missing else "")))

    report = explorer.cci_report
    n = len(explorer.cci_to_nist)
    out.append(result("data.cci-mapping", PASS if n else FAIL,
                      f"{n} CCIs kept, {len(report.get('redirected', {}))} redirected, "
                      f"{len(report.get('dropped_ambiguous', {})) + len(report.get('dropped_not_in_rev5', {}))} dropped"))

    files = sorted(f for f in os.listdir(stigs_dir) if f.lower().endswith(".xml")) if os.path.isdir(stigs_dir) else []
    loaded = explorer.ctx["stigs"]
    if not loaded or len(loaded) < len(files):
        out.append(result("data.stigs", FAIL, f"{len(loaded)} of {len(files)} STIG files in {stigs_dir} loaded"))
    for s in loaded:
        mapped = s["rule_count"] - s["unmapped_rules"]
        ok = s["rule_count"] > 0 and s["unmapped_rules"] == 0
        rel = re.search(r"\d+", str(s.get("release", "")))
        label = f"{s['technology']} V{s['version']}" + (f"R{rel.group()}" if rel else "")
        out.append(result("data.stig", PASS if ok else FAIL, f"{label}: {mapped}/{s['rule_count']} rules map"))
    return out


# ----------------------------------------------------------------------
#  2. CCI source
# ----------------------------------------------------------------------
def check_cci_source(cci_source: str) -> dict:
    name = os.path.basename(cci_source or "")
    if name == "U_CCI_List.xml":
        try:
            meta = cci_list_metadata(cci_source)
        except Exception as e:
            return result("cci", FAIL, f"DISA U_CCI_List.xml in use but its metadata did not parse ({e})")
        date = meta["publishdate"]
        if not date:
            return result("cci", WARN, "DISA U_CCI_List.xml in use; no <publishdate> in its metadata")
        year = re.match(r"\d{4}", date)
        if year and int(year.group()) < 2022:
            return result("cci", WARN, f"DISA U_CCI_List.xml published {date}; lists before 2022 have no Rev 5 references")
        return result("cci", PASS, f"DISA U_CCI_List.xml, published {date}")
    if name == "CciNistMappingData.ts":
        return result("cci", WARN, "MITRE Heimdall fallback in use (CciNistMappingData.ts); "
                                   "put DISA's U_CCI_List.xml in knowledge/")
    return result("cci", FAIL, "no CCI source loaded")


# ----------------------------------------------------------------------
#  3. MCP server surface
# ----------------------------------------------------------------------
@contextlib.contextmanager
def env_without(name: str):
    saved = os.environ.pop(name, None)
    try:
        yield
    finally:
        if saved is not None:
            os.environ[name] = saved


def check_mcp_surface(explorer=None) -> dict:
    try:
        from mcp_server.data import Explorer
        from mcp_server.server import build_server
    except ImportError as e:
        return result("mcp", FAIL, f"MCP server does not import ({e})")
    if explorer is None:
        explorer = Explorer({"controls": {}, "assessment": {}, "cci_to_nist": {}, "cci_parts": {}, "cci_report": {},
                             "cci_source": "none", "recommendations": {}, "stigs": [], "rules": {}}, {})
    # A placeholder rollup is passed so the ALLOW_ROLLUP_TO_LLM gate itself is exercised;
    # nothing is read from it unless the tool is called.
    placeholder = {"stig": "none", "summary": {"controls": []}}
    with env_without(ROLLUP_ENV):
        tools = asyncio.run(build_server(explorer, placeholder).list_tools())
    names = {t.name for t in tools}
    problems = []
    if "results_rollup" in names:
        problems.append("results_rollup is exposed")
    extra, missing = names - EXPECTED_TOOLS - {"results_rollup"}, EXPECTED_TOOLS - names
    if extra:
        problems.append(f"unexpected tools: {', '.join(sorted(extra))}")
    if missing:
        problems.append(f"missing tools: {', '.join(sorted(missing))}")
    not_ro = [t.name for t in tools if not (t.annotations and t.annotations.read_only_hint)
              or t.annotations.destructive_hint or t.annotations.open_world_hint]
    if not_ro:
        problems.append(f"not annotated read-only: {', '.join(sorted(not_ro))}")
    if problems:
        return result("mcp", FAIL, "; ".join(problems))
    return result("mcp", PASS, f"{len(names)} read-only tools, no results_rollup")


# ----------------------------------------------------------------------
#  4. Guardrail
# ----------------------------------------------------------------------
def check_rollup_env(environ=None) -> dict:
    value = (environ if environ is not None else os.environ).get(ROLLUP_ENV, "")
    if value.strip().lower() in ("1", "true", "yes"):
        return result("env", FAIL, f"{ROLLUP_ENV} is set to a true value; Ring 0 keeps results out of model context")
    return result("env", PASS, f"{ROLLUP_ENV} is not set" if not value else f"{ROLLUP_ENV}={value!r} (off)")


# ----------------------------------------------------------------------
#  5. Claude Code registration (optional)
# ----------------------------------------------------------------------
def check_claude_registration(timeout: float = 20) -> dict:
    exe = shutil.which("claude")
    if not exe:
        return result("claude", WARN, "claude CLI not on PATH; registration not checked")
    try:
        proc = subprocess.run([exe, "mcp", "list"], capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return result("claude", WARN, f"`claude mcp list` did not finish in {timeout:g}s")
    except OSError as e:
        return result("claude", WARN, f"`claude mcp list` could not run ({e.strerror or e})")
    for line in proc.stdout.splitlines():
        if line.strip().startswith(SERVER_NAME + ":"):
            # Lines look like "name: <command> - <status>". Print only the status, never the command.
            status = line.rsplit(" - ", 1)[1].strip() if " - " in line else "registered"
            return result("claude", PASS, f"{SERVER_NAME} registered ({status})")
    return result("claude", WARN, f"{SERVER_NAME} not registered in Claude Code")


# ----------------------------------------------------------------------
def run_checks(knowledge: str, stigs: str, check_claude: bool = True) -> list:
    explorer, error = load_explorer(knowledge, stigs)
    results = check_data(explorer, stigs, error)
    results.append(check_cci_source(explorer.ctx["cci_source"]) if explorer
                   else result("cci", FAIL, "reference data did not load"))
    results.append(check_mcp_surface(explorer))
    results.append(check_rollup_env())
    if check_claude:
        results.append(check_claude_registration())
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knowledge", default=os.path.join(ROOT, "knowledge"))
    ap.add_argument("--stigs", default=os.path.join(ROOT, "stigs"))
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    ap.add_argument("--no-claude", action="store_true", help="skip the Claude Code registration check")
    args = ap.parse_args(argv)
    results = run_checks(args.knowledge, args.stigs, check_claude=not args.no_claude)
    failed = any(r["status"] == FAIL for r in results)
    if args.json:
        print(json.dumps({"ok": not failed, "results": results}, indent=2))
    else:
        for r in results:
            print(f"  {r['status']}  {r['check']:<16} {r['detail']}")
        counts = {s: sum(r["status"] == s for r in results) for s in (PASS, WARN, FAIL)}
        print(f"Ring 0: {counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
