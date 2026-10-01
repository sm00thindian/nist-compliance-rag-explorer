#!/usr/bin/env python3
"""
Run the read-only MCP server (stdio) over the public data in knowledge/ and stigs/.

    python scripts/mcp_server.py [--knowledge knowledge] [--stigs stigs]
    ALLOW_ROLLUP_TO_LLM=1 python scripts/mcp_server.py --results scan.json --results-stig rhel

--results adds a results_rollup tool (statement and rule statuses only) and
only when ALLOW_ROLLUP_TO_LLM=1 is set; without it the file is not read.

Claude Code:  claude mcp add nist-explorer -- /path/to/venv/bin/python /path/to/scripts/mcp_server.py
"""
import argparse
import logging
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from checks.hdf import HDFError, import_hdf, rollup_summary  # noqa: E402
from checks.rollup import rollup  # noqa: E402
from mcp_server.data import Explorer  # noqa: E402
from mcp_server.server import build_server, rollup_allowed  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knowledge", default=os.path.join(ROOT, "knowledge"))
    ap.add_argument("--stigs", default=os.path.join(ROOT, "stigs"))
    ap.add_argument("--results", help="CINC Auditor / InSpec JSON or HDF results file (needs ALLOW_ROLLUP_TO_LLM=1)")
    ap.add_argument("--results-stig", help="the loaded STIG the results are for, e.g. rhel")
    args = ap.parse_args()
    # stdout carries the MCP protocol; logs go to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    explorer = Explorer.load(args.knowledge, args.stigs)
    summary = None
    if args.results:
        if not rollup_allowed():
            sys.exit("--results given but ALLOW_ROLLUP_TO_LLM is not set; refusing to load results. "
                     "Set ALLOW_ROLLUP_TO_LLM=1 to expose rolled-up status (IDs and statuses only) to the client.")
        if not args.results_stig:
            sys.exit("--results needs --results-stig (e.g. rhel).")
        try:
            tech = explorer._stig(args.results_stig)
            imported = import_hdf(args.results, explorer.ctx["rules"][tech])
        except (HDFError, ValueError) as e:
            sys.exit(str(e))
        summary = {"stig": tech,
                   "summary": rollup_summary(rollup(tech, imported["results"], explorer.ctx), imported)}
    build_server(explorer, summary).run("stdio")


if __name__ == "__main__":
    main()
