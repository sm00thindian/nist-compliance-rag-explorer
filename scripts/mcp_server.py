#!/usr/bin/env python3
"""
Run the read-only MCP server (stdio) over the public data in knowledge/ and stigs/.

    python scripts/mcp_server.py [--knowledge knowledge] [--stigs stigs]

Claude Code:  claude mcp add nist-explorer -- /path/to/venv/bin/python /path/to/scripts/mcp_server.py
"""
import argparse
import logging
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from mcp_server.data import Explorer  # noqa: E402
from mcp_server.server import build_server  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--knowledge", default=os.path.join(ROOT, "knowledge"))
    ap.add_argument("--stigs", default=os.path.join(ROOT, "stigs"))
    args = ap.parse_args()
    # stdout carries the MCP protocol; logs go to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    build_server(Explorer.load(args.knowledge, args.stigs)).run("stdio")


if __name__ == "__main__":
    main()
