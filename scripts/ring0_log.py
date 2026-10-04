#!/usr/bin/env python3
"""
Ring 0 dogfood log: one row per real lookup made with the MCP server (or CLI).

Ring 0 is two weeks of the product owner using the MCP server for daily
lookups on public data (feature #43). Targets, set in advance:

  - at least 30 real lookups
  - at least 80% answered without falling back to another source
  - every wrong or missing answer logged as a GitHub issue
  - at least 3 lookups clearly faster than before

Describe the question, not the system. The log records the *kind* of
question ("which RHEL 9 rules cover AU-3 a"), never hostnames, IP or MAC
addresses, configs, scan output or anything else about a real system. The
note field is capped at 120 characters and ``add`` refuses a note that
contains an IPv4, IPv6 or MAC address.

The default log is knowledge/ring0/log.csv; knowledge/ is gitignored, so the
log is never committed.

    python scripts/ring0_log.py add --type coverage --tool statement_coverage \
        --answered yes --correct yes --faster yes --note "AU-3 a rules for RHEL 9"
    python scripts/ring0_log.py add --type control --tool get_control --answered no \
        --correct no --faster no --issue 51
    python scripts/ring0_log.py list
    python scripts/ring0_log.py summary [--since 2026-10-01] [--until 2026-10-14]
"""
import argparse
import csv
import datetime as dt
import os
import re
import sys
from collections import Counter
from typing import List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG = os.path.join(ROOT, "knowledge", "ring0", "log.csv")

FIELDS = ["date", "question_type", "tool", "answered", "correct", "faster", "issue", "note"]
QUESTION_TYPES = ("control", "assessment", "stig_rule", "coverage", "gaps", "cci", "baseline", "other")
ANSWERED = ("yes", "no")
CORRECT = ("yes", "no", "unchecked")
FASTER = ("yes", "no", "same")
NOTE_MAX = 120

TARGET_LOOKUPS = 30
TARGET_ANSWER_RATE = 0.80
TARGET_FASTER = 3

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Full form (4+ hex groups) or compressed form with '::' next to at least one hex group.
IPV6 = re.compile(r"(?<![0-9A-Za-z_:])(?:"
                  r"(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}"
                  r"|(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?"
                  r"|::[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*"
                  r")(?![0-9A-Za-z_:])")
MAC = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
TOOL_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class LogError(ValueError):
    pass


def parse_date(value: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        raise LogError(f"date {value!r} is not YYYY-MM-DD")


def check_note(note: str) -> str:
    note = (note or "").strip()
    if len(note) > NOTE_MAX:
        raise LogError(f"note is {len(note)} characters; keep it to {NOTE_MAX} or fewer")
    if "\n" in note or "\r" in note:
        raise LogError("note must be a single line")
    for name, pattern in (("a MAC address", MAC), ("an IPv4 address", IPV4), ("an IPv6 address", IPV6)):
        if pattern.search(note):
            raise LogError(f"note contains {name}. Describe the question, not the system: "
                           "no hostnames, addresses, configs or scan output in the log.")
    return note


def make_row(question_type: str, tool: str, answered: str, correct: str, faster: str,
             date: Optional[str] = None, issue: Optional[str] = None, note: str = "") -> dict:
    def choice(name, value, options):
        value = (value or "").strip().lower()
        if value not in options:
            raise LogError(f"{name} must be one of {', '.join(options)} (got {value!r})")
        return value

    row = {
        "date": parse_date(date).isoformat() if date else dt.date.today().isoformat(),
        "question_type": choice("question_type", question_type, QUESTION_TYPES),
        "answered": choice("answered", answered, ANSWERED),
        "correct": choice("correct", correct, CORRECT),
        "faster": choice("faster", faster, FASTER),
    }
    tool = (tool or "").strip()
    if not TOOL_RE.fullmatch(tool):
        raise LogError(f"tool must be an MCP tool name like statement_coverage, or 'cli' (got {tool!r})")
    row["tool"] = tool
    issue = str(issue or "").strip().lstrip("#")
    if issue and not issue.isdigit():
        raise LogError(f"issue must be a GitHub issue number (got {issue!r})")
    row["issue"] = issue
    row["note"] = check_note(note)
    return {k: row[k] for k in FIELDS}


def append_row(path: str, row: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            writer.writeheader()
        writer.writerow(row)


def read_rows(path: str, since: Optional[str] = None, until: Optional[str] = None) -> List[dict]:
    if not os.path.exists(path):
        return []
    lo = parse_date(since) if since else None
    hi = parse_date(until) if until else None
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        d = parse_date(r["date"])
        if (lo and d < lo) or (hi and d > hi):
            continue
        out.append(r)
    return out


def needs_issue(row: dict) -> bool:
    return row["answered"] == "no" or row["correct"] == "no"


def metrics(rows: List[dict]) -> dict:
    n = len(rows)
    answered = sum(r["answered"] == "yes" for r in rows)
    problems = [r for r in rows if needs_issue(r)]
    m = {
        "lookups": n,
        "answered": answered,
        "answer_rate": answered / n if n else 0.0,
        "incorrect": sum(r["correct"] == "no" for r in rows),
        "unchecked": sum(r["correct"] == "unchecked" for r in rows),
        "problems": len(problems),
        "problems_with_issue": sum(bool(r["issue"]) for r in problems),
        "issues": sorted({int(r["issue"]) for r in rows if r["issue"]}),
        "faster": sum(r["faster"] == "yes" for r in rows),
        "by_type": Counter(r["question_type"] for r in rows),
        "by_tool": Counter(r["tool"] for r in rows),
        "first": min((r["date"] for r in rows), default=None),
        "last": max((r["date"] for r in rows), default=None),
    }
    m["targets"] = {
        "lookups": m["lookups"] >= TARGET_LOOKUPS,
        "answer_rate": n > 0 and m["answer_rate"] >= TARGET_ANSWER_RATE,
        "issues": m["problems_with_issue"] == m["problems"],
        "faster": m["faster"] >= TARGET_FASTER,
    }
    return m


def summary_markdown(rows: List[dict]) -> str:
    m = metrics(rows)
    t = m["targets"]

    def mark(ok):
        return "PASS" if ok else "MISS"

    span = f"{m['first']} to {m['last']}" if m["first"] else "no entries"
    issues = ", ".join(f"#{i}" for i in m["issues"]) or "none"
    lines = [
        "## Ring 0 dogfood summary",
        "",
        f"Period: {span}",
        "",
        "| Target | Result | Status |",
        "|---|---|---|",
        f"| >= {TARGET_LOOKUPS} real lookups | {m['lookups']} | {mark(t['lookups'])} |",
        f"| >= {TARGET_ANSWER_RATE:.0%} answered without fallback | {m['answered']}/{m['lookups']} "
        f"({m['answer_rate']:.0%}) | {mark(t['answer_rate'])} |",
        f"| Every wrong/missing answer has an issue | {m['problems_with_issue']}/{m['problems']} | {mark(t['issues'])} |",
        f"| >= {TARGET_FASTER} lookups clearly faster | {m['faster']} | {mark(t['faster'])} |",
        "",
        f"Correctness: {m['incorrect']} incorrect, {m['unchecked']} unchecked. Issues logged: {issues}.",
        "",
        "| Question type | Lookups |",
        "|---|---|",
        *(f"| {k} | {v} |" for k, v in sorted(m["by_type"].items(), key=lambda kv: (-kv[1], kv[0]))),
        "",
        "| Tool | Lookups |",
        "|---|---|",
        *(f"| {k} | {v} |" for k, v in sorted(m["by_tool"].items(), key=lambda kv: (-kv[1], kv[0]))),
    ]
    return "\n".join(lines) + "\n"


def table(rows: List[dict]) -> str:
    if not rows:
        return "(log is empty)\n"
    widths = {f: max(len(f), *(len(r[f]) for r in rows)) for f in FIELDS}
    fmt = "  ".join(f"{{{f}:<{widths[f]}}}" for f in FIELDS)
    out = [fmt.format(**{f: f for f in FIELDS}).rstrip(), "  ".join("-" * widths[f] for f in FIELDS)]
    out += [fmt.format(**r).rstrip() for r in rows]
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--log", default=DEFAULT_LOG, help=f"log CSV (default {os.path.relpath(DEFAULT_LOG, ROOT)})")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="append one lookup")
    # --log also works after the subcommand; SUPPRESS keeps the top-level value when it's absent.
    a.add_argument("--log", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    a.add_argument("--date", help="YYYY-MM-DD (default today)")
    a.add_argument("--type", dest="question_type", required=True, choices=QUESTION_TYPES)
    a.add_argument("--tool", required=True, help="MCP tool name, or 'cli'")
    a.add_argument("--answered", required=True, choices=ANSWERED)
    a.add_argument("--correct", required=True, choices=CORRECT)
    a.add_argument("--faster", required=True, choices=FASTER)
    a.add_argument("--issue", help="GitHub issue number for a wrong or missing answer")
    a.add_argument("--note", default="", help=f"short note, <= {NOTE_MAX} chars; describe the question, not the system")

    for name, helptext in (("summary", "metrics vs Ring 0 targets, as Markdown"), ("list", "print the log")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--log", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        s.add_argument("--since", help="YYYY-MM-DD, inclusive")
        s.add_argument("--until", help="YYYY-MM-DD, inclusive")

    args = p.parse_args(argv)
    try:
        if args.cmd == "add":
            row = make_row(args.question_type, args.tool, args.answered, args.correct, args.faster,
                           date=args.date, issue=args.issue, note=args.note)
            append_row(args.log, row)
            print(f"logged {row['date']} {row['question_type']} via {row['tool']} -> {args.log}")
            if needs_issue(row) and not row["issue"]:
                print("reminder: wrong or missing answers need an issue (dogfood template); "
                      "add it with a new entry or --issue next time", file=sys.stderr)
        elif args.cmd == "summary":
            sys.stdout.write(summary_markdown(read_rows(args.log, args.since, args.until)))
        else:
            sys.stdout.write(table(read_rows(args.log, args.since, args.until)))
    except LogError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
