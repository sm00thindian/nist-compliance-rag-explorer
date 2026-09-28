"""
Read-only MCP server over the public compliance data.

Tools answer questions about SP 800-53 Rev 5 controls, SP 800-53A Rev 5
determination statements and methods, CCI mappings, the bundled STIGs, and
which STIG rules are evidence for which statements. Everything served is
public source text. There are no tools for scan results, evidence or checks,
no tool accepts a file path, and the server holds no credentials.

One optional tool, results_rollup, reports rolled-up scan status (800-53A
statement and STIG rule statuses, IDs only). It exists only when the operator
starts the server with a results file *and* sets ALLOW_ROLLUP_TO_LLM=1; raw
results (test descriptions, messages, hostnames) are never returned.

    python scripts/mcp_server.py [--knowledge knowledge] [--stigs stigs]
    ALLOW_ROLLUP_TO_LLM=1 python scripts/mcp_server.py --results scan.json --results-stig rhel
"""
import functools
import os
from typing import Optional

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from checks.hdf import rollup_summary
from mcp_server.data import Explorer

INSTRUCTIONS = """\
Public NIST SP 800-53 Rev 5 / SP 800-53A Rev 5 / DISA CCI / DISA STIG data, joined.
Control IDs are canonical (AC-2, AC-2(1)); statement parts can be given as "AU-3 a" or "AU-03a".
statement_coverage answers "which STIG rules are evidence for this statement" and lists
statements with no STIG evidence (those need Examine/Interview). CCI mappings that were
ambiguous against Rev 5 are dropped and reported, never guessed. This server has no access
to scan results or system evidence."""

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


def rollup_allowed() -> bool:
    """The rollup tool is off unless ALLOW_ROLLUP_TO_LLM is explicitly set to a true value."""
    return os.getenv("ALLOW_ROLLUP_TO_LLM", "").strip().lower() in ("1", "true", "yes")


def build_server(explorer: Explorer, rollup: Optional[dict] = None) -> MCPServer:
    """rollup: {"stig", "summary"} from checks.hdf.rollup_summary. The tool is registered only if
    it is given and ALLOW_ROLLUP_TO_LLM is set."""
    server = MCPServer("nist-compliance-explorer", instructions=INSTRUCTIONS)

    def tool(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (LookupError, ValueError) as e:
                raise ToolError(str(e.args[0] if e.args else e)) from e
        return server.tool(annotations=READ_ONLY)(wrapper)

    @tool
    def get_control(control_id: str, include_guidance: bool = False) -> dict:
        """SP 800-53 Rev 5 control or enhancement: statement (parameters shown as assignments),
        parameters, baselines, related controls, enhancements, and withdrawal info."""
        return explorer.get_control(control_id, include_guidance)

    @tool
    def search_controls(query: str = "", family: Optional[str] = None, baseline: Optional[str] = None,
                        include_withdrawn: bool = False, limit: int = 25) -> dict:
        """Find controls whose title or statement contain every query word. With no query, lists
        controls, optionally filtered by family (e.g. AC) and baseline (LOW, MODERATE, HIGH)."""
        return explorer.search_controls(query, family, baseline, include_withdrawn, limit)

    @tool
    def get_assessment_procedure(control_id: str) -> dict:
        """SP 800-53A Rev 5 procedure for a control: its determination statements (e.g. AC-02a.01)
        and the EXAMINE / INTERVIEW / TEST assessment objects."""
        return explorer.get_assessment(control_id)

    @tool
    def list_stigs() -> dict:
        """The loaded DISA STIGs with release, rule counts and how many controls they map to."""
        return explorer.list_stigs()

    @tool
    def get_stig_rule(rule_id: str) -> dict:
        """Full text of a STIG rule (discussion, check, fix) and how each of its CCIs maps to a
        Rev 5 control and statement part. Accepts a Vuln ID, STIG ID or rule ID."""
        return explorer.get_stig_rule(rule_id)

    @tool
    def search_stig_rules(query: str = "", stig: Optional[str] = None, control_id: Optional[str] = None,
                          severity: Optional[str] = None, limit: int = 25) -> dict:
        """Find STIG rules whose title, discussion or check text contain every query word,
        optionally limited to one STIG (e.g. "rhel"), a control, or a severity (high, medium, low)."""
        return explorer.search_stig_rules(query, stig, control_id, severity, limit)

    @tool
    def lookup_cci(cci_id: str) -> dict:
        """Where a CCI maps in Rev 5 (control and statement part), whether it was redirected from a
        withdrawn control or dropped as ambiguous, and which STIG rules cite it."""
        return explorer.lookup_cci(cci_id)

    @tool
    def statement_coverage(control: str, stig: Optional[str] = None) -> dict:
        """For each 800-53A determination statement of a control, the STIG rules that are evidence
        for it, or that none are (assess with Examine/Interview). Give a statement ("AU-3 a",
        "AU-03a") to narrow it. Omit stig to use every loaded STIG."""
        return explorer.statement_coverage(control, stig)

    @tool
    def stig_coverage(stig: str, baseline: Optional[str] = None, family: Optional[str] = None) -> dict:
        """Per control, how many 800-53A statements a STIG provides evidence for. With a baseline,
        also lists baseline controls the STIG does not touch at all."""
        return explorer.stig_coverage(stig, baseline, family)

    @tool
    def list_gaps(stig: str, baseline: Optional[str] = None, family: Optional[str] = None, limit: int = 100) -> dict:
        """Determination statements, in controls a STIG touches, that no STIG rule provides evidence
        for. With a baseline, also lists baseline controls the STIG does not touch."""
        return explorer.list_gaps(stig, baseline, family, limit)

    if rollup is not None and rollup_allowed():
        summary = rollup["summary"]

        @tool
        def results_rollup(control: Optional[str] = None, status: Optional[str] = None) -> dict:
            """Rolled-up status of the scan results the operator loaded: per 800-53A determination
            statement (fail, pass, partial, unchecked, not_applicable, no_stig) with the STIG rule
            statuses behind it. IDs and statuses only. Filter by control (e.g. AC-8) or status."""
            cid = explorer._control(control)["control_id"] if control else None
            controls = []
            for c in summary["controls"]:
                if cid and c["control"] != cid:
                    continue
                statements = [s for s in c["statements"] if not status or s["status"] == status.lower()]
                if statements:
                    controls.append(dict(c, statements=statements))
            return {"stig": rollup["stig"], **{k: v for k, v in summary.items() if k != "controls"},
                    "controls": controls}

    return server
