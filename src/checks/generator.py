"""
Turn public STIG check text into structured checks with an LLM.

The model only ever sees a ``PublicRequirement``: fields copied from the
published STIG (title, check text, fix text, discussion). This module does
not import the evidence code, and ``build_prompt`` takes nothing else.

Generated checks are saved for a person to review before they are trusted
(``reviewed: false``). Checks already reviewed are never overwritten.
"""
import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from .spec import SCHEMA_VERSION, CheckSpecError, source_hash, validate_check


@dataclass(frozen=True)
class PublicRequirement:
    """Everything the model is allowed to see: published STIG content only."""
    technology: str
    vuln_id: str
    rule_id: str
    stig_id: str
    title: str
    severity: str
    check: str
    fix: str
    discussion: str

    @classmethod
    def from_rule(cls, rule: dict, technology: str) -> "PublicRequirement":
        return cls(technology=technology, vuln_id=rule.get("vuln_id", ""), rule_id=rule.get("rule_id", ""),
                   stig_id=rule.get("stig_id", ""), title=rule.get("title", ""), severity=rule.get("severity", ""),
                   check=rule.get("check", ""), fix=rule.get("fix", ""), discussion=rule.get("discussion", ""))


SYSTEM_PROMPT = """You convert DISA STIG check procedures into structured checks that a local program evaluates against evidence (copies of config files and saved command output) collected from a system.

Return ONE JSON object and nothing else. Use only these fields:
  "automatable": true or false
  "logic": "all" or "any"          (how conditions combine; default "all")
  "conditions": [ ... ]            (empty when automatable is false)
  "notes": short explanation of how the conditions implement the check
  "manual_reason": why it cannot be automated (required when automatable is false)

Condition types (use only these fields):
  {"type": "setting", "path": "/abs/path", "key": "...", "op": "eq|ne|lt|le|gt|ge|in|not_in|regex", "value": ...,
   "separator": "=" or ":" or null for whitespace, "occurrence": "first|last|all", "missing": "fail|pass", "files": "any|all"}
  {"type": "line", "path": "/abs/path", "pattern": "<Python regex>", "expect": "present|absent", "files": "any|all"}
  {"type": "file_exists", "path": "/abs/path", "expect": "present|absent"}
  {"type": "command", "command": "<the command from the check text>", "pattern": "<Python regex over its output lines>", "expect": "present|absent"}

Rules:
- Implement exactly what the check text says is (or is not) a finding. Do not add requirements.
- Prefer reading files ("setting", "line", "file_exists") over commands. Use a command only when the check depends on runtime state (service status, installed packages, kernel parameters in effect).
- For a command, reuse the command shown in the check text, without "sudo" and without pipes if a single command's output suffices.
- Numeric limits use lt/le/gt/ge with a numeric value. "Missing or commented out is a finding" means missing: "fail" (the default).
- Paths may use * wildcards (e.g. /etc/ssh/sshd_config.d/*.conf); set "files" to say whether any or all matches must satisfy.
- Mark automatable false when the check needs human judgment: documentation, an ISSO/ISSM decision, site-specific values not given in the text, interviews, or reviewing a list for appropriateness.
- Organization-defined values: if the check text gives a default (e.g. "3 or less"), use it; otherwise mark automatable false.

Example 1 check text: 'Verify RHEL 9 is configured to lock an account after three unsuccessful logon attempts: $ grep 'deny =' /etc/security/faillock.conf  deny = 3. If the "deny" option is not set to "3" or less (but not "0"), is missing or commented out, this is a finding.'
Example 1 output:
{"automatable": true, "logic": "all", "conditions": [
  {"type": "setting", "path": "/etc/security/faillock.conf", "key": "deny", "separator": "=", "op": "le", "value": 3},
  {"type": "setting", "path": "/etc/security/faillock.conf", "key": "deny", "separator": "=", "op": "ne", "value": 0}],
 "notes": "deny must be set, at most 3, and not 0."}

Example 2 check text: 'Verify the organization has a documented process for approving temporary accounts. If there is no documented process, this is a finding.'
Example 2 output:
{"automatable": false, "conditions": [], "manual_reason": "Requires reviewing organizational documentation.", "notes": ""}
"""


def build_prompt(req: PublicRequirement) -> str:
    return (
        f"Technology: {req.technology}\n"
        f"STIG rule: {req.vuln_id} ({req.stig_id}), severity {req.severity}\n"
        f"Title: {req.title}\n\n"
        f"Check text:\n{req.check}\n\n"
        f"Fix text (context only):\n{req.fix}\n"
    )


def parse_model_output(text: str) -> dict:
    """Extract the JSON object from a model reply (tolerates code fences and surrounding prose)."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else text[text.find("{"): text.rfind("}") + 1]
    if not candidate:
        raise CheckSpecError("model reply contains no JSON object")
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as e:
        raise CheckSpecError(f"model reply is not valid JSON: {e}")


def generate_check(req: PublicRequirement, client, retries: int = 1) -> dict:
    """Ask the model for a check, validate it, and add metadata we don't take from the model."""
    prompt = build_prompt(req)
    last_error = None
    for _ in range(retries + 1):
        reply = client.complete(SYSTEM_PROMPT, prompt if last_error is None else
                                f"{prompt}\nYour previous reply was rejected: {last_error}. Return corrected JSON only.")
        try:
            body = parse_model_output(reply)
            allowed = {"automatable", "logic", "conditions", "notes", "manual_reason"}
            extra = set(body) - allowed
            if extra:
                raise CheckSpecError(f"unexpected fields {sorted(extra)}")
            check = {
                "schema": SCHEMA_VERSION,
                "rule": req.vuln_id,
                "stig_id": req.stig_id,
                "title": req.title,
                "technology": req.technology,
                "source_sha256": source_hash(req.check),
                "automatable": body.get("automatable"),
                "logic": body.get("logic", "all"),
                "conditions": body.get("conditions") or [],
                "notes": body.get("notes", ""),
                "manual_reason": body.get("manual_reason"),
                "generated_by": getattr(client, "name", "unknown"),
                "reviewed": False,
            }
            return validate_check(check)
        except CheckSpecError as e:
            last_error = str(e)
    raise CheckSpecError(f"{req.vuln_id}: model did not return a valid check: {last_error}")


# ----------------------------------------------------------------------
#  Storage: checks/<technology-slug>/<Vuln-ID>.json
# ----------------------------------------------------------------------
def technology_slug(technology: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", technology.lower()).strip("-")


class CheckStore:
    def __init__(self, root: str = "checks"):
        self.root = root

    def path(self, technology: str, vuln_id: str) -> str:
        return os.path.join(self.root, technology_slug(technology), f"{vuln_id}.json")

    def load(self, technology: str, vuln_id: str) -> Optional[dict]:
        p = self.path(technology, vuln_id)
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def load_all(self, technology: str) -> Dict[str, dict]:
        folder = os.path.join(self.root, technology_slug(technology))
        out = {}
        if os.path.isdir(folder):
            for name in sorted(os.listdir(folder)):
                if name.endswith(".json"):
                    with open(os.path.join(folder, name), encoding="utf-8") as f:
                        check = json.load(f)
                    out[check["rule"]] = check
        return out

    def save(self, check: dict, overwrite_reviewed: bool = False) -> str:
        p = self.path(check["technology"], check["rule"])
        existing = self.load(check["technology"], check["rule"])
        if existing and existing.get("reviewed") and not overwrite_reviewed:
            raise FileExistsError(f"{p} is marked reviewed; not overwriting")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(check, f, indent=2)
            f.write("\n")
        return p


def stale_checks(checks: Dict[str, dict], rules: List[dict]) -> List[str]:
    """Checks whose STIG check text has changed since they were written."""
    current = {r["vuln_id"]: source_hash(r.get("check", "")) for r in rules}
    return sorted(v for v, c in checks.items()
                  if c.get("source_sha256") and v in current and current[v] != c["source_sha256"])
