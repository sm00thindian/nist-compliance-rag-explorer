"""
The structured check format.

A check is plain JSON so it can be generated, reviewed by a person, diffed and
committed. It describes what to look for in evidence; it never runs anything.

    {
      "schema": 1,
      "rule": "V-258054",                 # STIG Vuln ID
      "stig_id": "RHEL-09-411075",
      "title": "...",
      "technology": "Red Hat Enterprise Linux 9",
      "source_sha256": "...",             # hash of the STIG check text it was built from
      "automatable": true,
      "logic": "all",                     # all | any
      "conditions": [ ... ],
      "notes": "...",
      "manual_reason": null,              # required when automatable is false
      "generated_by": "anthropic:claude-sonnet-5" | "hand-written",
      "reviewed": false
    }

Condition types:

  setting      a key/value in a config file
               {type, path, key, op, value, separator?, occurrence?, missing?, files?}
  line         a line matching a regex in a file
               {type, path, pattern, expect: present|absent, files?}
  file_exists  {type, path, expect: present|absent}
  command      output of a command the assessor ran and saved
               {type, command, pattern, expect: present|absent}

Paths are absolute and may contain * wildcards. For wildcards, ``files``
says whether "any" or "all" matching files must satisfy the condition.
"""
import hashlib
import re
from typing import Any, Dict, List

SCHEMA_VERSION = 1

CONDITION_TYPES = {"setting", "line", "file_exists", "command"}
SETTING_OPS = {"eq", "ne", "lt", "le", "gt", "ge", "in", "not_in", "regex"}
NUMERIC_OPS = {"lt", "le", "gt", "ge"}

_ALLOWED_FIELDS = {
    "setting": {"type", "path", "key", "op", "value", "separator", "occurrence", "missing", "files",
                "case_sensitive", "comment"},
    "line": {"type", "path", "pattern", "expect", "files", "include_comments", "comment"},
    "file_exists": {"type", "path", "expect", "comment"},
    "command": {"type", "command", "pattern", "expect", "comment"},
}
_CHECK_FIELDS = {"schema", "rule", "stig_id", "title", "technology", "source_sha256", "automatable", "logic",
                 "conditions", "notes", "manual_reason", "generated_by", "reviewed"}


class CheckSpecError(ValueError):
    """A check does not conform to the format."""


def source_hash(check_text: str) -> str:
    """Hash of a STIG rule's check text, used to spot checks built from an older STIG release."""
    return hashlib.sha256((check_text or "").strip().encode("utf-8")).hexdigest()


def _require(cond: bool, msg: str):
    if not cond:
        raise CheckSpecError(msg)


def _validate_regex(pattern: Any, where: str):
    _require(isinstance(pattern, str) and pattern, f"{where}: pattern must be a non-empty string")
    try:
        re.compile(pattern)
    except re.error as e:
        raise CheckSpecError(f"{where}: invalid regex {pattern!r}: {e}")


def validate_condition(cond: Dict[str, Any], where: str = "condition") -> Dict[str, Any]:
    _require(isinstance(cond, dict), f"{where}: must be an object")
    ctype = cond.get("type")
    _require(ctype in CONDITION_TYPES, f"{where}: type must be one of {sorted(CONDITION_TYPES)}, got {ctype!r}")
    unknown = set(cond) - _ALLOWED_FIELDS[ctype]
    _require(not unknown, f"{where}: unknown fields for {ctype}: {sorted(unknown)}")

    if ctype in ("setting", "line", "file_exists"):
        path = cond.get("path")
        _require(isinstance(path, str) and path.startswith("/"), f"{where}: path must be absolute")
        _require(".." not in path.split("/"), f"{where}: path must not contain '..'")
    if ctype in ("setting", "line"):
        _require(cond.get("files", "any") in ("any", "all"), f"{where}: files must be 'any' or 'all'")

    if ctype == "setting":
        _require(isinstance(cond.get("key"), str) and cond["key"].strip(), f"{where}: key is required")
        op = cond.get("op")
        _require(op in SETTING_OPS, f"{where}: op must be one of {sorted(SETTING_OPS)}")
        _require("value" in cond, f"{where}: value is required")
        value = cond["value"]
        if op in NUMERIC_OPS:
            _require(isinstance(value, (int, float)) and not isinstance(value, bool),
                     f"{where}: op {op} needs a numeric value")
        if op in ("in", "not_in"):
            _require(isinstance(value, list) and value, f"{where}: op {op} needs a non-empty list")
        if op == "regex":
            _validate_regex(value, where)
        _require(cond.get("occurrence", "last") in ("first", "last", "all"),
                 f"{where}: occurrence must be first, last or all")
        _require(cond.get("missing", "fail") in ("fail", "pass"), f"{where}: missing must be fail or pass")
        sep = cond.get("separator")
        _require(sep is None or (isinstance(sep, str) and len(sep) <= 3),
                 f"{where}: separator must be a short string or null (whitespace)")
    elif ctype == "line":
        _validate_regex(cond.get("pattern"), where)
        _require(cond.get("expect") in ("present", "absent"), f"{where}: expect must be present or absent")
    elif ctype == "file_exists":
        _require(cond.get("expect") in ("present", "absent"), f"{where}: expect must be present or absent")
    elif ctype == "command":
        _require(isinstance(cond.get("command"), str) and cond["command"].strip(), f"{where}: command is required")
        _validate_regex(cond.get("pattern"), where)
        _require(cond.get("expect") in ("present", "absent"), f"{where}: expect must be present or absent")
    return cond


def validate_check(check: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a check object. Returns it unchanged, or raises CheckSpecError."""
    _require(isinstance(check, dict), "check must be an object")
    unknown = set(check) - _CHECK_FIELDS
    _require(not unknown, f"unknown check fields: {sorted(unknown)}")
    _require(check.get("schema", SCHEMA_VERSION) == SCHEMA_VERSION, f"unsupported schema {check.get('schema')!r}")
    _require(isinstance(check.get("rule"), str) and check["rule"], "rule (STIG Vuln ID) is required")
    _require(isinstance(check.get("automatable"), bool), "automatable must be true or false")
    if not check["automatable"]:
        _require(isinstance(check.get("manual_reason"), str) and check["manual_reason"].strip(),
                 "manual_reason is required when automatable is false")
        _require(not check.get("conditions"), "a manual check must not have conditions")
        return check
    _require(check.get("logic", "all") in ("all", "any"), "logic must be 'all' or 'any'")
    conditions = check.get("conditions")
    _require(isinstance(conditions, list) and conditions, "an automatable check needs at least one condition")
    for i, cond in enumerate(conditions):
        validate_condition(cond, f"conditions[{i}]")
    return check


def evidence_needed(check: Dict[str, Any]) -> Dict[str, List[str]]:
    """Files and commands a check reads, for building a collection plan."""
    files, commands = [], []
    for cond in check.get("conditions") or []:
        if cond["type"] == "command":
            commands.append(cond["command"])
        else:
            files.append(cond["path"])
    return {"files": files, "commands": commands}
