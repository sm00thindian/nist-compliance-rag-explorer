"""
Evaluate structured checks against local evidence. No network, no models.

Each result records the exact file and line (or command output line) that
decided it, so an assessor can verify the finding.

Statuses:
  pass           every condition met (logic "all") or at least one (logic "any")
  fail           a condition failed
  not_evaluated  evidence needed for the check is missing from the folder
  manual         the check needs human judgment (automatable is false)
  error          the check itself is invalid
"""
import re
from typing import Any, Dict, List, Optional, Tuple

from .evidence import EvidenceBundle
from .spec import CheckSpecError, validate_check

PASS, FAIL, MISSING, MANUAL, ERROR = "pass", "fail", "not_evaluated", "manual", "error"


def _active_lines(text: str, include_comments: bool = False) -> List[Tuple[int, str]]:
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if not include_comments and line.startswith(("#", ";")):
            continue
        out.append((n, raw.rstrip()))
    return out


def _split_setting(line: str, separator: Optional[str]) -> Optional[Tuple[str, str]]:
    stripped = line.strip()
    if separator is None or separator.strip() == "":
        parts = stripped.split(None, 1)
        return (parts[0], parts[1].strip() if len(parts) > 1 else "") if parts else None
    if separator not in stripped:
        return None
    key, _, value = stripped.partition(separator)
    return key.strip(), value.strip()


def _strip_inline_comment(value: str) -> str:
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def _as_number(value: str) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(actual: str, op: str, expected: Any, case_sensitive: bool) -> bool:
    if op in ("lt", "le", "gt", "ge"):
        num = _as_number(actual)
        if num is None:
            return False
        return {"lt": num < expected, "le": num <= expected, "gt": num > expected, "ge": num >= expected}[op]
    if op == "regex":
        return re.search(expected, actual, 0 if case_sensitive else re.IGNORECASE) is not None

    def norm(v):
        s = str(v).strip()
        return s if case_sensitive else s.lower()

    def same(a, b):
        na, nb = _as_number(a), _as_number(str(b))
        if na is not None and nb is not None and not isinstance(b, bool):
            return na == nb
        return norm(a) == norm(b)

    if op == "eq":
        return same(actual, expected)
    if op == "ne":
        return not same(actual, expected)
    if op == "in":
        return any(same(actual, e) for e in expected)
    if op == "not_in":
        return not any(same(actual, e) for e in expected)
    raise CheckSpecError(f"unknown op {op}")


def _result(status: str, detail: str, evidence: Optional[List[dict]] = None, cond: Optional[dict] = None) -> dict:
    return {"status": status, "detail": detail, "evidence": evidence or [], "condition": cond}


def _eval_setting(cond: dict, bundle: EvidenceBundle) -> dict:
    files = bundle.files(cond["path"])
    if not files:
        return _result(MISSING, f"{cond['path']} not in evidence", cond=cond)
    key = cond["key"]
    case_sensitive = cond.get("case_sensitive", False)
    per_file = []
    for target, local in files:
        hits = []
        for n, line in _active_lines(bundle.read(local)):
            kv = _split_setting(line, cond.get("separator", "="))
            if kv and (kv[0] == key if case_sensitive else kv[0].lower() == key.lower()):
                hits.append((n, line, _strip_inline_comment(kv[1])))
        if not hits:
            ok = cond.get("missing", "fail") == "pass"
            per_file.append((ok, f"{target}: {key} not set" + (" (allowed)" if ok else ""), []))
            continue
        occurrence = cond.get("occurrence", "last")
        chosen = hits if occurrence == "all" else [hits[0] if occurrence == "first" else hits[-1]]
        ok = all(_compare(v, cond["op"], cond["value"], case_sensitive) for _, _, v in chosen)
        values = ", ".join(repr(v) for _, _, v in chosen)
        per_file.append((ok, f"{target}: {key} = {values}; expected {cond['op']} {cond['value']!r}",
                         [{"source": target, "line": n, "text": line} for n, line, _ in chosen]))
    return _combine_files(cond, per_file)


def _eval_line(cond: dict, bundle: EvidenceBundle) -> dict:
    files = bundle.files(cond["path"])
    if not files:
        return _result(MISSING, f"{cond['path']} not in evidence", cond=cond)
    rx = re.compile(cond["pattern"])
    per_file = []
    for target, local in files:
        hits = [(n, line) for n, line in _active_lines(bundle.read(local), cond.get("include_comments", False))
                if rx.search(line)]
        present = bool(hits)
        ok = present if cond["expect"] == "present" else not present
        what = f"matches /{cond['pattern']}/" if present else f"no line matches /{cond['pattern']}/"
        per_file.append((ok, f"{target}: {what}", [{"source": target, "line": n, "text": line} for n, line in hits]))
    return _combine_files(cond, per_file)


def _combine_files(cond: dict, per_file: List[tuple]) -> dict:
    mode = cond.get("files", "any")
    ok = all(r[0] for r in per_file) if mode == "all" else any(r[0] for r in per_file)
    relevant = [r for r in per_file if r[0] == ok] or per_file
    return _result(PASS if ok else FAIL, "; ".join(r[1] for r in relevant),
                   [e for r in relevant for e in r[2]], cond)


def _eval_file_exists(cond: dict, bundle: EvidenceBundle) -> dict:
    if not bundle.has_files_folder():
        return _result(MISSING, "no files/ folder in evidence", cond=cond)
    present = bool(bundle.files(cond["path"]))
    ok = present if cond["expect"] == "present" else not present
    return _result(PASS if ok else FAIL, f"{cond['path']} {'exists' if present else 'is absent'} in evidence",
                   [{"source": cond["path"], "line": None, "text": "(file present)"}] if present else [], cond)


def _eval_command(cond: dict, bundle: EvidenceBundle) -> dict:
    output = bundle.command_output(cond["command"])
    if output is None:
        return _result(MISSING, f"no saved output for: {cond['command']}", cond=cond)
    rx = re.compile(cond["pattern"], re.MULTILINE)
    hits = [(n, line) for n, line in enumerate(output.splitlines(), 1) if rx.search(line)]
    present = bool(hits)
    ok = present if cond["expect"] == "present" else not present
    return _result(PASS if ok else FAIL,
                   f"`{cond['command']}` output {'matches' if present else 'has no line matching'} /{cond['pattern']}/",
                   [{"source": f"$ {cond['command']}", "line": n, "text": line} for n, line in hits], cond)


_EVALUATORS = {"setting": _eval_setting, "line": _eval_line, "file_exists": _eval_file_exists,
               "command": _eval_command}


def evaluate_check(check: dict, bundle: EvidenceBundle) -> dict:
    """Evaluate one check. Returns {rule, status, conditions: [...], reason?}."""
    base = {"rule": check.get("rule"), "stig_id": check.get("stig_id"), "title": check.get("title"),
            "reviewed": bool(check.get("reviewed")), "generated_by": check.get("generated_by")}
    try:
        validate_check(check)
    except CheckSpecError as e:
        return dict(base, status=ERROR, reason=str(e), conditions=[])
    if not check["automatable"]:
        return dict(base, status=MANUAL, reason=check["manual_reason"], conditions=[])

    results = [_EVALUATORS[c["type"]](c, bundle) for c in check["conditions"]]
    statuses = [r["status"] for r in results]
    if check.get("logic", "all") == "all":
        status = FAIL if FAIL in statuses else MISSING if MISSING in statuses else PASS
    else:
        status = PASS if PASS in statuses else MISSING if MISSING in statuses else FAIL
    return dict(base, status=status, conditions=results)
