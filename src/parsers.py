"""
Parsers for the source data behind the explorer.

Every parser here reads the *published* format of its source:

- NIST SP 800-53 Rev 5 catalog, OSCAL JSON (usnistgov/oscal-content). The same
  file carries the SP 800-53A Rev 5 assessment objectives and methods, so the
  assessment procedures are read from the catalog too.
- NIST SP 800-53 Rev 5 baseline profiles, OSCAL JSON.
- DISA CCI List (U_CCI_List.xml, namespace http://iase.disa.mil/cci).
- DISA STIG XCCDF 1.1 benchmarks.

All control references are normalized to one canonical form so the sources
join: base controls as ``AC-2`` and enhancements as ``AC-2(1)``. Statement
parts (``AC-2 a``, ``AC-2 a.1``) roll up to their control.
"""
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
#  Control IDs
# ----------------------------------------------------------------------
# Accepts: ac-2, AC-02, ac-2.1, AC-2(1), AC-02(01), "AC-2 (1)", "AC-2 a",
# "AC-2 (4) (a)", "ac-2_smt.a"
_CONTROL_RE = re.compile(
    r"""^\s*
        (?P<family>[A-Za-z]{2})\s*-\s*0*(?P<num>\d+)        # AC-2 / ac-02
        (?:                                                  # optional enhancement
            \s*\(\s*0*(?P<enh_paren>\d+)\s*\)                #   (1) / ( 01 )
          | \.0*(?P<enh_dot>\d+)                             #   .1 (OSCAL ids)
        )?
        (?P<rest>.*)$
    """,
    re.VERBOSE,
)


def parse_control_ref(ref: str) -> Tuple[str, str]:
    """Split a control reference into (canonical control ID, statement part).

    >>> parse_control_ref("AC-2 (4) (a)")
    ('AC-2(4)', '(a)')
    >>> parse_control_ref("ac-2.1")
    ('AC-2(1)', '')
    >>> parse_control_ref("AC-2 a.1")
    ('AC-2', 'a.1')
    """
    if not ref:
        return "", ""
    m = _CONTROL_RE.match(str(ref))
    if not m:
        return "", ""
    control = f"{m.group('family').upper()}-{int(m.group('num'))}"
    enh = m.group("enh_paren") or m.group("enh_dot")
    if enh:
        control += f"({int(enh)})"
    rest = m.group("rest").strip()
    rest = re.sub(r"^_(smt|obj)\.?", "", rest)  # OSCAL part ids: ac-2_smt.a
    return control, rest.strip(" .")


def normalize_control_id(control_id: str) -> str:
    """Return the canonical control ID (``AC-2`` / ``AC-2(1)``), or '' if unparseable.

    Statement parts are dropped so part-level references (as used by CCIs)
    join to their control.
    """
    return parse_control_ref(control_id)[0]


def part_key(part: str) -> str:
    """Canonical key for a statement part, matching OSCAL statement ids.

    >>> part_key("a 1 (a)")
    'a.1.a'
    >>> part_key("(c)")
    'c'
    >>> part_key("d.01")
    'd.1'
    """
    part = (part or "").split(",", 1)[0].lower()
    return ".".join(str(int(t)) if t.isdigit() else t for t in re.findall(r"[a-z]+|\d+", part))


def parts_overlap(a: str, b: str) -> bool:
    """True if one statement part contains the other (a == b, or a is a parent of b, or vice versa)."""
    if not a or not b:
        return False
    return a == b or b.startswith(a + ".") or a.startswith(b + ".")


def control_family(control_id: str) -> str:
    cid = normalize_control_id(control_id)
    return cid.split("-", 1)[0] if cid else ""


# ----------------------------------------------------------------------
#  OSCAL helpers
# ----------------------------------------------------------------------
_INSERT_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([^\s}]+)\s*\}\}")


def _prop(obj: dict, name: str, cls: Optional[str] = None, default: str = "") -> str:
    for p in obj.get("props", []) or []:
        if p.get("name") == name and (cls is None or p.get("class") == cls):
            return p.get("value", default)
    return default


def _has_prop_value(obj: dict, name: str, value: str) -> bool:
    return any(p.get("name") == name and p.get("value") == value for p in obj.get("props", []) or [])


def _index_params(catalog: dict) -> Dict[str, dict]:
    """Map every param id (and its alt-identifier) to the param object."""
    params: Dict[str, dict] = {}

    def add(param_list):
        for p in param_list or []:
            params[p["id"]] = p
            alt = _prop(p, "alt-identifier")
            if alt:
                params.setdefault(alt, p)

    def walk_controls(controls):
        for c in controls or []:
            add(c.get("params"))
            walk_controls(c.get("controls"))

    def walk_groups(groups):
        for g in groups or []:
            add(g.get("params"))
            walk_controls(g.get("controls"))
            walk_groups(g.get("groups"))

    add(catalog.get("params"))
    walk_controls(catalog.get("controls"))
    walk_groups(catalog.get("groups"))
    return params


def _render_param(param: dict, params: Dict[str, dict], depth: int = 0) -> str:
    """Render a parameter the way SP 800-53 prints it."""
    if depth > 5:
        return "[parameter]"
    if "select" in param:
        sel = param["select"]
        choices = [_substitute(c, params, depth + 1) for c in sel.get("choice", [])]
        prefix = "Selection (one or more)" if sel.get("how-many") == "one-or-more" else "Selection"
        return f"[{prefix}: {'; '.join(choices)}]"
    label = param.get("label") or param.get("id", "parameter")
    if not label.lower().startswith("organization-defined"):
        label = f"organization-defined {label}"
    return f"[Assignment: {label}]"


def _substitute(text: str, params: Dict[str, dict], depth: int = 0) -> str:
    if not text:
        return ""

    def repl(m):
        p = params.get(m.group(1))
        return _render_param(p, params, depth) if p else f"[{m.group(1)}]"

    return _INSERT_RE.sub(repl, text)


def _render_statement(part: dict, params: Dict[str, dict], indent: int = 0) -> List[str]:
    """Flatten a statement part (with labelled items) into lines."""
    lines = []
    label = _prop(part, "label")
    prose = _substitute(part.get("prose", ""), params).strip()
    text = " ".join(x for x in (label, prose) if x)
    if text:
        lines.append(("  " * indent) + text)
    for sub in part.get("parts", []) or []:
        if sub.get("name") in ("item", "statement"):
            lines.extend(_render_statement(sub, params, indent + (1 if text else 0)))
    return lines


def _iter_catalog_controls(catalog: dict) -> Iterable[Tuple[dict, dict, Optional[dict]]]:
    """Yield (control, group, parent_control) for every control and enhancement."""

    def walk_controls(controls, group, parent):
        for c in controls or []:
            yield c, group, parent
            yield from walk_controls(c.get("controls"), group, c)

    def walk_groups(groups):
        for g in groups or []:
            yield from walk_controls(g.get("controls"), g, None)
            yield from walk_groups(g.get("groups"))

    yield from walk_controls(catalog.get("controls"), {}, None)
    yield from walk_groups(catalog.get("groups"))


def _unwrap_catalog(catalog_json: dict) -> dict:
    if isinstance(catalog_json, dict) and isinstance(catalog_json.get("catalog"), dict):
        return catalog_json["catalog"]
    return catalog_json


# ----------------------------------------------------------------------
#  Catalog
# ----------------------------------------------------------------------
def extract_controls_from_json(catalog_json: dict) -> List[dict]:
    """Extract every control and enhancement from an OSCAL SP 800-53 catalog.

    Each record has: control_id (canonical), oscal_id, title, family,
    family_title, description (statement text with parameters rendered),
    guidance, parameters, related, parent, withdrawn, withdrawn_to,
    baseline_levels (empty until apply_baselines is called).
    """
    catalog = _unwrap_catalog(catalog_json)
    if "groups" not in catalog and "controls" not in catalog:
        raise ValueError(
            "Not an OSCAL catalog: expected 'catalog.groups' or 'catalog.controls'. "
            f"Top-level keys were: {list(catalog_json)[:10]}"
        )

    params = _index_params(catalog)
    records = []
    for ctrl, group, parent in _iter_catalog_controls(catalog):
        control_id = normalize_control_id(ctrl.get("id", ""))
        if not control_id:
            logger.warning("Skipping control with unparseable id: %r", ctrl.get("id"))
            continue

        statement_lines, guidance = [], ""
        for part in ctrl.get("parts", []) or []:
            if part.get("name") == "statement":
                statement_lines.extend(_render_statement(part, params))
            elif part.get("name") == "guidance":
                guidance = _substitute(part.get("prose", ""), params).strip()

        withdrawn = _has_prop_value(ctrl, "status", "withdrawn")
        withdrawn_to, withdrawn_refs, related = [], [], []
        withdrawn_to_parts: Dict[str, str] = {}
        for link in ctrl.get("links", []) or []:
            target, part = parse_control_ref(link.get("href", "").lstrip("#"))
            if not target:
                continue
            if link.get("rel") in ("incorporated-into", "moved-to"):
                withdrawn_to.append(target)
                withdrawn_refs.append(f"{target}{part}" if part else target)
                withdrawn_to_parts.setdefault(target, part_key(part))
            elif link.get("rel") == "related":
                related.append(target)
        withdrawn_to = sorted(set(withdrawn_to))

        description = "\n".join(statement_lines)
        if withdrawn and not description:
            description = "Withdrawn" + (f": incorporated into {', '.join(dict.fromkeys(withdrawn_refs))}." if withdrawn_refs else ".")

        parameters = [{
            "id": p.get("id"),
            "label": _prop(p, "label", "sp800-53a") or p.get("label", ""),
            "text": _render_param(p, params),
            "guideline": " ".join(g.get("prose", "") for g in p.get("guidelines", []) or []),
        } for p in ctrl.get("params", []) or []]

        records.append({
            "control_id": control_id,
            "oscal_id": ctrl.get("id"),
            "title": ctrl.get("title", ""),
            "family": control_family(control_id),
            "family_title": group.get("title", ""),
            "description": description,
            "guidance": guidance,
            "parameters": parameters,
            "related": related,
            "parent": normalize_control_id(parent["id"]) if parent else "",
            "withdrawn": withdrawn,
            "withdrawn_to": withdrawn_to,
            "withdrawn_to_parts": withdrawn_to_parts,
            "baseline_levels": [],
        })
    return records


def extract_assessment_details(catalog_json: dict) -> Dict[str, dict]:
    """Extract SP 800-53A Rev 5 objectives and methods embedded in the OSCAL catalog.

    Returns {control_id: {"objectives": [{"id", "label", "text", "part", "leaf"}],
                          "methods": {"EXAMINE"|"INTERVIEW"|"TEST": [objects]}}}

    "part" is the statement part the objective assesses (from its OSCAL
    "assessment-for" link, e.g. "d.1" for AC-2 d.1), and "leaf" marks the
    individual determination statements (objectives with no sub-objectives).
    """
    catalog = _unwrap_catalog(catalog_json)
    params = _index_params(catalog)
    out: Dict[str, dict] = {}

    def walk_objectives(part, acc):
        prose = _substitute(part.get("prose", ""), params).strip()
        children = [sub for sub in part.get("parts", []) or [] if sub.get("name") == "assessment-objective"]
        if prose:
            target = next((link.get("href", "") for link in part.get("links", []) or []
                           if link.get("rel") == "assessment-for"), "")
            acc.append({
                "id": part.get("id", ""),
                "label": _prop(part, "label", "sp800-53a") or _prop(part, "label"),
                "text": prose,
                "part": part_key(parse_control_ref(target.lstrip("#"))[1]) if target else "",
                "leaf": not children,
            })
        for sub in children:
            walk_objectives(sub, acc)

    for ctrl, _group, _parent in _iter_catalog_controls(catalog):
        control_id = normalize_control_id(ctrl.get("id", ""))
        objectives, methods = [], {}
        for part in ctrl.get("parts", []) or []:
            if part.get("name") == "assessment-objective":
                walk_objectives(part, objectives)
            elif part.get("name") == "assessment-method":
                method = _prop(part, "method")
                objects = []
                for sub in part.get("parts", []) or []:
                    if sub.get("name") == "assessment-objects":
                        objects.extend(x.strip() for x in re.split(r"\n\s*\n", sub.get("prose", "")) if x.strip())
                if method:
                    methods.setdefault(method, []).extend(objects)
        if control_id and (objectives or methods):
            out[control_id] = {"objectives": objectives, "methods": methods}
    return out


def extract_assessment_procedures(catalog_json: dict) -> Dict[str, List[str]]:
    """SP 800-53A procedures as display strings, keyed by canonical control ID.

    Objectives come first ("AU-03a. Determine if ..."), then the EXAMINE /
    INTERVIEW / TEST methods with their assessment objects.
    """
    procedures = {}
    for control_id, detail in extract_assessment_details(catalog_json).items():
        steps = [
            f"{o['label']} Determine if {o['text']}" if o["label"] else f"Determine if {o['text']}"
            for o in detail["objectives"]
        ]
        for method in ("EXAMINE", "INTERVIEW", "TEST"):
            objects = detail["methods"].get(method)
            if objects:
                steps.append(f"{method.title()}: {'; '.join(objects)}")
        procedures[control_id] = steps
    return procedures


# ----------------------------------------------------------------------
#  Baselines
# ----------------------------------------------------------------------
def extract_baseline_control_ids(profile_json: dict) -> Set[str]:
    """Return the canonical control IDs selected by an OSCAL baseline profile."""
    profile = profile_json.get("profile", profile_json)
    if "imports" not in profile:
        raise ValueError(
            "Not an OSCAL profile: expected 'profile.imports'. "
            f"Top-level keys were: {list(profile_json)[:10]}"
        )
    ids: Set[str] = set()
    for imp in profile.get("imports", []):
        if "include-all" in imp:
            raise ValueError("Profile uses include-all; resolve it against the catalog instead.")
        for inc in imp.get("include-controls", []) or []:
            for cid in inc.get("with-ids", []) or []:
                norm = normalize_control_id(cid)
                if norm:
                    ids.add(norm)
            if inc.get("matching"):
                logger.warning("Profile uses 'matching' selectors, which are not resolved here.")
        for exc in imp.get("exclude-controls", []) or []:
            for cid in exc.get("with-ids", []) or []:
                ids.discard(normalize_control_id(cid))
    return ids


def extract_high_baseline_controls(high_baseline_json: dict) -> List[str]:
    """Sorted canonical control IDs in the High baseline (kept for compatibility)."""
    return sorted(extract_baseline_control_ids(high_baseline_json))


def apply_baselines(control_details: Dict[str, dict], baselines: Dict[str, Set[str]]) -> None:
    """Fill each control's baseline_levels from {"LOW": ids, "MODERATE": ids, "HIGH": ids}."""
    for level, ids in baselines.items():
        for cid in sorted(ids):
            if cid in control_details:
                levels = control_details[cid].setdefault("baseline_levels", [])
                if level not in levels:
                    levels.append(level)
            else:
                logger.warning("Baseline %s lists %s, which is not in the catalog", level, cid)


# ----------------------------------------------------------------------
#  DISA CCI List
# ----------------------------------------------------------------------
def _local(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def load_cci_records(cci_xml_path: str) -> List[dict]:
    """Parse U_CCI_List.xml into records.

    Each record: cci_id, definition, status, type, and references — a list of
    {version, title, index, control_id, part} for every SP 800-53 reference
    (800-53A references are skipped).
    """
    tree = ET.parse(cci_xml_path)
    records = []
    for item in tree.getroot().iter():
        if _local(item.tag) != "cci_item":
            continue
        rec = {"cci_id": item.get("id", "").strip(), "definition": "", "status": "", "type": "", "references": []}
        for child in item:
            name = _local(child.tag)
            if name in ("definition", "status", "type"):
                rec[name] = (child.text or "").strip()
            elif name == "references":
                for ref in child:
                    if _local(ref.tag) != "reference":
                        continue
                    title = ref.get("title", "")
                    if "800-53" not in title or "800-53A" in title:
                        continue
                    index = ref.get("index", "")
                    control_id, part = parse_control_ref(index)
                    rec["references"].append({
                        "version": ref.get("version", "").strip(),
                        "title": title,
                        "index": index,
                        "control_id": control_id,
                        "part": part,
                    })
        if rec["cci_id"]:
            records.append(rec)
    return records


def load_cci_parts(cci_xml_path: str, revision: str = "5") -> Dict[str, str]:
    """Map CCI ID -> statement part key (e.g. "a.1") for the given revision; "" for control-level CCIs."""
    if not os.path.exists(cci_xml_path):
        return {}
    parts = {}
    for rec in load_cci_records(cci_xml_path):
        for ref in rec["references"]:
            if ref["version"] == revision and ref["control_id"]:
                parts[rec["cci_id"]] = part_key(ref["part"])
                break
    return parts


def load_cci_mapping(cci_xml_path: str, revision: str = "5") -> Dict[str, str]:
    """Map CCI ID -> canonical SP 800-53 control, using the given revision only.

    CCIs with no reference for that revision are left out rather than mapped
    to an older revision's control, since Rev 4 and Rev 5 numbering differ.
    """
    if not os.path.exists(cci_xml_path):
        logger.warning("CCI list not found at %s; STIG rules will not map to controls.", cci_xml_path)
        return {}
    mapping = {}
    for rec in load_cci_records(cci_xml_path):
        for ref in rec["references"]:
            if ref["version"] == revision and ref["control_id"]:
                mapping[rec["cci_id"]] = ref["control_id"]
                break
    return mapping


_HEIMDALL_ENTRY_RE = re.compile(r"""['"](CCI-\d{6})['"]\s*:\s*['"]([^'"]*)['"]""")


def load_cci_mapping_from_heimdall(path: str) -> Dict[str, str]:
    """Map CCI -> control from MITRE Heimdall's CciNistMappingData.ts.

    Fallback for when DISA's U_CCI_List.xml is unavailable. Heimdall's table
    mixes revisions (mostly Rev 5, some Rev 4-era targets), so pass the result
    through reconcile_cci_mapping() before use.
    """
    if not os.path.exists(path):
        logger.warning("Heimdall CCI mapping not found at %s", path)
        return {}
    with open(path, encoding="utf-8") as f:
        text = f.read()
    mapping = {}
    for cci, ref in _HEIMDALL_ENTRY_RE.findall(text):
        control = normalize_control_id(ref)
        if control:
            mapping[cci] = control
    return mapping


def load_cci_parts_from_heimdall(path: str) -> Dict[str, str]:
    """Map CCI -> statement part key from Heimdall's table; "" for control-level CCIs."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return {cci: part_key(parse_control_ref(ref)[1]) for cci, ref in _HEIMDALL_ENTRY_RE.findall(text)
            if normalize_control_id(ref)}


def reconcile_cci_mapping(mapping: Dict[str, str], control_details: Dict[str, dict],
                          parts: Optional[Dict[str, str]] = None) -> Tuple[Dict[str, str], dict]:
    """Make a CCI mapping consistent with the Rev 5 catalog.

    - Targets in the catalog and active: kept.
    - Targets withdrawn in Rev 5 with exactly one replacement ("incorporated
      into" / "moved to"): redirected to that control.
    - Targets withdrawn with none or several replacements: dropped (ambiguous).
    - Targets not in the Rev 5 catalog at all (e.g. Rev 4 privacy families
      AR, DI, TR): dropped.

    Returns (clean_mapping, report). report["redirected"] maps CCI ->
    (original, replacement) so the redirect can be shown to users.
    If ``parts`` (CCI -> statement part) is given, report["parts"] holds the
    parts for the clean mapping; redirected CCIs take the part named in the
    withdrawn control's "incorporated into" link (AC-2(10) -> AC-2 k).
    """
    parts = parts or {}
    clean: Dict[str, str] = {}
    report = {"kept": 0, "redirected": {}, "dropped_not_in_rev5": {}, "dropped_ambiguous": {}, "parts": {}}
    for cci, control in mapping.items():
        ctrl = control_details.get(control)
        if ctrl is None:
            report["dropped_not_in_rev5"][cci] = control
        elif not ctrl.get("withdrawn"):
            clean[cci] = control
            report["kept"] += 1
            report["parts"][cci] = parts.get(cci, "")
        else:
            targets = [t for t in ctrl.get("withdrawn_to", [])
                       if t in control_details and not control_details[t].get("withdrawn")]
            if len(targets) == 1:
                clean[cci] = targets[0]
                report["redirected"][cci] = (control, targets[0])
                report["parts"][cci] = ctrl.get("withdrawn_to_parts", {}).get(targets[0], "")
            else:
                report["dropped_ambiguous"][cci] = (control, targets)
    return clean, report


# ----------------------------------------------------------------------
#  800-53A objectives <-> STIG rules
# ----------------------------------------------------------------------
def link_objectives_to_rules(control_id: str, rules: List[dict], cci_to_nist: Dict[str, str],
                             cci_parts: Dict[str, str], assessment: Optional[dict]) -> dict:
    """Attach STIG rules to the 800-53A determination statements they provide evidence for.

    A rule supports an objective when one of its CCIs maps to this control and
    the CCI's statement part overlaps the part the objective assesses
    (AU-3 a -> AU-03a; AC-2 d -> AC-02d.01, AC-02d.02, ...). Objectives that
    assess the whole statement accept any CCI for the control. Rules whose
    CCIs name the whole control count for part-specific objectives only when
    the control has a single determination statement; otherwise they are
    reported as control-level evidence, since the CCI does not say which part
    they cover.

    Returns {"objectives": [objective + {"rules": [...]}], "control_level_rules": [...],
             "covered": int, "total": int}
    """
    leaves = [dict(o, rules=[]) for o in (assessment or {}).get("objectives", []) if o.get("leaf")]
    control_level: List[dict] = []
    single = len(leaves) == 1
    for rule in rules:
        rule_parts = {cci_parts.get(c, "") for c in rule.get("ccis", []) if cci_to_nist.get(c) == control_id}
        if not rule_parts:
            continue
        matched = False
        for obj in leaves:
            # An objective that assesses the whole statement (no part) is supported by any CCI for the control.
            if single or not obj["part"] or any(parts_overlap(p, obj["part"]) for p in rule_parts if p):
                obj["rules"].append(rule)
                matched = True
        if not matched:
            control_level.append(rule)
    return {
        "objectives": leaves,
        "control_level_rules": control_level,
        "covered": sum(1 for o in leaves if o["rules"]),
        "total": len(leaves),
    }


# ----------------------------------------------------------------------
#  STIG XCCDF
# ----------------------------------------------------------------------
def _child(el: ET.Element, name: str) -> Optional[ET.Element]:
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _child_text(el: ET.Element, name: str) -> str:
    c = _child(el, name)
    return (c.text or "").strip() if c is not None and c.text else ""


def _vuln_discussion(description: str) -> str:
    m = re.search(r"<VulnDiscussion>(.*?)</VulnDiscussion>", description or "", re.S)
    return (m.group(1) if m else description or "").strip()


def parse_stig_file(file_path: str) -> Tuple[dict, List[dict]]:
    """Parse one XCCDF benchmark into (stig_info, rules)."""
    root = ET.parse(file_path).getroot()
    title = _child_text(root, "title") or os.path.basename(file_path)
    release = ""
    for el in root:
        if _local(el.tag) == "plain-text" and el.get("id") == "release-info":
            release = (el.text or "").strip()
    info = {
        "file": os.path.basename(file_path),
        "title": title,
        "technology": re.sub(r"\s*Security Technical Implementation Guide\s*$", "", title).strip() or title,
        "version": _child_text(root, "version"),
        "release": release,
    }

    rules = []
    for group in root.iter():
        if _local(group.tag) != "Group":
            continue
        rule = _child(group, "Rule")
        if rule is None:
            continue
        check = _child(rule, "check")
        rules.append({
            "vuln_id": group.get("id", ""),
            "rule_id": rule.get("id", ""),
            "stig_id": _child_text(rule, "version"),
            "title": _child_text(rule, "title"),
            "severity": rule.get("severity", "medium"),
            "discussion": _vuln_discussion(_child_text(rule, "description")),
            "check": _child_text(check, "check-content") if check is not None else "",
            "fix": _child_text(rule, "fixtext"),
            "ccis": [
                (i.text or "").strip()
                for i in rule
                if _local(i.tag) == "ident" and "cci" in i.get("system", "").lower() and i.text
            ],
        })
    return info, rules


def load_stig_data(stig_folder: str, cci_to_nist: Dict[str, str]) -> tuple:
    """Load every XCCDF file in a folder and index its rules by control.

    Returns (recommendations, available_stigs) where recommendations is
    {technology: {control_id: [rule, ...]}}. Each stig_info also records
    rule_count and unmapped_rules so a missing CCI list is visible.
    """
    all_recommendations: Dict[str, Dict[str, List[dict]]] = {}
    available_stigs = []

    if not os.path.isdir(stig_folder):
        logger.warning("STIG folder not found: %s", stig_folder)
        return all_recommendations, available_stigs

    for stig_file in sorted(os.listdir(stig_folder)):
        if not stig_file.lower().endswith(".xml"):
            continue
        try:
            info, rules = parse_stig_file(os.path.join(stig_folder, stig_file))
        except ET.ParseError as e:
            logger.error("Error parsing %s: %s", stig_file, e)
            continue

        by_control: Dict[str, List[dict]] = {}
        unmapped = 0
        for rule in rules:
            controls = {cci_to_nist[c] for c in rule["ccis"] if c in cci_to_nist}
            if not controls:
                unmapped += 1
            for control in sorted(controls):
                by_control.setdefault(control, []).append(rule)

        info["rule_count"] = len(rules)
        info["unmapped_rules"] = unmapped
        available_stigs.append(info)
        all_recommendations[info["technology"]] = by_control
        if rules and unmapped == len(rules):
            logger.warning("%s: none of %d rules mapped to a control (is the CCI list loaded?)", stig_file, len(rules))
    return all_recommendations, available_stigs


def extract_actionable_steps(description: str) -> List[str]:
    """Fallback only: verb-led sentences from control text when no 800-53A data exists."""
    if not description:
        return []
    action_verbs = {
        "verify", "ensure", "confirm", "check", "review", "validate", "examine",
        "determine", "identify", "monitor", "assess", "test", "inspect",
    }
    sentences = [s.strip() for s in re.split(r"(?<=[.;:?])\s+|\n", description) if s.strip()]
    steps = [s for s in sentences if s.split() and s.split()[0].lower().strip(".,;") in action_verbs]
    return (steps or sentences[:1])[:10]
