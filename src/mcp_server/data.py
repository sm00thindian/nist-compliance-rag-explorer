"""
Read-only queries over the public data: SP 800-53 Rev 5, SP 800-53A Rev 5,
CCI mappings and the bundled STIGs.

This module is the MCP server's whole data surface. It reads only the public
source files loaded by ``checks.rollup.load_context`` plus the OSCAL
baselines. It never reads scan results, evidence or check results, takes no
file paths from callers (STIGs are picked by name from the loaded set), and
holds no credentials.

Every method returns plain JSON-serializable dicts and raises ``LookupError``
or ``ValueError`` with a message meant for the caller.
"""
import json
import os
import re
from typing import Dict, List, Optional

from checks.rollup import load_context
from parsers import (
    apply_baselines,
    extract_baseline_control_ids,
    link_objectives_to_rules,
    normalize_control_id,
    parse_control_ref,
    part_key,
    parts_overlap,
)

BASELINE_LEVELS = ("LOW", "MODERATE", "HIGH")
METHODS = ("EXAMINE", "INTERVIEW", "TEST")
NO_STIG_EVIDENCE = "no STIG rule provides evidence; assess with Examine/Interview"


def control_sort_key(control_id: str):
    return (control_id.split("-")[0], *map(int, re.findall(r"\d+", control_id)))


def rule_summary(rule: dict) -> dict:
    out = {k: rule[k] for k in ("vuln_id", "stig_id", "severity", "title")}
    if "stig" in rule:
        out["stig"] = rule["stig"]
    return out


class Explorer:
    def __init__(self, ctx: dict, baselines: Dict[str, set]):
        self.ctx = ctx
        self.controls = ctx["controls"]
        self.assessment = ctx["assessment"]
        self.cci_to_nist = ctx["cci_to_nist"]
        self.cci_parts = ctx["cci_parts"]
        self.cci_report = ctx.get("cci_report", {})
        self.baselines = baselines
        apply_baselines(self.controls, baselines)
        self.rule_index: Dict[str, List[tuple]] = {}
        self.cci_rules: Dict[str, List[tuple]] = {}
        for tech, rules in ctx["rules"].items():
            for rule in rules:
                keys = {rule["vuln_id"], rule["stig_id"], rule["rule_id"], rule["rule_id"].split("r", 1)[0]}
                for key in filter(None, keys):
                    self.rule_index.setdefault(key.upper(), []).append((tech, rule))
                for cci in rule["ccis"]:
                    self.cci_rules.setdefault(cci, []).append((tech, rule))

    @classmethod
    def load(cls, knowledge_dir: str = "knowledge", stig_folder: str = "stigs") -> "Explorer":
        catalog = os.path.join(knowledge_dir, "nist_800_53-rev5_catalog_json.json")
        if not os.path.exists(catalog):
            raise FileNotFoundError(f"{catalog} not found. Download the data listed in CLAUDE.md (Data section).")
        ctx = load_context(knowledge_dir, stig_folder)
        baselines = {}
        for level in BASELINE_LEVELS:
            path = os.path.join(knowledge_dir, f"nist_800_53-rev5_{level.lower()}-baseline_json.json")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    baselines[level] = extract_baseline_control_ids(json.load(f))
        return cls(ctx, baselines)

    # ------------------------------------------------------------------
    #  Lookups shared by the queries
    # ------------------------------------------------------------------
    def _control(self, ref: str) -> dict:
        cid = normalize_control_id(ref)
        if not cid:
            raise ValueError(f"{ref!r} is not a control ID (expected e.g. AC-2, AC-2(1), AU-3 a).")
        if cid not in self.controls:
            raise LookupError(f"{cid} is not in the SP 800-53 Rev 5 catalog.")
        return self.controls[cid]

    def _baseline(self, level: Optional[str]) -> Optional[set]:
        if not level:
            return None
        level = level.upper()
        if level not in self.baselines:
            raise ValueError(f"Unknown baseline {level!r}. Loaded: {', '.join(self.baselines) or 'none'}.")
        return self.baselines[level]

    def _stig(self, name: str) -> str:
        """Resolve a STIG name ('rhel', 'windows 10', a file name) to its technology key."""
        needle = (name or "").strip().lower()
        stigs = self.ctx["stigs"]
        matches = [s for s in stigs if needle and (needle in s["technology"].lower() or needle in s["file"].lower()
                   or (needle == "rhel" and "red hat" in s["technology"].lower()))]
        if len(matches) != 1:
            options = "; ".join(s["technology"] for s in stigs)
            raise ValueError(f"STIG {name!r} matched {len(matches)} of the loaded STIGs. Loaded: {options}.")
        return matches[0]["technology"]

    def _techs(self, stig: Optional[str]) -> List[str]:
        return [self._stig(stig)] if stig else [s["technology"] for s in self.ctx["stigs"]]

    def _rules_for(self, cid: str, techs: List[str]) -> List[dict]:
        rules = []
        for tech in techs:
            for rule in self.ctx["recommendations"].get(tech, {}).get(cid, []):
                rules.append(dict(rule, stig=tech))
        return rules

    def _cci_mapping(self, cci: str) -> dict:
        out = {"cci": cci}
        redirected = self.cci_report.get("redirected", {})
        if cci in self.cci_to_nist:
            out["control"] = self.cci_to_nist[cci]
            out["part"] = self.cci_parts.get(cci, "")
            if cci in redirected:
                out["redirected_from"] = redirected[cci][0]
        elif cci in self.cci_report.get("dropped_ambiguous", {}):
            original, targets = self.cci_report["dropped_ambiguous"][cci]
            out["dropped"] = (f"maps to {original}, withdrawn in Rev 5 with "
                              + (f"{len(targets)} possible replacements ({', '.join(targets)})" if targets
                                 else "no active replacement")
                              + "; not guessed")
        elif cci in self.cci_report.get("dropped_not_in_rev5", {}):
            out["dropped"] = f"maps to {self.cci_report['dropped_not_in_rev5'][cci]}, which is not in the Rev 5 catalog"
        else:
            out["dropped"] = "not in the loaded CCI mapping"
        return out

    # ------------------------------------------------------------------
    #  SP 800-53
    # ------------------------------------------------------------------
    def get_control(self, control_id: str, include_guidance: bool = False) -> dict:
        c = self._control(control_id)
        out = {
            "control_id": c["control_id"],
            "title": c["title"],
            "family": f"{c['family']} ({c['family_title']})",
            "baselines": [lvl for lvl in BASELINE_LEVELS if lvl in c.get("baseline_levels", [])],
            "withdrawn": c["withdrawn"],
            "statement": c["description"],
            "parameters": c["parameters"],
            "related": c["related"],
        }
        if c["parent"]:
            out["parent"] = c["parent"]
        if c["withdrawn"]:
            out["withdrawn_to"] = c["withdrawn_to"]
        else:
            out["enhancements"] = sorted((x["control_id"] for x in self.controls.values() if x["parent"] == c["control_id"]),
                                         key=control_sort_key)
        if include_guidance:
            out["guidance"] = c["guidance"]
        return out

    def search_controls(self, query: str = "", family: Optional[str] = None, baseline: Optional[str] = None,
                        include_withdrawn: bool = False, limit: int = 25) -> dict:
        terms = [t for t in re.findall(r"[a-z0-9]+", (query or "").lower()) if len(t) > 1]
        fam = (family or "").strip().upper()
        ids = self._baseline(baseline)
        hits = []
        for c in self.controls.values():
            if (fam and c["family"] != fam) or (ids is not None and c["control_id"] not in ids):
                continue
            if c["withdrawn"] and not include_withdrawn:
                continue
            title, body = c["title"].lower(), c["description"].lower()
            score = 0
            if terms:
                matched = [t for t in terms if t in title or t in body]
                if len(matched) < len(terms):
                    continue
                score = sum(3 if t in title else 1 for t in terms)
            hits.append((-score, control_sort_key(c["control_id"]), c))
        hits.sort(key=lambda h: h[:2])
        limit = max(1, min(limit, 200))
        return {
            "total": len(hits),
            "returned": min(len(hits), limit),
            "controls": [{"control_id": c["control_id"], "title": c["title"],
                          "baselines": [lvl for lvl in BASELINE_LEVELS if lvl in c.get("baseline_levels", [])],
                          **({"withdrawn": True} if c["withdrawn"] else {})}
                         for _, _, c in hits[:limit]],
        }

    # ------------------------------------------------------------------
    #  SP 800-53A
    # ------------------------------------------------------------------
    def get_assessment(self, control_id: str) -> dict:
        c = self._control(control_id)
        if c["withdrawn"]:
            raise LookupError(f"{c['control_id']} is withdrawn in Rev 5 (see {', '.join(c['withdrawn_to']) or 'no replacement'}); "
                              "it has no 800-53A procedure.")
        a = self.assessment.get(c["control_id"], {"objectives": [], "methods": {}})
        return {
            "control_id": c["control_id"],
            "title": c["title"],
            "determination_statements": [{"label": o["label"], "part": o["part"], "text": o["text"]}
                                         for o in a["objectives"] if o["leaf"]],
            "methods": {m: a["methods"][m] for m in METHODS if a["methods"].get(m)},
        }

    # ------------------------------------------------------------------
    #  STIGs and CCIs
    # ------------------------------------------------------------------
    def list_stigs(self) -> dict:
        out = []
        for s in self.ctx["stigs"]:
            out.append({"technology": s["technology"], "version": s["version"], "release": s["release"],
                        "rules": s["rule_count"], "unmapped_rules": s["unmapped_rules"],
                        "controls": len(self.ctx["recommendations"].get(s["technology"], {}))})
        return {"stigs": out, "cci_source": os.path.basename(self.ctx["cci_source"])}

    def get_stig_rule(self, rule_id: str) -> dict:
        found = self.rule_index.get((rule_id or "").strip().upper(), [])
        if not found:
            raise LookupError(f"No rule {rule_id!r} in the loaded STIGs (use a Vuln ID like V-258054, "
                              "a STIG ID like RHEL-09-211010, or a rule ID).")
        out = []
        for tech, rule in found:
            out.append({"stig": tech, **{k: rule[k] for k in ("vuln_id", "rule_id", "stig_id", "severity", "title",
                                                              "discussion", "check", "fix")},
                        "cci_mappings": [self._cci_mapping(c) for c in rule["ccis"]]})
        return out[0] if len(out) == 1 else {"matches": out}

    def search_stig_rules(self, query: str = "", stig: Optional[str] = None, control_id: Optional[str] = None,
                          severity: Optional[str] = None, limit: int = 25) -> dict:
        terms = [t for t in re.findall(r"[a-z0-9]+", (query or "").lower()) if len(t) > 1]
        cid = self._control(control_id)["control_id"] if control_id else None
        sev = (severity or "").lower()
        hits = []
        for tech in self._techs(stig):
            by_control = self.ctx["recommendations"].get(tech, {})
            candidates = by_control.get(cid, []) if cid else self.ctx["rules"][tech]
            for rule in candidates:
                if sev and rule["severity"] != sev:
                    continue
                text = f"{rule['title']} {rule['discussion']} {rule['check']}".lower()
                if any(t not in text for t in terms):
                    continue
                hits.append(dict(rule, stig=tech))
        limit = max(1, min(limit, 200))
        return {"total": len(hits), "returned": min(len(hits), limit),
                "rules": [rule_summary(r) for r in hits[:limit]]}

    def lookup_cci(self, cci_id: str) -> dict:
        m = re.fullmatch(r"(?:CCI-?)?0*(\d{1,6})", (cci_id or "").strip().upper())
        if not m:
            raise ValueError(f"{cci_id!r} is not a CCI ID (expected e.g. CCI-000130).")
        cci = f"CCI-{int(m.group(1)):06d}"
        out = self._cci_mapping(cci)
        rules = self.cci_rules.get(cci, [])
        out["stig_rules"] = [rule_summary(dict(r, stig=t)) for t, r in rules[:50]]
        out["stig_rule_count"] = len(rules)
        out["source"] = os.path.basename(self.ctx["cci_source"])
        return out

    # ------------------------------------------------------------------
    #  STIG -> 800-53A statement coverage
    # ------------------------------------------------------------------
    def statement_coverage(self, control_ref: str, stig: Optional[str] = None) -> dict:
        """Which STIG rules are evidence for each determination statement of a control.

        ``control_ref`` may name a statement ("AU-3 a", "AU-03a", "AC-2 d.1") to
        narrow the answer to that part.
        """
        c = self._control(control_ref)
        cid = c["control_id"]
        if c["withdrawn"]:
            raise LookupError(f"{cid} is withdrawn in Rev 5; see {', '.join(c['withdrawn_to']) or 'no replacement'}.")
        part = part_key(parse_control_ref(control_ref)[1])
        techs = self._techs(stig)
        rules = self._rules_for(cid, techs)
        link = link_objectives_to_rules(cid, rules, self.cci_to_nist, self.cci_parts, self.assessment.get(cid))
        objectives = [o for o in link["objectives"] if not part or parts_overlap(part, o["part"])]
        if part and not objectives:
            raise LookupError(f"{cid} has no determination statement for part {part!r}.")
        statements = []
        for o in objectives:
            entry = {"label": o["label"], "part": o["part"], "text": o["text"]}
            if o["rules"]:
                entry["stig_rules"] = [rule_summary(r) for r in o["rules"]]
            else:
                entry["evidence"] = NO_STIG_EVIDENCE
            statements.append(entry)
        a = self.assessment.get(cid, {"methods": {}})
        out = {
            "control_id": cid,
            "title": c["title"],
            "stigs": techs,
            "covered": sum(1 for s in statements if "stig_rules" in s),
            "total": len(statements),
            "statements": statements,
            "control_level_rules": [rule_summary(r) for r in link["control_level_rules"]],
            "control_level_note": ("These rules cite a CCI for the whole control, so which statement they cover "
                                   "is not stated; they are not assigned to one.") if link["control_level_rules"] else "",
            "methods": {m: a["methods"][m] for m in METHODS if a["methods"].get(m)},
        }
        if not rules:
            out["note"] = f"No rule in {', '.join(techs)} maps to {cid}."
            enh = sorted({e for t in techs for e in self.ctx["recommendations"].get(t, {})
                          if self.controls.get(e, {}).get("parent") == cid}, key=control_sort_key)
            if enh:
                out["enhancements_with_stig_rules"] = enh
        return out

    def _stig_links(self, tech: str, ids: Optional[set]):
        by_control = self.ctx["recommendations"].get(tech, {})
        for cid in sorted(by_control, key=control_sort_key):
            if ids is not None and cid not in ids:
                continue
            link = link_objectives_to_rules(cid, by_control[cid], self.cci_to_nist, self.cci_parts,
                                            self.assessment.get(cid))
            yield cid, by_control[cid], link

    def stig_coverage(self, stig: str, baseline: Optional[str] = None, family: Optional[str] = None) -> dict:
        tech = self._stig(stig)
        ids = self._baseline(baseline)
        fam = (family or "").strip().upper()
        rows, covered, total = [], 0, 0
        for cid, rules, link in self._stig_links(tech, ids):
            if fam and not cid.startswith(fam + "-"):
                continue
            covered += link["covered"]
            total += link["total"]
            rows.append({"control_id": cid, "title": self.controls[cid]["title"], "rules": len(rules),
                         "statements_covered": link["covered"], "statements_total": link["total"],
                         "control_level_rules": len(link["control_level_rules"])})
        out = {"stig": tech, "controls": len(rows), "statements_covered": covered, "statements_total": total,
               "by_control": rows}
        if ids is not None:
            touched = {r["control_id"] for r in rows}
            untouched = sorted((i for i in ids if i not in touched and (not fam or i.startswith(fam + "-"))),
                               key=control_sort_key)
            out["baseline"] = baseline.upper()
            out["baseline_controls_without_stig_rules"] = untouched
        return out

    def list_gaps(self, stig: str, baseline: Optional[str] = None, family: Optional[str] = None,
                  limit: int = 100) -> dict:
        """Determination statements the STIG gives no evidence for, in controls it touches."""
        tech = self._stig(stig)
        ids = self._baseline(baseline)
        fam = (family or "").strip().upper()
        gaps = []
        for cid, _rules, link in self._stig_links(tech, ids):
            if fam and not cid.startswith(fam + "-"):
                continue
            for o in link["objectives"]:
                if not o["rules"]:
                    gaps.append({"control_id": cid, "label": o["label"], "text": o["text"]})
        limit = max(1, min(limit, 500))
        out = {"stig": tech, "note": NO_STIG_EVIDENCE, "total": len(gaps), "returned": min(len(gaps), limit),
               "statements": gaps[:limit]}
        if ids is not None:
            touched = set(self.ctx["recommendations"].get(tech, {}))
            out["baseline"] = baseline.upper()
            out["baseline_controls_without_stig_rules"] = sorted(
                (i for i in ids if i not in touched and (not fam or i.startswith(fam + "-"))), key=control_sort_key)
        return out
