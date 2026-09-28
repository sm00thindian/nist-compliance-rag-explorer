# NIST Compliance RAG Explorer

Joins NIST SP 800-53 Rev 5, SP 800-53A Rev 5, DISA CCIs and DISA STIGs so that
questions like "which RHEL 9 rules are evidence for AU-03a, and which AC-2
statements need interviews?" get exact, citable answers. The joined data is the
product; the chat/CLI layer is a thin front end.

Owner works in federal Policy & Assurance (ATO). Treat anything about real
systems (configs, scan results, hostnames) as sensitive.

## Hard rules

- **Evidence never goes to a model.** Configs, logs and scan output are
  evaluated locally. Only public material (STIG text, NIST text, CCI mappings)
  may be sent to an LLM.
- **This tool holds no credentials for target systems and never starts scans.**
  Scans (CINC Auditor + MITRE SAF profiles) run outside it; it only reads
  result files.
- **Model-generated checks are data, not code.** The LLM emits the declarative
  JSON check format in `src/checks/spec.py`, never executable InSpec/Ruby or
  shell. The model never sets `reviewed`, rule IDs or hashes; those are set
  locally.
- **Don't guess mappings.** Ambiguous CCI → control redirects are dropped and
  reported, not inferred. Control-level CCIs are reported as control-level
  evidence unless the match is unambiguous.
- The evidence API (`src/api`) must keep `ALLOW_EVIDENCE_TO_LLM` defaulting to off.

## Layout

- `src/parsers.py`: all source parsing and joins. OSCAL catalog (controls,
  params, withdrawn), 800-53A objectives/methods (embedded in the catalog),
  OSCAL baselines, DISA CCI XML, MITRE Heimdall CCI table, STIG XCCDF,
  `reconcile_cci_mapping`, `link_objectives_to_rules`.
- `src/checks/`: local STIG checks. `spec` (format + validation), `engine`
  (evaluate against an evidence folder), `evidence` (folder layout + collection
  script), `generator` (LLM → checks, public text only), `llm` (provider
  interface), `rollup` (results → 800-53A statements).
- `scripts/checks.py`: `status | generate | review | plan | evaluate`.
- `scripts/validate_data.py`: parses every source and checks counts and joins.
- `checks/<technology>/<Vuln-ID>.json`: stored checks (4 hand-written RHEL 9
  examples, reviewed).
- `src/main.py`, `src/response_generator.py`: interactive CLI.
- `src/mcp_server/`: read-only MCP server (stdio). `data.Explorer` is the whole
  query surface (public data only, no paths, no results); `server.py` wraps it
  with the `mcp` 2.x SDK (`MCPServer`, not the 1.x `FastMCP`).
- `scripts/mcp_server.py`: entry point.
- `src/api/`: FastAPI evidence-evaluation proof of concept (older, gated).
- `stigs/`: bundled Windows 10 and RHEL 9 XCCDF files.

## Data (gitignored, in `knowledge/`)

```
B=https://raw.githubusercontent.com/usnistgov/oscal-content/refs/heads/main/nist.gov/SP800-53/rev5/json
mkdir -p knowledge
curl -o knowledge/nist_800_53-rev5_catalog_json.json        $B/NIST_SP-800-53_rev5_catalog.json
curl -o knowledge/nist_800_53-rev5_low-baseline_json.json   $B/NIST_SP-800-53_rev5_LOW-baseline_profile.json
curl -o knowledge/nist_800_53-rev5_moderate-baseline_json.json $B/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json
curl -o knowledge/nist_800_53-rev5_high-baseline_json.json  $B/NIST_SP-800-53_rev5_HIGH-baseline_profile.json
curl -o knowledge/CciNistMappingData.ts https://raw.githubusercontent.com/mitre/heimdall2/master/libs/hdf-converters/src/mappings/CciNistMappingData.ts
```

The authoritative CCI list is DISA's `U_CCI_List.xml`. Download it manually
from https://www.cyber.mil/stigs/downloads (search for "CCI List"; it is a zip).
Whether this download can be automated has not been checked, so there is no
curl line for it. Put it in `knowledge/`; it takes priority
over the Heimdall fallback. It must be 2022 or later: older copies (including
the 2014 and 2016 ones on GitHub) reference only Rev 4 and map nothing.

Expected with catalog 5.2.0: 1,196 controls (182 withdrawn); baselines
149 / 287 / 370; 800-53A for all 1,014 active controls. With the Heimdall
fallback: 4,489 CCIs kept, 364 redirected, 245 dropped; every rule in both
bundled STIGs maps; RHEL 9 covers 139/179 statements, Windows 10 77/117.
With the DISA list (2026-07-14, 5,149 CCIs, 3,847 with a Rev 5 reference, all
kept): every rule still maps; RHEL 9 137/175 (81 controls), Windows 10 76/113
(44). The difference: 29 STIG CCIs have only Rev 3/4 references in DISA's list
(Heimdall assigned them Rev 5 targets), so IA-4 drops out and some parts get
narrower (AU-9 -> AU-9 a). DISA's zip names the file `CCI_List.xml`; save it
as `knowledge/U_CCI_List.xml`.

## Commands

```
pytest test/test_parsers.py test/test_checks.py test/test_mcp_server.py   # 99 tests; real-data tests skip without knowledge/
python scripts/validate_data.py [--cci path/to/U_CCI_List.xml]
python scripts/checks.py status --stig rhel
python scripts/checks.py generate --stig rhel --control AC-7 --dry-run   # shows the exact prompt
python scripts/checks.py evaluate --stig rhel --evidence ./evidence --csv out.csv
python scripts/mcp_server.py            # stdio; claude mcp add nist-explorer -- <venv python> scripts/mcp_server.py
```

LLM provider: `LLM_PROVIDER=anthropic|bedrock|openai|xai` with
`ANTHROPIC_MODEL` (default `claude-sonnet-5`), `BEDROCK_MODEL_ID` + `AWS_REGION`,
`OPENAI_MODEL`, or `XAI_MODEL`. Request shapes were verified against mocked
endpoints only; no live call has been made yet.

## Key design decisions

- One canonical control ID everywhere: `AC-2`, `AC-2(1)`. Statement parts are
  kept separately as dot keys (`a.1.a`) via `parse_control_ref` / `part_key`.
- 800-53A comes from the OSCAL catalog's `assessment-objective` parts; each
  objective's `assessment-for` link gives the statement part it assesses. The
  separate 800-53A URL in older configs was a 404.
- CCI source order: DISA list with Rev 5 references, then Heimdall. Heimdall
  mixes Rev 4 and Rev 5 targets, so `reconcile_cci_mapping` redirects withdrawn
  controls with exactly one replacement (keeping the part from the
  "incorporated into" link) and drops the rest.
- Rule → 800-53A statement: a CCI's part overlaps the objective's part (parent
  or child). Whole-statement objectives accept any CCI for the control.
- FAISS index cache is keyed on document content (it used to cache an empty
  index forever).
- Checks run via CINC Auditor (free InSpec build) with MITRE SAF profiles where
  they exist (e.g. mitre/redhat-enterprise-linux-9-stig-baseline, Apache-2.0;
  controls tagged with gid/rid/cci/nist). Profile `input()`s are the
  organization-defined parameter values. The local JSON engine covers
  evidence-folder assessments and gaps.

## Roadmap (agreed direction)

1. **Read-only MCP server** over public data (first version done; 10 tools): control text/params/baselines,
   800-53A statements and methods, STIG rules, CCI mappings, profile-to-statement
   coverage, gap listing. No results, no credentials.
2. **Results importer** for CINC/InSpec JSON (HDF). Map controls by `gid` tag,
   flag `rid` revision mismatches with the loaded STIG, and feed
   `checks.rollup`. Expose only rolled-up status through a gated MCP tool;
   raw results stay out of model context by default.
3. **Redaction layer** for narrative evidence (policies, procedures) sent to an
   authorized endpoint: reversible placeholder tokenization (`10.2.3.4` →
   `IP_1`), restored locally, with a log of exactly what was sent.
4. Drop spaCy (`src/text_processing.py`); regex detection replaced it in
   responses. Keep sentence-transformer embeddings (local) for fuzzy queries,
   or make them optional.
5. ~~Get the current DISA CCI list and rerun `validate_data.py`.~~ Done (2026-07-14 list).
6. First live `generate` run on a handful of rules; measure check quality.

## Known issues

- `test/test_control_id.py`, `test_cci_id.py` and `test_stig_id.py` assert
  buggy spaCy output (`AC-7(2`, `CM-6 ARE`). Delete them with the spaCy removal.
- `test/test_rag_response.py` runs the full CLI with models; slow, not in the
  default test set.
- `src/api` is an older proof of concept; its LLM path is gated and it predates
  `src/checks`.

## Git workflow

- Target `main` directly. A PR stacked on another branch got merged into that
  branch instead of `main` once (#13), which took an extra PR (#14) to fix.
- Keep PR descriptions factual: what changed, verified numbers, what is untested.
