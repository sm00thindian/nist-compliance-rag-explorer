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
- The MCP `results_rollup` tool exists only when the server is started with
  `--results` and `ALLOW_ROLLUP_TO_LLM=1`; keep it off by default. It returns
  IDs and statuses only, never code_desc, messages, platform or passthrough.

## Layout

- `src/parsers.py`: all source parsing and joins. OSCAL catalog (controls,
  params, withdrawn), 800-53A objectives/methods (embedded in the catalog),
  OSCAL baselines, DISA CCI XML, MITRE Heimdall CCI table, STIG XCCDF,
  `reconcile_cci_mapping`, `link_objectives_to_rules`.
- `src/checks/`: local STIG checks. `spec` (format + validation), `engine`
  (evaluate against an evidence folder), `evidence` (folder layout + collection
  script), `generator` (LLM → checks, public text only), `llm` (provider
  interface), `rollup` (results → 800-53A statements), `hdf` (import CINC/InSpec
  HDF results: Heimdall's status rules, match on `gid`, flag `rid` mismatches).
- `scripts/checks.py`: `status | generate | review | plan | evaluate | import-results`.
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
The direct URL in `config/config.ini.template`
(`dl.dod.cyber.mil/.../U_CCI_List.zip`) still downloads, but as of 2026-09 it
serves the 2025-01-23 list, not the current one, so don't automate with it.
Put it in `knowledge/`; it takes priority
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
pytest test/test_parsers.py test/test_checks.py test/test_mcp_server.py test/test_hdf.py   # 119 tests; real-data tests skip without knowledge/
python scripts/validate_data.py [--cci path/to/U_CCI_List.xml]
python scripts/checks.py status --stig rhel
python scripts/checks.py generate --stig rhel --control AC-7 --dry-run   # shows the exact prompt
python scripts/checks.py evaluate --stig rhel --evidence ./evidence --csv out.csv
python scripts/checks.py import-results --stig rhel --hdf scan.json --csv out.csv
python scripts/mcp_server.py            # stdio; claude mcp add nist-explorer -- <venv python> scripts/mcp_server.py
ALLOW_ROLLUP_TO_LLM=1 python scripts/mcp_server.py --results scan.json --results-stig rhel   # adds results_rollup
```

LLM provider: `LLM_PROVIDER=anthropic|bedrock|openai|xai` with
`ANTHROPIC_MODEL` (default `claude-sonnet-5`), `BEDROCK_MODEL_ID` + `AWS_REGION`,
`OPENAI_MODEL`, or `XAI_MODEL`. Anthropic has had one live run (2026-10-03,
`claude-sonnet-5`); Bedrock, OpenAI and xAI are verified against mocked
endpoints only. For local use, `ant auth login` (short-lived OAuth, bound to one
workspace) works with `llm.py` unchanged when `ANTHROPIC_API_KEY` is unset; an
`ANTHROPIC_API_KEY` in the environment overrides it. A personal key that isn't
scoped to one workspace fails with a 400 (needs `anthropic-workspace-id`).

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

## Plan (tracking issue #33)

Narrowed direction: be the layer no open-source tool provides, mapping STIG
results to SP 800-53A Rev 5 determination statements and listing the
statements nothing automated covers. Leave review workflow, viewing and OSCAL
authoring to STIG Manager, Heimdall and Compliance Trestle, and plug into them.
DISA's CCI list only references 800-53A Revision 1, so the statement-level join
through OSCAL `assessment-for` links is this project's core. The MCP server
stays as an extra. Full plan, rationale and checklist: #33.

- **Phase 0, validate the bet:** #21 compare with STIG Manager and Heimdall;
  #22 pilot on one real system (results stay local). Go/no-go after #22.
- **Phase 1, make it consumable:** #23 OSCAL Assessment Results export; #24
  Examine/Interview worklist; #25 CKL/CKLB checklist input; #26 apply HDF
  attestations.
- **Phase 2, harden the core** (independent of the Phase 0 decision): #27
  fix the two check-generation defects; #28 CI; #29 core packaging and Python
  versions; #30 data source/version/checksum reporting; #31 README rewrite.
- **Phase 3:** #32 decide the future of the interactive RAG CLI and `src/api`.
- **Deferred:** redaction layer for narrative evidence (revisit if the pilot
  shows a need); Docker, Kubernetes and performance work.

### Done

- Read-only MCP server, 10 tools (#17).
- HDF results importer: `checks.hdf`, `checks.py import-results`, gated MCP
  `results_rollup` (#19). Tested on a synthetic fixture and MITRE's public
  RHEL 9 sample, not yet on a real CINC Auditor run. Attestations are listed
  but not applied (#26).
- spaCy removed (#19). Embeddings kept for the interactive CLI (#32).
- DISA CCI list 2026-07-14 in use (#18).
- First live `generate` run, 2026-10-03, 8 RHEL 9 rules, `claude-sonnet-5`
  (#20): 8/8 valid on the first try; 6 automatable, 2 manual (V-258106 NOPASSWD
  exceptions, V-257777 vendor support lifecycle). 14/15 scenario verdicts (the
  hand-written references score 15/15). Two defects, both of which can pass a
  non-compliant system, tracked in #27:
  - V-258151: pattern `^audit-\S+` also matches `audit-libs`.
  - V-257985: reads only `/etc/ssh/sshd_config` with `occurrence: last`. sshd
    uses the first value, and RHEL 9 includes `sshd_config.d/*.conf` first.
  Keep generated checks `reviewed: false` until a person approves them.

## Known issues

- `test/test_rag_response.py` runs the full CLI with models; slow, not in the
  default test set. Its future is part of #32.
- `src/api` is an older proof of concept; its LLM path is gated and it predates
  `src/checks`. Its future is #32.
- There's no CI yet (#28); run the default test set and `validate_data.py`
  before opening a PR.

## Git workflow

- Target `main` directly. A PR stacked on another branch got merged into that
  branch instead of `main` once (#13), which took an extra PR (#14) to fix.
- Keep PR descriptions factual: what changed, verified numbers, what is untested.
