# NIST Compliance RAG Explorer

The NIST Compliance RAG Explorer is a Python-based tool that leverages Retrieval-Augmented Generation (RAG) to provide detailed responses to compliance queries related to NIST 800-53 Revision 5 controls and Security Technical Implementation Guides (STIGs). It fetches and processes NIST 800-53 catalog data (JSON and Excel), high baseline controls, NIST SP 800-53A assessment procedures, and STIG recommendations, enabling users to query implementation guidance or detailed assessment steps for specific controls across various systems (e.g., Windows, Red Hat).

## Features
- **Control Details**: Retrieve titles, descriptions, parameters, and related controls from NIST 800-53 Rev 5 (JSON catalog prioritized for richer data).
- **Implementation Guidance**: Get NIST and STIG-based recommendations for implementing controls on specific systems.
- **Assessment Support**: Generate detailed assessment steps from NIST SP 800-53A, enriched with STIG checks and inferred steps using NLP when available.
- **Interactive CLI**: Query via a command-line interface with colored output for readability.
- **Vector Store**: Uses FAISS and Sentence Transformers for efficient document retrieval.

## Prerequisites
- **macOS** with Homebrew installed (for Python 3.12).
- **Internet Connection**: To fetch NIST data and STIG files.
- **Git**: To clone and manage the repository.

## Installation

## Prerequisites
- Python 3.12 installed and in your PATH (verify with `python3.12 --version` or `python --version` on Windows).
  - Download from https://www.python.org/downloads/.
- On macOS/Linux: Ensure `python3.12` is available (install via your package manager if needed).
- On Windows: Install the executable and add to PATH.

## Setup and Run
1. Run `python3 setup.py` (or `python setup.py` on Windows) from the project root.
2. Follow prompts to select a model and complete setup.
This script will:

Create a virtual environment (venv) using Python 3.12.
Install dependencies from requirements.txt (including spacy==3.7.2 and the en_core_web_sm model).
Download the CCI XML mapping file (U_CCI_List.xml).
Prompt you to select a Sentence Transformer model (e.g., all-mpnet-base-v2).
Launch the interactive demo (src/main.py).

## Data sources

| Source | Format | What it provides |
|---|---|---|
| [NIST SP 800-53 Rev 5 catalog](https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5/json) | OSCAL JSON | Controls, enhancements, parameters, guidance, **and the SP 800-53A Rev 5 assessment objectives and methods** |
| NIST Low / Moderate / High baselines | OSCAL profile JSON | Baseline membership |
| DISA CCI List (`U_CCI_List.xml`) | XML | CCI → SP 800-53 Rev 5 control mapping |
| [MITRE Heimdall CCI table](https://github.com/mitre/heimdall2/blob/master/libs/hdf-converters/src/mappings/CciNistMappingData.ts) (fallback) | TypeScript | CCI → control mapping when no usable DISA list is present |
| DISA STIGs | XCCDF XML in `stigs/` | Rules, check text and fix text, linked to controls through CCIs |

The NIST files download automatically into `knowledge/`.

**CCI mappings.** The official source is DISA's CCI list. It is public on the [DISA Cyber Exchange](https://public.cyber.mil/stigs/cci/) (no CAC needed), but the download is often blocked by proxies. Place `U_CCI_List.xml` in `knowledge/` if the automatic download fails. Use a list from 2022 or later: older copies, including those in many GitHub repos, only reference Rev 4.

If no DISA list is present, or it has no Rev 5 references, the app uses MITRE Heimdall's CCI table instead. That table mixes Rev 4 and Rev 5 targets, so it is reconciled against the Rev 5 catalog at load time:
- mappings to controls Rev 5 withdrew are redirected to the single control they were incorporated into (a CCI lookup notes the redirect);
- mappings to withdrawn controls with several or no replacements, and to controls that don't exist in Rev 5 (the Rev 4 privacy families AR, DI, TR, etc.), are dropped.

Startup prints which source was used and how many mappings were redirected or dropped.

URLs live in `config/config.ini` (copied from `config/config.ini.template`).

All sources are normalized to one control ID form: `AC-2`, `AC-2(1)`. Statement-part references such as `AC-2 a` (used by CCIs) roll up to their control.

## Validating the data

```
python scripts/validate_data.py                  # uses knowledge/ and stigs/
python scripts/validate_data.py --cci /path/to/U_CCI_List.xml
```

It parses every source the way the app does and checks that the catalog, baselines, 800-53A procedures, CCI mappings and STIG joins are complete and consistent. Expected on catalog 5.2.0: 1,196 controls (182 withdrawn), baselines 149 / 287 / 370, 800-53A procedures for all 1,014 active controls.

## Usage

After setup, the CLI starts automatically. Example queries:

- General info: `What is AC-7?`
- Implementation: `How should IA-5 be implemented for Windows?`
- Assessment: `How do I assess AU-3 on RHEL?`
- CCI lookup: `What is CCI-000130?` / `list cci mappings for CM-6`
- STIG rule lookup: `What is V-257987?`
- List STIGs: `list stigs`
- Exit: `exit`

Example output for `How do I assess AU-3 on RHEL?`:

```
### Assessing AU-3
Based on NIST 800-53 Rev 5 and STIGs for: Red Hat Enterprise Linux 9

1. AU-3 - Content of Audit Records
   - Purpose: Ensure that audit records contain information that establishes the following:
   - Baselines: LOW, MODERATE, HIGH
   Assessment Steps:
     1. AU-03a. Determine if audit records contain information that establishes what type of event occurred;
     ...
     7. Examine: Audit and accountability policy; system security plan; privacy plan; ...
     8. Interview: Organizational personnel with audit and accountability responsibilities; ...
     9. Test: Mechanisms implementing system auditing of auditable events
   STIG Guidance for Red Hat Enterprise Linux 9:
   (rules mapped to AU-3 through their CCIs, with the STIG check text)
```

## Testing

The project includes automated tests to verify functionality. All tests should be run within the virtual environment to ensure proper dependency isolation.

### Running Tests

1. **Ensure virtual environment is set up:**
   ```bash
   python setup.py
   ```

2. **Run all tests:**
   ```bash
   python test_runner.py
   ```

   This will automatically use the project's virtual environment and run:
   - Embedding system tests
   - Control ID detection tests
   - CCI ID detection tests
   - STIG ID detection tests
   - RAG response tests

3. **Run the parser tests** (fast, no model downloads; the real-data tests run when `knowledge/` is populated):

```
pytest test/test_parsers.py
```

4. **Run individual tests:**
   ```bash
   # Activate venv first
   source venv/bin/activate  # On macOS/Linux
   # or
   venv\Scripts\activate     # On Windows

   # Then run tests
   python test/test_control_id.py
   python test/test_cci_id.py
   python test_embedding.py
   ```

### Test Coverage

- **Embedding System**: Verifies model loading, text encoding, and vector store integration
- **Entity Recognition**: Tests detection of control IDs, CCI IDs, and STIG IDs in text
- **RAG Responses**: Validates the retrieval-augmented generation pipeline

# Dependencies
Listed in requirements.txt:
```
requests
sentence-transformers
faiss-cpu
numpy
pdfplumber
tqdm
pandas
openpyxl
colorama
spacy==3.7.2
```
# Project Structure

```
nist-compliance-rag-explorer/
├── setup.py                  # Creates the venv, installs deps, launches the CLI
├── src/
│   ├── main.py               # CLI: downloads data, loads and joins it, answers queries
│   ├── parsers.py            # OSCAL catalog/profiles, 800-53A, CCI list, STIG XCCDF
│   ├── response_generator.py # Formats answers
│   └── api/                  # Evidence evaluation API (proof of concept)
├── scripts/validate_data.py  # Checks the parsed data against the real sources
├── config/config.ini.template
├── stigs/                    # STIG XCCDF files
├── knowledge/                # Downloaded data and FAISS index (generated)
└── test/                     # Tests and fixtures
```

# Troubleshooting
Python Version Error: If /opt/homebrew/bin/python3.12 isn’t found, install it with brew install python@3.12.
STIGs Not Found: Ensure stigs/ contains valid XCCDF XML files and matches stig_folder in config.ini.
Network Issues: Verify internet connectivity for fetching NIST data and CCI XML.
STIG rules show no controls: the CCI list is missing. Place U_CCI_List.xml in knowledge/ and run scripts/validate_data.py.
Stale answers after updating data: the FAISS index is keyed on the document set, so it rebuilds automatically; delete knowledge/faiss_index_*.pkl to force it.

# Contributing
Fork the repository.
Create a feature branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push to your fork (git push origin feature/your-feature).
Open a pull request.
