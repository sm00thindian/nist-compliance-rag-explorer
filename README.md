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

##Configuration
The config.ini file specifies data sources. The default configuration is:
```
[DEFAULT]
stig_folder = ~/stigs
nist_800_53_xls_url = https://csrc.nist.gov/files/pubs/sp/800/53/r5/upd1/final/docs/sp800-53r5-control-catalog.xlsx
catalog_url = https://raw.githubusercontent.com/usnistgov/oscal-content/refs/heads/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
high_baseline_url = https://raw.githubusercontent.com/usnistgov/oscal-content/refs/heads/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json
nist_800_53a_json_url = https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_assessment.json
```
##Notes:
Update stig_folder to match your local STIG directory.
Place STIG XCCDF XML files in the stig_folder directory for parsing.
Usage
After setup, the CLI starts automatically. Enter queries like:

General Info: What is AC-7?
Implementation: How should IA-5 be implemented for Windows?
Assessment: How do I assess AU-3?
List STIGs: List STIGs or List STIGs for Red Hat
Exit: exit
Help: help for examples
Example output for How do I assess AU-3? (with 800-53A data):

### Response to 'How do I assess AU-3?'
**Answering:** 'How do I assess AU-3?'
Here’s what I found based on NIST 800-53 and available STIGs:

**Controls Covered:** AU-3

### Control: AU-3
- **Title:** Content of Audit Records
- **Description:** The information system generates audit records containing information that establishes what type of event occurred, when it occurred, where it occurred, the source of the event, the outcome of the event, and the identity of any individuals or subjects associated with the event.

#### How to Assess AU-3
- **NIST SP 800-53A Assessment Steps:**
  - Examine information system audit records to ensure they contain event type, timestamp, location, source, outcome, and identity as configured.
  - Interview personnel to verify audit configuration meets organizational requirements.
- No STIG assessment guidance found.

**More Info:** [NIST 800-53 Assessment Procedures](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/assessment-procedures)
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
├── classic_demo.py       # Setup script
├── nist_compliance_rag.py # Main program
├── requirements.txt      # Dependencies
├── config.ini            # Configuration
├── stigs/                # STIG XML files (user-provided)
├── knowledge/            # Generated data (e.g., FAISS index, logs)
├── README.md             # This file
└── LICENSE               # Apache 2.0 License
```

# Troubleshooting
Python Version Error: If /opt/homebrew/bin/python3.12 isn’t found, install it with brew install python@3.12.
STIGs Not Found: Ensure stigs/ contains valid XCCDF XML files and matches stig_folder in config.ini.
Network Issues: Verify internet connectivity for fetching NIST data and CCI XML.
Missing 800-53A Data: If assessment steps are inferred rather than detailed, ensure nist_800_53a_json_url is accessible.

# Contributing
Fork the repository.
Create a feature branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push to your fork (git push origin feature/your-feature).
Open a pull request.
