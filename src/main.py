import os
import sys
import re
import json
import logging
import requests
from colorama import Fore, Style, init
from tqdm import tqdm
import zipfile
import tempfile

# Local imports
from retriever import build_vector_store, retrieve_relevant_docs
from parsers import (
    extract_controls_from_json,
    extract_baseline_control_ids,
    extract_assessment_procedures,
    apply_baselines,
    load_cci_mapping,
    load_cci_mapping_from_heimdall,
    load_cci_parts,
    load_cci_parts_from_heimdall,
    extract_assessment_details,
    reconcile_cci_mapping,
    load_stig_data
)
from response_generator import generate_response
from config_loader import get_config
from embedding_manager import EmbeddingManager

init(autoreset=True)

# === CONFIG ===
KNOWLEDGE_DIR = "knowledge"
NIST_CATALOG = os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_catalog_json.json")
BASELINES = {
    "LOW": os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_low-baseline_json.json"),
    "MODERATE": os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_moderate-baseline_json.json"),
    "HIGH": os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_high-baseline_json.json"),
}
# SP 800-53A Rev 5 assessment objectives and methods ship inside the OSCAL
# catalog, so there is no separate assessment-procedures file.
CCI_XML = os.path.join(KNOWLEDGE_DIR, "U_CCI_List.xml")
CCI_XML_FALLBACKS = ["U_CCI_List.xml"]
# Used only when no DISA CCI list is available (see config cci_fallback_url).
CCI_HEIMDALL = os.path.join(KNOWLEDGE_DIR, "CciNistMappingData.ts")
STIG_FOLDER = "stigs"


def download_file(url: str, dest_path: str, description: str) -> None:
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    print(f"Downloading {description} from {url}")

    with requests.get(url, stream=True, timeout=60) as response:
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0) or 0)
        chunk_size = 8192
        downloaded = 0

        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            try:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if not chunk:
                        continue
                    tmp_file.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        percent = downloaded * 100 // total
                        print(f"\r  {description}: {percent}% ({downloaded}/{total} bytes)", end="", flush=True)
                if total:
                    print()
            finally:
                tmp_file.flush()
                tmp_name = tmp_file.name

        if url.lower().endswith('.zip') or 'zip' in response.headers.get('content-type', '').lower():
            with zipfile.ZipFile(tmp_name) as zh:
                members = [m for m in zh.namelist() if m.lower().endswith('.xml')]
                if not members:
                    raise ValueError('Zip archive does not contain an XML file')
                preferred = [m for m in members if 'cci_list' in os.path.basename(m).lower()]
                member = (preferred or members)[0]
                zh.extract(member, path=os.path.dirname(dest_path) or '.')
                extracted_path = os.path.join(os.path.dirname(dest_path) or '.', member)
                os.replace(extracted_path, dest_path)
            os.remove(tmp_name)
        else:
            os.replace(tmp_name, dest_path)

    print(f"Saved {description} to {dest_path}")


def verify_artifacts(data_urls: dict, stig_folder: str) -> None:
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)

    required_files = [
        (NIST_CATALOG, data_urls.get('catalog_url'), 'NIST SP 800-53 Rev 5 catalog (includes 800-53A)'),
        (BASELINES["LOW"], data_urls.get('low_baseline_url'), 'NIST Low baseline'),
        (BASELINES["MODERATE"], data_urls.get('moderate_baseline_url'), 'NIST Moderate baseline'),
        (BASELINES["HIGH"], data_urls.get('high_baseline_url'), 'NIST High baseline'),
    ]
    if not resolve_cci_path():
        required_files.append((CCI_XML, data_urls.get('cci_url'), 'DISA CCI list'))

    for path, url, description in required_files + [None]:
        if path is None:
            # After trying the DISA list: fetch the fallback only if still needed.
            # Fetched even when a DISA list exists, since an outdated list has no Rev 5 mappings.
            if os.path.exists(CCI_HEIMDALL) or not data_urls.get('cci_fallback_url'):
                break
            path, url, description = CCI_HEIMDALL, data_urls['cci_fallback_url'], 'CCI fallback mapping (MITRE Heimdall)'
        if os.path.exists(path):
            print(f"{description} exists: {path}")
            continue
        if not url:
            print(f"No URL configured for {description}; skipping download.")
            continue
        try:
            download_file(url, path, description)
        except Exception as exc:
            print(f"Failed to download {description}: {exc}")

    if not os.path.isdir(stig_folder):
        print(f"Warning: STIG folder not found: {stig_folder}")
        print("Place STIG XCCDF XML files in the configured STIG folder to enable STIG recommendations.")
    else:
        stig_files = [f for f in os.listdir(stig_folder) if f.endswith('.xml')]
        print(f"Found {len(stig_files)} STIG XML file(s) in {stig_folder}")

def resolve_cci_path():
    """Return the first CCI list found locally, or None."""
    for path in [CCI_XML] + CCI_XML_FALLBACKS:
        if os.path.exists(path):
            return path
    return None


def load_knowledge(stig_folder: str) -> dict:
    """Load and join every data source. Fails loudly if the catalog is empty."""
    with open(NIST_CATALOG, 'r', encoding='utf-8') as f:
        catalog_json = json.load(f)
    control_details = {c['control_id']: c for c in extract_controls_from_json(catalog_json)}
    if not control_details:
        raise RuntimeError(f"No controls parsed from {NIST_CATALOG}; is it an OSCAL SP 800-53 catalog?")

    baselines = {}
    for level, path in BASELINES.items():
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                baselines[level] = extract_baseline_control_ids(json.load(f))
        else:
            print(f"{Fore.YELLOW}Warning: {level} baseline not found at {path}{Style.RESET_ALL}")
    apply_baselines(control_details, baselines)

    assessment_procedures = extract_assessment_procedures(catalog_json)
    assessment_details = extract_assessment_details(catalog_json)

    cci_path = resolve_cci_path()
    cci_source, raw_cci, raw_parts = "none", {}, {}
    if cci_path:
        raw_cci = load_cci_mapping(cci_path)
        raw_parts = load_cci_parts(cci_path)
        cci_source = f"DISA CCI list ({cci_path})"
        if not raw_cci:
            print(f"{Fore.YELLOW}Warning: {cci_path} has no NIST SP 800-53 Rev 5 references "
                  f"(it predates DISA's Rev 5 mappings).{Style.RESET_ALL}")
    if not raw_cci and os.path.exists(CCI_HEIMDALL):
        raw_cci = load_cci_mapping_from_heimdall(CCI_HEIMDALL)
        raw_parts = load_cci_parts_from_heimdall(CCI_HEIMDALL)
        cci_source = f"MITRE Heimdall fallback ({CCI_HEIMDALL})"
    cci_to_nist, cci_report = reconcile_cci_mapping(raw_cci, control_details, raw_parts)
    all_stig_recommendations, available_stigs = load_stig_data(stig_folder, cci_to_nist)

    summary = {
        'controls': len(control_details),
        'withdrawn': sum(1 for c in control_details.values() if c['withdrawn']),
        'baselines': {k: len(v) for k, v in baselines.items()},
        'assessed_controls': len(assessment_procedures),
        'cci_mappings': len(cci_to_nist),
        'cci_source': cci_source,
        'cci_redirected': len(cci_report['redirected']),
        'cci_dropped': len(cci_report['dropped_not_in_rev5']) + len(cci_report['dropped_ambiguous']),
        'stigs': [
            f"{s['technology']}: {s['rule_count'] - s['unmapped_rules']}/{s['rule_count']} rules mapped"
            for s in available_stigs
        ],
    }
    return {
        'control_details': control_details,
        'high_baseline_controls': sorted(baselines.get('HIGH', set())),
        'assessment_procedures': assessment_procedures,
        'cci_to_nist': cci_to_nist,
        'cci_report': cci_report,
        'cci_parts': cci_report['parts'],
        'assessment_details': assessment_details,
        'all_stig_recommendations': all_stig_recommendations,
        'available_stigs': available_stigs,
        'summary': summary,
    }


# === MAIN ===
def main():
    # Load configuration
    config = get_config()
    embedding_config = config.get_embedding_config()
    app_config = config.get_app_config()
    data_urls = config.get_data_urls()

    selected_model = os.getenv('SELECTED_EMBEDDING_MODEL')
    if selected_model:
        embedding_config['model_name'] = selected_model

    if not logging.root.handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s"
        )

    print(f"{Fore.CYAN}Welcome to the Compliance RAG Demo{Style.RESET_ALL}")
    print(f"Using embedding model: {embedding_config['model_name']}")
    print(f"Similarity metric: {embedding_config['similarity_metric']}")
    print("Enter your compliance question (e.g., 'How do I assess AU-3?', 'exit'):")

    # Initialize embedding manager
    print("Loading embedding model...")
    embedding_manager = EmbeddingManager(embedding_config)
    model_info = embedding_manager.get_model_info()
    print(f"Model loaded: {model_info['model_name']} ({model_info['dimensions']}D, {model_info['device']})")

    stig_folder = app_config.get('stig_folder', STIG_FOLDER)
    verify_artifacts(data_urls, stig_folder)

    # Load and join NIST, CCI and STIG data
    try:
        print("Loading NIST SP 800-53 Rev 5 catalog, 800-53A procedures, baselines, CCI list and STIGs...")
        kb = load_knowledge(stig_folder)
    except FileNotFoundError as e:
        print(f"{Fore.RED}Error: required data file not found: {e.filename}")
        print(f"Check network access or place the file in the '{KNOWLEDGE_DIR}' directory.{Style.RESET_ALL}")
        sys.exit(1)
    control_details = kb['control_details']
    high_baseline_controls = kb['high_baseline_controls']
    assessment_procedures = kb['assessment_procedures']
    cci_to_nist = kb['cci_to_nist']
    all_stig_recommendations = kb['all_stig_recommendations']
    available_stigs = kb['available_stigs']

    summary = kb['summary']
    print(f"Loaded {summary['controls']} controls ({summary['withdrawn']} withdrawn), "
          f"baselines {summary['baselines']}, 800-53A procedures for {summary['assessed_controls']} controls, "
          f"{summary['cci_mappings']} CCI mappings")
    print(f"  CCI source: {summary['cci_source']}; {summary['cci_redirected']} redirected from withdrawn controls, "
          f"{summary['cci_dropped']} dropped (not in Rev 5 or ambiguous)")
    for line in summary['stigs']:
        print(f"  STIG {line}")
    if not cci_to_nist:
        print(f"{Fore.YELLOW}Warning: no CCI list loaded, so STIG rules cannot be linked to controls. "
              f"Place U_CCI_List.xml in '{KNOWLEDGE_DIR}'.{Style.RESET_ALL}")

    # Build vector store
    print("Building vector store...")
    all_docs = []
    for ctrl in control_details.values():
        all_docs.append(f"Catalog, {ctrl['control_id']}: {ctrl['title']}")
        if ctrl['description']:
            all_docs.append(f"Description, {ctrl['control_id']}: {ctrl['description'][:500]}")
        if ctrl.get('guidance'):
            all_docs.append(f"Guidance, {ctrl['control_id']}: {ctrl['guidance'][:500]}")
    index = build_vector_store(all_docs, embedding_manager)

    # Unknown query log
    unknown_queries = []

    # === MAIN LOOP ===
    while True:
        query = input(f"\n{Fore.GREEN}Enter your compliance question (e.g., 'How do I assess AU-3?', 'exit'): {Style.RESET_ALL}").strip()
        if query.lower() in ['exit', 'quit', 'q']:
            print("Goodbye!")
            break
        if not query:
            continue

        # Special command
        if query.lower() == "show unknown":
            if unknown_queries:
                print(f"{Fore.YELLOW}Unknown queries recorded:{Style.RESET_ALL}")
                for q in unknown_queries:
                    print(f"  • {q}")
            else:
                print(f"{Fore.CYAN}No unknown queries recorded.{Style.RESET_ALL}")
            continue

        generate_checklist = False
        if query.lower().endswith("?"):
            checklist_input = input(f"{Fore.YELLOW}Generate an assessment checklist? (y/n): {Style.RESET_ALL}").strip().lower()
            generate_checklist = checklist_input == 'y'

        print(f"\n{Fore.CYAN}Processing...{Style.RESET_ALL}")
        retrieved_docs = retrieve_relevant_docs(query, index, embedding_manager)

        # === INITIAL RESPONSE ===
        response = generate_response(
            query, retrieved_docs, control_details, high_baseline_controls,
            all_stig_recommendations, available_stigs, assessment_procedures,
            cci_to_nist, generate_checklist=generate_checklist,
            cci_redirects=kb['cci_report']['redirected'],
            assessment_details=kb['assessment_details'], cci_parts=kb['cci_parts']
        )

        # === CLARIFICATION HANDLING ===
        if "CLARIFICATION_NEEDED" in response:
            clarification_text = response.replace("\nCLARIFICATION_NEEDED", "")
            print(clarification_text)
            lines = clarification_text.split('\n')
            num_options = sum(1 for line in lines if re.match(r"^\d+\.\s", line.strip()))
            while True:
                tech_choice = input(f"{Fore.YELLOW}Enter a number (1-{num_options}, or 0 for all): {Style.RESET_ALL}").strip()
                if tech_choice.isdigit() and 0 <= int(tech_choice) <= num_options:
                    break
                print(f"Please enter a number between 0 and {num_options}.")
            original_query = re.sub(r" with technology index \d+$", "", query).strip()
            query = f"{original_query} with technology index {tech_choice}"
            # Reset retrieved_docs for new query
            retrieved_docs = retrieve_relevant_docs(query, index, embedding_manager)
            response = generate_response(
                query, retrieved_docs, control_details, high_baseline_controls,
                all_stig_recommendations, available_stigs, assessment_procedures,
                cci_to_nist, generate_checklist=generate_checklist,
                cci_redirects=kb['cci_report']['redirected'],
                assessment_details=kb['assessment_details'], cci_parts=kb['cci_parts']
            )

        # === FINAL OUTPUT ===
        print(response)

        # Record unknown controls
        if "Not found in NIST 800-53 Rev 5 catalog" in response:
            unknown_queries.append(query)

    # Save unknown queries
    if unknown_queries:
        with open("unknown_queries.txt", "w") as f:
            for q in unknown_queries:
                f.write(q + "\n")
        print(f"{Fore.YELLOW}Saved {len(unknown_queries)} unknown queries to unknown_queries.txt{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
