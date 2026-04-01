import os
import sys
import re
import json
import logging
import requests
from colorama import Fore, Style, init
import spacy
from tqdm import tqdm
import zipfile
import tempfile

# Local imports
from retriever import build_vector_store, retrieve_relevant_docs
from parsers import (
    extract_controls_from_json,
    extract_high_baseline_controls,
    extract_assessment_procedures,
    load_cci_mapping,
    load_stig_data
)
from response_generator import generate_response
from text_processing import nlp  # spaCy model
from config_loader import get_config
from embedding_manager import EmbeddingManager

init(autoreset=True)

# === CONFIG ===
KNOWLEDGE_DIR = "knowledge"
NIST_CATALOG = os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_catalog_json.json")
HIGH_BASELINE = os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_high-baseline_json.json")
ASSESSMENT_PROC = os.path.join(KNOWLEDGE_DIR, "nist_800_53A-rev5_assessment-procedures_json.json")
CCI_XML = os.path.join(KNOWLEDGE_DIR, "U_CCI_List.xml")
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
                member = members[0]
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
        (NIST_CATALOG, data_urls.get('catalog_url', "https://raw.githubusercontent.com/usnistgov/SP800-53-rev5/master/json/NIST_SP-800-53_rev5_CATALOG.json"), 'NIST catalog'),
        (HIGH_BASELINE, data_urls.get('high_baseline_url', "https://raw.githubusercontent.com/usnistgov/SP800-53-rev5/master/json/NIST_SP-800-53_rev5_HIGH-baseline.json"), 'NIST high baseline'),
        (ASSESSMENT_PROC, data_urls.get('assessment_url', "https://raw.githubusercontent.com/usnistgov/SP800-53-rev5/master/json/NIST_SP-800-53A_rev5_assessment-procedures.json"), 'NIST assessment procedures'),
        (CCI_XML, data_urls.get('cci_url', "https://public.cyber.mil/stigs/downloads/cci/U_CCI_List.xml"), 'CCI mapping XML'),
    ]

    for path, url, description in required_files:
        if os.path.exists(path):
            print(f"{description} exists: {path}")
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

    # Load spaCy (already done in text_processing.py)
    print(f"Loaded spaCy model: {nlp.meta['name']}")

    stig_folder = app_config.get('stig_folder', STIG_FOLDER)
    verify_artifacts(data_urls, stig_folder)

    # Load NIST data
    try:
        print("Fetching NIST SP 800-53 Rev 5 catalog data...")
        with open(NIST_CATALOG, 'r', encoding='utf-8') as f:
            catalog_json = json.load(f)
        control_details = {c['control_id']: c for c in extract_controls_from_json(catalog_json)}

        print("Fetching NIST SP 800-53 Rev 5 High baseline JSON data...")
        with open(HIGH_BASELINE, 'r', encoding='utf-8') as f:
            high_baseline_json = json.load(f)
        high_baseline_controls = extract_high_baseline_controls(high_baseline_json)

        print("Fetching NIST SP 800-53A assessment procedures JSON data...")
        with open(ASSESSMENT_PROC, 'r', encoding='utf-8') as f:
            assessment_json = json.load(f)
        assessment_procedures = extract_assessment_procedures(assessment_json)
    except FileNotFoundError as e:
        print(f"{Fore.RED}Error: Required data files not found. Please ensure the following files are present in the 'knowledge' directory:")
        print(f"  - {NIST_CATALOG}")
        print(f"  - {HIGH_BASELINE}")
        print(f"  - {ASSESSMENT_PROC}")
        print(f"  - {CCI_XML}")
        print("Download them from the appropriate NIST sources and place them in the 'knowledge' directory.{Style.RESET_ALL}")
        sys.exit(1)

    # Build vector store
    print("Building vector store...")
    all_docs = []
    for ctrl in control_details.values():
        all_docs.append(f"Catalog, {ctrl['control_id']}: {ctrl['title']}")
        all_docs.append(f"Description, {ctrl['control_id']}: {ctrl['description'][:500]}")
    index = build_vector_store(all_docs, embedding_manager)

    # Load CCI mapping
    print("Loading CCI-to-NIST mapping...")
    cci_to_nist = load_cci_mapping(CCI_XML)

    # Load STIG data
    print("Loading STIG data...")
    all_stig_recommendations, available_stigs = load_stig_data(stig_folder, cci_to_nist)

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
            cci_to_nist, generate_checklist=generate_checklist
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
                cci_to_nist, generate_checklist=generate_checklist
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
