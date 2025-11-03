import os
import sys
import re
import logging
from colorama import Fore, Style, init
from sentence_transformers import SentenceTransformer
import spacy
from tqdm import tqdm

# Local imports
from .retriever import build_vector_store, retrieve_relevant_docs
from .parsers import (
    extract_controls_from_json,
    extract_high_baseline_controls,
    extract_assessment_procedures,
    load_cci_mapping,
    load_stig_data
)
from .response_generator import generate_response
from .text_processing import nlp  # spaCy model

init(autoreset=True)

# === CONFIG ===
KNOWLEDGE_DIR = "knowledge"
NIST_CATALOG = os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_catalog_json.json")
HIGH_BASELINE = os.path.join(KNOWLEDGE_DIR, "nist_800_53-rev5_high-baseline_json.json")
ASSESSMENT_PROC = os.path.join(KNOWLEDGE_DIR, "nist_800_53A-rev5_assessment-procedures_json.json")
CCI_XML = os.path.join(KNOWLEDGE_DIR, "U_CCI_List.xml")
STIG_FOLDER = os.path.join(KNOWLEDGE_DIR, "stigs")

# === MAIN ===
def main():
    print(f"{Fore.CYAN}Welcome to the Compliance RAG Demo{Style.RESET_ALL}")
    print("Enter your compliance question (e.g., 'How do I assess AU-3?', 'exit'):")

    # Load embedding model
    print("Loading embedding model...")
    embedder = SentenceTransformer("all-MiniLM-L12-v2")
    print(f"Model loaded: {embedder}")

    # Load spaCy (already done in text_processing.py)
    print(f"Loaded spaCy model: {nlp.meta['name']}")

    # Load NIST data
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

    # Build vector store
    print("Building vector store...")
    all_docs = []
    for ctrl in control_details.values():
        all_docs.append(f"Catalog, {ctrl['control_id']}: {ctrl['title']}")
        all_docs.append(f"Description, {ctrl['control_id']}: {ctrl['description'][:500]}")
    index = build_vector_store(all_docs, embedder)

    # Load CCI mapping
    print("Loading CCI-to-NIST mapping...")
    cci_to_nist = load_cci_mapping(CCI_XML)

    # Load STIG data
    print("Loading STIG data...")
    all_stig_recommendations, available_stigs = load_stig_data(STIG_FOLDER, cci_to_nist)

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
        retrieved_docs = retrieve_relevant_docs(query, index, embedder)

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
            retrieved_docs = retrieve_relevant_docs(query, index, embedder)
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
