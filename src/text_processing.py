import spacy
import configparser
import os
import sys
import subprocess
import re

# === CONFIG ===
config = configparser.ConfigParser()
config.read('config/config.ini')
SPACY_MODEL = config.get('DEFAULT', 'spacy_model', fallback='en_core_web_trf')

# === LOAD MODEL ===
try:
    nlp = spacy.load(SPACY_MODEL)
    print(f"Loaded spaCy model: {SPACY_MODEL}")
except OSError:
    print(f"Model '{SPACY_MODEL}' not found. Downloading...")
    subprocess.run([sys.executable, "-m", "spacy", "download", SPACY_MODEL, "--force"], check=True)
    nlp = spacy.load(SPACY_MODEL)

# === ENTITYRULER: CONTROL_ID + CCI_ID ===
def add_entity_ruler(nlp):
    """
    Add EntityRuler for:
    - CONTROL_ID: AC-7, AC-7(2), AC-7 a
    - CCI_ID: CCI-000130, CCI - 001234
    """
    if "entity_ruler" in nlp.pipe_names:
        nlp.remove_pipe("entity_ruler")
    ruler = nlp.add_pipe("entity_ruler", before="ner")

    patterns = [
        # === CONTROL_ID ===
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+"}}]},
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\(\d+\)"}}]},
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\s*\(\d+\)"}}]},
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\s*[a-z]?"}}]},
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+(\(\d+\))?(\([a-z]\))?"}}]},

        # === CCI_ID ===
        # CCI-000130
        {"label": "CCI_ID", "pattern": [{"TEXT": {"REGEX": r"CCI-\d{6}"}}]},
        # CCI - 000130
        {"label": "CCI_ID", "pattern": [{"TEXT": {"REGEX": r"CCI\s*-\s*\d{6}"}}]},
        # CCI000130 (rare)
        {"label": "CCI_ID", "pattern": [{"TEXT": {"REGEX": r"CCI\d{6}"}}]},
    ]

    ruler.add_patterns(patterns)
    return nlp

# Apply ruler
nlp = add_entity_ruler(nlp)
print("EntityRuler: CONTROL_ID and CCI_ID patterns loaded")


def extract_actionable_steps(description):
    """
    Extract actionable steps + detect CONTROL_ID and CCI_ID
    """
    doc = nlp(description.lower())
    steps = []
    action_verbs = {'verify', 'ensure', 'check', 'review', 'confirm', 'examine'}

    # === DETECTED ENTITIES ===
    control_ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "CONTROL_ID"]
    cci_ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "CCI_ID"]

    if control_ids or cci_ids:
        print(f"Detected → Controls: {', '.join(control_ids) if control_ids else 'None'} | CCIs: {', '.join(cci_ids) if cci_ids else 'None'}")

    # === EXTRACT STEPS ===
    for token in doc:
        if token.text in action_verbs and token.pos_ == 'VERB':
            for child in token.children:
                if child.dep_ in ('dobj', 'attr', 'prep') or child.pos_ in ('NOUN', 'PROPN'):
                    steps.append(f"{token.text} {child.text}")
                    break
            else:
                for next_token in doc[token.i + 1:]:
                    if next_token.pos_ in ('NOUN', 'PROPN'):
                        steps.append(f"{token.text} {next_token.text}")
                        break
                    elif next_token.text == '.':
                        break

    return steps if steps else [f"verify {doc.text.split('.')[0]}"]
