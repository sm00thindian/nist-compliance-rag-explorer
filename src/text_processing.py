import spacy
import configparser
import os
import sys
import subprocess
import re

# === LOAD CONFIG ===
config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.ini')
config = configparser.ConfigParser()
if not config.read(config_path):
    raise FileNotFoundError(f"Config file not found: {config_path}")

SPACY_MODEL = config.get('DEFAULT', 'spacy_model', fallback='en_core_web_trf')

# === LOAD SPACY MODEL ===
def load_spacy_model():
    """Load spaCy model with auto-download fallback."""
    try:
        nlp = spacy.load(SPACY_MODEL)
        print(f"Loaded spaCy model: {SPACY_MODEL}")
        return nlp
    except OSError:
        print(f"Model '{SPACY_MODEL}' not found. Downloading...")
        try:
            subprocess.run(
                [sys.executable, "-m", "spacy", "download", SPACY_MODEL, "--force"],
                check=True,
                capture_output=True
            )
            nlp = spacy.load(SPACY_MODEL)
            print(f"Successfully downloaded and loaded: {SPACY_MODEL}")
            return nlp
        except Exception as e:
            print(f"Failed to download {SPACY_MODEL}: {e}")
            print("Attempting fallback to en_core_web_trf...")
            subprocess.run(
                [sys.executable, "-m", "spacy", "download", "en_core_web_trf", "--force"],
                check=True
            )
            nlp = spacy.load("en_core_web_trf")
            print("Fallback successful: en_core_web_trf")
            return nlp

nlp = load_spacy_model()


# === ENTITYRULER: CONTROL_ID, CCI_ID, STIG_RULE_ID ===
def add_entity_ruler(nlp):
    """
    Add EntityRuler for NIST control IDs, CCI IDs, and STIG rule IDs.
    """
    # Remove if already exists
    if "entity_ruler" in nlp.pipe_names:
        nlp.remove_pipe("entity_ruler")
    
    ruler = nlp.add_pipe("entity_ruler", before="ner")

    patterns = [
        # === CONTROL_ID ===
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+"}}]},  # AC-7
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\(\d+\)"}}]},  # AC-7(2)
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2\-\d+\s*\(\d+\)"}}]},  # AC-7 (2)
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\s*[a-z]?"}}]},  # AC-7 a
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+(\(\d+\))?(\([a-z]\))?"}}]},  # AC-7(1)(a)

        # === CCI_ID ===
        {"label": "CCI_ID", "pattern": [{"TEXT": {"REGEX": r"CCI-\d{6}"}}]},  # CCI-000130
        {"label": "CCI_ID", "pattern": [{"TEXT": {"REGEX": r"CCI\s*-\s*\d{6}"}}]},  # CCI - 001234
        {"label": "CCI_ID", "pattern": [{"TEXT": {"REGEX": r"CCI\d{6}"}}]},  # CCI000130

        # === STIG_RULE_ID ===
        {"label": "STIG_RULE_ID", "pattern": [{"TEXT": {"REGEX": r"SV-\d{5,6}r\d+_rule"}}]},  # SV-230456r1_rule
        {"label": "STIG_RULE_ID", "pattern": [{"TEXT": {"REGEX": r"SV\s*-\s*\d{5,6}\s*r\d+\s*rule"}}]},  # SV - 12345 r2 rule
        {"label": "STIG_RULE_ID", "pattern": [{"TEXT": {"REGEX": r"SV-\d{5,6}r\d+"}}]},  # SV-12345r1
    ]

    ruler.add_patterns(patterns)
    print("EntityRuler: CONTROL_ID, CCI_ID, STIG_RULE_ID patterns loaded")
    return nlp

# Apply EntityRuler
nlp = add_entity_ruler(nlp)


def extract_actionable_steps(description):
    """
    Extract actionable steps from control description.
    Detects and logs CONTROL_ID, CCI_ID, STIG_RULE_ID.
    """
    doc = nlp(description.lower())
    steps = []
    action_verbs = {'verify', 'ensure', 'check', 'review', 'confirm', 'examine'}

    # === DETECTED ENTITIES ===
    control_ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "CONTROL_ID"]
    cci_ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "CCI_ID"]
    stig_ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "STIG_RULE_ID"]

    if control_ids or cci_ids or stig_ids:
        print(
            f"Detected → "
            f"Controls: {', '.join(control_ids) if control_ids else '—'} | "
            f"CCIs: {', '.join(cci_ids) if cci_ids else '—'} | "
            f"STIGs: {', '.join(stig_ids) if stig_ids else '—'}"
        )

    # === EXTRACT ACTIONABLE STEPS ===
    for token in doc:
        if token.text in action_verbs and token.pos_ == 'VERB':
            # Look for direct object or noun
            for child in token.children:
                if child.dep_ in ('dobj', 'attr', 'prep') or child.pos_ in ('NOUN', 'PROPN'):
                    steps.append(f"{token.text} {child.text}")
                    break
            else:
                # Fallback: next noun after verb
                for next_token in doc[token.i + 1:]:
                    if next_token.pos_ in ('NOUN', 'PROPN'):
                        steps.append(f"{token.text} {next_token.text}")
                        break
                    elif next_token.text == '.':
                        break

    # Fallback if no steps found
    if not steps:
        first_sentence = doc.text.split('.')[0].strip()
        steps = [f"verify {first_sentence}"]

    return steps
