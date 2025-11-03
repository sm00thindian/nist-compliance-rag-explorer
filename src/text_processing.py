import spacy
import configparser
import os
import re

# Load config
config = configparser.ConfigParser()
config.read('config/config.ini')
SPACY_MODEL = config.get('DEFAULT', 'spacy_model', fallback='en_core_web_trf')

# Load model
try:
    nlp = spacy.load(SPACY_MODEL)
    print(f"Loaded spaCy model: {SPACY_MODEL}")
except OSError as e:
    print(f"Model '{SPACY_MODEL}' not found: {e}")
    print("Falling back to en_core_web_trf...")
    import subprocess
    subprocess.run([sys.executable, "-m", "spacy", "download", "en_core_web_trf"])
    nlp = spacy.load('en_core_web_trf')

# === ENTITYRULER FOR CONTROL IDs ===
def add_control_id_ruler(nlp):
    if "entity_ruler" in nlp.pipe_names:
        nlp.remove_pipe("entity_ruler")
    ruler = nlp.add_pipe("entity_ruler", before="ner")

    patterns = [
        # AC-7, CM-6
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+"}}]},
        # AC-7(2)
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\(\d+\)"}}]},
        # AC-7 (2)
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\s*\(\d+\)"}}]},
        # AC-7 a
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+\s*[a-z]?"}}]},
        # AC-7(1)(a)
        {"label": "CONTROL_ID", "pattern": [{"TEXT": {"REGEX": r"[A-Z]{2}-\d+(\(\d+\))?(\([a-z]\))?"}}]},
    ]
    ruler.add_patterns(patterns)
    return nlp

# Apply ruler
nlp = add_control_id_ruler(nlp)
print("EntityRuler: CONTROL_ID patterns loaded")


def extract_actionable_steps(description):
    doc = nlp(description.lower())
    steps = []
    action_verbs = {'verify', 'ensure', 'check', 'review', 'confirm', 'examine'}

    # Debug: Show detected control IDs
    control_ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "CONTROL_ID"]
    if control_ids:
        print(f"Detected: {', '.join(control_ids)}")

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
