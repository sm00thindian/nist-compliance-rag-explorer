import spacy
import configparser
import os

# Load config
config = configparser.ConfigParser()
config.read('config/config.ini')
SPACY_MODEL = config.get('DEFAULT', 'spacy_model', fallback='en_core_web_sm')

# Load spaCy model (with error handling)
try:
    nlp = spacy.load(SPACY_MODEL)
    print(f"Loaded spaCy model: {SPACY_MODEL}")
except OSError:
    print(f"Warning: Model '{SPACY_MODEL}' not found. Falling back to 'en_core_web_sm'.")
    nlp = spacy.load('en_core_web_sm')

def extract_actionable_steps(description):
    """
    Extract actionable steps from a control description using spaCy.
    """
    doc = nlp(description.lower())
    steps = []
    action_verbs = {'verify', 'ensure', 'check', 'review', 'confirm', 'examine'}
    
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
