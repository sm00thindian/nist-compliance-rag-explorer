from src.text_processing import nlp

def test_control_id_detection():
    text = "Ensure AC-7(2) and CM-6 are enforced. Also check AC-7 a and AC-7(1)(a)."
    doc = nlp(text)
    ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "CONTROL_ID"]
    expected = ["AC-7(2)", "CM-6", "AC-7 A", "AC-7(1)(A)"]
    assert set(ids) == set(expected), f"Expected {expected}, got {ids}"
    print("test_control_id.py: PASSED")
