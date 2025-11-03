from src.text_processing import nlp

def test_cci_id_detection():
    text = "This maps to CCI-000130 and CCI - 001234. Also CCI000135."
    doc = nlp(text)
    ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "CCI_ID"]
    expected = ["CCI-000130", "CCI - 001234", "CCI000135"]
    assert set(ids) == set(expected), f"Expected {expected}, got {ids}"
    print("test_cci_id.py: PASSED")
