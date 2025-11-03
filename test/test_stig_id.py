from src.text_processing import nlp

def test_stig_rule_id_detection():
    text = "Apply SV-230456r1_rule and SV-12345r2_rule. Also SV - 67890 r3 rule."
    doc = nlp(text)
    ids = [ent.text.upper() for ent in doc.ents if ent.label_ == "STIG_RULE_ID"]
    expected = ["SV-230456R1_RULE", "SV-12345R2_RULE", "SV - 67890 R3 RULE"]
    assert set(ids) == set(expected), f"Expected {expected}, got {ids}"
    print("test_stig_id.py: PASSED")
