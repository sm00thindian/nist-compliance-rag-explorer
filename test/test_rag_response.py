import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main import main
from unittest.mock import patch
import io

@patch('builtins.input', side_effect=[
    'What is CCI-000130?',  # Query
    'n',                     # No checklist
    'exit'                   # Exit
])
def test_rag_cci_lookup(mock_input):
    # Capture stdout
    captured = io.StringIO()
    sys.stdout = captured

    try:
        main()
    except SystemExit:
        pass

    output = captured.getvalue()
    assert "CCI-000130 maps to NIST AU-3" in output or "AU-3" in output
    print("test_rag_response.py: PASSED (CCI lookup)")
