import unittest
import os
import sys
import json
from unittest.mock import patch, mock_open

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.core import load_threats, scan_packet, KNOWN_THREATS
except ImportError:
    sys.modules['dotenv'] = type('dummy', (), {'load_dotenv': lambda: None})
    import types
    google_mod = types.ModuleType('google')
    genai_mod = types.ModuleType('genai')
    genai_mod.Client = lambda **kwargs: None
    google_mod.genai = genai_mod
    sys.modules['google'] = google_mod
    sys.modules['google.genai'] = genai_mod
    from src.core import load_threats, scan_packet, KNOWN_THREATS

class TestThreatVault(unittest.TestCase):

    def setUp(self):
        import src.core
        src.core.KNOWN_THREATS.clear()

    def test_load_threats_success(self):
        # Mock a valid threat database dictionary
        valid_json = json.dumps({
            "bad_code_1": {"status": "BLOCKED", "analysis": "Signature match 1"},
            "bad_code_2": {"status": "BLOCKED", "analysis": "Signature match 2"}
        })
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=valid_json)):
                load_threats()
                import src.core
                self.assertIn("bad_code_1", src.core.KNOWN_THREATS)
                self.assertEqual(src.core.KNOWN_THREATS["bad_code_1"]["status"], "BLOCKED")

    def test_load_threats_missing_file(self):
        # Simulate a missing file (os.path.exists returns False)
        with patch("os.path.exists", return_value=False):
            load_threats()
            import src.core
            self.assertEqual(len(src.core.KNOWN_THREATS), 0)

    def test_load_threats_corrupted_json(self):
        # Simulate a corrupted JSON file
        # v0.4.0 does not catch this, so we document the crash
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="{invalid_json: oops")):
                with self.assertRaises(json.JSONDecodeError):
                    load_threats()

    def test_whitespace_normalization_in_lookup(self):
        import src.core
        # Add a known threat to the module-level KNOWN_THREATS dictionary
        src.core.KNOWN_THREATS["exact_match_payload()"] = {
            "status": "BLOCKED", 
            "analysis": "STATIC VAULT (Tier 1): Known malicious payload matched exact signature."
        }
        
        # Payload with leading/trailing whitespaces and tabs
        packet = {"code_snippet": "   \n\t exact_match_payload() \n  "}
        
        # It should hit the vault because the engine strips whitespace
        result = scan_packet(packet, use_llm=False)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["source"], "VAULT")


if __name__ == '__main__':
    unittest.main()
