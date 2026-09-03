import unittest
import os
import sys
from unittest.mock import patch

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.core import scan_packet
except ImportError:
    # Fallback mock for missing dependencies
    sys.modules['dotenv'] = type('dummy', (), {'load_dotenv': lambda: None})
    import types
    google_mod = types.ModuleType('google')
    genai_mod = types.ModuleType('genai')
    genai_mod.Client = lambda **kwargs: None
    google_mod.genai = genai_mod
    sys.modules['google'] = google_mod
    sys.modules['google.genai'] = genai_mod
    from src.core import scan_packet

class TestErrorHandling(unittest.TestCase):

    def test_missing_code_snippet_key(self):
        # Test: packet = {} (missing key)
        packet = {}
        result = scan_packet(packet)
        self.assertEqual(result["status"], "CLEAN")
        self.assertEqual(result["source"], "TEXT")

    def test_empty_code_snippet(self):
        # Test: packet = {"code_snippet": ""}
        packet = {"code_snippet": ""}
        result = scan_packet(packet)
        self.assertEqual(result["status"], "CLEAN")
        self.assertEqual(result["source"], "TEXT")

    def test_none_code_snippet(self):
        # Test: packet = {"code_snippet": None}
        packet = {"code_snippet": None}
        result = scan_packet(packet)
        self.assertEqual(result["status"], "CLEAN")
        self.assertEqual(result["source"], "TEXT")

    def test_none_packet(self):
        # Test: packet = None
        # Should gracefully return safe default rather than raising AttributeError
        result = scan_packet(None)
        self.assertEqual(result["status"], "CLEAN")
        self.assertEqual(result["analysis"], "Invalid packet: Received None.")
        self.assertEqual(result["source"], "ERROR")

    @patch('src.core.client', new=None)
    def test_offline_mode(self):
        # Test with client=None (simulating failed API initialization)
        packet = {"code_snippet": "novel_code_pattern_not_in_vault()"}
        result = scan_packet(packet, use_llm=True)
        self.assertEqual(result["status"], "CLEAN")
        self.assertEqual(result["source"], "OFFLINE")
        self.assertIn("Offline Mode", result["analysis"])

    def test_manual_mode_skipped(self):
        # Test what happens if use_llm=False
        packet = {"code_snippet": "novel_code_pattern_not_in_vault()"}
        result = scan_packet(packet, use_llm=False)
        self.assertEqual(result["status"], "CLEAN")
        self.assertEqual(result["source"], "MANUAL")
        self.assertIn("SKIPPED", result["analysis"])

if __name__ == '__main__':
    unittest.main()
