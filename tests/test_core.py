import unittest
import os
import sys

# Add root directory to python path

from lobster.core import scan_packet, KNOWN_THREATS

class TestCore(unittest.TestCase):
    def test_text_only_packet(self):
        packet = {"text": "Hello world"}
        result = scan_packet(packet)
        self.assertEqual(result["status"], "ALLOW")
        self.assertEqual(result["source"], "TEXT")

    def test_iron_dome_blocked(self):
        # Iron dome blocks `rm -rf /`
        packet = {"code_snippet": "os.system('rm -rf /')"}
        result = scan_packet(packet)
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(result["source"], "IRON_DOME")

    def test_vault_corruption_resilience(self):
        """Phase 5: If the Threat Vault has a malformed entry, it should Fail-Closed."""
        from lobster.core import KNOWN_THREATS
        # Inject corrupted entry
        KNOWN_THREATS["bad_vault_payload"] = "not a dictionary"
        
        result = scan_packet({"code_snippet": "bad_vault_payload"})
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("corruption detected", result["analysis"])
        self.assertEqual(result["source"], "VAULT")

    def test_cache_corruption_resilience(self):
        """Phase 5: If the Runtime Cache is corrupted, it should clear it and fall back to API (which may ERROR if offline)."""
        from lobster.core import RUNTIME_CACHE
        # Inject corrupted entry
        RUNTIME_CACHE["bad_cache_payload"] = ["list", "instead", "of", "dict"]
        
        # When scan_packet hits it, it should delete it from cache and proceed to API fallback.
        # Since we are testing against the real API, we just check that it reached the API layer.
        result = scan_packet({"code_snippet": "bad_cache_payload"})
        from lobster.core import client
        if not client:
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["source"], "OFFLINE")
            self.assertIn("bad_cache_payload", RUNTIME_CACHE)
            self.assertEqual(RUNTIME_CACHE["bad_cache_payload"]["source"], "OFFLINE")
            self.assertEqual(RUNTIME_CACHE["bad_cache_payload"]["status"], result["status"])
        else:
            self.assertIn(result["status"], ["ALLOW", "BLOCK", "ERROR"], f"Expected ALLOW or BLOCK but got {result['status']}. Full result: {result}")
            self.assertEqual(result["source"], "GEMINI_API", f"Expected GEMINI_API but got {result['source']}. Full result: {result}")
            self.assertIn("bad_cache_payload", RUNTIME_CACHE)
            self.assertEqual(RUNTIME_CACHE["bad_cache_payload"]["source"], "GEMINI_API")
            self.assertEqual(RUNTIME_CACHE["bad_cache_payload"]["status"], result["status"])
        
    def test_green_dome_allowlist(self):
        # Green dome allows simple print
        packet = {"code_snippet": "print('hello')"}
        result = scan_packet(packet)
        self.assertEqual(result["status"], "ALLOW")
        self.assertEqual(result["source"], "GREEN_DOME")
        
    def test_vault_lookup(self):
        # We need to inject a known threat to test the vault
        KNOWN_THREATS["bad_static_code()"] = {"status": "BLOCK", "analysis": "Known bad"}
        
        packet = {"code_snippet": "bad_static_code()"}
        result = scan_packet(packet)
        self.assertEqual(result["status"], "BLOCK")
        self.assertEqual(result["source"], "VAULT")

if __name__ == '__main__':
    unittest.main()
