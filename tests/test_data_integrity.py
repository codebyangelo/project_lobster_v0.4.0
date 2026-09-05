import unittest
import os
import sys


try:
    from lobster.core import scan_packet, KNOWN_THREATS, RUNTIME_CACHE
except ImportError:
    # Handle dependency mocking if needed
    sys.modules['dotenv'] = type('dummy', (), {'load_dotenv': lambda: None})
    import types
    google_mod = types.ModuleType('google')
    genai_mod = types.ModuleType('genai')
    genai_mod.Client = lambda **kwargs: None
    google_mod.genai = genai_mod
    sys.modules['google'] = google_mod
    sys.modules['google.genai'] = genai_mod
    from lobster.core import scan_packet, KNOWN_THREATS, RUNTIME_CACHE

class TestDataIntegrity(unittest.TestCase):

    def setUp(self):
        RUNTIME_CACHE.clear()
        
    def test_vault_deep_copy(self):
        # Setup Vault Threat
        KNOWN_THREATS["test_copy_threat"] = {"status": "BLOCKED", "analysis": "Initial"}
        packet = {"code_snippet": "test_copy_threat"}
        
        # Scan packet, which pulls from the Vault
        result1 = scan_packet(packet, use_llm=False)
        
        # Mutate the result
        result1["analysis"] = "Mutated Analysis!"
        result1["status"] = "CLEAN"
        result1["new_injected_key"] = "HACKED"
        
        # Pull from the Vault again
        result2 = scan_packet(packet, use_llm=False)
        
        # Assert the second pull was NOT affected by the mutation of the first
        self.assertEqual(result2["status"], "BLOCKED")
        self.assertEqual(result2["analysis"], "Initial")
        self.assertNotIn("new_injected_key", result2)
        
        # Clean up
        del KNOWN_THREATS["test_copy_threat"]

    def test_cache_deep_copy(self):
        # Inject directly into Cache
        RUNTIME_CACHE["test_cache_payload"] = {"status": "CLEAN", "analysis": "Initial"}
        packet = {"code_snippet": "test_cache_payload"}
        
        # Scan packet, which pulls from the Cache
        result1 = scan_packet(packet, use_llm=True)
        
        # Mutate the result
        result1["analysis"] = "Mutated Analysis!"
        result1["status"] = "BLOCKED"
        result1["new_injected_key"] = "HACKED"
        
        # Pull from the Cache again
        result2 = scan_packet(packet, use_llm=True)
        
        # Assert the second pull was NOT affected by the mutation of the first
        self.assertEqual(result2["status"], "CLEAN")
        self.assertEqual(result2["analysis"], "Initial")
        self.assertNotIn("new_injected_key", result2)
        
    def test_packet_immutability(self):
        # The core engine should never mutate the input packet
        packet = {"code_snippet": "print('hello')", "metadata": "should_not_change"}
        
        # Make a manual shallow copy to check against
        packet_copy = packet.copy()
        
        scan_packet(packet)
        
        self.assertEqual(packet, packet_copy, "The core engine mutated the input packet!")


if __name__ == '__main__':
    unittest.main()
