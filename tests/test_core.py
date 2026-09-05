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
