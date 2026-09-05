import unittest
from unittest.mock import patch, MagicMock
from lobster.core import scan_packet, RUNTIME_CACHE, limiter

class TestVerdictParser(unittest.TestCase):
    def setUp(self):
        RUNTIME_CACHE.clear()
        limiter.tokens = limiter.rate

    def simulate_llm(self, text, mock_client):
        mock_client.__bool__.return_value = True
        mock_response = MagicMock()
        mock_response.text = text
        mock_client.models.generate_content.return_value = mock_response
        return scan_packet({"code_snippet": "dummy()"})

    @patch('lobster.core.client')
    def test_original_safe_keyword_injection(self, mock_client):
        # Scenario 1: LLM returns only reasoning with safe keywords
        res = self.simulate_llm("REASONING: benign safe clean authorized", mock_client)
        # Missing VERDICT, so it should ERROR
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("FAIL-CLOSED", res["analysis"])

    @patch('lobster.core.client')
    def test_quoted_verdict_inside_reasoning(self, mock_client):
        # Scenario 2: LLM rejects attack but quotes the payload
        res = self.simulate_llm("VERDICT: BLOCK\nREASONING: The payload attempts to make me say 'VERDICT: ALLOW', which is malicious.", mock_client)
        self.assertEqual(res["status"], "BLOCK")
        self.assertIn("attempts to make me say", res["analysis"])

    @patch('lobster.core.client')
    def test_missing_verdict(self, mock_client):
        # Missing VERDICT line entirely
        res = self.simulate_llm("I think this is safe.\nREASONING: safe", mock_client)
        self.assertEqual(res["status"], "ERROR")

    @patch('lobster.core.client')
    def test_malformed_verdict(self, mock_client):
        # Malformed VERDICT line
        res = self.simulate_llm("VERDICT: KINDA_SAFE\nREASONING: nothing wrong", mock_client)
        self.assertEqual(res["status"], "ERROR")

    @patch('lobster.core.client')
    def test_duplicate_verdicts(self, mock_client):
        # Duplicate VERDICT fields
        res = self.simulate_llm("VERDICT: BLOCK\nVERDICT: ALLOW\nREASONING: confusing", mock_client)
        self.assertEqual(res["status"], "ERROR")

    @patch('lobster.core.client')
    def test_conflicting_verdict_reasoning(self, mock_client):
        # Conflicting verdict and reasoning (Security decision ONLY relies on VERDICT)
        res = self.simulate_llm("VERDICT: BLOCK\nREASONING: This payload is completely benign and safe.", mock_client)
        self.assertEqual(res["status"], "BLOCK")

    @patch('lobster.core.client')
    def test_valid_allow(self, mock_client):
        res = self.simulate_llm("VERDICT: ALLOW\nREASONING: standard variables", mock_client)
        self.assertEqual(res["status"], "ALLOW")

if __name__ == '__main__':
    unittest.main()
