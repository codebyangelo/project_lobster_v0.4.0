import unittest
import os
import sys
from unittest.mock import patch, MagicMock


from lobster.core import scan_packet, client, RUNTIME_CACHE, limiter

class TestCacheManagement(unittest.TestCase):

    def setUp(self):
        # Always start with a clean cache and full rate limiter tokens
        RUNTIME_CACHE.clear()
        limiter.tokens = limiter.rate

    @patch('lobster.core.client')
    def test_cache_hit_bypasses_api(self, mock_client):
        # Setup mock API to return a CLEAN verdict
        mock_response = MagicMock()
        mock_response.text = "REASONING: The payload is standard and clean."
        mock_client.models.generate_content.return_value = mock_response
        mock_client.__bool__.return_value = True

        packet = {"code_snippet": "unique_uncached_function()"}

        # First scan should hit the LLM API
        result1 = scan_packet(packet)
        self.assertEqual(result1["source"], "GEMINI_API")
        self.assertEqual(mock_client.models.generate_content.call_count, 1)

        # Second scan with the EXACT same code should hit the cache
        result2 = scan_packet(packet)
        self.assertEqual(result2["source"], "CACHE")
        
        # Verify the API was NOT called a second time
        self.assertEqual(mock_client.models.generate_content.call_count, 1)
        
        # Verify the status remains the same
        self.assertEqual(result1["status"], result2["status"])

    @patch('lobster.core.client')
    def test_cache_miss_on_different_payload(self, mock_client):
        # Setup mock API
        mock_response = MagicMock()
        mock_response.text = "REASONING: The payload is standard and clean."
        mock_client.models.generate_content.return_value = mock_response
        mock_client.__bool__.return_value = True

        packet1 = {"code_snippet": "function_one()"}
        packet2 = {"code_snippet": "function_two()"}

        # Scan first payload
        res1 = scan_packet(packet1)
        self.assertEqual(res1["source"], "GEMINI_API")
        
        # Scan second payload (different code)
        res2 = scan_packet(packet2)
        self.assertEqual(res2["source"], "GEMINI_API")
        
        # API should have been called twice
        self.assertEqual(mock_client.models.generate_content.call_count, 2)
        
        # Cache should now have 2 entries
        self.assertEqual(len(RUNTIME_CACHE), 2)

if __name__ == '__main__':
    unittest.main()
