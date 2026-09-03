import unittest
import time
from unittest.mock import patch
import os
import sys

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.core import RateLimiter, scan_packet, limiter

class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        # Reset the global limiter before each test just in case
        limiter.tokens = limiter.rate
        limiter.last_check = time.time()

    def test_enforces_limit(self):
        # Test basic limit enforcement (5 tokens)
        rl = RateLimiter(rate=5, per=60)
        # Should allow 5 calls
        for _ in range(5):
            self.assertTrue(rl.allow())
        # Should block the 6th call
        self.assertFalse(rl.allow())

    @patch('time.time')
    def test_token_refill_logic(self, mock_time):
        rl = RateLimiter(rate=5, per=60)
        
        # Initial check at time 0
        mock_time.return_value = 0.0
        rl.last_check = 0.0
        
        # Consume 5 tokens
        for _ in range(5):
            self.assertTrue(rl.allow())
        
        # 6th should be blocked
        self.assertFalse(rl.allow())
        
        # Advance time by 12 seconds (should refill exactly 1 token since rate is 5 per 60 sec, 1 per 12 sec)
        mock_time.return_value = 12.0
        self.assertTrue(rl.allow())
        
        # Next one should be blocked again
        self.assertFalse(rl.allow())
        
        # Advance time by 60 seconds (should refill all 5 tokens)
        mock_time.return_value = 72.0
        for _ in range(5):
            self.assertTrue(rl.allow())
        self.assertFalse(rl.allow())

    @patch('time.time')
    def test_negative_time_passed(self, mock_time):
        rl = RateLimiter(rate=5, per=60)
        mock_time.return_value = 100.0
        rl.last_check = 100.0
        
        # Consume all tokens
        for _ in range(5):
            self.assertTrue(rl.allow())
        
        # Simulate time going backwards (e.g. clock sync)
        mock_time.return_value = 90.0
        # Time passed is negative, tokens will decrease or stay < 1
        self.assertFalse(rl.allow())

    def test_zero_rate(self):
        rl = RateLimiter(rate=0, per=60)
        self.assertFalse(rl.allow())

    def test_zero_per_error(self):
        rl = RateLimiter(rate=5, per=0)
        with self.assertRaises(ZeroDivisionError):
            rl.allow()

    def test_scan_packet_rate_limit_response(self):
        # Consume all tokens from the global limiter
        limiter.tokens = 0
        
        packet = {"code_snippet": "unknown_code_not_in_vault_or_cache_123"}
        
        # We also need to ensure client is not None so it doesn't fail on OFFLINE
        # It's fine if client is None, wait... 
        # In core.py:
        # if not client: return {"status": "CLEAN", "analysis": "Offline Mode...
        # RATE LIMIT CHECK is after `if not client:`
        # So we need to mock client.
        pass

    @patch('src.core.client')
    def test_scan_packet_rate_limit_exceeded(self, mock_client):
        # Ensure client is truthy so we get to rate limiter
        mock_client.__bool__.return_value = True 
        
        # Empty the global token bucket
        limiter.tokens = 0
        limiter.last_check = time.time()
        
        packet = {"code_snippet": "novel_payload_for_api"}
        result = scan_packet(packet, use_llm=True)
        
        self.assertEqual(result["status"], "API_ERROR")
        self.assertEqual(result["source"], "RATE_LIMITER")
        self.assertIn("RATE LIMIT EXCEEDED", result["analysis"])

if __name__ == '__main__':
    unittest.main()
