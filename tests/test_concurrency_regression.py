import sys

import unittest
from unittest.mock import patch
import threading
import time
from lobster.core import RateLimiter

class TestConcurrencyRegression(unittest.TestCase):
    @patch('lobster.core.time.time')
    def test_rate_limiter_thread_safety(self, mock_time):
        """
        Regression test for Phase 4: RateLimiter Thread Safety.
        We initialize a rate limiter with exactly 100 tokens.
        We spawn 200 threads that call allow() simultaneously.
        Exactly 100 should succeed, and 100 should fail.
        """
        mock_time.return_value = 2000.0
        limiter = RateLimiter(rate=100, per=60)
        
        success_count = 0
        failure_count = 0
        
        # We use a barrier to make all threads hit allow() at the exact same moment
        barrier = threading.Barrier(200)
        lock = threading.Lock()
        
        def worker():
            nonlocal success_count, failure_count
            barrier.wait() # wait for all 200 threads to be ready
            result = limiter.allow()
            with lock:
                if result:
                    success_count += 1
                else:
                    failure_count += 1

        threads = []
        for _ in range(200):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()
            
        self.assertEqual(success_count, 100, f"Race condition detected: {success_count} threads succeeded instead of 100.")
        self.assertEqual(failure_count, 100, f"Race condition detected: {failure_count} threads failed instead of 100.")
        self.assertEqual(limiter.tokens, 0.0, f"Race condition detected: tokens ended at {limiter.tokens} instead of 0.0.")

if __name__ == '__main__':
    unittest.main()
