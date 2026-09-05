import unittest
import os
import sys
import time


try:
    from lobster.core import scan_packet, KNOWN_THREATS, RUNTIME_CACHE
    from lobster.iron_dome import IronDome
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
    from lobster.iron_dome import IronDome

class TestPerformanceBenchmarks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.metrics = {}

    @classmethod
    def tearDownClass(cls):
        import json
        with open("performance_metrics.json", "w") as f:
            json.dump(cls.metrics, f, indent=2)

    def setUp(self):
        RUNTIME_CACHE.clear()
        
    def test_iron_dome_latency(self):
        # Create a massive payload string
        massive_payload = "print('hello world')\n" * 1000 + "rm -rf /\n" * 10
        
        start_time = time.perf_counter()
        result = IronDome.scan(massive_payload)
        end_time = time.perf_counter()
        
        latency_ms = (end_time - start_time) * 1000
        self.__class__.metrics["iron_dome_ms"] = round(latency_ms, 3)
        
        # We expect regex to parse this in under 10ms (generous ceiling for CI environments)
        self.assertLess(latency_ms, 10.0, f"Iron Dome heuristic scan was too slow! Latency: {latency_ms:.2f}ms")
        self.assertIsNotNone(result)

    def test_vault_lookup_latency(self):
        # Add 10,000 dummy threats to simulate a large vault
        for i in range(10000):
            KNOWN_THREATS[f"dummy_threat_{i}"] = {"status": "BLOCK", "analysis": "Dummy"}
            
        KNOWN_THREATS["performance_test_threat"] = {"status": "BLOCK", "analysis": "Target"}
        packet = {"code_snippet": "performance_test_threat"}
        
        start_time = time.perf_counter()
        result = scan_packet(packet)
        end_time = time.perf_counter()
        
        latency_ms = (end_time - start_time) * 1000
        self.__class__.metrics["vault_ms"] = round(latency_ms, 3)
        
        # O(1) dictionary lookup should be virtually instantaneous (under 2ms)
        self.assertLess(latency_ms, 2.0, f"Vault lookup was too slow! Latency: {latency_ms:.2f}ms")
        self.assertEqual(result["source"], "VAULT")
        
        # Clean up
        KNOWN_THREATS.clear()

    def test_cache_lookup_latency(self):
        # Inject target directly into Cache
        RUNTIME_CACHE["performance_test_cache"] = {"status": "ALLOW", "analysis": "Target"}
        packet = {"code_snippet": "performance_test_cache"}
        
        start_time = time.perf_counter()
        result = scan_packet(packet)
        end_time = time.perf_counter()
        
        latency_ms = (end_time - start_time) * 1000
        self.__class__.metrics["cache_ms"] = round(latency_ms, 3)
        
        # Cache hit should be under 2ms
        self.assertLess(latency_ms, 2.0, f"Cache lookup was too slow! Latency: {latency_ms:.2f}ms")
        self.assertEqual(result["source"], "CACHE")


if __name__ == '__main__':
    unittest.main()
