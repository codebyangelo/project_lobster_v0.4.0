import sys

import time
import concurrent.futures
from unittest.mock import patch, MagicMock

from lobster.core import scan_packet, RUNTIME_CACHE
import lobster.core

def measure_workload(name, packet_factory, concurrency, num_requests):
    latencies = []
    
    # Clear caches to avoid artificial hits between test runs
    RUNTIME_CACHE.clear()
    
    # We must patch the rate limiter to practically infinity for load testing, 
    # otherwise our concurrent tests will just instantly trigger RATE_LIMIT_EXCEEDED
    # which is a local fast-path return and invalidates our network/cache measurements.
    
    packets = [packet_factory(i) for i in range(num_requests)]
    
    start_time = time.time()
    
    # We must patch the rate limiter to practically infinity for load testing
    original_rate = lobster.core.limiter.rate
    original_tokens = lobster.core.limiter.tokens
    lobster.core.limiter.rate = 999999
    lobster.core.limiter.tokens = 999999
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            def task(pkt):
                t0 = time.time()
                scan_packet(pkt)
                return time.time() - t0
            
            results = list(executor.map(task, packets))
            latencies.extend(results)
            
    finally:
        lobster.core.limiter.rate = original_rate
        lobster.core.limiter.tokens = original_tokens
        
    total_time = time.time() - start_time
    
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)] * 1000
    p95 = latencies[int(len(latencies) * 0.95)] * 1000
    throughput = num_requests / total_time
    
    print(f"[{name}] - Concurrency: {concurrency} | Total Requests: {num_requests}")
    print(f"Throughput: {throughput:.2f} req/s | p50: {p50:.2f} ms | p95: {p95:.2f} ms\n")

def iron_dome_factory(i):
    return {"code_snippet": f"rm -rf /tmp/test_{i}"}

def cache_factory(i):
    key = "cache_test_packet"
    RUNTIME_CACHE[key] = {"status": "ALLOW", "analysis": "Cached safe"}
    return {"code_snippet": key}

def api_factory(i):
    # This must be unique so it doesn't hit the cache
    return {"code_snippet": f"novel_payload_for_api_{i}()"}

def run_baselines():
    print("================ PHASE 4A: BASELINE CONCURRENCY BENCHMARKS ================\n")
    
    levels = [1, 10, 50]
    
    print("--- Local Deterministic Path (Iron Dome) ---")
    for c in levels:
        measure_workload("Iron Dome", iron_dome_factory, c, 500)
        
    print("--- Memory State Path (Runtime Cache) ---")
    for c in levels:
        measure_workload("Cache Hit", cache_factory, c, 500)
    
    print("--- Network Path (Gemini API Escalation) ---")
    print("Mocking Gemini network request to 0.5s latency to prevent API billing/bans.\n")
    
    def fake_api_call(*args, **kwargs):
        time.sleep(0.5) # Simulate 500ms network round-trip
        mock_response = MagicMock()
        mock_response.text = '{"status": "ALLOW", "analysis": "Mocked AI analysis."}'
        return mock_response
        
    with patch('lobster.core.client.models.generate_content', side_effect=fake_api_call):
        for c in levels:
            measure_workload("API Escalation", api_factory, c, 50)

if __name__ == "__main__":
    run_baselines()
