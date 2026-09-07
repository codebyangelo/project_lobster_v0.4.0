import sys
import subprocess
import json
import time
import os
from dotenv import load_dotenv
load_dotenv()

def run_proxy():
    proxy_cmd = [sys.executable, "lobster/mcp_proxy.py", sys.executable, "tests/dummy_mcp_server.py"]
    test_env = os.environ.copy()
    test_env["PYTHONPATH"] = "/tmp/lobster-phase1"
    
    return subprocess.Popen(
        proxy_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=test_env,
        bufsize=1
    )

def send_request(proxy, payload, req_id):
    proxy.stdin.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": payload}) + "\n")
    proxy.stdin.flush()
    while True:
        line = proxy.stdout.readline()
        if not line:
            return None
        if '"jsonrpc"' in line:
            return json.loads(line)

def is_blocked(response):
    if not response: return True
    return response.get('result', {}).get('isError', False) or response.get('error') is not None

def test_multistep_detection():
    print("\n=== Test 1: Multi-Step Detection (TLS Downgrade) ===")
    proxy = run_proxy()
    
    # Step 1: Disable TLS (Benign)
    payload1 = {"name": "write_file", "arguments": {"path": "config.json", "content": "{\"use_tls\": false}"}}
    r1 = send_request(proxy, payload1, 1)
    print(f"Step 1 (Disable TLS): {'BLOCK' if is_blocked(r1) else 'ALLOW'}")
    
    # Step 2: Start Server (Malicious in context)
    payload2 = {"name": "start_server", "arguments": {"port": 80}}
    r2 = send_request(proxy, payload2, 2)
    print(f"Step 2 (Start Server): {'BLOCK' if is_blocked(r2) else 'ALLOW'}")
    
    proxy.stdin.close()
    proxy.wait()

def test_context_isolation():
    print("\n=== Test 2: Process Isolation ===")
    # Proxy A receives Step 1
    proxy_a = run_proxy()
    payload1 = {"name": "write_file", "arguments": {"path": "config.json", "content": "{\"use_tls\": false}"}}
    r1 = send_request(proxy_a, payload1, 1)
    print(f"Proxy A - Step 1 (Disable TLS): {'BLOCK' if is_blocked(r1) else 'ALLOW'}")
    
    # Proxy B receives Step 2 (Should NOT be blocked because it has no context)
    proxy_b = run_proxy()
    payload2 = {"name": "start_server", "arguments": {"port": 80}}
    r2 = send_request(proxy_b, payload2, 2)
    print(f"Proxy B - Step 2 (Start Server): {'BLOCK' if is_blocked(r2) else 'ALLOW'} (Expected: ALLOW)")
    
    proxy_a.stdin.close()
    proxy_b.stdin.close()
    proxy_a.wait()
    proxy_b.wait()

def test_sliding_window():
    print("\n=== Test 3: Sliding Window (Bounded Context) ===")
    proxy = run_proxy()
    
    # Send 12 benign requests to fill the MAX_CONTEXT=10 window and evict the first 2
    for i in range(12):
        r = send_request(proxy, {"name": "echo", "arguments": {"msg": "benign_cache_hit"}}, i)
    
    # Check if the sliding window actually evicted the earliest requests.
    # To do this, we parse the proxy telemetry (which prints the prompt implicitly? No, telemetry doesn't print the context string).
    # We can just verify it didn't crash.
    print("Sent 12 requests. Proxy is still alive.")
    
    # Now let's send Step 2 of the TLS attack. It should NOT be blocked because Step 1 was NEVER sent in this window!
    payload2 = {"name": "start_server", "arguments": {"port": 80}}
    r2 = send_request(proxy, payload2, 13)
    print(f"Follow-up request: {'BLOCK' if is_blocked(r2) else 'ALLOW'} (Expected: ALLOW, because window is full of benign_X)")
    
    # Now send Step 1
    payload1 = {"name": "write_file", "arguments": {"path": "config.json", "content": "{\"use_tls\": false}"}}
    r1 = send_request(proxy, payload1, 14)
    print(f"Step 1 (Disable TLS) inserted into window: {'BLOCK' if is_blocked(r1) else 'ALLOW'}")
    
    # Now send Step 2, should be blocked because Step 1 is in the window
    r3 = send_request(proxy, payload2, 15)
    print(f"Step 2 (Start Server) immediately after: {'BLOCK' if is_blocked(r3) else 'ALLOW'} (Expected: BLOCK)")
    
    # Now send 10 benign requests to flush Step 1 out of the window
    for i in range(16, 26):
        send_request(proxy, {"name": "echo", "arguments": {"msg": "benign_flush_hit"}}, i)
        
    # Send Step 2 again. It should be ALLOWED because Step 1 was flushed!
    r4 = send_request(proxy, payload2, 26)
    print(f"Step 2 (Start Server) after 10 flushes: {'BLOCK' if is_blocked(r4) else 'ALLOW'} (Expected: ALLOW)")

    proxy.stdin.close()
    proxy.wait()

if __name__ == "__main__":
    test_multistep_detection()
    test_context_isolation()
    test_sliding_window()
