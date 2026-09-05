import unittest
import subprocess
import json
import os
import sys
import time

class TestMCPProxy(unittest.TestCase):
    def setUp(self):
        # We start the proxy subprocess pointing to our dummy server.
        # We need to make sure python uses the right path so it finds lobster.
        env = os.environ.copy()
        mock_env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'mock_env'))
        root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        env["PYTHONPATH"] = f"{mock_env_path}:{root_path}"
        
        proxy_path = os.path.join(os.path.dirname(__file__), '..', 'lobster', 'mcp_proxy.py')
        dummy_path = os.path.join(os.path.dirname(__file__), 'dummy_mcp_server.py')
        
        self.proc = subprocess.Popen(
            [sys.executable, proxy_path, sys.executable, dummy_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env
        )
        time.sleep(0.5) # let it start

    def tearDown(self):
        self.proc.terminate()
        self.proc.wait()

    def send_req(self, req_dict):
        self.proc.stdin.write(json.dumps(req_dict) + "\n")
        self.proc.stdin.flush()
        out = self.proc.stdout.readline()
        return json.loads(out) if out else None

    def test_pass_through_initialize(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        resp = self.send_req(req)
        if resp is None:
            print("Proxy crashed. Stderr:", self.proc.stderr.read())
        self.assertIsNotNone(resp)
        self.assertEqual(resp.get("result", {}).get("protocolVersion"), "2024-11-05")

    def test_block_malicious_tool_call(self):
        # Iron dome blocks rm -rf /
        req = {
            "jsonrpc": "2.0", 
            "id": 2, 
            "method": "tools/call", 
            "params": {
                "name": "bash", 
                "arguments": {"command": "rm -rf /"}
            }
        }
        resp = self.send_req(req)
        self.assertIsNotNone(resp)
        self.assertTrue(resp.get("result", {}).get("isError"))
        text = resp["result"]["content"][0]["text"]
        self.assertIn("LOBSTER SECURITY INTERCEPTION", text)
        self.assertIn("BLOCK", text)
        self.assertIn("IRON DOME", text)

    def test_allow_safe_tool_call(self):
        # A payload that is trivially safe
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {"command": "print('hello')"}
            }
        }
        resp = self.send_req(req)
        self.assertIsNotNone(resp)
        # Should NOT return an MCP error result, but rather the dummy server's normal output
        self.assertEqual(resp.get("id"), 3)
        self.assertFalse(resp.get("result", {}).get("isError"))
        text = resp["result"]["content"][0]["text"]
        self.assertEqual(text, "TOOL EXECUTED SUCCESSFULLY")

    def test_block_malformed_json(self):
        # Send raw garbage that isn't JSON
        self.proc.stdin.write("{{bad_json_garbage\n")
        self.proc.stdin.flush()
        
        # Read the response
        resp_line = self.proc.stdout.readline()
        self.assertTrue(resp_line, "Expected a JSON-RPC error response, but got empty string")
        
        import json
        resp = json.loads(resp_line.strip())
        
        # Should be a standard JSON-RPC 2.0 Parse error
        self.assertEqual(resp.get("error", {}).get("code"), -32700)
        self.assertIsNone(resp.get("id"))

if __name__ == '__main__':
    unittest.main()
