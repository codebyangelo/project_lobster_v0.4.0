import sys
import json
import subprocess
import threading
from lobster.core import scan_packet

def forward_output(proc):
    """Read from downstream MCP server stdout and forward to Agent via Proxy stdout"""
    for line in iter(proc.stdout.readline, ''):
        sys.stdout.write(line)
        sys.stdout.flush()

def main():
    if len(sys.argv) < 2:
        print("Usage: lobster-proxy <command> [args...]", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1:]
    
    # Launch the downstream MCP server as a subprocess
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr, # pass stderr through directly
        text=True,
        bufsize=1
    )

    # Start a background thread to proxy output back to the agent
    out_thread = threading.Thread(target=forward_output, args=(proc,), daemon=True)
    out_thread.start()

    # Read incoming JSON-RPC requests from the Agent via stdin
    for line in sys.stdin:
        line_str = line.strip()
        if not line_str:
            continue
            
        try:
            req = json.loads(line_str)
        except json.JSONDecodeError:
            # If it's not valid JSON, we just pass it through blindly.
            proc.stdin.write(line)
            proc.stdin.flush()
            continue

        # Intercept MCP "tools/call" requests
        # Example: {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}}}
        if req.get("method") == "tools/call":
            params = req.get("params", {})
            args = params.get("arguments", {})
            
            # Serialize the tool arguments into a string payload for Lobster to scan
            # We treat the entire argument block as the "code_snippet"
            payload = json.dumps(args)
            
            packet = {"code_snippet": payload}
            verdict = scan_packet(packet)
            
            if verdict["status"] != "ALLOW":
                # LOBSTER INTERCEPTION!
                # We do NOT forward the payload to the downstream tool.
                # Instead, we construct an MCP ToolResult Error and send it back to the agent.
                msg_id = req.get("id")
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text", 
                                "text": f"LOBSTER SECURITY INTERCEPTION\nStatus: {verdict['status']}\nAnalysis: {verdict['analysis']}"
                            }
                        ],
                        "isError": True
                    }
                }
                print(json.dumps(error_resp), flush=True)
                continue

        # If it's safe, or if it's just a regular MCP message (like 'initialize'), forward it.
        proc.stdin.write(line)
        proc.stdin.flush()

if __name__ == "__main__":
    main()
