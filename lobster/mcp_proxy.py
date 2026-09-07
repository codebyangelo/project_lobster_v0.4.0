import sys
import json
import subprocess
import threading
import uuid
from lobster.core import scan_packet
from lobster.telemetry import telemetry

def forward_output(proc):
    """Read from downstream MCP server stdout and forward to Agent via Proxy stdout"""
    for line in iter(proc.stdout.readline, ''):
        sys.stdout.write(line)
        sys.stdout.flush()

def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--health":
        print("Healthy")
        sys.exit(0)
        
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

    try:
        MAX_CONTEXT = 10
        session_history = []
        
        # Read incoming JSON-RPC requests from the Agent via stdin
        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue
            
            correlation_id = "MCP-" + str(uuid.uuid4())[:8]
                
            try:
                req = json.loads(line_str)
            except json.JSONDecodeError:
                # LOBSTER FIREWALL: Drop malformed JSON to protect downstream server from crash/overflow.
                telemetry.log_proxy_error(correlation_id, "Malformed JSON", line_str[:100])
                
                # Return standard JSON-RPC 2.0 Parse error.
                error_resp = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None
                }
                print(json.dumps(error_resp), flush=True)
                continue

            # Intercept MCP "tools/call" requests
            # Example: {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "run_command", "arguments": {"command": "rm -rf /"}}}
            if isinstance(req, dict) and req.get("method") == "tools/call":
                params = req.get("params", {})
                
                # Serialize the entire params block (including tool name and arguments)
                # so the LLM understands the full intent of the MCP call.
                payload = json.dumps(params)
                
                packet = {"code_snippet": payload}
                verdict = scan_packet(packet, context_history=session_history, correlation_id=correlation_id)
                
                # Record action and resulting security status in history
                history_packet = {"code_snippet": f"Payload: {payload}\nLobster Verdict: {verdict['status']}"}
                session_history.append(history_packet)
                if len(session_history) > MAX_CONTEXT:
                    session_history.pop(0)
                
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
    except KeyboardInterrupt:
        pass
    except Exception as e:
        telemetry.log_proxy_error("N/A", f"Proxy Exception: {str(e)}")
    finally:
        telemetry.print_summary()
        proc.terminate()

if __name__ == "__main__":
    main()
