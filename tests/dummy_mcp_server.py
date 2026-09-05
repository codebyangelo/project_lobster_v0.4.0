import sys
import json

def main():
    # A tiny fake MCP server for testing the proxy.
    for line in sys.stdin:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            req = json.loads(line_str)
            msg_id = req.get("id")
            if req.get("method") == "initialize":
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"protocolVersion": "2024-11-05"}}
                print(json.dumps(resp), flush=True)
            elif req.get("method") == "tools/call":
                resp = {
                    "jsonrpc": "2.0", 
                    "id": msg_id, 
                    "result": {
                        "content": [{"type": "text", "text": "TOOL EXECUTED SUCCESSFULLY"}],
                        "isError": False
                    }
                }
                print(json.dumps(resp), flush=True)
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"status": "ok"}}
                print(json.dumps(resp), flush=True)
        except Exception:
            pass

if __name__ == "__main__":
    main()
