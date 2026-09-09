# Security Assumptions & Threat Model (v1.0.0)

This document formalizes the security contract and threat model for Project Lobster based on evidence gathered during Phases 1-8. It distinguishes between mathematically demonstrated behavior and heuristic-dependent boundaries.

## 1. Enforcement Contract
Lobster operates on a deterministic, fail-closed `ALLOW/BLOCK/ERROR` security contract. 
- **ALLOW:** The payload is permitted to reach the downstream tool.
- **BLOCK:** The payload is intercepted, and an MCP standard error is synthesized back to the agent. The downstream tool is strictly isolated from the payload.
- **ERROR (Fail-Closed):** If Lobster encounters an internal failure, malformed JSON-RPC traffic, provider-side API outage (e.g., 503), or rate-limit exhaustion, it assumes an `ERROR` state. This automatically halts execution and blocks the request from reaching the downstream tool. 

## 2. Threat Model: In-Scope Protections
Lobster is designed to intercept and evaluate downstream tool payloads. Based on Phase 8 testing, Lobster provides defense against:
- **Direct Malicious Execution:** Detection of static known-bad signatures (e.g., downstream RCE, data exfiltration) via the deterministic Threat Vault.
- **Context-Dependent Attacks:** Detection of multi-step distributed intent (e.g., disabling TLS in Step 1, starting a server in Step 2). The `mcp_proxy.py` tracks history up to `MAX_CONTEXT=10` sequential packets per session.

## 3. Process Isolation Guarantees
Due to the stdio architecture of the MCP proxy, each session operates in its own memory space. **No cross-session context contamination was observed in Phase 8 process-isolation testing.** Concurrent agent sessions cannot view, influence, or bleed context into one another.

## 4. Explicitly Unsupported (Out of Scope)
Lobster is a security middleware for *tools*, not a complete agent firewall. The following are explicitly out of scope:
- **Prompt Leakage & Jailbreaks:** Protecting the upstream AI agent from being manipulated by its own prompts or data inputs.
- **Upstream Agent Compromise:** Lobster protects the tool boundary, not the agent's internal memory or operational state.
- **Proxy Configuration Bypass:** If an agent is granted network access that circumvents the `mcp_proxy.py` wrapper, Lobster cannot protect the tool.
