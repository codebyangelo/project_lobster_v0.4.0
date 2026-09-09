# Known Limitations (v1.0.0)

This document outlines the known architectural and operational limitations of Project Lobster as of v1.0.0.

## 1. Process-Local State (Caching & Rate Limiting)
Because `mcp_proxy.py` operates via standard I/O streams, each agent session spawns a completely isolated Python process.
- **Rate Limiting:** The global `RateLimiter` (configured to 5 requests per 60 seconds) is process-local. If 10 concurrent proxies are spawned by an agent, the theoretical combined API throughput could reach up to 50 requests per minute before the individual proxies throttle themselves. 
- **Runtime Cache:** Cache hits do not cross-pollinate. A threat identified and cached by Proxy Session A will not accelerate or protect Proxy Session B until the threat is permanently added to the static Threat Vault.

## 2. Context Correlation Horizon
The proxy's sliding window retains a strict upper bound of `MAX_CONTEXT=10` operations. Context loss beyond this window represents a **correlation limitation**. While it does not guarantee an automatic bypass (as individual malicious payloads may still independently trigger Tier 0 or Tier 1 defenses), distributed intent spanning more than 10 sequential tool calls may evade context-aware detection.

## 3. Upstream Provider Dependency
Zero-day or unknown payloads unconditionally rely on the configured LLM API (currently Gemini 3.1 Flash-Lite). 
- Any provider-side outage, 503 error, or timeout will trigger a fail-closed `ERROR`.
- During provider unavailability, Lobster will paralyze downstream execution for any novel payloads, prioritizing safety over availability.

## 4. Evidence Gaps
- **LLM Performance Distributions:** The performance distribution metrics for LLM network calls are highly variable and were captured in Phase 8 harness logs, but are intentionally absent from the formal `performance_metrics.json` baseline to distinguish them from deterministic local speeds.
- **Cross-Process State:** Cross-process state management (e.g., Redis-backed cache or distributed rate limiting) has not been implemented or tested for the MCP proxy architecture.
