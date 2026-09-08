# Performance Guide (v1.0.0)

This guide documents the expected latency and throughput characteristics of Lobster, distinguishing between formally recorded local metrics and harness-observed integration metrics.

## 1. Formally Recorded Local Baselines
The following metrics represent the deterministic execution overhead of the local security engine, recorded formally in `performance_metrics.json` on reference hardware:
- **Green Dome (Heuristics):** `~0.05ms - 0.2ms`
- **Threat Vault (Static):** `0.495ms`
- **Runtime Cache (Hit):** `1.003ms`
- **Proxy Context Tracking:** Sub-millisecond (`<0.1ms` overhead for array shifting)

These operations are strictly CPU-bound. Phase 8 testing confirmed that standard synchronous execution does not significantly bottleneck the OS CPU scheduler.

## 2. Harness-Observed Integration Latency (Environment-Dependent)
For novel payloads that bypass the local cache and Threat Vault, Lobster escalates to the Gemini API. These metrics were observed during Phase 8 acceptance testing and are **highly environment and provider-dependent**:
- **API Response Time:** Observed up to `~2.66s` during standard load.
- **End-to-End Latency (Cache-Miss):** Observed up to `~6.56s` (including agent processing, proxy overhead, API transmission, and downstream execution).

## 3. Concurrency and Throughput
During the Phase 8 10-proxy concurrency baseline, the system maintained a `p50 Latency: 1.88ms` for local-only operations.

**Dominant Cost Factor:** External LLM/API latency was the dominant observed cost on cache-miss paths. The local proxy architecture (including the synchronous JSON-RPC stdio loop and process-local memory) did not artificially restrict throughput during Phase 8 benchmarks.
