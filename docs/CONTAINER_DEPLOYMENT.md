# Lobster Container Deployment Guide

Lobster is packaged as a minimal, non-root, multi-stage Docker container based on Python Slim. 

## Design Philosophy
Lobster operates as an MCP `stdio` sidecar proxy. This means it **does not bind to TCP ports** (no `-p 8080:8080`). Instead, it reads from `stdin` and writes to `stdout`.

When deploying Lobster in a container, you must pass streams into it.

## Running the Container

You can execute the proxy by piping JSON-RPC payloads into the container:

```bash
docker run -i --rm \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp \
  -e GEMINI_API_KEY="your_api_key" \
  project-lobster:latest downstream_mcp_executable < payload.json
```

## Security Defaults
1. **Non-Root Execution:** The Dockerfile creates a user named `lobster` and drops root privileges immediately.
2. **Read-Only Filesystem:** The `docker-compose.yml` configures the container as `read_only: true` with a `tmpfs` mount at `/tmp`. This prevents attackers from dropping files on disk even if they bypass the proxy.
3. **No New Privileges:** Prevents privilege escalation attacks via `suid`.

## Health Checks
Orchestrators (Kubernetes, Docker Swarm) can verify the proxy runtime is healthy using the built-in health flag:
```bash
docker run --rm project-lobster:latest --health
```
This is configured natively in the `Dockerfile`'s `HEALTHCHECK` directive.

## Continuous Integration
Since the proxy is intended to be highly secure, every PR push triggers `.github/workflows/docker.yml`.
This pipeline:
1. Builds the image using Buildx.
2. Scans the image for `CRITICAL` and `HIGH` CVEs using Trivy.
3. Fails the build if any vulnerabilities are found.
