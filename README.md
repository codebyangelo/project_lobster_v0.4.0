# 🦞 Project Lobster v1.0.0-Alpha
### "Hybrid-Tiered Agentic Immune System"

[![CI: Python Test](https://github.com/codebyangelo/project_lobster_v0.4.0/actions/workflows/test.yml/badge.svg)](https://github.com/codebyangelo/project_lobster_v0.4.0/actions/workflows/test.yml)
[![Iron Dome Latency](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/codebyangelo/290c37849ba326c70233c878e2090b65/raw/iron_dome_latency.json)](https://github.com/codebyangelo/project_lobster_v0.4.0)
[![Vault Latency](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/codebyangelo/290c37849ba326c70233c878e2090b65/raw/vault_latency.json)](https://github.com/codebyangelo/project_lobster_v0.4.0)
[![Cache Latency](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/codebyangelo/290c37849ba326c70233c878e2090b65/raw/cache_latency.json)](https://github.com/codebyangelo/project_lobster_v0.4.0)

**Engine:** Google Gemini 3 Flash Preview

**Interface:** Terminal User Interface (TUI) via `rich`

**Status:** Alpha - Feature complete, seeking production feedback

---

## 📖 The Vision
As the internet evolves from a network of humans to a network of **Autonomous AI Agents**, traditional security tools (firewalls, antivirus) are becoming obsolete. Agents talk to agents using natural language and code, not just HTTP requests.

**Project Lobster** is an "Immune System" for this new agentic web. It sits alongside your AI agent, monitoring input/output traffic only. It detects malicious prompts, jailbreaks, and dangerous code execution attempts *before* they reach your agent's core logic.

---

## 🚀 Key Features

### 1. Hybrid Defense Architecture
-   **Layer 0: Iron Dome/Green Dome (Local)**: Effectively zero-latency local Regex heuristics block known threats (rm -rf) and approve known-safe patterns (import math) instantly, before invoking the AI layer.
-   **Layer 1: The Vault (Cached Intelligence)**: A local database of previously analyzed threats prevents redundant API calls.
-   **Layer 2: AI Sentinel (Gemini 3 Flash Preview)**: The "Brain". Analyzes novel, complex threats using the reasoning capabilities of Gemini 3 Flash Preview.

### 2. Efficiency & Sustainability
-   **Live Efficiency Monitor**: The dashboard tracks `API Calls` vs. `Local Blocks` in real-time.
-   **Token Bucket Rate Limiter**: Strictly enforces a **5 RPM** limit (Free Tier compliant) while maintaining 100% uptime via caching and heuristics.
-   **Cost Savings**: Demos how an enterprise-grade system scales without linear cost growth.

### 3. Context-Aware Security
-   **The "Killer Feature"**: Unlike simple firewalls, Lobster analyzes the *history* of the conversation.
-   **Demo Scenario**: It detects multi-step attacks (e.g., setting an environment variable in Packet A, then exfiltrating it in Packet B) that are benign in isolation but malicious in context.

---

## ⚙️ Usage Guide

### prerequisites
-   Python 3.10+
-   Google Cloud Project with Gemini API enabled
-   `GEMINI_API_KEY` set in `.env`

### Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install .
```
*(Dependencies like `google-genai` and `rich` are automatically handled)*

### Running the Demo
Since Project Lobster is now a standard Python package, it installs a global command line tool:

```bash
# Launch the Dashboard
lobster
```

### Controls
| Key | Function |
| :--- | :--- |
| **S** | **Start** the live simulation. |
| **A** | **Toggle AI** (Watch the difference between Pattern Matching vs. Intelligence). |
| **SPACE** | **Pause/Resume** the stream. |
| **E** | **Export** a detailed forensic report (HTML + JSON). |
| **Q** | **Quit**. |

---

*Project Lobster - Securing the Agentic Web*

## Copyright 2026 Angelo Ayton

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
