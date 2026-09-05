# Copyright 2026 [Angelo Ayton]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import time
from dotenv import load_dotenv
from google import genai
from lobster.iron_dome import IronDome

# Load Environment
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

# Client Setup (Graceful Failure)
try:
    if api_key:
        client = genai.Client(api_key=api_key)
    else:
        client = None
except Exception:
    client = None

import json

# --- THE VAULT (Pre-Calculated Analyses) ---
# Loaded from external JSON for O(1) Access and separation of concerns.
KNOWN_THREATS = {}
# Runtime Cache to prevent API spam for repeated novel packets (The "Short-Term Memory")
RUNTIME_CACHE = {}

def load_threats():
    """Loads the threat database from JSON into memory."""
    global KNOWN_THREATS
    threat_db_path = "data/threat_db.json"
    if os.path.exists(threat_db_path):
        with open(threat_db_path, "r") as f:
            raw_data = json.load(f)
            # Normalize keys (strip whitespace) for robust O(1) lookup
            KNOWN_THREATS = {k.strip(): v for k, v in raw_data.items()}

# Load threats on module import
load_threats()

# --- RATE LIMITER (Token Bucket) ---
class RateLimiter:
    def __init__(self, rate=60, per=60):
        self.rate = rate
        self.per = per
        self.tokens = rate
        self.last_check = time.time()
    
    def allow(self):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        self.tokens += time_passed * (self.rate / self.per)
        if self.tokens > self.rate:
            self.tokens = self.rate
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True

# Initialize Global Rate Limiter
# 5 requests per minute (Gemini Free Tier Quota)
limiter = RateLimiter(rate=5, per=60)

def scan_packet(packet, context_history=None):
    """
    Phase 2 Security Contract:
    1. Iron Dome (Block Known Bad) - Tier 0
    2. Green Dome (Allow Known Good) - Tier 0.5
    3. The Vault (Static DB) - Tier 1
    4. Runtime Cache (Dynamic DB) - Tier 2
    5. Gemini 3 Flash Preview (LLM) - Tier 3 (Rate Limited)
    """
    
    # Check for invalid packet
    if packet is None or not isinstance(packet, dict):
        return {
            "status": "ERROR",
            "analysis": "Invalid packet: Malformed payload.",
            "source": "ERROR"
        }

    # 1. PASS-THROUGH (Text Only)
    if not packet.get('code_snippet'):
        return {
            "status": "ALLOW", 
            "analysis": "Text-only payload. No execution risk.",
            "source": "TEXT"
        }

    code = packet['code_snippet']
    normalized_code = code.strip()
    
    # 0. IRON DOME (Local Heuristics - Tier 0)
    heuristic_verdict = IronDome.scan(code)
    if heuristic_verdict:
        heuristic_verdict["source"] = "IRON_DOME"
        return heuristic_verdict

    # 0.5. GREEN DOME (Local Allowlist - Tier 0.5)
    green_verdict = IronDome.scan_allowlist(code)
    if green_verdict:
        green_verdict["source"] = "GREEN_DOME"
        return green_verdict
        
    # 1. THE VAULT LOOKUP (Static DB)
    if normalized_code in KNOWN_THREATS:
        result = KNOWN_THREATS[normalized_code].copy()
        result["source"] = "VAULT"
        return result

    # 2. RUNTIME CACHE (Dynamic DB)
    if normalized_code in RUNTIME_CACHE:
        result = RUNTIME_CACHE[normalized_code].copy()
        result["source"] = "CACHE"
        return result

    # 3. LIVE API FALLBACK (The "Danger Zone")
    try:
        if not client:
            return {
                "status": "ERROR", 
                "analysis": "FAIL-CLOSED: AI Sentinel offline (Missing API Key) and payload is UNKNOWN.", 
                "source": "OFFLINE"
            }
            
        # RATE LIMIT CHECK
        if not limiter.allow():
            return {
                "status": "ERROR", 
                "analysis": "FAIL-CLOSED: Rate Limit Exceeded. Traffic throttled to prevent 503 errors.",
                "source": "RATE_LIMITER"
            }

        # Build Context String
        history_str = ""
        if context_history:
            history_str = "\n".join([f"Packet {i-len(context_history)}: {p.get('code_snippet', 'No Code')}" for i, p in enumerate(context_history)])
            history_str = f"--- PREVIOUS CONTEXT (Last {len(context_history)} Packets) ---\n{history_str}\n--------------------------------------------"

        prompt = f"""
        You are an AI Security Sentinel powered by Gemini 3.0. 
        Your job is to analyze the sequence of events and the specific code payload for malicious intent.
        
        {history_str}
        
        CURRENT PAYLOAD TO ANALYZE:
        {code}
        
        INSTRUCTIONS:
        1. Context Matters: Look for multi-step attacks (e.g., establishing env vars then using them).
        2. Analyze the 'CURRENT PAYLOAD'.
        3. Respond with a single SENTENCE starting with "REASONING:". 
           Example: "REASONING: Safe variable assignment detected." or "REASONING: Malicious RCE attempt via subprocess detected."
        """
        
        response = client.models.generate_content(
            model='gemini-3-flash-preview', 
            contents=prompt
        )
        
        full_text = response.text.strip()
        
        # Parse standard "REASONING:" format
        analysis = full_text
        if "REASONING:" in full_text:
            analysis = full_text.split("REASONING:")[1].strip()
            
        analysis_lower = analysis.lower()
        is_safe = False
        safe_keywords = ["benign", "standard", "clean", "authorized", "safe"]
        
        if any(k in analysis_lower for k in safe_keywords) and "unsafe" not in analysis_lower:
            is_safe = True
            
        status = "ALLOW" if is_safe else "BLOCK"
        
        result = {"status": status, "analysis": analysis, "source": "GEMINI_API"}
        
        # CACHE IT!
        RUNTIME_CACHE[normalized_code] = result
        
        return result

    except Exception as e:
        # FAIL-SAFE: If API is unreachable, we must BLOCK unknown traffic.
        return {
            "status": "ERROR", 
            "analysis": f"FAIL-CLOSED: API Outage/Error: {str(e)}", 
            "source": "API_ERROR"
        }
