import re

class IronDome:
    """
    Tier 0 Security Layer: The Iron Dome
    Blocks known high-risk logic patterns using regex heuristics.
    Zero Latency. Zero Dependency.
    """
    
    PATTERNS = {
        "CRITICAL_RCE": [
            r"rm\s+-(?:r|f|rf|fr)\s+/",  # rm -rf /
            r"mkfs\.[a-z]+\s+/dev/",    # Formatting drives
            r":\(\)\{ :\|:& \};:",      # Fork bomb
            r"dd\s+if=/dev/zero",       # Disk wiping
            r"chmod\s+777\s+/",         # Root permission grant
            r"encrypt_files",           # Ransomware heuristic
            r"cryptography.*encrypt"    # Ransomware heuristic
        ],
        "CRITICAL_NET": [
            r"wget\s+http",             # Unsecured download
            r"curl\s+http",             # Unsecured download
            r"nc\s+-e\s+/bin/sh",       # Netcat reverse shell
            r"/dev/tcp/\d+\.\d+\.\d+\.\d+", # Bash reverse shell
            r"socket\.gethostbyname",   # DNS exfil specific check
            r"socket\.socket",          # Raw socket creation
            r"socket\.connect",         # Socket connection
            r"SELECT\s+\*\s+FROM",      # SQL Injection (Crude)
            r"cursor\.execute.*f'.*'"   # SQL Injection (f-string)
        ],
        "SUSPICIOUS_OBFUSCATION": [
            r"base64\.b64decode",       # Base64 decoding
            r"eval\(",                  # Eval usage
            r"exec\("                   # Exec usage
        ]
    }

    # Pre-compile patterns at class load time for O(1) Access overhead (vs O(N) compilation)
    COMPILED_PATTERNS = {
        threat_type: [re.compile(p, re.IGNORECASE) for p in patterns]
        for threat_type, patterns in PATTERNS.items()
    }

    GREEN_PATTERNS = {
        "SAFE_PRINT": [r"print\(\s*(?:'[^']*'|\"[^\"]*\"|\d+(?:\.\d+)?)\s*\)"],
        "SAFE_IMPORT": [r"import\s+(math|json|time|datetime|random|uuid|logging)"],
        "SAFE_MATH": [r"math\.[a-z]+", r"\d+\s*[\+\-\*\/]\s*\d+"],
        "SAFE_ASSIGNMENT": [r"^[a-z_][a-z0-9_]*\s*=\s*[0-9]+$", r"^[a-z_][a-z0-9_]*\s*=\s*['\"].*['\"]$"]
    }

    COMPILED_GREEN_PATTERNS = {
        safety_type: [re.compile(p, re.IGNORECASE) for p in patterns]
        for safety_type, patterns in GREEN_PATTERNS.items()
    }

    @staticmethod
    def scan(code_snippet: str):
        if not code_snippet:
            return None
            
        # Check all patterns using pre-compiled regex objects
        for threat_type, patterns in IronDome.COMPILED_PATTERNS.items():
            for pattern in patterns:
                # Optimized search using compiled object
                if pattern.search(code_snippet):
                    return {
                        "status": "BLOCKED",
                        "analysis": f"IRON DOME (Tier 0): Blocked by heuristic signature for {threat_type}."
                    }
        
        return None

    @staticmethod
    def scan_allowlist(code_snippet: str):
        """
        Green Dome (Tier 0.5):
        Checks for known safe patterns to bypass expensive API calls.
        """
        if not code_snippet: 
            return None

        # Quick check for obviously safe patterns
        for safety_type, patterns in IronDome.COMPILED_GREEN_PATTERNS.items():
            for pattern in patterns:
                if pattern.fullmatch(code_snippet.strip()) or pattern.search(code_snippet):
                     return {
                        "status": "CLEAN",
                        "analysis": f"GREEN DOME (Tier 0.5): Approved by heuristic allowlist for {safety_type}."
                    }
        return None
