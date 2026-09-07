import logging
import json
import time
import uuid
import os
import sys

class Telemetry:
    def __init__(self, log_file=None, log_payloads=False):
        self.log_payloads = log_payloads
        
        # Metrics state
        self.metrics = {
            "total_requests": 0,
            "status_counts": {"ALLOW": 0, "BLOCK": 0, "ERROR": 0},
            "source_counts": {},
            "total_latency_ms": 0.0
        }
        
        # Setup structured logger
        self.logger = logging.getLogger("lobster_telemetry")
        self.logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers if instantiated multiple times
        if not self.logger.handlers:
            formatter = logging.Formatter('%(message)s') # We'll format as JSON strings
            
            # Console handler (stderr so it doesn't break MCP stdout)
            ch = logging.StreamHandler(sys.stderr)
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
            
            # Optional file handler
            if log_file:
                fh = logging.FileHandler(log_file)
                fh.setFormatter(formatter)
                self.logger.addHandler(fh)

    def log_decision(self, correlation_id, status, source, analysis, latency_ms, payload=None):
        """Log a security decision and update metrics."""
        self.metrics["total_requests"] += 1
        
        if status in self.metrics["status_counts"]:
            self.metrics["status_counts"][status] += 1
            
        self.metrics["source_counts"][source] = self.metrics["source_counts"].get(source, 0) + 1
        self.metrics["total_latency_ms"] += latency_ms
        
        log_entry = {
            "timestamp": time.time(),
            "correlation_id": correlation_id,
            "event": "SECURITY_DECISION",
            "status": status,
            "source": source,
            "latency_ms": round(latency_ms, 2),
            "analysis": analysis
        }
        
        if self.log_payloads and payload:
            log_entry["payload"] = payload
            
        self.logger.info(json.dumps(log_entry))

    def log_proxy_error(self, correlation_id, error_msg, payload_preview=None):
        """Log an infrastructure or proxy-level error."""
        log_entry = {
            "timestamp": time.time(),
            "correlation_id": correlation_id,
            "event": "PROXY_ERROR",
            "error": error_msg
        }
        if payload_preview:
            log_entry["payload_preview"] = payload_preview
            
        self.logger.error(json.dumps(log_entry))

    def export_metrics(self):
        """Return a snapshot of current operational metrics."""
        avg_latency = 0
        if self.metrics["total_requests"] > 0:
            avg_latency = self.metrics["total_latency_ms"] / self.metrics["total_requests"]
            
        return {
            "total_requests": self.metrics["total_requests"],
            "status_counts": self.metrics["status_counts"],
            "source_counts": self.metrics["source_counts"],
            "average_latency_ms": round(avg_latency, 2)
        }

    def print_summary(self):
        """Print a human-readable summary of metrics to stderr."""
        summary = self.export_metrics()
        msg = f"\n=== LOBSTER TELEMETRY SUMMARY ===\n"
        msg += f"Total Requests: {summary['total_requests']}\n"
        msg += f"Average Latency: {summary['average_latency_ms']} ms\n"
        msg += f"Decisions: ALLOW: {summary['status_counts']['ALLOW']} | BLOCK: {summary['status_counts']['BLOCK']} | ERROR: {summary['status_counts']['ERROR']}\n"
        msg += f"Sources:\n"
        for src, count in summary['source_counts'].items():
            msg += f"  - {src}: {count}\n"
        msg += "=================================\n"
        sys.stderr.write(msg)
        sys.stderr.flush()

# Global telemetry instance
_log_payloads = os.getenv("LOBSTER_LOG_PAYLOADS", "false").lower() == "true"
telemetry = Telemetry(log_payloads=_log_payloads)
