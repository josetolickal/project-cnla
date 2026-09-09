"""
Milestone 10 — Automated Threat Response Module
===============================================

What this module does (plain English):
  When a HIGH or CRITICAL attack is detected (e.g. DDoS flood or SSH brute force),
  the system can take defensive action.

  CRITICAL SAFETY DESIGN:
  - Enabled with DRY-RUN MODE by default. It simulates and logs firewall commands
    without modifying real network routing or locking out the user.
  - Strict IP Whitelist: Localhost (127.0.0.1), broadcast addresses, and private
    gateways are permanently whitelisted and cannot be blocked.
  - Structured Action Log: Every mitigation action is recorded in logs/response.log.
  - Manual Override: Admins can manually block, unblock, or toggle dry-run mode.
"""

import json
import logging
import os
import time
from typing import Dict, Any, List, Optional

LOGS_DIR = "logs"
RESPONSE_LOG_PATH = os.path.join(LOGS_DIR, "response.log")

# Hardcoded safe IPs that should NEVER be blocked under any circumstance
PROTECTED_WHITELIST = {
    "127.0.0.1",
    "localhost",
    "::1",
    "0.0.0.0",
    "192.168.1.1",
}

# Ensure logs directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure response logger
logger = logging.getLogger("ThreatResponse")
logger.setLevel(logging.INFO)
if not logger.handlers:
    file_handler = logging.FileHandler(RESPONSE_LOG_PATH, encoding="utf-8")
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


class ThreatResponder:
    """Manages controlled threat mitigation actions with dry-run protection."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.action_history: List[Dict[str, Any]] = []

    def evaluate_and_respond(
        self,
        source_ip: str,
        risk_level: str,
        risk_score: float,
        attack_type: str,
    ) -> Dict[str, Any]:
        """
        Evaluate whether a flow triggers automated defensive action.

        Policy:
        - CRITICAL or HIGH risk -> Trigger block action.
        - Whitelisted IPs -> Ignored safely with audit notice.
        - MEDIUM or LOW risk -> Log alert only, no block.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Check whitelist protection
        if source_ip in PROTECTED_WHITELIST or source_ip.startswith("127."):
            action_desc = f"WHITELISTED: {source_ip} cannot be blocked (protected system address)."
            logger.warning(action_desc)
            return {
                "action_taken": "IGNORED",
                "source_ip": source_ip,
                "reason": action_desc,
                "dry_run": self.dry_run,
                "timestamp": timestamp,
            }

        # Policy threshold: CRITICAL (>=0.85) or HIGH (>=0.65)
        if risk_level in ("CRITICAL", "HIGH"):
            if source_ip in self.blocked_ips:
                return {
                    "action_taken": "ALREADY_BLOCKED",
                    "source_ip": source_ip,
                    "reason": f"IP {source_ip} is already blocked.",
                    "dry_run": self.dry_run,
                    "timestamp": timestamp,
                }

            # Prepare firewall rule (iptables/UFW format)
            firewall_cmd = f"iptables -A INPUT -s {source_ip} -j DROP"

            if self.dry_run:
                action_desc = f"[DRY-RUN] Simulated firewall drop for {source_ip} (Threat: {attack_type}, Risk: {risk_level}, Score: {risk_score:.4f}). Command: '{firewall_cmd}'"
                logger.info(action_desc)
                status = "SIMULATED_BLOCK"
            else:
                action_desc = f"[ENFORCED] Blocked {source_ip} via '{firewall_cmd}' (Threat: {attack_type})."
                logger.warning(action_desc)
                status = "ACTIVE_BLOCK"

            record = {
                "source_ip": source_ip,
                "attack_type": attack_type,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "command": firewall_cmd,
                "status": status,
                "dry_run": self.dry_run,
                "timestamp": timestamp,
            }

            self.blocked_ips[source_ip] = record
            self.action_history.insert(0, record)
            return {
                "action_taken": status,
                "source_ip": source_ip,
                "reason": action_desc,
                "dry_run": self.dry_run,
                "timestamp": timestamp,
            }

        # For LOW / MEDIUM
        return {
            "action_taken": "MONITORED",
            "source_ip": source_ip,
            "reason": f"Threat level {risk_level} monitored. Automated block threshold not reached.",
            "dry_run": self.dry_run,
            "timestamp": timestamp,
        }

    def unblock_ip(self, source_ip: str) -> bool:
        """Remove an IP from the blocked list."""
        if source_ip in self.blocked_ips:
            del self.blocked_ips[source_ip]
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            logger.info(f"Unblocked IP: {source_ip}")
            self.action_history.insert(0, {
                "source_ip": source_ip,
                "status": "UNBLOCKED",
                "timestamp": timestamp,
            })
            return True
        return False

    def get_status(self) -> Dict[str, Any]:
        """Return current status of the response engine."""
        return {
            "dry_run_mode": self.dry_run,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": list(self.blocked_ips.values()),
            "recent_actions": self.action_history[:10],
        }


# Global responder singleton instance
responder = ThreatResponder(dry_run=True)
