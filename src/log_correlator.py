"""
Milestone 9 — Linux System Log Correlation Module
=================================================

What this module does (plain English):
  A network intrusion detection system only sees packets on the wire.
  However, a true security analyst checks the HOST server as well:
  - If network traffic shows an SSH brute-force attempt (SSH-Patator) from IP 45.33.32.156,
    AND the Linux host authentication log (/var/log/auth.log) simultaneously shows
    multiple "Failed password for root from 45.33.32.156",
    then confidence in the intrusion is near 100%!

  This module cross-references network detections with host system logs.
  When correlated evidence is found, it calculates a risk boost (+0.10 to +0.20)
  that feeds into Milestone 7's calculate_risk(log_correlation_boost=...).

  Cross-platform design:
  - On Linux, it can inspect /var/log/auth.log, /var/log/secure, or journalctl.
  - On portable or test environments, it also monitors logs/auth.log.
"""

import os
import re
import time
from typing import Dict, Any, List, Optional

# Standard Linux log paths with fallback to project logs/auth.log
LINUX_AUTH_LOGS = [
    "/var/log/auth.log",       # Debian / Ubuntu
    "/var/log/secure",         # RHEL / CentOS / Arch default syslog
]
DEFAULT_LOCAL_AUTH_LOG = os.path.join("logs", "auth.log")

# Common SSH failure log patterns (OpenSSH standard syslog format)
FAILED_LOGIN_REGEX = re.compile(
    r"(?:Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})|"
    r"authentication failure;.*rhost=(?P<rhost>\d{1,3}(?:\.\d{1,3}){3}))"
)


def get_active_log_path(override_path: Optional[str] = None) -> str:
    """Return the most appropriate authentication log path available."""
    if override_path and os.path.exists(override_path):
        return override_path

    for system_path in LINUX_AUTH_LOGS:
        if os.path.exists(system_path) and os.access(system_path, os.R_OK):
            return system_path

    # Fallback to local project log
    os.makedirs(os.path.dirname(DEFAULT_LOCAL_AUTH_LOG), exist_ok=True)
    if not os.path.exists(DEFAULT_LOCAL_AUTH_LOG):
        # Create initial seed auth log for demonstration
        seed_sample_auth_log(DEFAULT_LOCAL_AUTH_LOG)
    return DEFAULT_LOCAL_AUTH_LOG


def seed_sample_auth_log(log_path: str) -> None:
    """Create a sample Linux auth.log with realistic brute-force records for demo."""
    sample_lines = [
        "Sep  9 18:21:04 server sshd[14201]: Failed password for invalid user admin from 45.33.32.156 port 48212 ssh2\n",
        "Sep  9 18:21:07 server sshd[14205]: Failed password for root from 45.33.32.156 port 48218 ssh2\n",
        "Sep  9 18:21:11 server sshd[14210]: Failed password for root from 45.33.32.156 port 48224 ssh2\n",
        "Sep  9 18:21:15 server sshd[14215]: Failed password for invalid user test from 45.33.32.156 port 48230 ssh2\n",
        "Sep  9 18:22:30 server sshd[14240]: Accepted password for developer from 192.168.1.105 port 51230 ssh2\n",
    ]
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.writelines(sample_lines)


def correlate_ip_with_system_logs(
    source_ip: str,
    log_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Search host authentication logs for failed login attempts originating from source_ip.

    Parameters
    ----------
    source_ip : str
        The IP address flagged in network traffic.
    log_path : Optional[str]
        Specific log file to parse; defaults to auto-detected path.

    Returns
    -------
    dict with keys:
        "correlated"      : bool (True if failed logins found for this IP)
        "failed_attempts" : int (number of failed login attempts found)
        "targeted_users"  : list of unique usernames attempted
        "boost"           : float (recommended risk score boost, e.g. 0.15)
        "evidence"        : str (human-readable evidence explanation)
    """
    active_path = get_active_log_path(log_path)
    if not os.path.exists(active_path):
        return {
            "correlated": False,
            "failed_attempts": 0,
            "targeted_users": [],
            "boost": 0.0,
            "evidence": "No host authentication logs available for correlation.",
        }

    failed_count = 0
    targeted_users = set()

    try:
        with open(active_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                match = FAILED_LOGIN_REGEX.search(line)
                if match:
                    ip = match.group("ip") or match.group("rhost")
                    user = match.group("user") or "unknown"
                    if ip == source_ip:
                        failed_count += 1
                        targeted_users.add(user)
    except Exception as exc:
        return {
            "correlated": False,
            "failed_attempts": 0,
            "targeted_users": [],
            "boost": 0.0,
            "evidence": f"Log read error: {exc}",
        }

    if failed_count > 0:
        # Calculate dynamic risk boost based on attempt volume
        # 1 attempt: +0.08, 3+ attempts: +0.15, 10+ attempts: +0.20
        if failed_count >= 10:
            boost = 0.20
        elif failed_count >= 3:
            boost = 0.15
        else:
            boost = 0.08

        users_str = ", ".join(f"'{u}'" for u in targeted_users)
        evidence = (
            f"Host Log Match: Found {failed_count} failed SSH login attempt(s) "
            f"from {source_ip} targeting account(s): {users_str}."
        )

        return {
            "correlated": True,
            "failed_attempts": failed_count,
            "targeted_users": list(targeted_users),
            "boost": boost,
            "evidence": evidence,
        }

    return {
        "correlated": False,
        "failed_attempts": 0,
        "targeted_users": [],
        "boost": 0.0,
        "evidence": f"No suspicious authentication activity found in host logs for {source_ip}.",
    }


def record_test_auth_failure(source_ip: str, username: str = "root") -> None:
    """Helper to append a simulated authentication failure to the local log."""
    path = get_active_log_path()
    timestamp = time.strftime("%b %d %H:%M:%S")
    entry = f"{timestamp} server sshd[{os.getpid()}]: Failed password for {username} from {source_ip} port 49152 ssh2\n"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(entry)
