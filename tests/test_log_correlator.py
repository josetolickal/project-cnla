"""
Unit tests for Milestone 9 (Linux Log Correlation Module)
"""

import os
import tempfile
import unittest

from src.log_correlator import (
    correlate_ip_with_system_logs,
    record_test_auth_failure,
)
from src.risk_engine import calculate_risk


class TestLogCorrelator(unittest.TestCase):
    """Test Linux authentication log parsing and risk correlation."""

    def setUp(self):
        # Create a temporary log file for testing
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_log = os.path.join(self.temp_dir.name, "test_auth.log")
        with open(self.test_log, "w", encoding="utf-8") as fh:
            fh.write(
                "Sep  9 18:20:00 server sshd[100]: Failed password for invalid user admin from 198.51.100.50 port 3312 ssh2\n"
                "Sep  9 18:20:05 server sshd[101]: Failed password for root from 198.51.100.50 port 3314 ssh2\n"
                "Sep  9 18:20:10 server sshd[102]: Failed password for root from 198.51.100.50 port 3318 ssh2\n"
                "Sep  9 18:20:15 server sshd[103]: Accepted password for dev from 192.168.1.55 port 22 ssh2\n"
            )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_correlate_matching_ip(self):
        result = correlate_ip_with_system_logs("198.51.100.50", log_path=self.test_log)
        self.assertTrue(result["correlated"])
        self.assertEqual(result["failed_attempts"], 3)
        self.assertIn("root", result["targeted_users"])
        self.assertIn("admin", result["targeted_users"])
        self.assertGreater(result["boost"], 0.0)
        self.assertIn("Host Log Match", result["evidence"])

    def test_correlate_clean_ip(self):
        result = correlate_ip_with_system_logs("192.168.1.55", log_path=self.test_log)
        self.assertFalse(result["correlated"])
        self.assertEqual(result["failed_attempts"], 0)
        self.assertEqual(result["boost"], 0.0)

    def test_risk_engine_integration_with_log_boost(self):
        # Without log boost: SSH-Patator with P=0.70
        risk_base = calculate_risk(
            is_malicious=1,
            probability=0.70,
            attack_type="SSH-Patator",
            log_correlation_boost=0.0,
        )

        # Get correlation result from log
        log_res = correlate_ip_with_system_logs("198.51.100.50", log_path=self.test_log)
        self.assertTrue(log_res["correlated"])

        # With log boost
        risk_boosted = calculate_risk(
            is_malicious=1,
            probability=0.70,
            attack_type="SSH-Patator",
            log_correlation_boost=log_res["boost"],
        )

        self.assertGreater(risk_boosted["risk_score"], risk_base["risk_score"])
        self.assertTrue(
            any("System log correlation" in r for r in risk_boosted["rationale"])
        )


if __name__ == "__main__":
    unittest.main()
