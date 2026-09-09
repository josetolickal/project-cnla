"""
Tests for Milestone 6 (SHAP Explainability) and Milestone 7 (Threat Risk Engine)
"""

import unittest
import numpy as np

from src.risk_engine import (
    calculate_risk,
    map_score_to_level,
    get_attack_severity,
    ATTACK_SEVERITY_WEIGHTS,
)
from src.predict import load_pipeline
from src.explain import explain_flow, format_explanation_table
from src.setup_dev_models import ensure_models_and_samples


class TestRiskEngine(unittest.TestCase):
    """Test deterministic calculations in the Risk Engine."""

    def test_benign_risk(self):
        result = calculate_risk(is_malicious=0, probability=0.05, attack_type="Benign")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertLess(result["risk_score"], 0.35)
        self.assertEqual(result["severity"], 0.0)

    def test_ddos_critical_risk(self):
        result = calculate_risk(is_malicious=1, probability=0.99, attack_type="DDoS")
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertGreaterEqual(result["risk_score"], 0.85)

    def test_portscan_medium_risk(self):
        result = calculate_risk(is_malicious=1, probability=0.80, attack_type="PortScan")
        # (0.80 * 0.6) + (0.30 * 0.4) = 0.48 + 0.12 = 0.60 -> MEDIUM
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertAlmostEqual(result["risk_score"], 0.60, places=2)

    def test_log_correlation_boost(self):
        result_without = calculate_risk(is_malicious=1, probability=0.70, attack_type="SSH-Patator")
        result_with = calculate_risk(is_malicious=1, probability=0.70, attack_type="SSH-Patator", log_correlation_boost=0.15)
        self.assertGreater(result_with["risk_score"], result_without["risk_score"])
        self.assertTrue(any("System log correlation" in r for r in result_with["rationale"]))


class TestSHAPExplainability(unittest.TestCase):
    """Test SHAP tree explainer integration and feature explanations."""

    @classmethod
    def setUpClass(cls):
        ensure_models_and_samples()
        cls.pipeline = load_pipeline()
        cls.feature_names = cls.pipeline["feature_names"]

    def test_explain_benign_flow(self):
        flow = {f: 10.0 for f in self.feature_names}
        flow["Flow Packets/s"] = 5.0
        flow["Flow Bytes/s"] = 200.0
        
        explanation = explain_flow(flow, self.pipeline, top_k=3)
        self.assertIn("label", explanation)
        self.assertIn("probability", explanation)
        self.assertIn("top_benign_drivers", explanation)
        self.assertIn("summary", explanation)
        self.assertIsInstance(explanation["top_benign_drivers"], list)

        table_str = format_explanation_table(explanation)
        self.assertIn("BENIGN", table_str)

    def test_explain_malicious_flow(self):
        flow = {f: 10.0 for f in self.feature_names}
        flow["Flow Packets/s"] = 18500.0
        flow["Flow Bytes/s"] = 900000.0
        flow["Init Fwd Win Bytes"] = 29200.0

        explanation = explain_flow(flow, self.pipeline, top_k=3)
        self.assertEqual(explanation["label"], "malicious")
        self.assertEqual(explanation["is_malicious"], 1)
        self.assertGreater(len(explanation["top_attack_drivers"]), 0)

        # Check that high packet rate or window bytes is identified as a top driver
        driver_features = [d["feature"] for d in explanation["top_attack_drivers"]]
        self.assertTrue(
            "Init Fwd Win Bytes" in driver_features or "Flow Bytes/s" in driver_features
        )


if __name__ == "__main__":
    unittest.main()
