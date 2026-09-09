"""
Unit tests for Milestone 8 (Network Capture & Feature Mapping)
"""

import json
import os
import unittest

from src.capture import FlowExtractor, simulate_packet_capture_stream, FEATURE_NAMES_PATH
from src.predict import load_pipeline, predict_flow
from src.setup_dev_models import ensure_models_and_samples


class TestNetworkCapture(unittest.TestCase):
    """Test packet aggregation into bidirectional flows and CICIDS feature mapping."""

    @classmethod
    def setUpClass(cls):
        ensure_models_and_samples()
        cls.pipeline = load_pipeline()
        with open(FEATURE_NAMES_PATH, "r") as fh:
            cls.expected_features = json.load(fh)

    def test_flow_packet_aggregation(self):
        extractor = FlowExtractor(flow_timeout_sec=2.0)
        t = 1000.0

        # Fwd SYN packet
        fin_flow = extractor.process_packet(
            src_ip="10.0.0.5", dst_ip="10.0.0.1",
            src_port=12345, dst_port=80, protocol=6,
            length=64, timestamp=t, flags={"SYN": 1}, win_size=8192
        )
        self.assertIsNone(fin_flow)

        # Bwd SYN-ACK packet
        fin_flow = extractor.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.5",
            src_port=80, dst_port=12345, protocol=6,
            length=64, timestamp=t + 0.01, flags={"SYN": 1, "ACK": 1}, win_size=8192
        )
        self.assertIsNone(fin_flow)

        # Fwd FIN packet (terminates flow)
        completed_features = extractor.process_packet(
            src_ip="10.0.0.5", dst_ip="10.0.0.1",
            src_port=12345, dst_port=80, protocol=6,
            length=64, timestamp=t + 0.05, flags={"FIN": 1}
        )
        self.assertIsNotNone(completed_features)
        self.assertEqual(completed_features["Total Fwd Packets"], 2.0)
        self.assertEqual(completed_features["Total Backward Packets"], 1.0)
        self.assertEqual(completed_features["FIN Flag Count"], 1.0)
        self.assertEqual(completed_features["SYN Flag Count"], 2.0)

    def test_full_77_features_mapped(self):
        flow = simulate_packet_capture_stream("DDoS", packet_count=15)
        self.assertTrue(len(flow) >= 77)

        # Confirm every expected feature exists in the output dictionary
        for feature_name in self.expected_features:
            self.assertIn(feature_name, flow, f"Missing required feature: {feature_name}")

    def test_end_to_end_capture_to_prediction(self):
        flow = simulate_packet_capture_stream("Benign", packet_count=10)
        prediction = predict_flow(flow, self.pipeline)

        self.assertIn("label", prediction)
        self.assertIn("probability", prediction)
        self.assertIn("is_malicious", prediction)


if __name__ == "__main__":
    unittest.main()
