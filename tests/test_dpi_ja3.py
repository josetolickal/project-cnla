"""
Unit & Integration Tests for Phase 3: Deep Packet Inspection & TLS JA3 Fingerprinting
"""

import unittest
from src.dpi_engine import DPIEngine, DPI_ENGINE, generate_synthetic_tls_handshake


class TestDPIAndJA3(unittest.TestCase):
    def setUp(self):
        self.engine = DPIEngine()

    def test_parse_cobalt_strike_handshake(self):
        pkt = generate_synthetic_tls_handshake(malware_profile="Cobalt Strike Beacon")
        result = self.engine.inspect_packet_payload(pkt)

        self.assertTrue(result["is_tls"])
        self.assertEqual(result["tls_version"], "TLS 1.2")
        self.assertTrue(result["is_threat"])
        self.assertIn("Cobalt Strike", result["threat_name"])
        self.assertEqual(result["ja3_hash"], "f7afdc93a493feb7b8abba161b61c228")

    def test_parse_trickbot_handshake(self):
        pkt = generate_synthetic_tls_handshake(malware_profile="TrickBot Banking Trojan")
        result = self.engine.inspect_packet_payload(pkt)

        self.assertTrue(result["is_tls"])
        self.assertTrue(result["is_threat"])
        self.assertIn("TrickBot", result["threat_name"])
        self.assertEqual(result["ja3_hash"], "ab80e5af92ad6af2a2df314090d8bc94")

    def test_parse_benign_chrome_handshake(self):
        pkt = generate_synthetic_tls_handshake(malware_profile=None)
        result = self.engine.inspect_packet_payload(pkt)

        self.assertTrue(result["is_tls"])
        self.assertFalse(result["is_threat"])
        self.assertIn("Chrome", result["threat_name"])
        self.assertIsNotNone(result["ja3_hash"])
        self.assertIn("secure-api.corp.internal", result.get("sni", ""))

    def test_non_tls_payload_handled_gracefully(self):
        dummy_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = self.engine.inspect_packet_payload(dummy_data)
        self.assertFalse(result["is_tls"])
        self.assertFalse(result["is_threat"])
        self.assertIsNone(result["ja3_hash"])


if __name__ == "__main__":
    unittest.main()
