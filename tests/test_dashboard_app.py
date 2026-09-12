"""
Unit and integration tests for Milestone 11 Flask Dashboard
"""

import json
import unittest

from src.app import app


class TestDashboardApp(unittest.TestCase):
    """Test Flask dashboard routes and API endpoints."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_index_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Automated Linux NIDS", response.data)

    def test_api_status(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "OPERATIONAL")
        self.assertIn("total_flows", data)
        self.assertIn("responder", data)

    def test_api_events(self):
        response = self.client.get("/api/events")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("events", data)
        self.assertIsInstance(data["events"], list)
        self.assertGreater(len(data["events"]), 0)

    def test_api_simulate_benign(self):
        response = self.client.post(
            "/api/simulate",
            data=json.dumps({"scenario": "Benign"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["is_malicious"], 0)
        self.assertEqual(data["risk_level"], "LOW")
        self.assertIn("summary", data)

    def test_api_simulate_ddos(self):
        response = self.client.post(
            "/api/simulate",
            data=json.dumps({"scenario": "DDoS"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["is_malicious"], 1)
        self.assertEqual(data["risk_level"], "CRITICAL")
        self.assertGreaterEqual(data["risk_score"], 0.85)

    def test_toggle_dry_run(self):
        response = self.client.post("/api/mitigation/toggle_dry_run")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("dry_run_mode", data)

    def test_wireshark_sample_pcaps_listing(self):
        response = self.client.get("/api/sample_pcaps")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("samples", data)
        self.assertIsInstance(data["samples"], list)

    def test_wireshark_load_sample_pcap(self):
        response = self.client.post(
            "/api/load_sample_pcap",
            data=json.dumps({"filename": "syn_flood_ddos.pcap"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertGreater(data["flows_processed"], 0)

    def test_wireshark_live_capture_controls(self):
        res_start = self.client.post(
            "/api/capture/start",
            data=json.dumps({"interface": "eth0"}),
            content_type="application/json",
        )
        self.assertEqual(res_start.status_code, 200)
        res_status = self.client.get("/api/capture/status")
        self.assertEqual(res_status.status_code, 200)
        res_stop = self.client.post("/api/capture/stop")
        self.assertEqual(res_stop.status_code, 200)

    def test_events_contain_wireshark_packets(self):
        response = self.client.get("/api/events?limit=5")
        self.assertEqual(response.status_code, 200)
        events = response.get_json()["events"]
        self.assertGreater(len(events), 0)
        first_event = events[0]
        self.assertIn("packets", first_event)
        self.assertIsInstance(first_event["packets"], list)
        if first_event["packets"]:
            pkt = first_event["packets"][0]
            self.assertIn("no", pkt)
            self.assertIn("protocol", pkt)
            self.assertIn("length", pkt)


if __name__ == "__main__":
    unittest.main()
