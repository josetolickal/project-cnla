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


if __name__ == "__main__":
    unittest.main()
