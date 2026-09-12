"""
Unit & Integration Tests for Phase 4: Automated PDF Incident Report Generation
"""

import unittest
from src.app import app, EVENT_HISTORY
from src.report_generator import generate_pdf_report
from src.response import responder


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_generate_pdf_report_binary(self):
        sample_events = EVENT_HISTORY[:5]
        resp_status = responder.get_status()
        pdf_bytes = generate_pdf_report(sample_events, resp_status)

        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 1000)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_pdf_report_endpoint(self):
        res = self.client.get("/api/report/pdf")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("Content-Type"), "application/pdf")
        self.assertIn("attachment", res.headers.get("Content-Disposition", ""))
        self.assertTrue(res.data.startswith(b"%PDF"))

    def test_report_summary_endpoint(self):
        res = self.client.get("/api/report/summary")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_analyzed_flows", data)
        self.assertIn("malicious_detected", data)
        self.assertIn("registered_sensors", data)


if __name__ == "__main__":
    unittest.main()
