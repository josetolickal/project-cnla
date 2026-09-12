"""
Unit & Integration Tests for Phase 1: Real-Time Server-Sent Events (SSE) Streaming
"""

import json
import unittest
from src.app import app, SSEBroadcaster, SSE_MANAGER


class TestSSEStream(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.broadcaster = SSEBroadcaster()

    def test_sse_broadcaster_subscribe_and_broadcast(self):
        q = self.broadcaster.subscribe()
        self.assertIn(q, self.broadcaster.subscribers)

        sample_event = {"id": 999, "attack_type": "TestDDoS", "is_malicious": 1}
        self.broadcaster.broadcast(sample_event, event_name="threat_event")

        msg = q.get(timeout=1.0)
        self.assertTrue(msg.startswith("event: threat_event\n"))
        self.assertIn('"id": 999', msg)
        self.assertIn('"attack_type": "TestDDoS"', msg)

        self.broadcaster.unsubscribe(q)
        self.assertNotIn(q, self.broadcaster.subscribers)

    def test_sse_stream_endpoint_connects(self):
        response = self.client.get("/api/stream")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/event-stream", response.headers.get("Content-Type", ""))
        self.assertEqual(response.headers.get("Cache-Control"), "no-cache")


if __name__ == "__main__":
    unittest.main()
