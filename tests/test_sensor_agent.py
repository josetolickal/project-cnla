"""
Unit & Integration Tests for Phase 2: Distributed Multi-Sensor Sniffing & Ingestion
"""

import json
import unittest
from src.app import app, REGISTERED_SENSORS
from src.sensor_agent import SensorAgent


class TestDistributedSensor(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_sensor_registration_api(self):
        payload = {
            "sensor_id": "probe-test-01",
            "hostname": "test-host.local",
            "location": "Test Datacenter A",
            "interface": "eth1",
        }
        res = self.client.post("/api/sensor/register", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "REGISTERED")
        self.assertEqual(data["sensor_id"], "probe-test-01")
        self.assertIn("probe-test-01", REGISTERED_SENSORS)

    def test_sensor_heartbeat_api(self):
        # Register first
        self.client.post("/api/sensor/register", json={"sensor_id": "probe-hb-01"})
        
        hb_payload = {
            "sensor_id": "probe-hb-01",
            "packets_delta": 45,
            "flows_delta": 2,
        }
        res = self.client.post("/api/sensor/heartbeat", json=hb_payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "PONG")
        self.assertEqual(REGISTERED_SENSORS["probe-hb-01"]["packets_observed"], 45)

    def test_sensor_flow_ingest_api(self):
        from src.app import SAMPLE_FLOWS
        sample_flow = dict(SAMPLE_FLOWS["DDoS"])
        sample_flow["source_ip"] = "198.51.100.99"
        sample_flow["dest_ip"] = "10.0.0.5"
        sample_flow["dest_port"] = 80
        sample_flow["attack_type"] = "DDoS"

        ingest_payload = {
            "sensor_id": "probe-ingest-01",
            "location": "Cloud Edge Frankfurt",
            "flows": [sample_flow],
        }
        res = self.client.post("/api/sensor/ingest", json=ingest_payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["received_flows"], 1)

    def test_sensor_list_api(self):
        res = self.client.get("/api/sensors")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("sensors", data)
        self.assertGreaterEqual(data["total_sensors"], 1)

    def test_sensor_agent_class_initialization(self):
        agent = SensorAgent(
            server_url="http://localhost:5000",
            sensor_id="unit-test-agent",
            location="Unit Lab",
            interface="eth0",
        )
        self.assertEqual(agent.sensor_id, "unit-test-agent")
        self.assertEqual(agent.location, "Unit Lab")
        flow_record = agent._build_flow_record("10.0.0.1", "10.0.0.2", 443, "Benign")
        self.assertEqual(flow_record["source_ip"], "10.0.0.1")
        self.assertEqual(flow_record["dest_port"], 443)


if __name__ == "__main__":
    unittest.main()
