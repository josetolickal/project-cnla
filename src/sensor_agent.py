"""
Phase 2: Distributed Multi-Sensor Sniffing Agent
================================================

Lightweight daemon deployed on remote Linux servers, cloud VMs, and edge gateways.
Captures live network traffic, reconstructs bidirectional 5-tuple flows, computes
77 statistical metrics, extracts TLS JA3 fingerprints via DPI, and securely streams
telemetry back to the Central SOC Management Dashboard.

Usage:
  python src/sensor_agent.py --sensor-id sensor-web-dmz --location "DMZ-Zone-A" --demo
  python src/sensor_agent.py --server http://192.168.1.100:5000 --interface eth0
"""

import argparse
import json
import os
import platform
import random
import sys
import threading
import time
from typing import Dict, Any, List, Optional
import urllib.request
import urllib.error

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.capture import FlowExtractor, process_scapy_packet
from src.dpi_engine import DPI_ENGINE


class SensorAgent:
    """Distributed network telemetry probe client."""

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:5000",
        sensor_id: Optional[str] = None,
        location: str = "Corporate-LAN",
        interface: str = "eth0",
        interval: float = 3.0,
    ):
        self.server_url = server_url.rstrip("/")
        self.sensor_id = sensor_id or f"sensor-{platform.node()}"
        self.location = location
        self.interface = interface
        self.interval = interval
        self.is_running = False
        self.packets_observed = 0
        self.flows_forwarded = 0
        self.lock = threading.Lock()
        self.extractor = FlowExtractor(flow_timeout_sec=2.5)

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send HTTP POST request to Central SOC server."""
        url = f"{self.server_url}{endpoint}"
        try:
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data_bytes,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"NIDS-Sensor-Agent/1.0 ({self.sensor_id})",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    body = response.read().decode("utf-8")
                    return json.loads(body)
        except Exception as e:
            print(f"[!] Communication failure with SOC ({url}): {e}")
            return None

    def _build_flow_record(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        attack_type: str = "Benign",
    ) -> Dict[str, Any]:
        """Construct synthetic flow record for probe verification or testing."""
        return {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "Destination Port": dst_port,
            "Flow Duration": 150000,
            "Total Fwd Packets": 8,
            "Total Backward Packets": 6,
            "attack_type": attack_type,
            "sensor_id": self.sensor_id,
            "location": self.location,
        }

    def register(self) -> bool:
        """Register probe with the Central SOC dashboard."""
        payload = {
            "sensor_id": self.sensor_id,
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "location": self.location,
            "interface": self.interface,
            "timestamp": time.time(),
        }
        res = self._post("/api/sensor/register", payload)
        if res and str(res.get("status")).upper() == "REGISTERED":
            print(f"[+] Successfully registered with Central SOC as '{self.sensor_id}' ({self.location})")
            return True
        else:
            print(f"[!] Warning: Could not register with SOC server at {self.server_url}. Retrying in background.")
            return False

    def send_heartbeat(self):
        """Transmit periodic liveness heartbeat and telemetry counters."""
        payload = {
            "sensor_id": self.sensor_id,
            "packets_observed": self.packets_observed,
            "flows_forwarded": self.flows_forwarded,
            "status": "ONLINE",
            "timestamp": time.time(),
        }
        self._post("/api/sensor/heartbeat", payload)

    def forward_flows(self, flows: List[Dict[str, Any]]):
        """Batch and forward reconstructed flows to Central SOC."""
        if not flows:
            return

        payload = {
            "sensor_id": self.sensor_id,
            "location": self.location,
            "flows": flows,
            "timestamp": time.time(),
        }
        res = self._post("/api/sensor/ingest", payload)
        if res and res.get("success"):
            with self.lock:
                self.flows_forwarded += len(flows)
            print(f"[{time.strftime('%H:%M:%S')}] Pushed {len(flows)} flow(s) to SOC -> Alerts Flagged: {res.get('malicious_detected', 0)}")

    def run_live_sniff(self, packet_count: int = 0):
        """Capture live interface packets using Scapy raw sockets on Linux."""
        try:
            from scapy.all import sniff
        except ImportError:
            print("[!] Scapy is required for live sniffing. Falling back to synthetic simulation stream.")
            self.run_demo_stream()
            return

        print(f"[*] Probe '{self.sensor_id}' listening on interface '{self.interface}'...")
        self.is_running = True

        def _packet_callback(pkt):
            if not self.is_running:
                return
            with self.lock:
                self.packets_observed += 1

            completed_flow = process_scapy_packet(pkt, self.extractor)
            if completed_flow:
                self.forward_flows([completed_flow])

        # Background heartbeat thread
        def _heartbeat_loop():
            while self.is_running:
                time.sleep(10.0)
                self.send_heartbeat()

        hb_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
        hb_thread.start()

        iface = None if self.interface in ("default", "any") else self.interface
        try:
            sniff(iface=iface, prn=_packet_callback, count=packet_count, store=False)
        except Exception as e:
            print(f"[!] Raw packet capture failed on '{iface}': {e}")
            print("[*] Switching to probe demo stream mode...")
            self.run_demo_stream()

    def run_demo_stream(self):
        """Simulate distributed network traffic with periodic intrusion events."""
        print(f"[*] Probe '{self.sensor_id}' running in simulated multi-sensor telemetry stream mode.")
        self.is_running = True

        sample_flows_path = os.path.join("data", "sample_flows.json")
        sample_flows = {}
        if os.path.exists(sample_flows_path):
            with open(sample_flows_path, "r") as fh:
                sample_flows = json.load(fh)

        scenarios = ["Benign", "Benign", "PortScan", "Benign", "SSH-Patator", "DDoS"]
        ip_map = {
            "Benign": "10.0.4.15",
            "PortScan": "198.51.100.22",
            "SSH-Patator": "45.33.32.156",
            "DDoS": "203.0.113.45",
        }

        counter = 0
        while self.is_running:
            time.sleep(self.interval)
            sc = random.choice(scenarios)
            raw_flow = sample_flows.get(sc, sample_flows.get("Benign", {}))
            if not raw_flow:
                continue

            flow_copy = dict(raw_flow)
            s_ip = ip_map.get(sc, "10.0.4.88")
            d_port = 22 if "SSH" in sc or "Port" in sc else 443

            # Inject sensor-specific 5-tuple key
            flow_copy["_flow_key"] = {
                "src_ip": s_ip,
                "dst_ip": "10.0.1.50",
                "src_port": random.randint(40000, 60000),
                "dst_port": d_port,
                "protocol": 6,
            }

            # If TLS/HTTPS scenario, attach synthetic DPI JA3 record
            if d_port == 443:
                is_c2 = (sc == "DDoS" or sc == "PortScan")
                tls_client = "CobaltStrike" if is_c2 else "Chrome"
                tls_bytes = DPI_ENGINE.generate_synthetic_tls_handshake(tls_client)
                flow_copy["_dpi_meta"] = DPI_ENGINE.inspect_payload(tls_bytes)

            with self.lock:
                self.packets_observed += random.randint(15, 60)

            self.forward_flows([flow_copy])

            counter += 1
            if counter % 3 == 0:
                self.send_heartbeat()

    def stop(self):
        """Terminate probe capture."""
        self.is_running = False
        print(f"[*] Probe '{self.sensor_id}' stopped.")


def main():
    parser = argparse.ArgumentParser(description="Distributed NIDS Sensor Probe Daemon")
    parser.add_argument("--server", type=str, default="http://127.0.0.1:5000", help="Central SOC Dashboard URL")
    parser.add_argument("--sensor-id", type=str, default=None, help="Unique Probe Sensor Name")
    parser.add_argument("--location", type=str, default="DMZ-Gateway-01", help="Network Subnet / Geographic Location")
    parser.add_argument("--interface", type=str, default="eth0", help="Network Interface to sniff")
    parser.add_argument("--demo", action="store_true", help="Run in continuous multi-sensor demo simulation mode")
    parser.add_argument("--interval", type=float, default=3.0, help="Push interval in seconds")
    args = parser.parse_args()

    agent = SensorAgent(
        server_url=args.server,
        sensor_id=args.sensor_id,
        location=args.location,
        interface=args.interface,
        interval=args.interval,
    )

    agent.register()

    try:
        if args.demo:
            agent.run_demo_stream()
        else:
            agent.run_live_sniff()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
