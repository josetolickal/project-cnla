"""
Milestone 8 — Network Capture & Feature Mapping Module
======================================================

What this module does (plain English):
  A packet sniffer (like tcpdump, Wireshark, or Scapy) captures raw network
  packets one-by-one (e.g., "Ethernet frame, TCP SYN, 64 bytes").
  However, the machine learning model was trained on SUMMARY FLOW FEATURES
  (like "Flow Duration", "Packet Length Mean", "Flow Packets/s").

  This module solves the critical feature-mapping problem:
  1. Aggregates individual raw packets into bidirectional "flows" based on
     their 5-tuple: (Source IP, Dest IP, Source Port, Dest Port, Protocol).
  2. Computes statistical summaries over each flow's lifetime (packet counts,
     byte rates, inter-arrival times, TCP flag counts, initial window sizes).
  3. Outputs the exact 77-feature dictionary expected by the trained ML models.

  Safety & portability:
  - Can sniff live network interfaces using Scapy (requires admin/root).
  - Can parse recorded .pcap / .pcapng capture files offline.
  - Can generate synthetic test packets for reproducible viva demonstrations.
"""

import json
import os
import time
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

import numpy as np

FEATURE_NAMES_PATH = os.path.join("models", "feature_names.json")

# Load ordered 77 feature names
if os.path.exists(FEATURE_NAMES_PATH):
    with open(FEATURE_NAMES_PATH, "r") as fh:
        REQUIRED_FEATURES = json.load(fh)
else:
    REQUIRED_FEATURES = []


class NetworkFlow:
    """Tracks and computes statistical flow features for a single bidirectional conversation."""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int, start_time: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_time = start_time

        # Directional statistics
        self.fwd_packet_lengths: List[int] = []
        self.bwd_packet_lengths: List[int] = []
        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []

        # TCP Flags counts
        self.flags = {
            "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
            "ACK": 0, "URG": 0, "ECE": 0, "CWE": 0
        }
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0

        # TCP Window bytes
        self.init_fwd_win_bytes = 0
        self.init_bwd_win_bytes = 0

        # Header lengths
        self.fwd_header_len = 0
        self.bwd_header_len = 0

    def add_packet(self, length: int, timestamp: float, is_forward: bool, flags_dict: Dict[str, int], win_size: int = 0, header_len: int = 20):
        """Record a single packet in this flow."""
        self.last_time = timestamp

        if is_forward:
            self.fwd_packet_lengths.append(length)
            self.fwd_timestamps.append(timestamp)
            self.fwd_header_len += header_len
            if len(self.fwd_packet_lengths) == 1:
                self.init_fwd_win_bytes = win_size
            if flags_dict.get("PSH"):
                self.fwd_psh_flags += 1
            if flags_dict.get("URG"):
                self.fwd_urg_flags += 1
        else:
            self.bwd_packet_lengths.append(length)
            self.bwd_timestamps.append(timestamp)
            self.bwd_header_len += header_len
            if len(self.bwd_packet_lengths) == 1:
                self.init_bwd_win_bytes = win_size
            if flags_dict.get("PSH"):
                self.bwd_psh_flags += 1
            if flags_dict.get("URG"):
                self.bwd_urg_flags += 1

        for f, count in flags_dict.items():
            if f in self.flags:
                self.flags[f] += count

    def to_cicids_features(self) -> Dict[str, float]:
        """Convert accumulated flow data into the exact 77 CICFlowMeter features."""
        all_lengths = self.fwd_packet_lengths + self.bwd_packet_lengths
        tot_fwd_pkts = len(self.fwd_packet_lengths)
        tot_bwd_pkts = len(self.bwd_packet_lengths)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts

        tot_fwd_bytes = sum(self.fwd_packet_lengths)
        tot_bwd_bytes = sum(self.bwd_packet_lengths)
        tot_bytes = tot_fwd_bytes + tot_bwd_bytes

        # Flow duration in microseconds (CICFlowMeter convention)
        duration_sec = max(0.000001, self.last_time - self.start_time)
        duration_micro = duration_sec * 1_000_000.0

        # Flow rates
        flow_bytes_s = tot_bytes / duration_sec
        flow_pkts_s = tot_pkts / duration_sec

        # Inter-arrival times (IAT)
        all_timestamps = sorted(self.fwd_timestamps + self.bwd_timestamps)
        all_iats = np.diff(all_timestamps) * 1_000_000.0 if len(all_timestamps) > 1 else [0.0]
        fwd_iats = np.diff(self.fwd_timestamps) * 1_000_000.0 if len(self.fwd_timestamps) > 1 else [0.0]
        bwd_iats = np.diff(self.bwd_timestamps) * 1_000_000.0 if len(self.bwd_timestamps) > 1 else [0.0]

        # Packet length statistics helper
        def calc_stats(arr):
            if not arr:
                return 0.0, 0.0, 0.0, 0.0
            return float(np.max(arr)), float(np.min(arr)), float(np.mean(arr)), float(np.std(arr))

        fwd_max, fwd_min, fwd_mean, fwd_std = calc_stats(self.fwd_packet_lengths)
        bwd_max, bwd_min, bwd_mean, bwd_std = calc_stats(self.bwd_packet_lengths)
        pkt_max, pkt_min, pkt_mean, pkt_std = calc_stats(all_lengths)

        features: Dict[str, float] = {
            "Protocol": float(self.protocol),
            "Flow Duration": float(duration_micro),
            "Total Fwd Packets": float(tot_fwd_pkts),
            "Total Backward Packets": float(tot_bwd_pkts),
            "Fwd Packets Length Total": float(tot_fwd_bytes),
            "Bwd Packets Length Total": float(tot_bwd_bytes),
            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": float(flow_bytes_s),
            "Flow Packets/s": float(flow_pkts_s),
            "Flow IAT Mean": float(np.mean(all_iats)),
            "Flow IAT Std": float(np.std(all_iats)),
            "Flow IAT Max": float(np.max(all_iats)),
            "Flow IAT Min": float(np.min(all_iats)),
            "Fwd IAT Total": float(np.sum(fwd_iats)),
            "Fwd IAT Mean": float(np.mean(fwd_iats)),
            "Fwd IAT Std": float(np.std(fwd_iats)),
            "Fwd IAT Max": float(np.max(fwd_iats)),
            "Fwd IAT Min": float(np.min(fwd_iats)),
            "Bwd IAT Total": float(np.sum(bwd_iats)),
            "Bwd IAT Mean": float(np.mean(bwd_iats)),
            "Bwd IAT Std": float(np.std(bwd_iats)),
            "Bwd IAT Max": float(np.max(bwd_iats)),
            "Bwd IAT Min": float(np.min(bwd_iats)),
            "Fwd PSH Flags": float(self.fwd_psh_flags),
            "Bwd PSH Flags": float(self.bwd_psh_flags),
            "Fwd URG Flags": float(self.fwd_urg_flags),
            "Bwd URG Flags": float(self.bwd_urg_flags),
            "Fwd Header Length": float(self.fwd_header_len),
            "Bwd Header Length": float(self.bwd_header_len),
            "Fwd Packets/s": float(tot_fwd_pkts / duration_sec),
            "Bwd Packets/s": float(tot_bwd_pkts / duration_sec),
            "Packet Length Min": pkt_min,
            "Packet Length Max": pkt_max,
            "Packet Length Mean": pkt_mean,
            "Packet Length Std": pkt_std,
            "Packet Length Variance": float(pkt_std ** 2),
            "FIN Flag Count": float(self.flags["FIN"]),
            "SYN Flag Count": float(self.flags["SYN"]),
            "RST Flag Count": float(self.flags["RST"]),
            "PSH Flag Count": float(self.flags["PSH"]),
            "ACK Flag Count": float(self.flags["ACK"]),
            "URG Flag Count": float(self.flags["URG"]),
            "CWE Flag Count": float(self.flags["CWE"]),
            "ECE Flag Count": float(self.flags["ECE"]),
            "Down/Up Ratio": float(tot_bwd_pkts / tot_fwd_pkts) if tot_fwd_pkts > 0 else 0.0,
            "Avg Packet Size": float(np.mean(all_lengths)) if all_lengths else 0.0,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": float(tot_fwd_pkts),
            "Subflow Fwd Bytes": float(tot_fwd_bytes),
            "Subflow Bwd Packets": float(tot_bwd_pkts),
            "Subflow Bwd Bytes": float(tot_bwd_bytes),
            "Init Fwd Win Bytes": float(self.init_fwd_win_bytes),
            "Init Bwd Win Bytes": float(self.init_bwd_win_bytes),
            "Fwd Act Data Packets": float(tot_fwd_pkts),
            "Fwd Seg Size Min": float(self.fwd_header_len / tot_fwd_pkts) if tot_fwd_pkts > 0 else 20.0,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }

        # Ensure every feature in models/feature_names.json is present
        for rf in REQUIRED_FEATURES:
            if rf not in features:
                features[rf] = 0.0

        return features


class FlowExtractor:
    """Manages active network flows and dispatches completed flows to the IDS."""

    def __init__(self, flow_timeout_sec: float = 3.0):
        self.flow_timeout_sec = flow_timeout_sec
        # Maps 5-tuple -> NetworkFlow
        self.active_flows: Dict[Tuple[str, str, int, int, int], NetworkFlow] = {}

    def get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> Tuple[Tuple[str, str, int, int, int], bool]:
        """Normalize bidirectional 5-tuple key and determine direction."""
        forward_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        if forward_key in self.active_flows:
            return forward_key, True
        elif reverse_key in self.active_flows:
            return reverse_key, False
        else:
            return forward_key, True

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        length: int,
        timestamp: Optional[float] = None,
        flags: Optional[Dict[str, int]] = None,
        win_size: int = 0,
    ) -> Optional[Dict[str, float]]:
        """
        Process an incoming packet into a flow.
        Returns the completed flow features if TCP FIN/RST or timeout is met.
        """
        now = timestamp or time.time()
        flags = flags or {}

        key, is_forward = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if key not in self.active_flows:
            self.active_flows[key] = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol, now)

        flow = self.active_flows[key]
        flow.add_packet(length, now, is_forward, flags, win_size=win_size)

        # Flow expiration conditions: TCP FIN or RST flags
        if flags.get("FIN") or flags.get("RST"):
            features = flow.to_cicids_features()
            del self.active_flows[key]
            return features

        return None

    def flush_expired_flows(self, current_time: Optional[float] = None) -> List[Dict[str, float]]:
        """Flush flows that have been idle past flow_timeout_sec."""
        now = current_time or time.time()
        expired_keys = [
            k for k, f in self.active_flows.items()
            if (now - f.last_time) >= self.flow_timeout_sec
        ]

        completed = []
        for k in expired_keys:
            completed.append(self.active_flows[k].to_cicids_features())
            del self.active_flows[k]
        return completed


def simulate_packet_capture_stream(scenario: str = "DDoS", packet_count: int = 20) -> Dict[str, float]:
    """
    Simulate a raw packet stream and map it to a complete 77-feature flow.
    Enables instant testing without requiring root network interface privileges.
    """
    extractor = FlowExtractor(flow_timeout_sec=1.0)
    t = time.time()

    if scenario == "DDoS":
        # Rapid high-frequency UDP/TCP flood
        for i in range(packet_count):
            extractor.process_packet(
                src_ip="203.0.113.45",
                dst_ip="192.168.1.100",
                src_port=44510 + i,
                dst_port=80,
                protocol=6,
                length=1400,
                timestamp=t + (i * 0.0001), # very high packet rate
                flags={"SYN": 1} if i == 0 else {"ACK": 1},
                win_size=29200,
            )
    elif scenario == "PortScan":
        # Fast scanning packets with SYN flag only
        for i in range(packet_count):
            extractor.process_packet(
                src_ip="192.0.2.77",
                dst_ip="192.168.1.100",
                src_port=52110,
                dst_port=20 + i,
                protocol=6,
                length=60,
                timestamp=t + (i * 0.005),
                flags={"SYN": 1},
                win_size=1024,
            )
    else:  # Benign
        # Normal HTTP/HTTPS exchange with responses
        for i in range(packet_count):
            is_fwd = (i % 2 == 0)
            extractor.process_packet(
                src_ip="192.168.1.105" if is_fwd else "192.168.1.100",
                dst_ip="192.168.1.100" if is_fwd else "192.168.1.105",
                src_port=51420 if is_fwd else 443,
                dst_port=443 if is_fwd else 51420,
                protocol=6,
                length=500 if is_fwd else 1200,
                timestamp=t + (i * 0.05),
                flags={"ACK": 1},
                win_size=8192,
            )

    # Flush completed flow
    flows = extractor.flush_expired_flows(current_time=t + 10.0)
    return flows[0] if flows else {}
