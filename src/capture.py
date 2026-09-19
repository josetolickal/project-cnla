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

        # Wireshark packet inspection samples (stores up to 25 packets)
        self.packet_samples: List[Dict[str, Any]] = []

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

        # Store Wireshark-compatible packet breakdown
        if len(self.packet_samples) < 25:
            active_flags = [k for k, v in flags_dict.items() if v]
            flag_str = f"[{', '.join(active_flags)}]" if active_flags else ""
            proto_name = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else f"IP({self.protocol})")
            
            # Formulate Wireshark-style summary info string
            info_parts = []
            if flag_str:
                info_parts.append(flag_str)
            info_parts.append(f"Len={length}")
            if win_size > 0:
                info_parts.append(f"Win={win_size}")
            
            src_str = f"{self.src_ip}:{self.src_port}" if is_forward else f"{self.dst_ip}:{self.dst_port}"
            dst_str = f"{self.dst_ip}:{self.dst_port}" if is_forward else f"{self.src_ip}:{self.src_port}"
            
            ts_str = time.strftime("%H:%M:%S", time.localtime(timestamp)) + f".{int((timestamp % 1) * 1000):03d}"

            self.packet_samples.append({
                "no": len(self.packet_samples) + 1,
                "time": ts_str,
                "timestamp_raw": timestamp,
                "source": src_str,
                "destination": dst_str,
                "protocol": proto_name,
                "length": length,
                "info": " ".join(info_parts)
            })

    def to_cicids_features(self) -> Dict[str, Any]:
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
            "Destination Port": float(self.dst_port),
            "Flow Duration": float(duration_micro),
            "Total Fwd Packets": float(tot_fwd_pkts),
            "Total Backward Packets": float(tot_bwd_pkts),
            "Total Length of Fwd Packets": float(tot_fwd_bytes),
            "Total Length of Bwd Packets": float(tot_bwd_bytes),
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
            "Min Packet Length": pkt_min,
            "Max Packet Length": pkt_max,
            "Packet Length Mean": pkt_mean,
            "Packet Length Std": pkt_std,
            "Packet Length Variance": float(pkt_std**2),
            "FIN Flag Count": float(self.flags["FIN"]),
            "SYN Flag Count": float(self.flags["SYN"]),
            "RST Flag Count": float(self.flags["RST"]),
            "PSH Flag Count": float(self.flags["PSH"]),
            "ACK Flag Count": float(self.flags["ACK"]),
            "URG Flag Count": float(self.flags["URG"]),
            "CWE Flag Count": float(self.flags["CWE"]),
            "ECE Flag Count": float(self.flags["ECE"]),
            "Down/Up Ratio": float(tot_bwd_pkts / tot_fwd_pkts)
            if tot_fwd_pkts > 0
            else 0.0,
            "Average Packet Size": float(np.mean(all_lengths)) if all_lengths else 0.0,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Fwd Header Length.1": float(self.fwd_header_len),
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
            "Init_Win_bytes_forward": float(self.init_fwd_win_bytes),
            "Init_Win_bytes_backward": float(self.init_bwd_win_bytes),
            "act_data_pkt_fwd": float(tot_fwd_pkts),
            "min_seg_size_forward": float(self.fwd_header_len / tot_fwd_pkts)
            if tot_fwd_pkts > 0
            else 20.0,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }

        # Attach flow metadata and Wireshark packet inspection traces
        features["_packet_samples"] = list(self.packet_samples)
        features["_flow_key"] = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
        }

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
    ) -> Optional[Dict[str, Any]]:
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

    def flush_expired_flows(self, current_time: Optional[float] = None, force_all: bool = False) -> List[Dict[str, Any]]:
        """Flush flows that have been idle past flow_timeout_sec, or all active flows if force_all=True."""
        now = current_time or time.time()
        if force_all:
            expired_keys = list(self.active_flows.keys())
        else:
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


def process_scapy_packet(pkt: Any, extractor: FlowExtractor) -> Optional[Dict[str, float]]:
    """
    Parse a live Scapy network packet and feed it to the flow extractor.
    Returns the completed 77-feature dictionary if the flow finishes.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP
    except ImportError:
        return None

    if IP not in pkt:
        return None

    src_ip = str(pkt[IP].src)
    dst_ip = str(pkt[IP].dst)
    proto = int(pkt[IP].proto)
    length = len(pkt)
    timestamp = float(getattr(pkt, "time", time.time()))

    src_port = 0
    dst_port = 0
    flags = {}
    win_size = 0

    if TCP in pkt:
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        tcp_flags = pkt[TCP].flags
        flags = {
            "FIN": 1 if "F" in str(tcp_flags) else 0,
            "SYN": 1 if "S" in str(tcp_flags) else 0,
            "RST": 1 if "R" in str(tcp_flags) else 0,
            "PSH": 1 if "P" in str(tcp_flags) else 0,
            "ACK": 1 if "A" in str(tcp_flags) else 0,
            "URG": 1 if "U" in str(tcp_flags) else 0,
            "ECE": 1 if "E" in str(tcp_flags) else 0,
            "CWE": 1 if "C" in str(tcp_flags) else 0,
        }
        win_size = int(pkt[TCP].window)
    elif UDP in pkt:
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)

    return extractor.process_packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        length=length,
        timestamp=timestamp,
        flags=flags,
        win_size=win_size,
    )


def start_live_capture(
    interface: Optional[str] = None,
    packet_count: int = 50,
    flow_callback: Optional[Any] = None,
) -> List[Dict[str, float]]:
    """
    Listen on a physical network interface (e.g. eth0 / wlan0), aggregate
    packets into flows, and dispatch completed flows to the callback.
    Requires administrator/root privileges to access raw sockets.
    """
    try:
        from scapy.all import sniff
    except ImportError:
        print("[!] Scapy not installed. Run: pip install scapy")
        return []

    extractor = FlowExtractor(flow_timeout_sec=3.0)
    completed_flows = []

    def _packet_handler(pkt):
        flow = process_scapy_packet(pkt, extractor)
        if flow:
            completed_flows.append(flow)
            if flow_callback:
                flow_callback(flow)

    print(f"[*] Starting live sniffing on interface '{interface or 'default'}' (Count: {packet_count})...")
    sniff(iface=interface, prn=_packet_handler, count=packet_count, store=False)

    # Flush any remaining flows
    remaining = extractor.flush_expired_flows()
    completed_flows.extend(remaining)
    return completed_flows


def read_pcap_file(
    pcap_path: str,
    flow_callback: Optional[Any] = None,
) -> List[Dict[str, float]]:
    """
    Read packets from a Wireshark / tcpdump capture file (.pcap or .pcapng),
    aggregate them into bidirectional flows, and compute the 77 CICFlowMeter features.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    try:
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.utils import rdpcap
    except ImportError:
        print("[!] Scapy not installed. Run: pip install scapy")
        return []

    extractor = FlowExtractor(flow_timeout_sec=3.0)
    completed_flows = []

    print(f"[*] Reading Wireshark capture file: {pcap_path}...")
    packets = rdpcap(pcap_path)
    for pkt in packets:
        flow = process_scapy_packet(pkt, extractor)
        if flow:
            completed_flows.append(flow)
            if flow_callback:
                flow_callback(flow)

    remaining = extractor.flush_expired_flows(force_all=True)
    completed_flows.extend(remaining)
    print(f"[+] Extracted {len(completed_flows)} completed flow(s) from PCAP.")
    return completed_flows
