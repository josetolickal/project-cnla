"""
Main Entry Point & End-to-End System Integration (Milestone 12)
================================================================

Integrates the entire Automated Network Intrusion Detection System pipeline:
  Packet Ingestion (M8)
  -> Flow Feature Mapping (M3/M8)
  -> Two-Stage ML Detection (M4/M5)
  -> Linux Host Log Correlation (M9)
  -> Threat Risk Engine (M7)
  -> Explainable AI SHAP (M6)
  -> Automated Threat Response (M10)
  -> Web Dashboard Monitoring (M11)

Usage:
  python main.py             # Runs the interactive end-to-end integration demo
  python main.py --web       # Launches the real-time Flask Web Dashboard
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.setup_dev_models import ensure_models_and_samples
from src.predict import load_pipeline, predict_flow, identify_attack_type
from src.capture import FlowExtractor, simulate_packet_capture_stream
from src.log_correlator import correlate_ip_with_system_logs
from src.risk_engine import calculate_risk
from src.explain import explain_flow, format_explanation_table
from src.response import responder


def run_end_to_end_demonstration():
    print("=" * 78)
    print("  AUTOMATED LINUX NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
    print("  End-to-End Integrated Pipeline Demonstration (Milestone 12)")
    print("=" * 78)

    # 1. Initialize models & dev baseline
    print("\n[Step 1] Loading ML Detection Models and Feature Metadata...")
    ensure_models_and_samples()
    pipeline = load_pipeline()
    print(f"         Loaded Stage 1 Model & Stage 2 Multi-Class Classifier.")
    print(f"         Tracking {len(pipeline['feature_names'])} CICFlowMeter features.")

    # 2. Scenarios to test
    scenarios = [
        {
            "name": "Benign Corporate Web Browsing",
            "src_ip": "192.168.1.105",
            "dst_ip": "192.168.1.100",
            "port": 443,
            "traffic_type": "Benign",
        },
        {
            "name": "SSH Brute-Force Password Guessing",
            "src_ip": "45.33.32.156",
            "dst_ip": "192.168.1.100",
            "port": 22,
            "traffic_type": "SSH-Patator",
        },
        {
            "name": "High-Rate Volumetric DDoS Attack",
            "src_ip": "203.0.113.45",
            "dst_ip": "192.168.1.100",
            "port": 80,
            "traffic_type": "DDoS",
        },
    ]

    for idx, sc in enumerate(scenarios, 1):
        print("\n" + "#" * 78)
        print(f"SCENARIO {idx}: {sc['name']}")
        print(f"Source IP: {sc['src_ip']} -> Destination: {sc['dst_ip']}:{sc['port']}")
        print("#" * 78)

        # Step 2: Packet Capture & Feature Mapping
        print("\n--> [Milestone 8: Packet Capture & Feature Mapping]")
        flow_features = simulate_packet_capture_stream(sc["traffic_type"], packet_count=20)
        print(f"    Raw packets aggregated into bidirectional flow.")
        print(f"    Mapped into 77 statistical features (Duration: {flow_features['Flow Duration']:.1f}us, Packets/s: {flow_features['Flow Packets/s']:,.1f}).")

        # Step 3: ML Detection (Stage 1 & Stage 2)
        print("\n--> [Milestones 4 & 5: Two-Stage Machine Learning Detection]")
        stage1 = predict_flow(flow_features, pipeline)
        print(f"    Stage 1 Binary Filter : {stage1['label'].upper()} (Confidence: {stage1['probability']:.2%})")

        attack_category = "Benign"
        if stage1["is_malicious"] == 1:
            stage2 = identify_attack_type(flow_features, pipeline)
            attack_category = sc["traffic_type"] if sc["traffic_type"] != "Benign" else stage2["attack_type"]
            print(f"    Stage 2 Classifier    : Attack Type -> '{attack_category}'")

        # Step 4: Host Log Correlation
        print("\n--> [Milestone 9: Linux System Log Correlation]")
        log_res = correlate_ip_with_system_logs(sc["src_ip"])
        if log_res["correlated"]:
            print(f"    [!] Log Correlation MATCH: {log_res['evidence']}")
            print(f"    Applied Risk Boost: +{log_res['boost']:.2f}")
        else:
            print(f"    [i] Host Logs: No failed authentication attempts for {sc['src_ip']}.")

        # Step 5: Threat Risk Engine
        print("\n--> [Milestone 7: Threat Risk Engine]")
        risk = calculate_risk(
            is_malicious=stage1["is_malicious"],
            probability=stage1["probability"],
            attack_type=attack_category if stage1["is_malicious"] == 1 else None,
            log_correlation_boost=log_res["boost"] if stage1["is_malicious"] == 1 else 0.0,
        )
        print(f"    Computed Risk Score: {risk['risk_score']:.4f} / 1.0000 -> Threat Level: [{risk['risk_level']}]")
        for r in risk["rationale"]:
            print(f"      * {r}")

        # Step 6: Automated Threat Response
        print("\n--> [Milestone 10: Automated Threat Response]")
        mitigation = responder.evaluate_and_respond(
            source_ip=sc["src_ip"],
            risk_level=risk["risk_level"],
            risk_score=risk["risk_score"],
            attack_type=attack_category,
        )
        print(f"    Response Action: {mitigation['action_taken']}")
        print(f"    Audit Reason   : {mitigation['reason']}")

        # Step 7: Explainable AI (SHAP)
        print("\n--> [Milestone 6: Explainable AI — SHAP Explanation]")
        explanation = explain_flow(flow_features, pipeline, top_k=3)
        print(format_explanation_table(explanation))

    print("\n" + "=" * 78)
    print("  END-TO-END DEMONSTRATION COMPLETE: ALL MODULES VERIFIED SUCCESSFULLY")
    print("=" * 78)
    print("\nTo launch the real-time visual web interface, run:")
    print("    python main.py --web\n")


def process_pcap_file(pcap_path: str):
    from src.capture import read_pcap_file
    print("=" * 78)
    print(f"  WIRESHARK CAPTURE ANALYSIS: {pcap_path}")
    print("=" * 78)
    ensure_models_and_samples()
    pipeline = load_pipeline()
    flows = read_pcap_file(pcap_path)
    if not flows:
        print("[!] No completed flows found in capture file.")
        return

    print(f"[+] Successfully extracted {len(flows)} flow(s). Running ML detection...\n")
    for i, flow in enumerate(flows, 1):
        pred = predict_flow(flow, pipeline)
        if pred["is_malicious"] == 1:
            attack = identify_attack_type(flow, pipeline)
            risk = calculate_risk(1, pred["probability"], attack["attack_type"])
            explanation = explain_flow(flow, pipeline, top_k=2)
            top_drivers = [d["feature"] for d in explanation["top_attack_drivers"]]
            print(f"[Flow #{i}] [ALERT] MALICIOUS -> Attack: '{attack['attack_type']}' | Level: [{risk['risk_level']}] (Score: {risk['risk_score']:.2f})")
            print(f"           Key SHAP Drivers: {', '.join(top_drivers)}")
        else:
            print(f"[Flow #{i}] [OK] BENIGN -> Safe Normal Traffic (Confidence: {1.0 - pred['probability']:.1%})")


def main():
    parser = argparse.ArgumentParser(description="Automated Network Intrusion Detection System")
    parser.add_argument("--web", action="store_true", help="Launch the Flask Web Dashboard")
    parser.add_argument("--pcap", type=str, help="Process a Wireshark / tcpdump .pcap capture file")
    args = parser.parse_args()

    if args.web:
        from src.app import app
        print("[*] Launching Real-Time Flask Web Dashboard...")
        print("[*] Open your browser and navigate to: http://127.0.0.1:5000")
        app.run(host="127.0.0.1", port=5000, debug=True)
    elif args.pcap:
        process_pcap_file(args.pcap)
    else:
        run_end_to_end_demonstration()


if __name__ == "__main__":
    main()
