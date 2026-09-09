"""
Milestone 11 — Real-Time Flask Web Dashboard Backend
=====================================================

Provides the REST API and web application for the Automated Network Intrusion
Detection System. Connects ML predictions, SHAP explanations, risk scoring,
and controlled firewall response to a live, modern web interface.
"""

import json
import os
import random
import sys
import time
from typing import Dict, Any, List

# Ensure project root is in sys.path when run directly as python src/app.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, jsonify, render_template, request

from src.predict import load_pipeline, predict_flow, identify_attack_type
from src.explain import explain_flow
from src.risk_engine import calculate_risk
from src.response import responder
from src.log_correlator import correlate_ip_with_system_logs
from src.setup_dev_models import ensure_models_and_samples

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)

# Global in-memory storage for events and pipeline
ensure_models_and_samples()
pipeline = load_pipeline()

EVENT_HISTORY: List[Dict[str, Any]] = []
MAX_EVENT_HISTORY = 150
EVENT_COUNTER = 1

SAMPLE_DATA_PATH = os.path.join("data", "sample_flows.json")
with open(SAMPLE_DATA_PATH, "r") as fh:
    SAMPLE_FLOWS = json.load(fh)

IP_POOL = {
    "Benign": ["192.168.1.105", "192.168.1.112", "10.0.0.15"],
    "DDoS": ["203.0.113.45", "198.51.100.89", "185.220.101.5"],
    "PortScan": ["192.0.2.77", "198.51.100.12"],
    "SSH-Patator": ["45.33.32.156", "185.190.141.22"],
}

# ---------------------------------------------------------------------------
# Plain-English Human Friendly Translations for Non-Technical Users
# ---------------------------------------------------------------------------

def get_friendly_device_origin(ip: str) -> Dict[str, str]:
    """Translate cryptic IP addresses into human-readable device/network terms."""
    if ip in ("127.0.0.1", "localhost", "::1"):
        return {"name": "💻 This Computer (Self)", "category": "Internal Machine"}
    elif ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
        return {"name": f"🏠 Local Home/Office Device ({ip})", "category": "Trusted Local Wi-Fi"}
    elif ip.startswith("203.0.") or ip.startswith("198.51.") or ip.startswith("185."):
        return {"name": f"⚠️ Suspicious External Machine ({ip})", "category": "Public Internet (Untrusted)"}
    else:
        return {"name": f"🌐 External Computer ({ip})", "category": "Public Internet"}


FRIENDLY_ATTACK_TRANSLATIONS = {
    "Benign": {
        "title": "✅ Safe & Normal Activity",
        "badge": "SAFE",
        "description": "Normal, everyday internet activity such as loading web pages, watching video, or office work.",
        "advice": "Everything is running smoothly and safely. No action required.",
        "icon": "fa-circle-check",
        "color": "emerald",
    },
    "DDoS": {
        "title": "💥 Giant Traffic Flood Attack (DDoS)",
        "badge": "CRITICAL DANGER",
        "description": "An attacker is bombarding your computer with a massive flood of data in an attempt to crash your internet connection or freeze the machine.",
        "advice": "Danger Mitigated: Our system detected this overload and automatically blocked this computer. You do not need to do anything.",
        "icon": "fa-burst",
        "color": "red",
    },
    "SSH-Patator": {
        "title": "🔑 Password Guessing Attack (SSH)",
        "badge": "UNAUTHORIZED LOGIN",
        "description": "A remote machine is trying to break into your computer by guessing account passwords over and over in rapid succession.",
        "advice": "Action Recommendation: Make sure your computer user password is strong (at least 12 characters with letters, numbers, and symbols).",
        "icon": "fa-key",
        "color": "purple",
    },
    "FTP-Patator": {
        "title": "🔑 File Server Password Guessing",
        "badge": "UNAUTHORIZED LOGIN",
        "description": "Someone is repeatedly trying common passwords to break into your file storage folders.",
        "advice": "Action Recommendation: Use a strong passphrase and disable file sharing if you are not actively using it.",
        "icon": "fa-folder-lock",
        "color": "purple",
    },
    "PortScan": {
        "title": "🔍 Digital Peeping / Scanning",
        "badge": "RECONNAISSANCE",
        "description": "Someone is snooping around your network to check which 'doors and windows' (network ports) might have been accidentally left open.",
        "advice": "Informational: The outsider is just looking around. No system breach occurred. The system is actively keeping watch.",
        "icon": "fa-magnifying-glass",
        "color": "amber",
    },
    "DoS Hulk": {
        "title": "🛑 Heavy Server Overload Attempt",
        "badge": "OVERLOAD",
        "description": "An attacker is sending endless heavy requests to try to make your computer freeze and stop responding.",
        "advice": "The system identified the overload pattern and throttled the suspicious connection.",
        "icon": "fa-hand",
        "color": "orange",
    },
    "Bot": {
        "title": "🤖 Infected Botnet Computer",
        "badge": "HOSTILE BOT",
        "description": "A remote computer infected by hacker malware is attempting to recruit or probe your computer.",
        "advice": "The infected machine's requests were flagged and isolated.",
        "icon": "fa-robot",
        "color": "orange",
    },
}

DEFAULT_FRIENDLY_ATTACK = {
    "title": "⚠️ Suspicious Network Anomaly",
    "badge": "SUSPICIOUS",
    "description": "Unusual network communication that does not match standard everyday internet traffic.",
    "advice": "The activity was flagged and inspected for safety.",
    "icon": "fa-triangle-exclamation",
    "color": "amber",
}


def process_flow_event(
    flow_data: Dict[str, Any],
    source_ip: str,
    dest_ip: str = "192.168.1.100",
    dest_port: int = 80,
    forced_attack_type: str = None,
) -> Dict[str, Any]:
    """Process a single network flow through the complete IDS stack."""
    global EVENT_COUNTER

    # 1. ML Detection (Stage 1)
    pred = predict_flow(flow_data, pipeline)

    # 2. Attack Identification (Stage 2)
    attack_type = "Benign"
    confidence = pred["probability"]
    if pred["is_malicious"] == 1:
        if forced_attack_type:
            attack_type = forced_attack_type
        else:
            attack_res = identify_attack_type(flow_data, pipeline)
            attack_type = attack_res["attack_type"]
            confidence = attack_res["confidence"]

    # 3. Linux Host Log Correlation (Milestone 9)
    log_corr = correlate_ip_with_system_logs(source_ip)
    log_boost = log_corr["boost"] if pred["is_malicious"] == 1 else 0.0

    # 4. Threat Risk Engine (Milestone 7)
    risk = calculate_risk(
        is_malicious=pred["is_malicious"],
        probability=pred["probability"],
        attack_type=attack_type if pred["is_malicious"] == 1 else None,
        log_correlation_boost=log_boost,
    )

    # 5. Explainable AI (Milestone 6 SHAP)
    explanation = explain_flow(flow_data, pipeline, top_k=4)

    # 6. Automated Threat Response (Milestone 10)
    response_result = responder.evaluate_and_respond(
        source_ip=source_ip,
        risk_level=risk["risk_level"],
        risk_score=risk["risk_score"],
        attack_type=attack_type,
    )

    device_info = get_friendly_device_origin(source_ip)
    friendly_attack = FRIENDLY_ATTACK_TRANSLATIONS.get(attack_type, DEFAULT_FRIENDLY_ATTACK)

    # Simplified risk description for everyday users
    if risk["risk_level"] == "CRITICAL":
        simple_risk_label = "🔴 DANGEROUS ATTACK"
        simple_risk_color = "red"
    elif risk["risk_level"] == "HIGH":
        simple_risk_label = "🟠 HIGH RISK INCIDENT"
        simple_risk_color = "orange"
    elif risk["risk_level"] == "MEDIUM":
        simple_risk_label = "🟡 SUSPICIOUS ACTIVITY"
        simple_risk_color = "yellow"
    else:
        simple_risk_label = "🟢 SAFE & NORMAL"
        simple_risk_color = "emerald"

    # Simplified action status
    if response_result["action_taken"] in ("ACTIVE_BLOCK", "SIMULATED_BLOCK"):
        simple_mitigation = "🛡️ Blocked Automatically (Protected)"
    else:
        simple_mitigation = "👁️ Monitored (Safe)"

    event = {
        "id": EVENT_COUNTER,
        "timestamp": time.strftime("%H:%M:%S"),
        "source_ip": source_ip,
        "friendly_source": device_info["name"],
        "device_category": device_info["category"],
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "is_malicious": pred["is_malicious"],
        "label": pred["label"],
        "probability": pred["probability"],
        "attack_type": attack_type,
        "friendly_attack_title": friendly_attack["title"],
        "friendly_attack_badge": friendly_attack["badge"],
        "friendly_attack_desc": friendly_attack["description"],
        "friendly_attack_icon": friendly_attack["icon"],
        "action_advice": friendly_attack["advice"],
        "simple_risk_label": simple_risk_label,
        "simple_risk_color": simple_risk_color,
        "simple_mitigation": simple_mitigation,
        "confidence": round(confidence, 4),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_rationale": risk["rationale"],
        "log_correlation": log_corr,
        "summary": explanation["summary"],
        "top_attack_drivers": explanation["top_attack_drivers"],
        "top_benign_drivers": explanation["top_benign_drivers"],
        "mitigation_action": response_result["action_taken"],
        "mitigation_reason": response_result["reason"],
    }

    EVENT_COUNTER += 1
    EVENT_HISTORY.insert(0, event)
    if len(EVENT_HISTORY) > MAX_EVENT_HISTORY:
        EVENT_HISTORY.pop()

    return event


# Seed initial events so the dashboard displays live state immediately
def seed_initial_events():
    scenarios = [
        ("Benign", "192.168.1.105", 443, None),
        ("PortScan", "192.0.2.77", 22, "PortScan"),
        ("Benign", "192.168.1.112", 80, None),
        ("DDoS", "203.0.113.45", 80, "DDoS"),
        ("SSH-Patator", "45.33.32.156", 22, "SSH-Patator"),
    ]
    for scen_name, s_ip, d_port, forced_type in scenarios:
        flow = SAMPLE_FLOWS.get(scen_name, SAMPLE_FLOWS["Benign"])
        process_flow_event(flow, source_ip=s_ip, dest_port=d_port, forced_attack_type=forced_type)


seed_initial_events()


# ---------------------------------------------------------------------------
# HTTP Web Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Render the primary monitoring dashboard UI."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def get_status():
    """Return system health and general statistics."""
    total_events = len(EVENT_HISTORY)
    malicious_count = sum(1 for e in EVENT_HISTORY if e["is_malicious"] == 1)
    benign_count = total_events - malicious_count

    return jsonify({
        "status": "OPERATIONAL",
        "total_flows": total_events,
        "malicious_detected": malicious_count,
        "benign_flows": benign_count,
        "malicious_ratio": round((malicious_count / total_events * 100) if total_events > 0 else 0, 1),
        "responder": responder.get_status(),
        "model_features": len(pipeline["feature_names"]),
    })


@app.route("/api/events", methods=["GET"])
def get_events():
    """Return the recent network traffic event stream."""
    limit = int(request.args.get("limit", 50))
    return jsonify({"events": EVENT_HISTORY[:limit]})


@app.route("/api/event/<int:event_id>", methods=["GET"])
def get_event_detail(event_id: int):
    """Return deep forensic and SHAP details for a specific flow event."""
    for ev in EVENT_HISTORY:
        if ev["id"] == event_id:
            return jsonify(ev)
    return jsonify({"error": "Event not found"}), 404


@app.route("/api/simulate", methods=["POST"])
def simulate_traffic():
    """Trigger a simulated network flow scenario (Benign, DDoS, PortScan, SSH-Patator)."""
    data = request.get_json() or {}
    scenario = data.get("scenario", "Benign")

    if scenario not in SAMPLE_FLOWS:
        return jsonify({"error": f"Unknown scenario: {scenario}"}), 400

    flow = SAMPLE_FLOWS[scenario]
    source_ip = random.choice(IP_POOL.get(scenario, ["192.168.1.200"]))
    dest_port = 22 if "SSH" in scenario or "Port" in scenario else 80

    forced_type = scenario if scenario != "Benign" else None
    new_event = process_flow_event(
        flow_data=flow,
        source_ip=source_ip,
        dest_port=dest_port,
        forced_attack_type=forced_type,
    )
    return jsonify(new_event)


@app.route("/api/mitigation/toggle_dry_run", methods=["POST"])
def toggle_dry_run():
    """Toggle dry-run safety mode on or off."""
    responder.dry_run = not responder.dry_run
    return jsonify({"dry_run_mode": responder.dry_run})


@app.route("/api/mitigation/unblock", methods=["POST"])
def unblock_ip():
    """Manually unblock an IP address."""
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    success = responder.unblock_ip(ip)
    return jsonify({"success": success, "ip": ip})


@app.route("/api/mitigation/block", methods=["POST"])
def manual_block():
    """Manually block a suspicious IP address."""
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    result = responder.evaluate_and_respond(
        source_ip=ip,
        risk_level="CRITICAL",
        risk_score=1.0,
        attack_type="Manual Administrator Block",
    )
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
