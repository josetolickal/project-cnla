# Automated Network Intrusion Detection System

An academic prototype of a Linux-based Network Intrusion Detection System (IDS).
It analyses network-traffic data with two-stage machine learning, explains individual
predictions with SHAP, calculates a transparent risk level, and visualizes results in a
real-time Flask dashboard with native Wireshark packet inspection.

## Project structure

- data/ — downloaded and processed datasets and sample PCAP captures.
- models/ — saved trained machine-learning models and metric JSON files.
- src/ — Python source code for data preprocessing, training, prediction, risk scoring, response, and web UI.
- logs/ — generated detection and response audit logs.
- 	ests/ — automated unit and integration tests (23 tests).
- docs/ — comprehensive documentation, status reports, and viva notes.
- PROJECT_CONTEXT.md — agreed project requirements and milestone plan.

## Current status

All Milestones 1 through 14 are complete:

- CICIDS2017 benchmark dataset processed and validated.
- Two-Stage Random Forest ML detection pipeline (Stage 1 Binary: 99.88% accuracy; Stage 2 Multi-Class: 99.71% accuracy).
- src/predict.py: Reusable prediction and batch inference modules.
- src/explain.py: Explainable AI (SHAP TreeExplainer) with feature attributions.
- src/risk_engine.py: Transparent composite threat risk engine (LOW/MED/HIGH/CRITICAL).
- src/capture.py: Network packet sniffer and 77-feature statistical flow mapper.
- src/log_correlator.py: Linux host log correlation (/var/log/auth.log) with dynamic risk boost.
- src/response.py: Automated firewall mitigation with safe dry-run mode and IP whitelisting.
- src/app.py & src/templates/index.html: Real-time Flask SOC web dashboard:
  - **Dual-Mode UI:** Non-technical *Simple Mode* vs SOC Analyst *Expert Mode*.
  - **Wireshark Engine:** In-browser .pcap upload, live Linux sniffer, and interactive 3-pane packet dissector (Frames, OSI Tree, Hex Dump).
- main.py: Master end-to-end integration orchestrator (--web, --pcap).
- **23 automated unit and integration tests** passing in 	ests/.
- Detailed project status and future roadmap: [docs/PROJECT_STATUS_REPORT.md](docs/PROJECT_STATUS_REPORT.md).

Current model artifacts:

- models/random_forest_baseline.joblib
- models/attack_type_classifier.joblib
- models/attack_type_label_encoder.joblib
- models/feature_names.json
- models/baseline_metrics.json
- models/attack_type_metrics.json

## Setup & Running the Dashboard

1. Install required dependencies:
   `ash
   python -m pip install -r requirements.txt
   `

2. Run the automated test suite:
   `ash
   python -m unittest discover tests
   `

3. Launch the Real-Time Web Dashboard:
   `ash
   python main.py --web
   `
   Open http://127.0.0.1:5000 in your web browser.

4. (Optional) Run Wireshark Capture Analysis via CLI:
   `ash
   python main.py --pcap data/sample_pcaps/syn_flood_ddos.pcap
   `

## Safety note

The automated-response module runs in **dry-run mode** by default. It logs
firewall actions to logs/response.log without modifying system firewall rules
unless explicitly configured.
