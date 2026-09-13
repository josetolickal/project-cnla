# Automated Linux Network Intrusion Detection System (NIDS) with Explainable AI

[![System Status](https://img.shields.io/badge/System%20Status-Production%20Ready-emerald.svg)](#current-status)
[![Tests Passing](https://img.shields.io/badge/Tests-37%2F37%20Passing-brightgreen.svg)](#automated-test-suite)
[![Linux Platform](https://img.shields.io/badge/Platform-Arch%20Linux%20%7C%20Ubuntu%20%7C%20Debian%20%7C%20Docker-blue.svg)](#deployment--execution)
[![ML Performance](https://img.shields.io/badge/Stage%201%20Accuracy-99.88%25-cyan.svg)](#machine-learning-architecture)
[![Stage 2 Performance](https://img.shields.io/badge/Stage%202%20Accuracy-99.71%25-cyan.svg)](#machine-learning-architecture)

An enterprise-grade, academic prototype of an autonomous **Linux Network Intrusion Detection System (NIDS)**. It analyzes live packet traffic with a **Two-Stage Machine Learning hierarchy**, explains predictions with **SHAP TreeExplainer**, correlates anomalous flows against **Linux OS authentication logs (`/var/log/auth.log`)**, extracts **TLS Client Hello JA3/JA3S cryptographic fingerprints** to detect encrypted C2 malware beacons without payload decryption, broadcasts alerts with sub-millisecond latency over **Server-Sent Events (SSE)**, monitors **distributed remote probe daemons**, and visualizes forensic intelligence in a dual-mode Web SOC dashboard with native **Wireshark 3-pane packet dissection** and automated **PDF incident briefing generation**.

---

## Quick Navigation for Developers & AI Agents

- [Architecture Diagram](#architecture-diagram)
- [Project State & Progress Ledger](#project-state--progress-ledger)
- [Complete Directory Manifest](#complete-directory-manifest)
- [Machine Learning Architecture](#machine-learning-architecture)
- [Deployment & Execution Guide](#deployment--execution-guide)
- [Automated Test Suite](#automated-test-suite)
- [AI Agent Handoff Context](#ai-agent-handoff-context)

---

## Architecture Diagram

```
                       [ Distributed Remote Linux Servers / Cloud VMs / Edge Nodes ]
                                                    │
                                                    ▼
                                   [ src/sensor_agent.py: Phase 2 ]
                                   • Live Interface Sniffing (Scapy / AF_PACKET)
                                   • Bidirectional 5-Tuple Flow Assembly
                                   • 77 Statistical Flow Metrics Extraction
                                   • Raw TLS Client Hello Inspection (JA3/JA3S)
                                   • Autonomous Heartbeat & Telemetry Forwarding
                                                    │
                                                    ▼ (HTTP POST /api/sensor/ingest)
[ Central SOC Management Controller: src/app.py ] ◄── [ In-Browser Wireshark .pcap Upload ]
       │
       ├───────────────────────────────┬───────────────────────────────┐
       ▼                               ▼                               ▼
[ src/predict.py ]             [ src/dpi_engine.py ]           [ src/log_correlator.py ]
• Stage 1: Binary Filter       • TLS Client Hello Parser       • Linux /var/log/auth.log
• Stage 2: Attack Specialist   • JA3 / JA3S MD5 Hashing        • Failed SSH Logins
  (DDoS, PortScan, Patator)    • C2 Beacon Signatures          • Cross-Layer Auth Boost
       │                         (Cobalt Strike, TrickBot)             │
       └───────────────────────────────┼───────────────────────────────┘
                                       │
                                       ▼
                         [ src/risk_engine.py: M7 ]
                         • Composite Threat Severity Score (0.00 - 1.00)
                         • Priority Tiers: LOW, MEDIUM, HIGH, CRITICAL
                         • C2 JA3 Signature & Auth Log Risk Escalation
                                       │
                       ┌───────────────┴───────────────┐
                       ▼                               ▼
            [ src/explain.py: M6 ]           [ src/response.py: M10 ]
            • SHAP TreeExplainer Attributions• Linux kernel iptables DROP rules
            • Positive/Negative Driver Values• Failsafe IP Whitelist
            • Human Natural Language Summary • Safe Dry-Run Simulation Toggle
                       │                               │
                       └───────────────┬───────────────┘
                                       ▼
                      [ Real-Time Dispatch & Reporting ]
                                       │
       ┌───────────────────────────────┴───────────────────────────────┐
       ▼                                                               ▼
[ src/app.py: /api/stream ]                                [ src/report_generator.py ]
• Server-Sent Events (SSE) Broadcast                       • Binary Executive PDF Generation
• Sub-millisecond alert delivery                           • Risk KPI Summary & Top SHAP Drivers
• Zero polling lag to Web Dashboard                        • Active Firewall & Defense Logs
       │                                                   • SHA-256 Audit Integrity Signature
       ▼                                                               │
[ Web Dashboard UI: src/templates/index.html ]                         ▼
• Real-time SSE Live Listener                              [ Download Executive Briefing (PDF) ]
• Dual-Mode UI (Simple Non-Technical vs SOC Expert)
• Interactive 3-Pane Wireshark Dissector
• Distributed Sensor Status Badges
• Encrypted Traffic DPI & JA3 Forensic Inspection
```

---

## Project State & Progress Ledger

Every milestone and production phase is **100% complete, fully implemented in source, and verified by automated unit and integration tests**:

| Stage | Milestone / Phase | Implementation Details | Status |
| :--- | :--- | :--- | :---: |
| **Foundation** | **M1 & M2: Architecture & Baseline** | Virtual environment, PEP-8 compliance, modular file architecture, strict `.gitignore`. | ✅ Completed |
| **Data Engine** | **M3: 77-Feature Processing** | Full CICFlowMeter dataset mapping, NaN/infinity cleaning, flow normalization. | ✅ Completed |
| **Inference** | **M4 & M5: Two-Stage ML Models** | Stage 1 Binary (99.88%) + Stage 2 Multi-Class Classifier (99.71%). | ✅ Completed |
| **XAI** | **M6: Explainable AI (SHAP)** | `shap.TreeExplainer` computing mathematical Shapley feature attributions. | ✅ Completed |
| **Scoring** | **M7: Threat Risk Engine** | Composite risk calculation ($0.0 - 1.0$) with `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` tiers. | ✅ Completed |
| **Capture** | **M8: 5-Tuple Flow Aggregator** | Bidirectional TCP/UDP flow reconstruction with 77 statistical metric extraction. | ✅ Completed |
| **Host Audit** | **M9: Linux Log Correlator** | Cross-referencing network events with `/var/log/auth.log` failed authentication logs. | ✅ Completed |
| **Mitigation** | **M10: Automated Firewall Shield** | Autonomous Linux kernel `iptables` drop execution with IP whitelisting & dry-run mode. | ✅ Completed |
| **Frontend** | **M11: Dual-Mode Web SOC** | Flask dashboard: *Simple Mode* (plain-English) & *Expert Mode* (SHAP charts & metrics). | ✅ Completed |
| **CLI** | **M12 & M13: Master Orchestrator** | Headless CLI in `main.py` supporting `--web` and `--pcap` analysis flags. | ✅ Completed |
| **Forensics** | **M14: Native Wireshark Engine** | In-browser `.pcap` upload, live Linux sniffer, and interactive 3-pane packet dissector. | ✅ Completed |
| **Phase 1** | **Real-Time SSE Alert Streaming** | `/api/stream` Server-Sent Events broadcasting alerts with sub-millisecond latency. | ✅ Completed |
| **Phase 2** | **Distributed Multi-Sensor Probes** | `src/sensor_agent.py` daemon capturing traffic on remote Linux VMs/servers for central SOC. | ✅ Completed |
| **Phase 3** | **DPI & TLS JA3 Fingerprinting** | `src/dpi_engine.py` decoding Client Hello handshakes to detect C2 beacons (Cobalt Strike, TrickBot). | ✅ Completed |
| **Phase 4** | **Automated PDF Incident Briefing** | `src/report_generator.py` generating auditor-ready executive PDF reports with SHA-256 seal. | ✅ Completed |
| **Phase 5** | **Docker & Systemd Deployment** | `Dockerfile`, `docker-compose.yml`, and `deploy/nids.service` with Arch Linux `pacman` support. | ✅ Completed |

---

## Complete Directory Manifest

```
project-cnla/
├── Dockerfile                      # Production containerization (Python 3.11-slim, libpcap, iptables)
├── docker-compose.yml              # Multi-container orchestration (SOC Controller + Remote Probe)
├── requirements.txt                # Production Python dependencies (numpy, pandas, scikit-learn, shap, flask, scapy, reportlab, requests)
├── main.py                         # Master system CLI orchestrator (--web, --pcap, demo modes)
├── PROJECT_CONTEXT.md              # Living specification of technical requirements, ML metrics, and architecture
├── README.md                       # Primary engineering documentation and system guide
│
├── deploy/                         # Production Linux service deployment assets
│   ├── nids.service                # Systemd unit file with CAP_NET_ADMIN & CAP_NET_RAW capabilities
│   ├── install_linux_service.sh    # Zero-friction installer (supports Arch Linux pacman, apt, dnf, yum)
│   └── uninstall_linux_service.sh  # Clean service teardown and removal script
│
├── src/                            # Core application source code
│   ├── app.py                      # Primary Flask SOC controller with SSE streaming & sensor ingestion
│   ├── capture.py                  # Scapy live sniffer, .pcap reader, and 77-feature CICFlowMeter extractor
│   ├── dpi_engine.py               # Deep Packet Inspection & TLS Client Hello JA3/JA3S fingerprint engine
│   ├── explain.py                  # SHAP TreeExplainer integration producing local feature attributions
│   ├── log_correlator.py           # Linux /var/log/auth.log parsing & dynamic correlation risk boost
│   ├── predict.py                  # Reusable inference pipeline for Stage 1 (binary) & Stage 2 (attack type)
│   ├── report_generator.py         # ReportLab PDF executive incident briefing generator with SHA-256 seal
│   ├── response.py                 # Linux iptables firewall manager with safe dry-run mode & whitelist
│   ├── risk_engine.py              # Multi-factor threat risk severity calculator (LOW/MED/HIGH/CRITICAL)
│   ├── sensor_agent.py             # Standalone Python probe daemon for distributed multi-server sniffing
│   ├── setup_dev_models.py         # Fallback generator ensuring valid pipeline weights on cold clone
│   └── templates/
│       └── index.html              # Dual-Mode Web SOC Dashboard (Tailwind CSS, FontAwesome, Chart.js, SSE)
│
├── models/                         # Serialized machine learning models and metadata
│   ├── random_forest_baseline.joblib   # Stage 1: Binary classifier (Benign vs Malicious)
│   ├── attack_type_classifier.joblib   # Stage 2: Multi-class attack specialist
│   ├── attack_type_label_encoder.joblib# Attack category label encoder
│   ├── feature_names.json              # Ordered list of the 77 CICFlowMeter features
│   ├── baseline_metrics.json           # Validation metrics for Stage 1 (99.88% accuracy)
│   └── attack_type_metrics.json        # Validation metrics for Stage 2 (99.71% accuracy)
│
├── data/                           # Data directory for captures and sample flows
│   ├── sample_flows.json           # Pre-compiled benchmark test flows for instant simulation
│   ├── sample_pcaps/               # Bundled attack captures for offline viva testing
│   │   ├── syn_flood_ddos.pcap
│   │   ├── ssh_bruteforce.pcap
│   │   └── benign_web_browsing.pcap
│   └── uploads/                    # Target directory for in-browser user .pcap uploads
│
├── logs/                           # Runtime audit logs
│   ├── response.log                # Mitigation action history (firewall block/unblock logs)
│   └── detections.log              # Persistent detection chronology
│
├── tests/                          # Automated test suite (37 unit & integration tests)
│   ├── test_capture.py             # Tests 77-feature extraction, flow grouping, and .pcap parsing
│   ├── test_dashboard_app.py       # Tests web REST endpoints, simulations, and PCAP uploads
│   ├── test_dpi_ja3.py             # Tests TLS Client Hello parsing, JA3 hashing, and C2 matching
│   ├── test_log_correlator.py      # Tests /var/log/auth.log correlation & risk boost logic
│   ├── test_report_generator.py    # Tests binary PDF generation and summary metrics
│   ├── test_sensor_agent.py        # Tests remote probe daemon registration, heartbeat, and ingest
│   ├── test_sse_stream.py          # Tests Server-Sent Events (SSE) broadcaster and /api/stream
│   └── test_xai_and_risk.py        # Tests SHAP TreeExplainer attributions and composite risk scoring
│
└── docs/                           # Project status reports and viva documentation
    ├── PROJECT_STATUS_REPORT.md    # Comprehensive system status report & test verification log
    ├── REPORT_NOTES.md             # Technical viva talking points, formulas, and examiner Q&A
    └── FUTURE_ENHANCEMENTS.md      # Long-term strategic horizon (Suricata, Kubernetes, STIX/TAXII)
```

---

## Machine Learning Architecture

The intrusion detection pipeline utilizes a **Two-Stage Machine Learning Hierarchy** trained on the standard Canadian Institute for Cybersecurity benchmark (`CICIDS2017`):

### 1. Stage 1: Fast Binary Traffic Filter
- **Algorithm:** Random Forest Classifier (`n_estimators=100`, balanced class weights).
- **Function:** Determines whether an incoming flow is **Benign (0)** or **Malicious (1)** in under 1 millisecond.
- **Performance:**
  - **Accuracy:** `99.88%`
  - **Precision:** `0.9951`
  - **Recall:** `0.9965`
  - **F1-Score:** `0.9958`
- **Design Rationale:** Filtering 99% of normal traffic with an optimized binary classifier prevents computational exhaustion from evaluating expensive multi-class trees on everyday benign packets.

### 2. Stage 2: Attack Category Specialist
- **Algorithm:** Multi-Class Random Forest Classifier.
- **Function:** Invoked **only** when Stage 1 flags traffic as malicious. Identifies the precise threat vector:
  - `DDoS` / `DoS Hulk` / `DoS GoldenEye` / `DoS Slowloris`
  - `PortScan` (SYN scan, FIN scan, Xmas scan)
  - `SSH-Patator` (SSH credential brute-force)
  - `FTP-Patator` (FTP credential brute-force)
  - `Web Attack` (SQL Injection, XSS, Brute Force)
  - `Botnet` / `Infiltration`
- **Performance:**
  - **Accuracy:** `99.71%`
  - **Weighted F1-Score:** `0.9970`

### 3. The 77 CICFlowMeter Features
The feature extraction engine calculates 77 statistical metrics per bidirectional 5-tuple flow, including:
- **Temporal & Volume:** `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Flow Packets/s`, `Flow Bytes/s`.
- **Packet Size Moments:** `Packet Length Mean`, `Packet Length Std`, `Packet Length Variance`, `Fwd Packet Length Max/Min`.
- **Inter-Arrival Time (IAT):** `Flow IAT Mean/Std/Max/Min`, `Fwd IAT Mean`, `Bwd IAT Mean`.
- **TCP Control Flags:** `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `ECE`, `CWE` flag counts.
- **Window Dynamics & Bulk Rates:** `Init_Win_bytes_forward`, `Init_Win_bytes_backward`, `Fwd Header Length`, `Bwd Bulk Rate Avg`.

---

## Deployment & Execution Guide

### Option A: Running on Arch Linux (Bare Metal / Native)

```bash
# 1. Install Arch Linux system dependencies via pacman
sudo pacman -Syu --needed libpcap iptables iproute2 tcpdump python python-pip

# 2. Clone repository and setup Python virtual environment
git clone https://github.com/josetolickal/project-cnla.git
cd project-cnla
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Grant raw network sniffing privileges without requiring full root (Recommended)
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))

# 4. Launch the Web SOC Dashboard
python main.py --web
# Access at: http://localhost:5000
```

### Option B: Running on Ubuntu / Debian / Fedora

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y libpcap-dev iptables python3-venv curl

# Fedora
sudo dnf install -y libpcap-devel iptables python3-pip curl

# Install virtualenv & start
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/python main.py --web
```

### Option C: Production Linux Systemd Service (Autonomous 24/7 Daemon)

```bash
# Deploy as a native Linux systemd service in /opt/nids
sudo bash deploy/install_linux_service.sh

# Management commands
sudo systemctl status nids.service
journalctl -u nids.service -f
sudo systemctl restart nids.service
```

### Option D: Docker Compose Deployment

```bash
# Build and orchestrate SOC Controller + Remote Probe Daemon
docker-compose up -d --build

# View container status
docker-compose ps

# Dashboard accessible at http://localhost:5000
```

### Option E: Running Distributed Remote Probe Agents

On remote Linux servers or VMs across your network, run the standalone sensor agent to forward live telemetry to your Central SOC:

```bash
python src/sensor_agent.py \
    --server http://<SOC_IP>:5000 \
    --sensor-id sensor-branch-office-01 \
    --location "Branch-DC-Munich" \
    --interface eth0
```

---

## Automated Test Suite

The project includes **37 comprehensive unit and integration tests** verifying all layers from low-level packet capture to web endpoints and PDF rendering:

```bash
python -m unittest discover -s tests -v
```

### Test Coverage Summary:
```text
test_capture.py           4 tests   [Full 77 features, flow aggregation, PCAP reading, end-to-end]
test_dashboard_app.py    10 tests   [Web API endpoints, simulations, PCAP upload, live sniffer]
test_dpi_ja3.py           4 tests   [Client Hello parsing, JA3 hashing, C2 threat matching, benign TLS]
test_log_correlator.py    3 tests   [/var/log/auth.log parsing, IP matching, dynamic risk boost]
test_report_generator.py  3 tests   [Binary PDF generation, /api/report/pdf endpoint, summary API]
test_sensor_agent.py      5 tests   [Agent initialization, registration API, heartbeat, flow ingest]
test_sse_stream.py        2 tests   [SSE broadcaster subscription, message formatting, /api/stream]
test_xai_and_risk.py      6 tests   [SHAP TreeExplainer attributions, multi-factor risk scores]

Ran 37 tests in 0.558s — ALL 37 PASSING (100% OK)
```

---

## AI Agent Handoff Context

> **Instructions for downstream AI Coding Assistants:**
> - **Working Directory:** All code must run from the workspace root (`C:\Users\Jose T Olickal\Desktop\project-cnla` on Windows, or `/opt/nids` / cloned path on Linux).
> - **Data Contracts:**
>   - Flows input to `predict_flow()` must be a dictionary containing all **77 feature keys** defined in `models/feature_names.json`.
>   - `process_flow_event()` in `src/app.py` is the single central entry point that executes ML prediction, attack typing, DPI inspection, host log correlation, SHAP explanation, firewall response, and SSE broadcast.
>   - DPI records generated by `src/dpi_engine.py` contain both standardized keys (`is_tls`, `has_tls`, `ja3_hash`, `threat_name`, `signature_name`, `is_threat`).
> - **Dry-Run Safety:** `src/response.py` defaults to `dry_run = True` (`logs/response.log`). It will not alter live kernel `iptables` rules unless explicitly toggled off in the UI or CLI.
> - **Server-Sent Events:** Frontend listens on `/api/stream` with event name `threat_event` and `ping`.
> - **Tests:** Always verify any changes by running `python -m unittest discover -s tests -v`. All 37 tests must pass.
