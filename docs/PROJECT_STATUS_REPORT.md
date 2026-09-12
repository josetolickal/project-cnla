# Automated Linux Network Intrusion Detection & Explainable Threat Response System
## Comprehensive Project Status Report & Strategic Architecture Reference

---

## 1. Executive Summary

| Attribute | Details |
| :--- | :--- |
| **Project Name** | Automated Linux Network Intrusion Detection System (NIDS) with XAI |
| **Target OS** | Linux (Arch Linux / Ubuntu / Debian / Fedora) |
| **Core Architecture** | Two-Stage Machine Learning (Binary Random Forest + Multi-Class Specialist) |
| **Feature Extraction** | 77 Bidirectional Statistical Network Features (CICFlowMeter standard) |
| **Explainable AI** | SHAP (*SHapley Additive exPlanations*) TreeExplainer |
| **Threat Intelligence** | Deep Packet Inspection (DPI) with TLS Client Hello JA3 / JA3S Fingerprinting |
| **Telemetry Ingestion** | Sub-millisecond Server-Sent Events (SSE) + Distributed Multi-Sensor Agent Network |
| **Forensic Reporting** | Automated Auditor-Ready Executive PDF Incident Briefing Generation (ReportLab) |
| **Defense Mechanism** | Multi-Factor Risk Engine + Automated Linux kernel `iptables` Mitigation |
| **Host Correlation** | Cross-referencing Network Flows with Linux OS `/var/log/auth.log` |
| **User Interfaces** | 1. Dual-Mode Real-Time Web SOC Dashboard (Simple Mode & Expert Mode)<br>2. Headless Terminal CLI Orchestrator (`main.py`) |
| **Packet Ingestion** | Native Wireshark / `tcpdump` `.pcap` Ingestion & Live Scapy Interface Sniffer |
| **Deployment Modes** | Docker Containerization (`Dockerfile`, `docker-compose.yml`) & Linux Systemd Daemon (`nids.service`) |
| **Repository** | https://github.com/josetolickal/project-cnla |

---

## 2. End-to-End System Architecture

```
                       [ Distributed Remote Linux Servers / VMs / Edge Nodes ]
                                              │
                                              ▼
                             [ src/sensor_agent.py: Phase 2 ]
                             • Live Interface Sniffing (Scapy / AF_PACKET)
                             • Bidirectional 5-Tuple Flow Assembly
                             • 77 Statistical Flow Metrics Extraction
                             • Raw TLS Client Hello Inspection (JA3/JA3S)
                             • Autonomous Heartbeat & Telemetry Forwarding
                                              │
                                              ▼ (HTTP /api/sensor/ingest)
[ Central SOC Management Controller: src/app.py ] ◄── [ In-Browser Wireshark .pcap Upload ]
       │
       ├───────────────────────────────┬───────────────────────────────┐
       ▼                               ▼                               ▼
[ src/predict.py ]             [ src/dpi_engine.py ]           [ src/log_correlator.py ]
• Stage 1: Binary Filter       • TLS Client Hello Parser       • Host /var/log/auth.log
• Stage 2: Attack Specialist   • JA3 / JA3S MD5 Hashing        • Linux SSH Failed Logins
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

## 3. What We Have Built (Complete Milestone & Phase Review)

### Foundation & Core Intelligence (Milestones 1 – 14)
1. **Milestones 1 & 2 (Environment & Architecture):** Isolated virtual environment, modular Python architecture, PEP-8 compliance, and clean Git repository structure.
2. **Milestone 3 (77-Feature Pipeline):** Bidirectional session reconstruction mapping network flows to the full 77 CICFlowMeter statistical features with NaN/infinite filtering.
3. **Milestones 4 & 5 (Two-Stage Machine Learning):**
   - *Stage 1 (Binary Filter):* 99.88% accuracy on CICIDS2017. Eliminates 99% of harmless background traffic in under 1 millisecond.
   - *Stage 2 (Multi-Class Specialist):* 99.71% accuracy. Classifies specific cyber attack categories (DDoS, PortScan, SSH-Patator, FTP-Patator, Web Attacks).
4. **Milestone 6 (Explainable AI via SHAP):** Local TreeExplainer attribution generating exact mathematical Shapley values to eliminate black-box opacity.
5. **Milestone 7 (Multi-Factor Risk Scoring):** Dynamic threat formula translating raw ML probabilities into actionable operational tiers: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
6. **Milestone 8 (Native Flow Reconstruction):** Bidirectional 5-tuple tracking engine with TCP flag handling and sliding flow windows.
7. **Milestone 9 (Host Log Correlation):** Cross-references incoming suspicious IP addresses against Linux OS `/var/log/auth.log` for coordinated brute-force detection.
8. **Milestone 10 (Automated Firewall Shield):** Automated Linux kernel `iptables` drop mitigation with safety whitelisting (loopback, gateway, DNS) and dry-run safety modes.
9. **Milestone 11 (Dual-Mode Web Dashboard):**
   - *Simple Mode for Non-Technical Users:* Translates cryptic IPs into human-friendly device names (*This Computer*, *Local Wi-Fi*, *Suspicious External Server*) with plain-English attack explanations and actionable advice.
   - *Expert Mode for SOC Analysts:* Interactive SHAP contribution charts, 5-tuple flow metrics, and firewall controls.
10. **Milestones 12 & 13 (Master Orchestrator):** Headless CLI orchestrator in `main.py` supporting `--web` and `--pcap` flags.
11. **Milestone 14 (Wireshark Integration):** In-browser `.pcap` upload, live Linux network interface sniffer (`eth0`), pre-packaged demo attack captures, and full interactive 3-pane packet dissection (Frame List, OSI Layer Tree, Hex Dump).

### Advanced Production Phases (Phases 1 – 5)

#### Phase 1: Real-Time Server-Sent Events (SSE) Streaming
- **Backend:** Implemented thread-safe `SSEBroadcaster` in `src/app.py` with queue-based client subscriptions and periodic 20-second keep-alive heartbeats.
- **Endpoint:** `/api/stream` streaming `text/event-stream` with sub-millisecond alert delivery upon incident detection.
- **Frontend:** Integrated native browser `EventSource` in `src/templates/index.html` with instant table insertion, live status LED, and fallback to periodic synchronization.

#### Phase 2: Distributed Multi-Sensor Sniffing Network
- **Sensor Daemon:** Built lightweight client probe `src/sensor_agent.py` for deployment across remote Linux servers, cloud VMs, and edge gateways.
- **Telemetry Protocol:** Automatic registration (`/api/sensor/register`), periodic liveness heartbeats (`/api/sensor/heartbeat`), and flow batch forwarding (`/api/sensor/ingest`).
- **SOC Integration:** Central dashboard tracking active sensor nodes, geographic locations, and displaying sensor origin tags on every incident.

#### Phase 3: Deep Packet Inspection (DPI) & TLS JA3/JA3S Fingerprinting
- **Binary Handshake Parser:** Built enterprise DPI engine `src/dpi_engine.py` parsing raw binary TLS Client Hello records (Record version, Handshake length, Cipher suites, Extensions, Supported elliptic curves, and EC point formats).
- **JA3 Computation:** Computes standardized MD5 fingerprint hashes per the Salesforce JA3 specification without decrypting HTTPS payloads.
- **C2 Threat Database:** Built-in threat detection signatures for **Cobalt Strike Malleable C2**, **Cobalt Strike TeamServer**, **TrickBot Banking Trojan**, **Emotet Downloader**, **Metasploit Reverse HTTPS**, and **Tor Onion Proxy**.
- **Risk Escalation:** Immediately elevates incident risk score to `CRITICAL` (0.98+) and triggers automated firewall isolation upon detecting active C2 malware beacons.

#### Phase 4: Automated PDF Incident Report Generation
- **ReportLab Engine:** Implemented professional PDF document generator `src/report_generator.py` rendering high-resolution executive briefings.
- **Forensic Content:** Includes Executive Threat Summary KPI table, Forensic Incident Chronology, SHAP Feature Attribution breakdown, Host Authentication & Firewall Defense status, and SHA-256 cryptographic audit verification hash.
- **Export Endpoint:** One-click instant browser download via `/api/report/pdf` and dashboard header button.

#### Phase 5: Production Linux Systemd Daemon & Dockerization
- **Containerization:** Production `Dockerfile` (Python 3.11-slim, `libpcap-dev`, `iptables`, `iproute2`, `curl`, healthcheck) and `docker-compose.yml` orchestrating the Central SOC Controller and a simulated remote Sensor Probe.
- **Systemd Unit:** Created hardened Linux service `deploy/nids.service` configured with `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` for autonomous 24/7 background operation.
- **Automation Scripts:** Created `deploy/install_linux_service.sh` and `deploy/uninstall_linux_service.sh` for zero-friction Linux administration.

---

## 4. Test Suite Verification & Validation Results

The comprehensive test suite in `tests/` was executed via Python's standard `unittest` framework. **All 37 unit and integration tests passed with 100% success:**

| Test Module | Test Case | Status |
| :--- | :--- | :--- |
| `test_capture.py` | `test_end_to_end_capture_to_prediction` | ✅ PASS |
| `test_capture.py` | `test_flow_packet_aggregation` | ✅ PASS |
| `test_capture.py` | `test_full_77_features_mapped` | ✅ PASS |
| `test_capture.py` | `test_pcap_file_reading` | ✅ PASS |
| `test_dashboard_app.py` | `test_api_events` | ✅ PASS |
| `test_dashboard_app.py` | `test_api_simulate_benign` | ✅ PASS |
| `test_dashboard_app.py` | `test_api_simulate_ddos` | ✅ PASS |
| `test_dashboard_app.py` | `test_api_status` | ✅ PASS |
| `test_dashboard_app.py` | `test_events_contain_wireshark_packets` | ✅ PASS |
| `test_dashboard_app.py` | `test_index_page` | ✅ PASS |
| `test_dashboard_app.py` | `test_toggle_dry_run` | ✅ PASS |
| `test_dashboard_app.py` | `test_wireshark_live_capture_controls` | ✅ PASS |
| `test_dashboard_app.py` | `test_wireshark_load_sample_pcap` | ✅ PASS |
| `test_dashboard_app.py` | `test_wireshark_sample_pcaps_listing` | ✅ PASS |
| `test_dpi_ja3.py` | `test_non_tls_payload_handled_gracefully` | ✅ PASS |
| `test_dpi_ja3.py` | `test_parse_benign_chrome_handshake` | ✅ PASS |
| `test_dpi_ja3.py` | `test_parse_cobalt_strike_handshake` | ✅ PASS |
| `test_dpi_ja3.py` | `test_parse_trickbot_handshake` | ✅ PASS |
| `test_log_correlator.py` | `test_correlate_clean_ip` | ✅ PASS |
| `test_log_correlator.py` | `test_correlate_matching_ip` | ✅ PASS |
| `test_log_correlator.py` | `test_risk_engine_integration_with_log_boost` | ✅ PASS |
| `test_report_generator.py` | `test_generate_pdf_report_binary` | ✅ PASS |
| `test_report_generator.py` | `test_pdf_report_endpoint` | ✅ PASS |
| `test_report_generator.py` | `test_report_summary_endpoint` | ✅ PASS |
| `test_sensor_agent.py` | `test_sensor_agent_class_initialization` | ✅ PASS |
| `test_sensor_agent.py` | `test_sensor_flow_ingest_api` | ✅ PASS |
| `test_sensor_agent.py` | `test_sensor_heartbeat_api` | ✅ PASS |
| `test_sensor_agent.py` | `test_sensor_list_api` | ✅ PASS |
| `test_sensor_agent.py` | `test_sensor_registration_api` | ✅ PASS |
| `test_sse_stream.py` | `test_sse_broadcaster_subscribe_and_broadcast` | ✅ PASS |
| `test_sse_stream.py` | `test_sse_stream_endpoint_connects` | ✅ PASS |
| `test_xai_and_risk.py` | `test_benign_risk` | ✅ PASS |
| `test_xai_and_risk.py` | `test_ddos_critical_risk` | ✅ PASS |
| `test_xai_and_risk.py` | `test_log_correlation_boost` | ✅ PASS |
| `test_xai_and_risk.py` | `test_portscan_medium_risk` | ✅ PASS |
| `test_xai_and_risk.py` | `test_explain_benign_flow` | ✅ PASS |
| `test_xai_and_risk.py` | `test_explain_malicious_flow` | ✅ PASS |

---

## 5. Deployment & Operation Guide

### Option A: Running as a Linux Systemd Daemon (Bare Metal / VM)
```bash
# 1. Clone repository on Linux host
git clone https://github.com/josetolickal/project-cnla.git /opt/nids
cd /opt/nids

# 2. Run automated installer with root privileges
sudo bash deploy/install_linux_service.sh

# 3. Check service status
sudo systemctl status nids.service

# 4. View live systemd logs
journalctl -u nids.service -f
```

### Option B: Running with Docker Compose (Multi-Container Deployment)
```bash
# Build and start SOC Dashboard and Remote Probe Sensor
docker-compose up -d --build

# Verify running containers
docker-compose ps

# Access SOC Dashboard at http://localhost:5000
```

### Option C: Running Standalone Remote Probe Daemons
```bash
# On any remote Linux server or branch office VM:
python src/sensor_agent.py \
    --server http://<SOC_CONTROLLER_IP>:5000 \
    --sensor-id sensor-branch-office-01 \
    --location "Munich-Datacenter-Rack-4" \
    --interface eth0
```

---

## 6. Future Strategic Horizons

1. **Suricata / Snort Signature Hybridization:** Ingest standard emerging threat Suricata rules (`.rules`) alongside machine learning flow inference.
2. **Kubernetes Helm Chart & DaemonSet:** Deploy probe agents as a Kubernetes DaemonSet to monitor container east-west pod traffic.
3. **STIX / TAXII Threat Intelligence Synchronization:** Automated synchronization with MISP or AlienVault OTX feeds to continuously update JA3 hash and malicious IP lists.
