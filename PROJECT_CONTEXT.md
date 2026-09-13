# PROJECT CONTEXT — Automated Linux Network Intrusion Detection System (NIDS)

## 1. Project Title & Overview

**Automated Linux Network Intrusion Detection & Explainable Threat Response System**

An enterprise-grade, academic prototype of an autonomous Linux Network Intrusion Detection System (IDS). It analyzes network traffic with two-stage machine learning, explains predictions with SHAP, calculates a multi-factor risk score, cross-correlates host authentication logs, performs non-decrypting Deep Packet Inspection (DPI) on encrypted TLS handshakes via JA3 fingerprinting, triggers controlled firewall mitigation via `iptables`, and streams telemetry with sub-millisecond latency via Server-Sent Events (SSE) to a dual-mode Web SOC dashboard.

---

## 2. Project State & Milestone Progression

Every milestone and advanced phase in this project is **100% complete, fully implemented, and validated with a 37-test automated suite (100% pass rate)**.

### Milestones Ledger (Milestones 1 – 14)

| Milestone | Domain | Implementation Summary | Status |
| :--- | :--- | :--- | :---: |
| **Milestone 1** | **Repository Architecture** | Git directory structure, PEP-8 compliance, isolated environment, and clean `.gitignore`. | ✅ Complete |
| **Milestone 2** | **Project Scope Baseline** | Problem formalization, CICIDS2017 schema definition, and two-stage pipeline design. | ✅ Complete |
| **Milestone 3** | **Data Preprocessing Engine** | Full 77-feature extraction from CICIDS2017 parquet files with NaN and infinity sanitization. | ✅ Complete |
| **Milestone 4** | **Stage 1 Binary ML Model** | Fast Random Forest binary classifier (99.88% accuracy) filtering benign background traffic. | ✅ Complete |
| **Milestone 5** | **Stage 2 Multi-Class ML Model**| Multi-Class Random Forest classifier (99.71% accuracy) classifying specific attack types. | ✅ Complete |
| **Milestone 6** | **Explainable AI (SHAP)** | `shap.TreeExplainer` integration generating mathematical local feature attribution drivers. | ✅ Complete |
| **Milestone 7** | **Composite Risk Engine** | Dynamic multi-factor risk calculation assigning operational severity tiers (`LOW`, `MED`, `HIGH`, `CRIT`). | ✅ Complete |
| **Milestone 8** | **Packet Flow Reconstructor** | Bidirectional 5-tuple tracking engine computing rolling 77 statistical features from raw packets. | ✅ Complete |
| **Milestone 9** | **Linux Host Log Correlator** | Cross-referencing network events with `/var/log/auth.log` failed authentication attempts. | ✅ Complete |
| **Milestone 10**| **Automated Firewall Shield** | Autonomous Linux kernel `iptables` drop mitigation with protected IP whitelisting & dry-run mode. | ✅ Complete |
| **Milestone 11**| **Dual-Mode Web SOC Dashboard** | Flask dashboard: *Simple Mode* (plain-English for beginners) & *Expert Mode* (SHAP charts for SOC). | ✅ Complete |
| **Milestone 12**| **System Integration Pipeline**| End-to-end multi-module linkage uniting capture, prediction, XAI, risk, and response. | ✅ Complete |
| **Milestone 13**| **Master CLI Orchestrator** | Headless CLI in `main.py` supporting `--web` and `--pcap` analysis flags. | ✅ Complete |
| **Milestone 14**| **Native Wireshark Integration** | In-browser `.pcap` upload, live Linux sniffer, and interactive 3-pane packet dissector. | ✅ Complete |

### Advanced Production Phases Ledger (Phases 1 – 5)

| Phase | Technology | Implementation Summary | Status |
| :--- | :--- | :--- | :---: |
| **Phase 1** | **Real-Time SSE Streaming** | `/api/stream` Server-Sent Events broadcasting alerts with sub-millisecond latency. | ✅ Complete |
| **Phase 2** | **Distributed Multi-Sensor Probes**| `src/sensor_agent.py` daemon capturing traffic on remote Linux VMs/servers for central SOC. | ✅ Complete |
| **Phase 3** | **DPI & TLS JA3 Fingerprinting** | `src/dpi_engine.py` decoding Client Hello handshakes to detect C2 beacons (Cobalt Strike, TrickBot).| ✅ Complete |
| **Phase 4** | **Automated PDF Incident Reports** | `src/report_generator.py` generating auditor-ready executive PDF reports with SHA-256 seal. | ✅ Complete |
| **Phase 5** | **Docker & Systemd Deployment** | `Dockerfile`, `docker-compose.yml`, and `deploy/nids.service` with Arch Linux `pacman` support. | ✅ Complete |

---

## 3. Machine Learning Pipeline & Metrics

### Two-Stage Detection Hierarchy

```
[ Raw Network Flow: 77 Features ]
               │
               ▼
[ Stage 1: Binary Classifier (Random Forest) ]
├── Benign (0)  ──► Monitored (Passed to regular egress)
└── Malicious (1)
        │
        ▼
[ Stage 2: Attack Type Classifier (Random Forest) ]
├── DDoS / DoS Hulk / Slowloris
├── PortScan (SYN / FIN / Xmas)
├── SSH-Patator (Brute Force)
├── FTP-Patator (Brute Force)
└── Web Attack (SQLi / XSS)
        │
        ▼
[ SHAP TreeExplainer + Risk Engine + iptables Firewall ]
```

### Validated Model Metrics (CICIDS2017 Benchmark)

- **Stage 1 (Binary Random Forest):**
  - **Test Accuracy:** `99.88%`
  - **Precision:** `0.9951`
  - **Recall:** `0.9965`
  - **F1-Score:** `0.9958`
  - **Inference Latency:** `< 1 ms` per flow
- **Stage 2 (Multi-Class Attack Specialist):**
  - **Test Accuracy:** `99.71%`
  - **Weighted F1-Score:** `0.9970`
  - **Macro F1-Score:** `0.9624`
- **Model Files:**
  - `models/random_forest_baseline.joblib`
  - `models/attack_type_classifier.joblib`
  - `models/attack_type_label_encoder.joblib`
  - `models/feature_names.json` (77 ordered features)

---

## 4. Key Subsystem Specifications

### 1. Explainable AI (SHAP TreeExplainer) — `src/explain.py`
- Utilizes `shap.TreeExplainer` on Random Forest decision trees.
- Extracts mathematical Shapley values $\phi_i$ for each feature:
  $$\sum_{i=1}^{M} \phi_i = f(x) - E[f(x)]$$
- Outputs top 4 positive drivers (features increasing malicious confidence) and top 4 negative drivers (features suggesting benign nature).
- Formats dual explanations: technical SHAP metrics for analysts and natural-language narrative for non-technical users.

### 2. Multi-Factor Risk Engine — `src/risk_engine.py`
- Calculates composite risk score ($0.00 - 1.00$):
  $$\text{Risk Score} = \min\left(1.0, (P_{\text{malicious}} \times W_{\text{attack}}) + B_{\text{host\_log}} + B_{\text{dpi}}\right)$$
- Severity Tiers:
  - **LOW** ($0.00 - 0.35$): Standard safe traffic or minor reconnaissance.
  - **MEDIUM** ($0.35 - 0.65$): Repetitive scanning or isolated authentication anomaly.
  - **HIGH** ($0.65 - 0.85$): Active brute-force or high-rate denial of service.
  - **CRITICAL** ($0.85 - 1.00$): Confirmed C2 malware beacon (Cobalt Strike) or high-volume DDoS.

### 3. Deep Packet Inspection & TLS JA3 Engine — `src/dpi_engine.py`
- Decodes binary TLS Record Layer (`0x16`) and Client Hello (`0x01`).
- Extracts SSL version, cipher suites, extensions, supported elliptic curves, and EC point formats without decrypting HTTPS traffic.
- Computes MD5 hash of canonical JA3 string.
- Matches against built-in threat database: Cobalt Strike C2 (`f7afdc93a493feb7b8abba161b61c228`), TrickBot (`ab80e5af92ad6af2a2df314090d8bc94`), Emotet, Metasploit, and Tor.
- Immediately escalates risk to `CRITICAL` upon C2 beacon detection.

### 4. Real-Time Server-Sent Events (SSE) — `src/app.py`
- Thread-safe `SSEBroadcaster` managing client queue subscriptions.
- Pushes `threat_event` payloads to connected browsers over `/api/stream` with zero polling lag.
- Periodic 20-second `ping` keep-alive ensures persistent connection across reverse proxies.

### 5. Distributed Multi-Sensor Sniffing Agent — `src/sensor_agent.py`
- Standalone Python daemon deployed on remote Linux servers and edge nodes.
- Reconstructs bidirectional flows from live network interfaces (`AF_PACKET`).
- Sends heartbeats to Central SOC (`/api/sensor/heartbeat`) and ingests flow batches (`/api/sensor/ingest`).

### 6. Automated Firewall Responder — `src/response.py`
- Enforces Linux kernel `iptables` drop rules:
  ```bash
  iptables -A INPUT -s <ATTACKER_IP> -j DROP
  ```
- **Safety Whitelist:** Never blocks loopback (`127.0.0.1`), gateway (`192.168.1.1`), or DNS (`8.8.8.8`).
- **Dry-Run Mode:** Enabled by default (`logs/response.log`) to allow harmless evaluation.

### 7. Executive PDF Incident Briefing Generator — `src/report_generator.py`
- Native ReportLab binary PDF generation (`/api/report/pdf`).
- Includes Executive Threat Summary KPI Table, Forensic Incident Chronology, SHAP Feature Attribution breakdown, Host Correlation & Firewall Defense status, and a SHA-256 cryptographic verification seal.

---

## 5. Directory Structure & Key Files

```
project-cnla/
├── src/
│   ├── app.py                      # Flask SOC controller, SSE broadcast, REST routes
│   ├── capture.py                  # Scapy sniffer, 5-tuple flow aggregator, PCAP parser
│   ├── dpi_engine.py               # TLS Client Hello decoder & JA3 C2 signature engine
│   ├── explain.py                  # SHAP TreeExplainer local attribution generator
│   ├── log_correlator.py           # Linux /var/log/auth.log failed login correlator
│   ├── predict.py                  # Reusable 2-stage inference pipeline
│   ├── report_generator.py         # ReportLab PDF executive briefing generator
│   ├── response.py                 # Linux iptables firewall manager (dry-run & whitelist)
│   ├── risk_engine.py              # Composite threat risk calculator (LOW/MED/HIGH/CRIT)
│   ├── sensor_agent.py             # Distributed sensor daemon for remote Linux nodes
│   ├── setup_dev_models.py         # Model artifact verifier & synthetic model builder
│   └── templates/index.html        # Dual-Mode Web SOC Dashboard (Simple/Expert, Wireshark)
├── deploy/
│   ├── nids.service                # Systemd service unit (CAP_NET_ADMIN, CAP_NET_RAW)
│   ├── install_linux_service.sh    # Linux installer (Arch pacman, apt, dnf, yum)
│   └── uninstall_linux_service.sh  # Clean service uninstaller
├── Dockerfile                      # Production containerization
├── docker-compose.yml              # SOC Controller + Remote Probe multi-service compose
├── requirements.txt                # Production Python dependencies
├── main.py                         # Master CLI orchestrator (--web, --pcap)
└── tests/                          # 37 unit and integration tests (100% passing)
```

---

## 6. Automated Verification Status

```text
======================================================================
Ran 37 tests in 0.558s

OK (100% Passing)
======================================================================
```

Every subsystem has dedicated test coverage in `tests/`:
- `test_capture.py` — PCAP parsing, 77-feature extraction, flow grouping.
- `test_dashboard_app.py` — Web endpoints, PCAP upload, live sniffer control.
- `test_dpi_ja3.py` — TLS Client Hello decoding, JA3 hashing, C2 detection.
- `test_log_correlator.py` — Linux auth log parsing, IP matching, risk boost.
- `test_report_generator.py` — Binary PDF generation, executive summary metrics.
- `test_sensor_agent.py` — Remote probe enrollment, heartbeat, flow batch ingest.
- `test_sse_stream.py` — Server-Sent Events subscription, event delivery.
- `test_xai_and_risk.py` — SHAP TreeExplainer attributions, multi-factor risk scores.

---

## 7. Guidelines for Downstream AI Agents

When interacting with this codebase:
1. **Model Features:** Never modify or drop keys from `models/feature_names.json`. All 77 CICFlowMeter features are strictly required by the trained models.
2. **Central Dispatch:** Always route new flow events through `process_flow_event()` in `src/app.py`. It coordinates Stage 1/2 inference, DPI, SHAP, Risk, Firewall response, and SSE broadcast.
3. **Safety Defaults:** Retain `dry_run = True` in `src/response.py` by default so testing does not inadvertently lock out network interfaces.
4. **Test Verification:** Always run `python -m unittest discover -s tests -v` after any code modifications. All 37 tests must remain passing.
