# Automated Linux Network Intrusion Detection System (NIDS)

An enterprise-grade, academic prototype of a Linux-based Network Intrusion Detection System (IDS).
It analyses network-traffic data with two-stage machine learning, explains individual
predictions with SHAP, calculates a transparent risk level, decodes encrypted TLS handshakes (JA3/JA3S),
streams alerts via Server-Sent Events (SSE), monitors distributed remote probes, and visualizes results in a
real-time Flask SOC dashboard with native Wireshark packet inspection and automated PDF report export.

## Project Structure

- `data/` — downloaded and processed datasets and sample PCAP captures.
- `models/` — saved trained machine-learning models and metric JSON files.
- `src/` — Python source code for data preprocessing, training, prediction, risk scoring, response, DPI, and web UI.
  - `src/app.py` — Flask SOC controller with SSE streaming and distributed sensor ingestion.
  - `src/dpi_engine.py` — Deep Packet Inspection and TLS Client Hello JA3/JA3S fingerprinting engine.
  - `src/sensor_agent.py` — Standalone daemon for distributed network probe sniffing across remote servers.
  - `src/report_generator.py` — ReportLab executive PDF incident briefing generator.
  - `src/capture.py` — Scapy packet sniffer, PCAP reader, and 77-feature flow extractor.
- `deploy/` — Linux production deployment assets:
  - `deploy/nids.service` — Hardened systemd unit file with Linux ambient capabilities.
  - `deploy/install_linux_service.sh` — Zero-friction systemd installer script.
  - `deploy/uninstall_linux_service.sh` — Clean uninstaller script.
- `Dockerfile` & `docker-compose.yml` — Containerized multi-service deployment.
- `logs/` — generated detection and response audit logs.
- `tests/` — automated unit and integration tests (**37 tests passing with 100% success**).
- `docs/` — comprehensive documentation, architecture diagrams, and viva notes:
  - [docs/PROJECT_STATUS_REPORT.md](docs/PROJECT_STATUS_REPORT.md)
  - [docs/REPORT_NOTES.md](docs/REPORT_NOTES.md)

## Current Status

All Milestones 1 through 14 and all 5 Advanced Production Phases are complete:

- **Two-Stage Machine Learning Pipeline:** Stage 1 Binary Classifier (99.88% accuracy) + Stage 2 Attack Type Specialist (99.71% accuracy) trained on CICIDS2017.
- **Explainable AI (SHAP TreeExplainer):** Polynomial-time mathematical feature attributions explaining detection rationale.
- **Composite Threat Risk Engine:** Multi-factor risk calculation (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Deep Packet Inspection (DPI) & TLS JA3 Fingerprinting:** Non-decrypting TLS Client Hello parser detecting Command & Control (C2) malware beacons (Cobalt Strike, TrickBot, Emotet).
- **Real-Time Server-Sent Events (SSE):** Sub-millisecond incident alert streaming (`/api/stream`).
- **Distributed Multi-Sensor Network:** Remote probe daemon (`src/sensor_agent.py`) forwarding live flow telemetry to central SOC.
- **Automated PDF Incident Briefings:** One-click auditor-ready executive PDF report export (`/api/report/pdf`).
- **Host Log Correlation:** Linux `/var/log/auth.log` authentication event correlation.
- **Automated Firewall Response:** Linux kernel `iptables` mitigation with safe dry-run mode and whitelisting.
- **Wireshark Integration:** In-browser `.pcap` upload, live sniffer, and interactive 3-pane packet dissector.
- **Containerization & Systemd Daemon:** Docker, Docker Compose, and native Linux `systemd` service unit.
- **Test Suite:** **37 automated unit and integration tests** passing in `tests/`.

## Quickstart & Usage

### 1. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
python -m unittest discover -s tests -v
```

### 3. Launch Web SOC Dashboard
```bash
python main.py --web
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your web browser.

### 4. Deploy with Docker Compose
```bash
docker-compose up -d --build
```

### 5. Install as Linux Systemd Daemon
```bash
sudo bash deploy/install_linux_service.sh
```

### 6. Run Distributed Remote Probe
```bash
python src/sensor_agent.py --server http://127.0.0.1:5000 --sensor-id sensor-branch-01 --demo
```

### 7. Analyze Wireshark Capture via CLI
```bash
python main.py --pcap data/sample_pcaps/syn_flood_ddos.pcap
```

## Safety Note

The automated-response module runs in **dry-run mode** by default (`logs/response.log`). It will not alter system firewall rules unless dry-run mode is toggled off in the dashboard or CLI.
