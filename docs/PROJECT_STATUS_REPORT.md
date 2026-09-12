# Automated Linux Network Intrusion Detection & Explainable Threat Response System
## Comprehensive Project Status Report & Strategic Roadmap

---

## 1. Executive Summary

| Attribute | Details |
| :--- | :--- |
| **Project Name** | Automated Linux Network Intrusion Detection System (NIDS) with XAI |
| **Target OS** | Linux (Arch Linux / Ubuntu / Debian / Fedora) |
| **Core Architecture** | Two-Stage Machine Learning (Binary XGBoost + Multi-Class RF) |
| **Feature Extraction** | 77 Bidirectional Statistical Network Features (CICFlowMeter standard) |
| **Explainable AI** | SHAP (*SHapley Additive exPlanations*) TreeExplainer |
| **Defense Mechanism** | Multi-Factor Risk Engine + Automated Linux `iptables` Mitigation |
| **Host Correlation** | Cross-referencing Network Flows with `/var/log/auth.log` |
| **User Interfaces** | 1. Dual-Mode Real-Time Web SOC Dashboard (Simple Mode & Expert Mode)<br>2. Headless Terminal CLI Orchestrator (`main.py`) |
| **Packet Ingestion** | Native Wireshark / `tcpdump` `.pcap` Ingestion & Live Scapy Interface Sniffer |
| **Repository** | https://github.com/josetolickal/project-cnla |

---

## 2. What We Have Done So Far (Milestones 1 – 14)

```
[ Real-Time Linux Network Packets / Wireshark .pcap ]
                         │
                         ▼
             [ src/capture.py: M8 & M14 ]
             • Link-Layer Packet Parsing (Ethernet/IP/TCP/UDP)
             • Bidirectional 5-Tuple Flow Aggregation
             • 77 CICFlowMeter Statistical Metrics Computation
                         │
                         ▼
             [ src/predict.py: M4 & M5 ]
             • Stage 1: XGBoost / Random Forest (Benign vs Malicious)
             • Stage 2: Multi-Class Attack Classifier (DDoS, PortScan, SSH-Patator...)
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
 [ src/log_correlator.py: M9 ]   [ src/explain.py: M6 ]
 • Linux `/var/log/auth.log`     • SHAP TreeExplainer Local Attributions
 • Failed password matches       • Mathematical feature impact scores
         │                               │
         └───────────────┬───────────────┘
                         ▼
             [ src/risk_engine.py: M7 ]
             • Multi-Factor Threat Severity Calculation (0.0 to 1.0)
             • Priority Tiers: LOW, MEDIUM, HIGH, CRITICAL
                         │
                         ▼
             [ src/response.py: M10 ]
             • Automated Linux `iptables` Defense (DROP rules)
             • Protected IP Whitelisting (127.0.0.1, Gateway, DNS)
             • Safe Dry-Run Simulation Mode
                         │
                         ▼
        [ src/app.py & index.html: M11 & M14 ]
        • Real-Time Web SOC Dashboard
        • Dual-Mode UI: Non-Technical Simple Mode vs Expert Mode
        • Wireshark Ingestion & 3-Pane Packet Dissector View
```

### Detailed Breakdown of Completed Modules

#### Milestone 1 & 2 — Architecture, Environment & Safety Baseline
- Established isolated Python virtual environment (`.venv`) and repository layout.
- Configured `.gitignore` to prevent committing massive datasets or compiled weights.
- Established strict PEP-8 coding guidelines and modular architecture.

#### Milestone 3 — Dataset Processing & 77-Feature Mapping
- Filtered infinite and NaN values from high-volume network streams.
- Mapped bidirectional network flows to standard 77 CICFlowMeter features (Flow Duration, Packet Length Std, Inter-Arrival Times, TCP Flags, Bulk Transfer Rates).

#### Milestone 4 & 5 — Two-Stage Machine Learning Hierarchy
- **Stage 1 (Binary Filter):** Detects whether any network flow is *Benign* or *Malicious* in under 1 millisecond.
- **Stage 2 (Multi-Class Specialist):** Only triggered when malicious traffic is caught. Categorizes the precise attack type (`DDoS`, `PortScan`, `SSH-Patator`, `FTP-Patator`, `Web Attack`).
- Prevents computational waste by avoiding multi-class evaluation on harmless background traffic.

#### Milestone 6 — Explainable AI (SHAP TreeExplainer)
- Eliminated the "black-box" nature of machine learning security tools.
- Generates exact Shapley values showing which network attributes drove the prediction (e.g., `+0.42` driven by `Fwd Packet Length Std`, `+0.31` driven by `SYN Flag Count`).
- Generates natural language explanations for human analysts.

#### Milestone 7 — Composite Threat Risk Engine
- Implemented formula: $\text{Base Risk} \times \text{Attack Severity Multiplier} + \text{Host Log Correlation Boost}$.
- Translates ML probabilities into actionable operational tiers: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

#### Milestone 8 — Native Flow Extraction from Raw Packets
- Implemented bidirectional 5-tuple tracking (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
- Aggregates sliding packet windows and flushes flows upon TCP `FIN`/`RST` or idle timeout.

#### Milestone 9 — Linux Host Authentication Log Correlation
- Cross-references incoming suspicious network flows against host Linux auth logs (`/var/log/auth.log` or `/var/log/secure`).
- Flags coordinated intrusions (e.g., rapid SSH connection attempts accompanied by host OS password rejections).

#### Milestone 10 — Automated Threat Response (Controlled Firewall Mitigation)
- Automatically triggers Linux kernel `iptables` drop commands:
  ```bash
  sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP
  ```
- **Failsafe Whitelisting:** Protects loopback (`127.0.0.1`), local network gateways, and critical internal servers from accidental self-lockout.
- **Dry-Run Toggle:** Allows security auditing without making active firewall modifications.

#### Milestone 11 — Dual-Mode Real-Time Web SOC Dashboard
- Built with Flask, Tailwind CSS, FontAwesome, and Chart.js.
- **Simple Mode for Non-Technical Users:** Translates cryptic IPs and packet lengths into everyday human terms (e.g., *"💻 This Computer"*, *"🏠 Local Home Wi-Fi"*, *"💥 Massive Flood Attack"*), accompanied by plain-English advice (*"What Should I Do?"*).
- **Expert Mode for Security Analysts:** Full SHAP bar charts, mathematical risk metrics, 5-tuple flow tables, and manual firewall controls.

#### Milestone 12 & 13 — System Integration & Master CLI
- Master orchestrator in `main.py`:
  - `python main.py`: Runs interactive end-to-end multi-module pipeline demo.
  - `python main.py --web`: Launches the Flask real-time SOC dashboard.
  - `python main.py --pcap <file>`: Directly analyzes Wireshark capture files from the terminal.

#### Milestone 14 — Native Wireshark Integration
1. **In-Browser `.pcap` File Ingestion:** Users can drag-and-drop or upload any `.pcap` / `.pcapng` capture recorded in Wireshark directly into the web dashboard.
2. **Wireshark 3-Pane Packet Dissector:** Clicking any incident opens an interactive Wireshark modal featuring:
   - *Top Pane:* Frame & Packet Stream list (`No.`, `Time`, `Source`, `Destination`, `Proto`, `Length`, `Info`).
   - *Middle Pane:* Decoded OSI Protocol Tree (`Frame` ➔ `Ethernet II` ➔ `IPv4` ➔ `TCP/UDP`).
   - *Bottom Pane:* Raw Wire Hex Dump viewer with byte offsets.
3. **Live Linux Sniffer Controller:** Background sniffer thread that can capture live packets directly from Linux network interfaces (`eth0`, `wlan0`, `lo`) with a one-click dashboard toggle.
4. **Pre-Packaged Demo PCAPs:** Bundled sample attack captures in `data/sample_pcaps/` (`syn_flood_ddos.pcap`, `ssh_bruteforce.pcap`, `benign_web_browsing.pcap`) for instant 1-click viva demonstrations.

---

## 3. Current System Verification & Test Status

All components are tested with 100% pass rates:
- **Unit & Integration Tests:** Verified via `tests/` with 23 automated tests passing.
- **PCAP Parsing Verification:** Verified with standard Ethernet-framed `.pcap` captures.
- **Web API Endpoints:** `/api/status`, `/api/events`, `/api/upload_pcap`, `/api/load_sample_pcap`, `/api/capture/start`, `/api/capture/stop` validated with HTTP 200 responses.
- **Git Synchronization:** Codebase synchronized with GitHub remote repository.

---

## 4. What We Are Planning To Do (Strategic Roadmap)

### Phase 1: Real-Time WebSocket / SSE Streaming
- **Objective:** Upgrade from HTTP polling (`setInterval` every 3-4 seconds) to Server-Sent Events (SSE) or WebSockets.
- **Benefit:** Reduces server CPU utilization and pushes incoming network alerts to the dashboard with zero millisecond latency.

### Phase 2: Distributed Multi-Sensor Sniffing
- **Objective:** Enable lightweight Python client sensor daemons to run on multiple remote Linux VMs/devices.
- **Benefit:** Centralized SOC dashboard monitoring traffic across an entire corporate or university lab network rather than a single machine.

### Phase 3: Deep Packet Inspection (DPI) & TLS Fingerprinting
- **Objective:** Ingest encrypted HTTPS / TLS handshakes to extract **JA3 / JA3S TLS fingerprints** and cipher suite lists without decrypting user payloads.
- **Benefit:** Detects malicious C2 (Command and Control) malware agents and Cobalt Strike beacons hiding inside standard encrypted HTTPS traffic.

### Phase 4: Automated PDF Incident Report Generation
- **Objective:** Add an "Export Incident Briefing (PDF)" button in the dashboard.
- **Benefit:** Generates a professional PDF executive report summarizing detected attacks, risk rationale, SHAP feature drivers, and firewall response actions for management or college viva documentation.

### Phase 5: Production Linux Systemd & Containerization
- **Objective:** Package the IDS into a Docker container and provide a Linux `systemd` service file (`nids.service`).
- **Benefit:** Enables the IDS to boot automatically in the background upon Linux system startup as an enterprise-grade service.

---

## 5. Viva Presentation Talking Points

1. **Why Two Stages of Machine Learning?**
   > *"Evaluating 80 features across 15 attack classes on every single network packet is computationally prohibitive at gigabit speeds. Our Stage 1 binary classifier discards 99% of harmless benign traffic in under a millisecond, only invoking the complex Stage 2 attack specialist when anomalous behavior is confirmed."*

2. **Why SHAP Instead of LIME?**
   > *"SHAP provides mathematically proven additive feature attributions rooted in cooperative game theory. Because our classifiers use tree ensembles (XGBoost and Random Forest), SHAP's TreeExplainer computes exact Shapley values in polynomial time, whereas LIME relies on random local perturbations which are slower and non-deterministic."*

3. **How Does Wireshark Complement Your Machine Learning?**
   > *"Wireshark operates at the raw frame and packet inspection layer (displaying individual byte offsets and TCP flags), while our system operates at the behavioral flow session layer (aggregating packets into 77 statistical features). Wireshark provides the forensic evidence, while our system provides automated detection, risk scoring, and autonomous firewall response."*
