# Future Enhancements & System Roadmap — Network Intrusion Detection System

> **Note**: This document is a standalone technical report outlining potential enhancements, upgrades, and future milestones for the Automated Network Intrusion Detection System (IDS). It does **not** alter or replace the living test record located in [`docs/REPORT_NOTES.md`](file:///home/Jose/Documents/project%20cnla/docs/REPORT_NOTES.md).

---

## 1. System Overview & Current Baseline

The existing system implements a **two-stage intrusion detection pipeline**:
1. **Stage 1 (Binary Classifier)**: Random Forest model predicting whether a traffic flow is `benign` (0) or `malicious` (1).
   - Test Accuracy: **99.88%** | Precision: **0.9951** | Recall: **0.9965** | F1-Score: **0.9958**
2. **Stage 2 (Attack-only Multi-class Classifier)**: Random Forest model predicting the exact attack category after Stage 1 flags a flow as malicious (e.g., `DDoS`, `PortScan`, `FTP-Patator`, `DoS Hulk`).
   - Test Accuracy: **99.71%** | Weighted F1-Score: **0.9970**

The dataset processed consists of **2,313,810 rows** across 77 numerical network features derived from CICIDS2017.

---

## 2. Recommended Future Enhancements & Upgrades

The following upgrades are categorized by project domain and can be implemented incrementally without breaking existing features.

### A. Machine Learning & Model Performance

1. **Rare Class Imbalance Handling (SMOTE / ADASYN)**
   - *Current limitation*: Rare attack types such as `Web Attack - Sql Injection` (21 rows total), `Heartbleed` (11 rows), and `Infiltration` (36 rows) have lower recall in Stage 2.
   - *Proposed update*: Apply synthetic oversampling (SMOTE/ADASYN) or focal loss algorithms specifically during Stage 2 training to boost minority class detection.

2. **Model Comparison & Benchmarking (XGBoost / LightGBM)**
   - *Current implementation*: Scikit-learn `RandomForestClassifier`.
   - *Proposed update*: Train an XGBoost or LightGBM model on the same 77 features to compare memory usage, inference speed per row, and recall on rare attacks.

3. **Hyperparameter Tuning & Feature Selection**
   - *Proposed update*: Perform SHAP-guided feature selection to reduce the feature count from 77 down to top 15–20 features (e.g., `Flow Bytes/s`, `Init Fwd Win Bytes`, `Packet Length Mean`). This speeds up live inference during real-time packet capture.

---

### B. Explainability & Interpretability (Milestone 6)

1. **SHAP (SHapley Additive exPlanations) Integration**
   - *Proposed update*: Integrate `shap.TreeExplainer` into `src/predict.py`. For every positive detection, generate a waterfall plot or tabular output listing top 3 contributing features (e.g., *"Flagged malicious due to high Fwd Packets/s (val: 15,000) and low Flow Duration"*).

2. **LIME (Local Interpretable Model-agnostic Explanations)**
   - *Proposed update*: Add LIME as an alternative fast local explainer for real-time dashboard display.

---

### C. Threat Scoring & Risk Engine (Milestone 7)

1. **Rule-Based & Contextual Risk Engine**
   - *Proposed update*: Combine prediction probability ($P_{malicious}$) with attack severity weights:
     $$\text{Risk Score} = (P_{malicious} \times 0.6) + (\text{Attack Severity Weight} \times 0.4)$$
   - *Risk Levels*:
     - **LOW**: $0.0 - 0.35$ (Suspicious single scan)
     - **MEDIUM**: $0.35 - 0.65$ (Brute force attempt)
     - **HIGH**: $0.65 - 0.85$ (Active DoS / Botnet C2 traffic)
     - **CRITICAL**: $0.85 - 1.00$ (Exfiltration / SQL Injection / Active DDoS)

---

### D. Live Capture & Feature Extraction (Milestone 8)

1. **Real-time Live Packet Capture (tcpdump / Scapy / PyShark)**
   - *Proposed update*: Build a live packet listener capturing raw network interface packets (`eth0`/`wlan0`) and computing rolling window statistics to map raw TCP/UDP fields into the expected 77 CICFlowMeter features.

---

### E. Linux Log Correlation & System Audit (Milestone 9)

1. **System Log Integration (`journalctl` / `/var/log/auth.log`)**
   - *Proposed update*: Correlate network alerts with Linux system logs (e.g., cross-referencing an `SSH-Patator` network detection with actual failed login attempts in `/var/log/auth.log` or `sshd` systemd logs).

---

### F. Automated Threat Response & Containment (Milestone 10)

1. **Firewall Response Engine (iptables / UFW)**
   - *Proposed update*: Implement a controlled responder script that automatically drops packets or blocks source IPs using `iptables` or `ufw` when a **CRITICAL** risk score is triggered.
   - *Safety feature*: Include a **dry-run mode** and an explicit IP whitelist (`127.0.0.1`, local subnet) to avoid locking out legitimate users.

---

### G. Live Web Dashboard (Milestones 11 & 12)

1. **Flask / FastAPI Real-Time Monitoring Interface**
   - *Proposed update*: Web dashboard presenting:
     - Real-time traffic flow counters & benign vs malicious ratios.
     - Live alert table with Attack Type, Source IP, Risk Level, and Timestamp.
     - Interactive SHAP feature importance charts.
     - Manual "Block IP / Unblock IP" control toggle.

---

## 3. Implementation Priority Matrix

| Priority | Feature / Enhancement | Target Milestone | Effort | Value |
|---|---|---|---|---|
| **P1** | SHAP Feature Explainability | Milestone 6 | Medium | High |
| **P1** | Risk Engine (LOW/MED/HIGH/CRIT) | Milestone 7 | Low | High |
| **P2** | Flask Web Dashboard | Milestone 11 | Medium | High |
| **P2** | Automated UFW/iptables Response | Milestone 10 | Medium | High |
| **P3** | Live Capture & CICFlowMeter Mapping | Milestone 8 | High | Medium |
| **P3** | SMOTE Oversampling for Rare Attacks | Extension | Low | Medium |
