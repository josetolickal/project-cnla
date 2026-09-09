# Automated Network Intrusion Detection System

An academic prototype of a Linux-based Network Intrusion Detection System (IDS).
It will analyse network-traffic data with machine learning, explain individual
predictions, calculate a transparent risk level, and later show results in a
Flask dashboard.

## Project structure

- `data/` — downloaded and processed datasets. Dataset files are not committed
  to Git because they can be large.
- `models/` — saved trained machine-learning models and metric JSON files.
- `src/` — the Python code that will preprocess data, train the model, make
  predictions, and support later modules.
- `logs/` — generated detection and response logs.
- `tests/` — small automated checks for the Python code.
- `PROJECT_CONTEXT.md` — the agreed project requirements and milestone plan.

## Current status

Milestones 1-7, 9, 10, and 11 are complete:

- CICIDS2017 data has been inspected, validated, and saved as processed
  Parquet files.
- A binary Random Forest classifier detects benign vs malicious traffic.
- A second attack-only Random Forest classifier identifies the specific
  attack type after Stage 1 flags a flow as malicious.
- `src/predict.py` loads both models and exposes the reusable prediction
  functions.
- `src/explain.py` integrates SHAP explainability to explain why a flow was
  classified as malicious or benign.
- `src/risk_engine.py` calculates a transparent threat score and assigns
  threat levels (LOW, MEDIUM, HIGH, CRITICAL).
- `src/log_correlator.py` correlates host authentication logs (`/var/log/auth.log`)
  with network detections to dynamically escalate threat levels.
- `src/response.py` executes automated mitigation with safe dry-run mode and
  hardcoded IP whitelisting.
- `src/app.py` and `src/templates/index.html` deliver a real-time web dashboard
  for live detection monitoring, interactive SHAP visualization, and firewall
  management.
- 15 automated unit and integration tests verify the pipeline.

Current model artifacts:

- `models/random_forest_baseline.joblib`
- `models/attack_type_classifier.joblib`
- `models/attack_type_label_encoder.joblib`
- `models/feature_names.json`
- `models/baseline_metrics.json`
- `models/attack_type_metrics.json`

## Setup & Running the Dashboard

1. Install required dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

2. Run the automated test suite:
   ```bash
   python -m unittest discover tests
   ```

3. Launch the Real-Time Web Dashboard:
   ```bash
   python src/app.py
   ```
   Open your browser and navigate to: **`http://127.0.0.1:5000`**

## Safety note

The automated-response module runs in **dry-run mode** by default. It logs
firewall actions to `logs/response.log` without modifying system firewall rules
unless explicitly configured.
