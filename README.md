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

All Milestones 1 through 13 are complete:

- CICIDS2017 benchmark dataset processed and validated.
- Two-Stage Random Forest ML detection pipeline (Stage 1 Binary: 99.88% accuracy;
  Stage 2 Multi-Class: 99.71% accuracy).
- `src/predict.py` reusable prediction and batch inference modules.
- `src/explain.py` Explainable AI (SHAP TreeExplainer) with feature attributions.
- `src/risk_engine.py` transparent composite threat risk engine (LOW/MED/HIGH/CRITICAL).
- `src/capture.py` network packet sniffer and 77-feature statistical flow mapper.
- `src/log_correlator.py` Linux host log correlation (`/var/log/auth.log`) with dynamic risk boost.
- `src/response.py` automated firewall mitigation with safe dry-run mode and IP whitelisting.
- `src/app.py` & `src/templates/index.html` real-time Flask SOC web dashboard.
- `main.py` master end-to-end integration orchestrator and demo script.
- 18 automated unit and integration tests passing in `tests/`.

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
