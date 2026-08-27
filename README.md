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

Milestones 1-5 are complete:

- CICIDS2017 data has been inspected, validated, and saved as processed
  Parquet files.
- A binary Random Forest classifier detects benign vs malicious traffic.
- A second attack-only Random Forest classifier identifies the specific
  attack type after Stage 1 flags a flow as malicious.
- `src/predict.py` loads both models and exposes the reusable prediction
  functions.
- Demo scripts are available for binary prediction and the two-stage pipeline.

Current model artifacts:

- `models/random_forest_baseline.joblib`
- `models/attack_type_classifier.joblib`
- `models/attack_type_label_encoder.joblib`
- `models/feature_names.json`
- `models/baseline_metrics.json`
- `models/attack_type_metrics.json`

## Setup

Create and activate the project virtual environment:

```bash
source .venv/bin/activate
```

Install the baseline Python packages after the user has reviewed them:

```bash
python -m pip install -r requirements.txt
```

## Safety note

The automated-response module will be developed in dry-run mode first. It will
not change firewall rules unless this is explicitly enabled and tested safely.
