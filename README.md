# Automated Network Intrusion Detection System

An academic prototype of a Linux-based Network Intrusion Detection System (IDS).
It will analyse network-traffic data with machine learning, explain individual
predictions, calculate a transparent risk level, and later show results in a
Flask dashboard.

## Project structure

- `data/` — downloaded and processed datasets. Dataset files are not committed
  to Git because they can be large.
- `models/` — saved trained machine-learning models. These are generated later.
- `src/` — the Python code that will preprocess data, train the model, make
  predictions, and support later modules.
- `logs/` — generated detection and response logs.
- `tests/` — small automated checks for the Python code.
- `PROJECT_CONTEXT.md` — the agreed project requirements and milestone plan.

## Current milestone

Milestone 3 is complete: the CICIDS2017 data has been inspected, validated,
and saved in a processed binary-classification format. The next milestone is a
baseline Random Forest model. No model has been trained yet.

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
