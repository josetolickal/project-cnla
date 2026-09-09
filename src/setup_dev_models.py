"""
Setup Development Models and Sample Flows
=========================================

What this script does:
  Checks whether the trained model files (models/*.joblib) exist.
  If they are missing (e.g. fresh git clone or working on a new machine
  without the multi-gigabyte dataset), this script initializes clean,
  working Random Forest models matching the exact 77-feature schema from
  models/feature_names.json.

  This allows:
  - Immediate local testing of src/predict.py
  - Immediate local testing of src/explain.py (SHAP)
  - Immediate local testing of src/risk_engine.py
  - Immediate local testing of the web dashboard

  When the full 2.3M-row dataset is available, running src/train_model.py
  and src/train_attack_classifier.py will naturally overwrite these models.
"""

import json
import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

FEATURE_NAMES_PATH = os.path.join("models", "feature_names.json")
BASELINE_MODEL_PATH = os.path.join("models", "random_forest_baseline.joblib")
ATTACK_MODEL_PATH = os.path.join("models", "attack_type_classifier.joblib")
ENCODER_PATH = os.path.join("models", "attack_type_label_encoder.joblib")
SAMPLE_DATA_PATH = os.path.join("data", "sample_flows.json")


def ensure_models_and_samples():
    os.makedirs("models", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    with open(FEATURE_NAMES_PATH, "r") as fh:
        features = json.load(fh)
    num_features = len(features)

    classes = [
        "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
        "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration",
        "PortScan", "SSH-Patator", "Web Attack - Brute Force",
        "Web Attack - Sql Injection", "Web Attack - XSS"
    ]

    # Check if models already exist
    models_exist = (
        os.path.exists(BASELINE_MODEL_PATH)
        and os.path.exists(ATTACK_MODEL_PATH)
        and os.path.exists(ENCODER_PATH)
    )

    if not models_exist:
        print("[*] Model artifacts not found. Initializing development baseline models...")
        np.random.seed(42)

        # Generate synthetic realistic feature distributions
        n_samples = 600
        X = np.random.uniform(0.0, 100.0, size=(n_samples, num_features)).astype(np.float32)
        
        # Label 0: Benign (first 300), Label 1: Malicious (next 300)
        y_binary = np.array([0] * 300 + [1] * 300)

        # Give malicious samples high packet rate and high flow bytes (feature index 15, 16)
        flow_bytes_idx = features.index("Flow Bytes/s") if "Flow Bytes/s" in features else 15
        flow_pkts_idx = features.index("Flow Packets/s") if "Flow Packets/s" in features else 16
        init_win_idx = features.index("Init Fwd Win Bytes") if "Init Fwd Win Bytes" in features else 67

        X[300:, flow_bytes_idx] += 5000.0
        X[300:, flow_pkts_idx] += 12000.0
        X[300:, init_win_idx] += 29200.0

        # 1. Train Binary Random Forest
        binary_rf = RandomForestClassifier(n_estimators=30, random_state=42, class_weight="balanced")
        binary_rf.fit(X, y_binary)
        joblib.dump(binary_rf, BASELINE_MODEL_PATH, compress=3)
        print(f"    -> Saved {BASELINE_MODEL_PATH}")

        # 2. Train Multi-class Attack Classifier on malicious rows
        X_mal = X[300:]
        attack_labels = [classes[i % len(classes)] for i in range(len(X_mal))]
        
        le = LabelEncoder()
        y_attack = le.fit_transform(attack_labels)
        joblib.dump(le, ENCODER_PATH)
        print(f"    -> Saved {ENCODER_PATH}")

        attack_rf = RandomForestClassifier(n_estimators=30, random_state=42)
        attack_rf.fit(X_mal, y_attack)
        joblib.dump(attack_rf, ATTACK_MODEL_PATH, compress=3)
        print(f"    -> Saved {ATTACK_MODEL_PATH}")

    # Generate sample test flows if not already present
    if not os.path.exists(SAMPLE_DATA_PATH):
        print("[*] Generating reference sample flows for testing...")
        samples = {}
        
        # Benign sample
        benign_row = {f: float(np.random.uniform(5, 50)) for f in features}
        benign_row["Flow Packets/s"] = 12.5
        benign_row["Flow Bytes/s"] = 450.0
        benign_row["Flow Duration"] = 12000.0
        samples["Benign"] = benign_row

        # DDoS sample
        ddos_row = {f: float(np.random.uniform(10, 80)) for f in features}
        ddos_row["Flow Packets/s"] = 18500.0
        ddos_row["Flow Bytes/s"] = 950000.0
        ddos_row["Flow Duration"] = 540.0
        ddos_row["Init Fwd Win Bytes"] = 29200.0
        samples["DDoS"] = ddos_row

        # PortScan sample
        scan_row = {f: float(np.random.uniform(5, 40)) for f in features}
        scan_row["Flow Packets/s"] = 1250.0
        scan_row["SYN Flag Count"] = 1.0
        scan_row["ACK Flag Count"] = 0.0
        scan_row["Flow Duration"] = 85.0
        samples["PortScan"] = scan_row

        # SSH-Patator sample
        ssh_row = {f: float(np.random.uniform(10, 60)) for f in features}
        ssh_row["Flow Packets/s"] = 3400.0
        ssh_row["Flow Bytes/s"] = 45000.0
        ssh_row["Total Fwd Packets"] = 48.0
        samples["SSH-Patator"] = ssh_row

        with open(SAMPLE_DATA_PATH, "w") as fh:
            json.dump(samples, fh, indent=2)
        print(f"    -> Saved {SAMPLE_DATA_PATH}")


if __name__ == "__main__":
    ensure_models_and_samples()
