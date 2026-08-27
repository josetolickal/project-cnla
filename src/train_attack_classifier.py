"""
Milestone 5 (extension) — Multi-class attack type classifier
=============================================================

What this script does (plain English):
  The binary model (train_model.py) tells us WHETHER a flow is malicious.
  This script trains a second Random Forest that tells us WHAT KIND of
  attack it is — DDoS, PortScan, SSH brute-force, etc.

  The two models work as a pipeline:
    Stage 1 (binary model)       → "Is this malicious?"
    Stage 2 (multi-class model)  → "What kind of attack is it?"

  This second model is trained on ALL rows (including Benign) using the
  same 77 features. It predicts one of 15 possible labels:
    Benign, DDoS, DoS Hulk, DoS GoldenEye, DoS slowloris,
    DoS Slowhttptest, FTP-Patator, SSH-Patator, PortScan,
    Web Attack – Brute Force, Web Attack – XSS,
    Web Attack – Sql Injection, Bot, Infiltration, Heartbleed.

  Note on rare classes: Heartbleed has only 11 rows and Infiltration has
  36. The model will have difficulty identifying these reliably. This is
  honest and expected — the report documents it.

Run from the project root:
    python src/train_attack_classifier.py
"""

import json
import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

DATA_DIR   = os.path.join("data", "processed", "cicids2017_binary")
MODELS_DIR = "models"
MODEL_PATH        = os.path.join(MODELS_DIR, "attack_type_classifier.joblib")
ENCODER_PATH      = os.path.join(MODELS_DIR, "attack_type_label_encoder.joblib")
METRICS_PATH      = os.path.join(MODELS_DIR, "attack_type_metrics.json")

RANDOM_SEED  = 42
N_ESTIMATORS = 100
TEST_SIZE    = 0.20
NON_FEATURE_COLS = ["attack_type", "is_malicious"]


def load_all_parquet(data_dir: str) -> pd.DataFrame:
    files = sorted(f for f in os.listdir(data_dir) if f.endswith(".parquet"))
    parts = []
    for filename in files:
        df = pd.read_parquet(os.path.join(data_dir, filename))
        parts.append(df)
        print(f"  Loaded {filename}: {len(df):,} rows")
    combined = pd.concat(parts, ignore_index=True)
    print(f"\nTotal rows: {len(combined):,}")
    return combined


def main() -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)

    # ------------------------------------------------------------------
    # Step 1: Load data
    # ------------------------------------------------------------------
    print("=" * 60)
    print("Step 1: Loading processed data")
    print("=" * 60)
    df = load_all_parquet(DATA_DIR)

    print("\nAttack type distribution:")
    for label, count in df["attack_type"].value_counts().items():
        print(f"  {label:<42} {count:>8,}")

    # ------------------------------------------------------------------
    # Step 2: Encode the target label
    # ------------------------------------------------------------------
    # Machine learning models need numbers, not text strings.
    # LabelEncoder converts "DDoS" → 2, "Benign" → 0, etc.
    # We save the encoder so later code can convert numbers back to names.
    print("\n" + "=" * 60)
    print("Step 2: Encoding attack type labels as numbers")
    print("=" * 60)

    le = LabelEncoder()
    y = le.fit_transform(df["attack_type"])

    print(f"  Classes ({len(le.classes_)}):")
    for i, cls in enumerate(le.classes_):
        print(f"    {i:>2} → {cls}")

    # Save encoder
    joblib.dump(le, ENCODER_PATH)
    print(f"\n  Encoder saved to: {ENCODER_PATH}")

    # ------------------------------------------------------------------
    # Step 3: Features
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 3: Preparing feature matrix")
    print("=" * 60)

    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X = df[feature_cols].values.astype(np.float32)
    print(f"  Features: {len(feature_cols)}  |  Rows: {X.shape[0]:,}")

    # ------------------------------------------------------------------
    # Step 4: Stratified train/test split
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 4: Stratified 80/20 train/test split")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    print(f"  Training rows : {len(X_train):,}")
    print(f"  Test rows     : {len(X_test):,}")

    # ------------------------------------------------------------------
    # Step 5: Train
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 5: Training multi-class Random Forest")
    print("  (100 trees, 15 classes — may take a few minutes)")
    print("=" * 60)

    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        class_weight="balanced",   # handles the extreme imbalance
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    t_start = time.time()
    clf.fit(X_train, y_train)
    train_seconds = time.time() - t_start
    print(f"  Training finished in {train_seconds:.1f} seconds")

    # ------------------------------------------------------------------
    # Step 6: Evaluate
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 6: Evaluating on test set")
    print("=" * 60)

    y_pred = clf.predict(X_test)

    print("\nPer-class results:")
    report_str = classification_report(
        y_test, y_pred, target_names=le.classes_, zero_division=0
    )
    print(report_str)

    # Parse overall weighted avg for saving
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall    = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1        = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print(f"  Overall Accuracy  : {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"  Weighted Precision: {precision:.4f}")
    print(f"  Weighted Recall   : {recall:.4f}")
    print(f"  Weighted F1       : {f1:.4f}")

    # ------------------------------------------------------------------
    # Step 7: Save
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 7: Saving model and metrics")
    print("=" * 60)

    joblib.dump(clf, MODEL_PATH, compress=3)
    print(f"  Model saved to: {MODEL_PATH}")

    metrics = {
        "model": "RandomForestClassifier (multi-class)",
        "n_estimators": N_ESTIMATORS,
        "class_weight": "balanced",
        "random_seed": RANDOM_SEED,
        "n_classes": int(len(le.classes_)),
        "classes": list(le.classes_),
        "n_train_rows": int(len(X_train)),
        "n_test_rows": int(len(X_test)),
        "accuracy": round(float(accuracy), 6),
        "weighted_precision": round(float(precision), 6),
        "weighted_recall": round(float(recall), 6),
        "weighted_f1": round(float(f1), 6),
        "train_time_seconds": round(train_seconds, 1),
    }

    with open(METRICS_PATH, "w") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"  Metrics saved to: {METRICS_PATH}")

    print("\n" + "=" * 60)
    print("Attack type classifier training complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
