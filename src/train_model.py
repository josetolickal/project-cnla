"""
Milestone 4 — Baseline Random Forest model trainer
===================================================

What this script does (plain English):
  1. Loads all 8 processed Parquet files from data/processed/cicids2017_binary/.
  2. Combines them into one big table.
  3. Splits the data 80 % training / 20 % test using stratified sampling so
     both halves keep the same ratio of benign vs malicious rows.
  4. Trains a Random Forest classifier (100 decision trees).
  5. Measures Accuracy, Precision, Recall, and F1-score on the test set.
  6. Saves the trained model to  models/random_forest_baseline.joblib
  7. Saves the metrics to        models/baseline_metrics.json

Run from the project root after activating the virtual environment:
    python src/train_model.py
"""

import json
import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------------------------
# Paths — everything is relative to the project root
# ---------------------------------------------------------------------------
DATA_DIR = os.path.join("data", "processed", "cicids2017_binary")
MODELS_DIR = "models"
MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_baseline.joblib")
METRICS_PATH = os.path.join(MODELS_DIR, "baseline_metrics.json")

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
# Random seed: fixing this number means we get the same split and the same
# trees every time we run the script, which makes results reproducible.
RANDOM_SEED = 42

# How many decision trees to grow.  More trees → more accurate but slower.
N_ESTIMATORS = 100

# class_weight="balanced" tells Random Forest to give extra importance to the
# minority class (malicious rows).  Without this the model might learn to just
# predict "benign" most of the time and still look 85 % accurate.
CLASS_WEIGHT = "balanced"

# n_jobs=-1 means "use every CPU core available".  Training 100 trees in
# parallel is much faster than doing them one by one.
N_JOBS = -1

# Test set size: 20 % of the data is held back for evaluation.
TEST_SIZE = 0.20

# Column names that are NOT features
# attack_type reveals the answer — never use it as a feature.
# is_malicious is the target we are trying to predict.
NON_FEATURE_COLS = ["attack_type", "is_malicious"]


def load_all_parquet(data_dir: str) -> pd.DataFrame:
    """Load every .parquet file in data_dir and stack them into one table."""
    files = sorted(f for f in os.listdir(data_dir) if f.endswith(".parquet"))
    if not files:
        raise FileNotFoundError(f"No .parquet files found in {data_dir}")

    parts = []
    for filename in files:
        path = os.path.join(data_dir, filename)
        df = pd.read_parquet(path)
        parts.append(df)
        print(f"  Loaded {filename}: {len(df):,} rows")

    combined = pd.concat(parts, ignore_index=True)
    print(f"\nTotal rows after combining all files: {len(combined):,}")
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

    # Class balance summary
    n_benign = int((df["is_malicious"] == 0).sum())
    n_malicious = int((df["is_malicious"] == 1).sum())
    n_total = len(df)
    print(f"\nClass balance:")
    print(f"  Benign    : {n_benign:,}  ({n_benign / n_total * 100:.1f} %)")
    print(f"  Malicious : {n_malicious:,}  ({n_malicious / n_total * 100:.1f} %)")

    # ------------------------------------------------------------------
    # Step 2: Separate features (X) from the target label (y)
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 2: Preparing features and target label")
    print("=" * 60)

    # X = everything except the non-feature columns
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X = df[feature_cols].values.astype(np.float32)  # float32 saves memory
    y = df["is_malicious"].values

    print(f"  Feature columns : {len(feature_cols)}")
    print(f"  Feature matrix  : {X.shape}")
    print(f"  Target vector   : {y.shape}")

    # Save the list of feature names for use by the prediction pipeline later
    feature_names_path = os.path.join(MODELS_DIR, "feature_names.json")
    with open(feature_names_path, "w") as fh:
        json.dump(feature_cols, fh, indent=2)
    print(f"  Feature names saved to: {feature_names_path}")

    # ------------------------------------------------------------------
    # Step 3: Stratified train/test split
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 3: Stratified 80 / 20 train/test split")
    print("=" * 60)

    # stratify=y ensures that both the training set and the test set contain
    # roughly the same proportion of benign vs malicious rows.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )

    print(f"  Training rows : {len(X_train):,}")
    print(f"  Test rows     : {len(X_test):,}")
    print(f"  Training malicious %  : {y_train.mean() * 100:.2f} %")
    print(f"  Test     malicious %  : {y_test.mean() * 100:.2f} %")

    # ------------------------------------------------------------------
    # Step 4: Train the Random Forest
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 4: Training Random Forest")
    print("  (This may take a few minutes — 100 trees on 1.8 M rows)")
    print("=" * 60)

    clf = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        class_weight=CLASS_WEIGHT,
        random_state=RANDOM_SEED,
        n_jobs=N_JOBS,
    )

    t_start = time.time()
    clf.fit(X_train, y_train)
    train_seconds = time.time() - t_start
    print(f"  Training finished in {train_seconds:.1f} seconds")

    # ------------------------------------------------------------------
    # Step 5: Evaluate on the held-out test set
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Step 5: Evaluating on the test set")
    print("=" * 60)

    y_pred = clf.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)

    # average="binary" measures performance specifically on the positive
    # class (malicious = 1), which is what we really care about.
    precision = precision_score(y_test, y_pred, average="binary")
    recall = recall_score(y_test, y_pred, average="binary")
    f1 = f1_score(y_test, y_pred, average="binary")

    print(f"\n  Accuracy  : {accuracy:.4f}  ({accuracy * 100:.2f} %)")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1-score  : {f1:.4f}")
    print("\n  Full classification report:")
    print(
        classification_report(
            y_test, y_pred, target_names=["Benign (0)", "Malicious (1)"]
        )
    )

    # ------------------------------------------------------------------
    # Step 6: Save the trained model
    # ------------------------------------------------------------------
    print("=" * 60)
    print("Step 6: Saving model and metrics")
    print("=" * 60)

    joblib.dump(clf, MODEL_PATH, compress=3)
    print(f"  Model saved to: {MODEL_PATH}")

    # Save metrics to JSON so other scripts can read them without re-training
    metrics = {
        "model": "RandomForestClassifier",
        "n_estimators": N_ESTIMATORS,
        "class_weight": CLASS_WEIGHT,
        "random_seed": RANDOM_SEED,
        "test_size_fraction": TEST_SIZE,
        "n_train_rows": int(len(X_train)),
        "n_test_rows": int(len(X_test)),
        "n_features": int(len(feature_cols)),
        "accuracy": round(float(accuracy), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1_score": round(float(f1), 6),
        "train_time_seconds": round(train_seconds, 1),
    }

    with open(METRICS_PATH, "w") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"  Metrics saved to: {METRICS_PATH}")

    print("\n" + "=" * 60)
    print("Milestone 4 complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
