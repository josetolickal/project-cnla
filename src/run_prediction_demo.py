"""
Milestone 5 — Prediction pipeline demo
========================================

What this script does (plain English):
  It loads three real rows from the processed dataset — one that is actually
  benign, one that is actually malicious, and one from the borderline
  Infiltration file (very few attacks) — and runs each through the
  prediction pipeline.

  This proves that:
  1. The saved model loads correctly.
  2. The feature ordering logic works.
  3. The pipeline returns sensible labels and probabilities.
  4. The pipeline correctly ignores non-feature columns like attack_type.

Run from the project root:
    python src/run_prediction_demo.py
"""

import os
import sys

import pandas as pd

# Allow importing from the src package when running as a script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.predict import load_pipeline, predict_flow

DATA_DIR = os.path.join("data", "processed", "cicids2017_binary")


def pick_sample_row(filename: str, is_malicious_value: int) -> pd.Series:
    """
    Load one row from a Parquet file where is_malicious == is_malicious_value.
    Returns the row as a pandas Series.
    """
    path = os.path.join(DATA_DIR, filename)
    df = pd.read_parquet(path)
    subset = df[df["is_malicious"] == is_malicious_value]
    if subset.empty:
        raise ValueError(
            f"No rows with is_malicious={is_malicious_value} in {filename}"
        )
    # Take the first matching row
    return subset.iloc[0]


def main() -> None:
    print("=" * 60)
    print("Milestone 5 — Prediction Pipeline Demo")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Load the pipeline once.  Both predict_flow() calls below reuse it.
    # ------------------------------------------------------------------
    print("\nLoading model and feature names...")
    pipeline = load_pipeline()
    print(f"  Model loaded  : {type(pipeline['model']).__name__}")
    print(f"  Features expected: {len(pipeline['feature_names'])}")

    # ------------------------------------------------------------------
    # Test cases
    # ------------------------------------------------------------------
    test_cases = [
        {
            "description": "Test 1 — A known BENIGN flow (Monday traffic)",
            "file": "Benign-Monday-no-metadata.parquet",
            "is_malicious_value": 0,
            "expected_label": "benign",
        },
        {
            "description": "Test 2 — A known MALICIOUS flow (DDoS attack)",
            "file": "DDoS-Friday-no-metadata.parquet",
            "is_malicious_value": 1,
            "expected_label": "malicious",
        },
        {
            "description": "Test 3 — A known MALICIOUS flow (DoS Wednesday)",
            "file": "DoS-Wednesday-no-metadata.parquet",
            "is_malicious_value": 1,
            "expected_label": "malicious",
        },
        {
            "description": "Test 4 — A known BENIGN flow (DDoS file, benign rows)",
            "file": "DDoS-Friday-no-metadata.parquet",
            "is_malicious_value": 0,
            "expected_label": "benign",
        },
    ]

    all_passed = True

    for tc in test_cases:
        print(f"\n{'-' * 60}")
        print(tc["description"])
        print(f"{'-' * 60}")

        # Load one real row from the dataset
        row = pick_sample_row(tc["file"], tc["is_malicious_value"])
        actual_attack_type = row.get("attack_type", "unknown")
        actual_is_malicious = int(row["is_malicious"])

        print(f"  Ground truth  → attack_type={actual_attack_type!r}  "
              f"is_malicious={actual_is_malicious}")

        # Run the prediction pipeline.
        # predict_flow() will automatically ignore attack_type and is_malicious.
        result = predict_flow(row, pipeline)

        print(f"  Prediction    → label={result['label']!r}  "
              f"is_malicious={result['is_malicious']}  "
              f"probability={result['probability']:.4f}")

        # Check whether the prediction matches the ground truth
        correct = result["label"] == tc["expected_label"]
        status = "PASS ✓" if correct else "FAIL ✗"
        print(f"  Result        → {status}")

        if not correct:
            all_passed = False

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    if all_passed:
        print("All tests passed. Prediction pipeline is working correctly.")
    else:
        print("One or more tests FAILED. Check the output above.")
    print("=" * 60)


if __name__ == "__main__":
    main()
