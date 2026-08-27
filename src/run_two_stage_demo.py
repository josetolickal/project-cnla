"""
Run the full two-stage prediction pipeline on real CICIDS2017 rows.

Stage 1 decides whether a flow is benign or malicious. Stage 2 runs only
for malicious predictions and returns the specific attack type.

Run from the project root:
    python src/run_two_stage_demo.py
"""

from __future__ import annotations

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.predict import identify_attack_type, load_pipeline, predict_flow


DATA_DIR = os.path.join("data", "processed", "cicids2017_binary")

LABEL_REPLACEMENTS = {
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack � Sql Injection": "Web Attack - Sql Injection",
    "Web Attack � XSS": "Web Attack - XSS",
    "Web Attack – Brute Force": "Web Attack - Brute Force",
    "Web Attack – Sql Injection": "Web Attack - Sql Injection",
    "Web Attack – XSS": "Web Attack - XSS",
}


def pick_sample_row(filename: str, attack_type: str) -> pd.Series:
    path = os.path.join(DATA_DIR, filename)
    frame = pd.read_parquet(path)
    labels = frame["attack_type"].replace(LABEL_REPLACEMENTS)
    subset = frame[labels == attack_type]
    if subset.empty:
        raise ValueError(f"No rows with attack_type={attack_type!r} in {filename}")
    row = subset.iloc[0].copy()
    row["attack_type"] = LABEL_REPLACEMENTS.get(row["attack_type"], row["attack_type"])
    return row


def main() -> None:
    pipeline = load_pipeline()

    test_cases = [
        ("Benign", "Benign-Monday-no-metadata.parquet", "Benign"),
        ("DDoS", "DDoS-Friday-no-metadata.parquet", "DDoS"),
        ("DoS Hulk", "DoS-Wednesday-no-metadata.parquet", "DoS Hulk"),
        ("DoS slowloris", "DoS-Wednesday-no-metadata.parquet", "DoS slowloris"),
        ("FTP-Patator", "Bruteforce-Tuesday-no-metadata.parquet", "FTP-Patator"),
        ("SSH-Patator", "Bruteforce-Tuesday-no-metadata.parquet", "SSH-Patator"),
        ("PortScan", "Portscan-Friday-no-metadata.parquet", "PortScan"),
        ("Bot", "Botnet-Friday-no-metadata.parquet", "Bot"),
        ("Web Attack - XSS", "WebAttacks-Thursday-no-metadata.parquet", "Web Attack - XSS"),
    ]

    print("=" * 72)
    print("Two-stage prediction demo")
    print("=" * 72)
    print(f"{'Ground truth':<24} {'Stage 1':<12} {'Stage 2':<28} {'Confidence'}")
    print("-" * 72)

    all_passed = True
    for expected, filename, attack_type in test_cases:
        row = pick_sample_row(filename, attack_type)
        stage1 = predict_flow(row, pipeline)

        if stage1["is_malicious"]:
            stage2 = identify_attack_type(row, pipeline)
            predicted_attack = stage2["attack_type"]
            confidence = f"{stage2['confidence']:.4f}"
        else:
            predicted_attack = "-"
            confidence = "-"

        stage1_correct = (
            stage1["label"] == "benign"
            if expected == "Benign"
            else stage1["label"] == "malicious"
        )
        stage2_valid = expected == "Benign" or predicted_attack != "Benign"
        all_passed = all_passed and stage1_correct and stage2_valid
        if not stage1_correct:
            status = "STAGE1_FAIL"
        elif not stage2_valid:
            status = "STAGE2_INVALID"
        elif expected != "Benign" and predicted_attack != expected:
            status = "TYPE_MISMATCH"
        else:
            status = "PASS"

        print(
            f"{expected:<24} {stage1['label']:<12} "
            f"{predicted_attack:<28} {confidence}  {status}"
        )

    print("=" * 72)
    if all_passed:
        print("Stage 1 passed and Stage 2 returned attack-only labels.")
        print("TYPE_MISMATCH rows are model limitations, not pipeline failures.")
    else:
        print("One or more pipeline checks failed.")
    print("=" * 72)


if __name__ == "__main__":
    main()
