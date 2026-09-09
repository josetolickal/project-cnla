"""
Demo: Two-Stage Detection + SHAP Explainability + Risk Engine
=============================================================

Demonstrates Milestones 5, 6, and 7 working together:
  1. Prediction Pipeline (Stage 1 Binary + Stage 2 Attack Type)
  2. Explainable AI (SHAP TreeExplainer local feature contributions)
  3. Threat Risk Engine (Risk Score & Threat Level: LOW/MED/HIGH/CRITICAL)

Run from project root:
    python src/run_xai_and_risk_demo.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.predict import load_pipeline, predict_flow, identify_attack_type
from src.explain import explain_flow, format_explanation_table
from src.risk_engine import calculate_risk

SAMPLE_DATA_PATH = os.path.join("data", "sample_flows.json")


def main():
    print("=" * 80)
    print("DEMO: INTRUSION DETECTION + SHAP EXPLAINABILITY + RISK ENGINE")
    print("=" * 80)

    # 1. Load pipeline
    pipeline = load_pipeline()
    print("[+] Pipeline loaded successfully.")

    # 2. Load sample test flows
    if not os.path.exists(SAMPLE_DATA_PATH):
        from src.setup_dev_models import ensure_models_and_samples
        ensure_models_and_samples()

    with open(SAMPLE_DATA_PATH, "r") as fh:
        samples = json.load(fh)

    # 3. Process each sample through the full intelligence stack
    for name, flow in samples.items():
        print("\n" + "#" * 80)
        print(f"FLOW SCENARIO: {name.upper()}")
        print("#" * 80)

        # Stage 1: Detection
        pred = predict_flow(flow, pipeline)
        print(f"\n[Stage 1] Classification: {pred['label'].upper()} (Confidence: {pred['probability']:.2%})")

        # Stage 2: Attack Classification (if malicious)
        attack_type = None
        if pred["is_malicious"] == 1:
            attack_info = identify_attack_type(flow, pipeline)
            attack_type = attack_info["attack_type"]
            print(f"[Stage 2] Attack Category: {attack_type} (Confidence: {attack_info['confidence']:.2%})")
        else:
            print("[Stage 2] Stage 2 bypassed (traffic is benign).")

        # Milestone 7: Risk Engine Assessment
        risk = calculate_risk(
            is_malicious=pred["is_malicious"],
            probability=pred["probability"],
            attack_type=attack_type
        )
        print(f"\n[Threat Risk Engine]")
        print(f"  Risk Level : [{risk['risk_level']}]")
        print(f"  Risk Score : {risk['risk_score']:.4f} / 1.0000")
        print("  Rationale  :")
        for r in risk["rationale"]:
            print(f"    - {r}")

        # Milestone 6: SHAP Explainability
        print(f"\n[Explainable AI — SHAP Explanation]")
        explanation = explain_flow(flow, pipeline, top_k=3)
        print(format_explanation_table(explanation))

    print("\n" + "=" * 80)
    print("Demo execution finished successfully!")
    print("=" * 80)


if __name__ == "__main__":
    main()
