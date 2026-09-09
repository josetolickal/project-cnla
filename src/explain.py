"""
Milestone 6 — Explainable AI (SHAP Explainer)
=============================================

What this module does (plain English):
  A standard Machine Learning classifier gives a prediction (e.g. "malicious"),
  but security analysts and viva examiners want to know:
      "WHY did the model make this decision?"

  This module uses SHAP (SHapley Additive exPlanations) to explain individual
  predictions by calculating the contribution of each network feature:
  - A POSITIVE SHAP value means that feature pushed the model toward "malicious".
    (e.g., abnormally high packet rate or unusual byte count).
  - A NEGATIVE SHAP value means that feature pushed the model toward "benign".
    (e.g., standard packet size or normal flow duration).

  This turns the Random Forest from a "black box" into a transparent system.
"""

from typing import Dict, Any, List, Union, Optional
import numpy as np
import pandas as pd
import shap

from src.predict import predict_flow

# Module-level cache for the TreeExplainer so it doesn't get rebuilt on every call
_CACHED_EXPLAINER: Optional[shap.TreeExplainer] = None
_CACHED_MODEL_ID: Optional[int] = None


def get_tree_explainer(model: Any) -> shap.TreeExplainer:
    """
    Get or create a cached SHAP TreeExplainer for the given tree-based model.
    Building the TreeExplainer inspects all 100 trees, so caching it
    ensures fast repeated inference.
    """
    global _CACHED_EXPLAINER, _CACHED_MODEL_ID
    model_id = id(model)
    if _CACHED_EXPLAINER is None or _CACHED_MODEL_ID != model_id:
        _CACHED_EXPLAINER = shap.TreeExplainer(model)
        _CACHED_MODEL_ID = model_id
    return _CACHED_EXPLAINER


def _generate_feature_rationale(feature_name: str, value: float, shap_val: float) -> str:
    """Produce a concise, human-friendly explanation for a specific feature contribution."""
    direction = "increased" if shap_val > 0 else "decreased"
    magnitude = "significantly" if abs(shap_val) > 0.05 else "moderately"
    return f"{feature_name} = {value:,.2f} {magnitude} {direction} attack probability (SHAP: {shap_val:+.4f})"


def explain_flow(
    flow: Union[dict, pd.Series],
    pipeline: dict,
    top_k: int = 5,
) -> Dict[str, Any]:
    """
    Explain a single network flow prediction using SHAP.

    Parameters
    ----------
    flow : dict or pandas.Series
        Traffic flow containing the required 77 features.
    pipeline : dict
        Pipeline loaded via load_pipeline(). Contains 'model' and 'feature_names'.
    top_k : int
        Number of top contributing features to return (default: 5).

    Returns
    -------
    dict with keys:
        "label"              : "benign" or "malicious"
        "probability"        : malicious confidence (0.0 to 1.0)
        "base_value"         : model base rate expectation
        "top_attack_drivers" : list of top features pushing towards malicious
        "top_benign_drivers" : list of top features pushing towards benign
        "summary"            : plain-English paragraph summarizing the decision
    """
    model = pipeline["model"]
    feature_names = pipeline["feature_names"]

    # First get the standard prediction
    pred = predict_flow(flow, pipeline)

    # Convert flow to dictionary
    if isinstance(flow, pd.Series):
        flow_dict = flow.to_dict()
    else:
        flow_dict = dict(flow)

    # Format 1-row vector in the exact feature order
    row = np.array(
        [float(flow_dict[f]) for f in feature_names], dtype=np.float32
    ).reshape(1, -1)

    # Compute SHAP values
    explainer = get_tree_explainer(model)
    shap_output = explainer(row, check_additivity=False)

    # Extract SHAP values and base value for class 1 (malicious)
    # SHAP output shape can be (1, n_features, 2) or (1, n_features) depending on version
    if len(shap_output.values.shape) == 3 and shap_output.values.shape[2] == 2:
        values_malicious = shap_output.values[0, :, 1]
        base_val = float(shap_output.base_values[0, 1])
    elif len(shap_output.values.shape) == 2:
        values_malicious = shap_output.values[0, :]
        base_val = float(shap_output.base_values[0])
    else:
        # Fallback for tree explainer raw shap_values list
        raw_vals = explainer.shap_values(row)
        if isinstance(raw_vals, list) and len(raw_vals) > 1:
            values_malicious = raw_vals[1][0]
        else:
            values_malicious = raw_vals[0]
        base_val = float(explainer.expected_value[1] if isinstance(explainer.expected_value, (list, np.ndarray)) else explainer.expected_value)

    # Pair each feature with its value and SHAP contribution
    contributions = []
    for i, name in enumerate(feature_names):
        feat_val = float(row[0, i])
        s_val = float(values_malicious[i])
        contributions.append({
            "feature": name,
            "value": round(feat_val, 4),
            "shap_value": round(s_val, 4),
            "rationale": _generate_feature_rationale(name, feat_val, s_val),
        })

    # Sort descending for attack drivers (positive SHAP)
    attack_drivers = sorted(
        [c for c in contributions if c["shap_value"] > 0],
        key=lambda x: x["shap_value"],
        reverse=True
    )[:top_k]

    # Sort ascending for benign drivers (negative SHAP)
    benign_drivers = sorted(
        [c for c in contributions if c["shap_value"] < 0],
        key=lambda x: x["shap_value"]
    )[:top_k]

    # Generate a readable explanation summary
    if pred["is_malicious"] == 1:
        top_driver_names = [f"'{d['feature']}'" for d in attack_drivers[:3]]
        summary = (
            f"Classified as MALICIOUS ({pred['probability']:.1%} confidence). "
            f"Primary factors driving the attack classification were: {', '.join(top_driver_names)}."
        )
    else:
        top_driver_names = [f"'{d['feature']}'" for d in benign_drivers[:3]]
        summary = (
            f"Classified as BENIGN ({1.0 - pred['probability']:.1%} confidence). "
            f"Flow exhibits normal characteristics, driven primarily by: {', '.join(top_driver_names)}."
        )

    return {
        "label": pred["label"],
        "is_malicious": pred["is_malicious"],
        "probability": pred["probability"],
        "base_value": round(base_val, 4),
        "top_attack_drivers": attack_drivers,
        "top_benign_drivers": benign_drivers,
        "summary": summary,
    }


def format_explanation_table(explanation: Dict[str, Any]) -> str:
    """Format an explanation dictionary into a clean CLI string."""
    lines = []
    lines.append("-" * 72)
    lines.append(f"Prediction : {explanation['label'].upper()} (Confidence: {explanation['probability']:.1%})")
    lines.append(f"Summary    : {explanation['summary']}")
    lines.append("-" * 72)

    if explanation["is_malicious"] == 1:
        lines.append("Top Features Driving MALICIOUS Classification (Positive SHAP Impact):")
        lines.append(f"  {'Feature Name':<30} {'Value':>12} {'SHAP Impact':>14}")
        lines.append(f"  {'-'*30} {'-'*12} {'-'*14}")
        for item in explanation["top_attack_drivers"]:
            lines.append(f"  {item['feature']:<30} {item['value']:>12,.2f} {item['shap_value']:>+14.4f}")
    else:
        lines.append("Top Features Driving BENIGN Classification (Negative SHAP Impact):")
        lines.append(f"  {'Feature Name':<30} {'Value':>12} {'SHAP Impact':>14}")
        lines.append(f"  {'-'*30} {'-'*12} {'-'*14}")
        for item in explanation["top_benign_drivers"]:
            lines.append(f"  {item['feature']:<30} {item['value']:>12,.2f} {item['shap_value']:>+14.4f}")

    lines.append("-" * 72)
    return "\n".join(lines)
