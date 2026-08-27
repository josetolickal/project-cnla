"""
Milestone 5 — Prediction pipeline
==================================

What this module does (plain English):
  It provides a single reusable function, predict_flow(), that you can call
  from anywhere in the project.

  You give it one row of network traffic features (a dict or pandas Series).
  It loads the trained Random Forest model, checks that the features match
  what the model expects, and returns:
    - label       : "benign" or "malicious"
    - probability : how confident the model is (0.0 to 1.0)
    - is_malicious: 0 or 1

  This module is intentionally kept simple so that the Flask dashboard,
  the SHAP explainer, and the risk engine can all call it without
  duplicating any logic.

Usage example:
    from src.predict import load_pipeline, predict_flow

    pipeline = load_pipeline()
    result = predict_flow({"Flow Duration": 100, "Total Fwd Packets": 5, ...}, pipeline)
    print(result["label"])       # "benign" or "malicious"
    print(result["probability"]) # e.g. 0.97
"""

import json
import os
from typing import Union

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Default paths (relative to the project root)
# ---------------------------------------------------------------------------
DEFAULT_MODEL_PATH = os.path.join("models", "random_forest_baseline.joblib")
DEFAULT_FEATURE_NAMES_PATH = os.path.join("models", "feature_names.json")


# ---------------------------------------------------------------------------
# Pipeline loader
# ---------------------------------------------------------------------------

def load_pipeline(
    model_path: str = DEFAULT_MODEL_PATH,
    feature_names_path: str = DEFAULT_FEATURE_NAMES_PATH,
) -> dict:
    """
    Load the trained model and the list of expected feature names from disk.

    Returns a dict with two keys:
      "model"         : the trained RandomForestClassifier object
      "feature_names" : ordered list of 77 feature name strings

    Why load both together?
    The model was trained on features in a specific order. If a caller
    provides features in a different order, the prediction will be wrong.
    Storing the feature names alongside the model lets us always reorder
    the input correctly before predicting.

    Parameters
    ----------
    model_path : str
        Path to the saved .joblib model file.
    feature_names_path : str
        Path to the saved feature_names.json file.
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model file not found: {model_path}\n"
            "Run src/train_model.py first to generate it."
        )
    if not os.path.exists(feature_names_path):
        raise FileNotFoundError(
            f"Feature names file not found: {feature_names_path}\n"
            "Run src/train_model.py first to generate it."
        )

    model = joblib.load(model_path)
    with open(feature_names_path, "r") as fh:
        feature_names = json.load(fh)

    return {"model": model, "feature_names": feature_names}


# ---------------------------------------------------------------------------
# Core prediction function
# ---------------------------------------------------------------------------

def predict_flow(
    flow: Union[dict, pd.Series],
    pipeline: dict,
) -> dict:
    """
    Predict whether a single network flow is benign or malicious.

    Parameters
    ----------
    flow : dict or pandas.Series
        Feature values for one traffic flow.
        Keys/index must include all 77 feature names the model was trained on.
        Extra keys (e.g. "attack_type", "is_malicious") are silently ignored.

    pipeline : dict
        The dict returned by load_pipeline().  Contains "model" and
        "feature_names".

    Returns
    -------
    dict with keys:
        "label"        : str  — "benign" or "malicious"
        "is_malicious" : int  — 0 or 1
        "probability"  : float — probability of being malicious (0.0–1.0)
                          Values close to 1.0 mean the model is very
                          confident it is an attack.

    Raises
    ------
    ValueError
        If any of the 77 required feature names are missing from the input.
    """
    model = pipeline["model"]
    feature_names = pipeline["feature_names"]

    # Convert input to a plain dict so we can work with it uniformly
    if isinstance(flow, pd.Series):
        flow_dict = flow.to_dict()
    else:
        flow_dict = dict(flow)

    # Check that all required features are present
    missing = [f for f in feature_names if f not in flow_dict]
    if missing:
        raise ValueError(
            f"Input is missing {len(missing)} required feature(s).\n"
            f"First few missing: {missing[:5]}"
        )

    # Build a 1-row numpy array in the exact column order the model expects.
    # This is critical — the model internally maps column index 0 to the
    # first feature it was trained on, index 1 to the second, and so on.
    row = np.array(
        [float(flow_dict[f]) for f in feature_names], dtype=np.float32
    ).reshape(1, -1)  # reshape to (1, 77) — one sample, 77 features

    # predict() returns 0 or 1
    prediction = int(model.predict(row)[0])

    # predict_proba() returns [[prob_benign, prob_malicious]]
    # We take index [0][1] to get the probability of the malicious class.
    probability = float(model.predict_proba(row)[0][1])

    label = "malicious" if prediction == 1 else "benign"

    return {
        "label": label,
        "is_malicious": prediction,
        "probability": round(probability, 4),
    }


# ---------------------------------------------------------------------------
# Batch prediction (optional helper — useful for the dashboard later)
# ---------------------------------------------------------------------------

def predict_batch(
    flows: pd.DataFrame,
    pipeline: dict,
) -> pd.DataFrame:
    """
    Run predictions on a whole DataFrame of flows at once.

    Parameters
    ----------
    flows : pd.DataFrame
        Each row is one traffic flow. Must contain all 77 feature columns.
        Extra columns are ignored.

    pipeline : dict
        The dict returned by load_pipeline().

    Returns
    -------
    pd.DataFrame
        The input DataFrame with three new columns appended:
        "label", "is_malicious", "probability".
    """
    model = pipeline["model"]
    feature_names = pipeline["feature_names"]

    missing = [f for f in feature_names if f not in flows.columns]
    if missing:
        raise ValueError(
            f"DataFrame is missing {len(missing)} required feature column(s).\n"
            f"First few missing: {missing[:5]}"
        )

    X = flows[feature_names].values.astype(np.float32)
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    result = flows.copy()
    result["is_malicious"] = predictions
    result["probability"] = np.round(probabilities, 4)
    result["label"] = ["malicious" if p == 1 else "benign" for p in predictions]

    return result
