"""
Milestone 5 — Prediction pipeline
==================================

What this module does (plain English):
  It provides reusable functions that you can call from anywhere in the project.

  Two-stage pipeline:
    Stage 1 — predict_flow()
        Takes one row of network traffic features.
        Returns: label ("benign"/"malicious"), probability, is_malicious.

    Stage 2 — identify_attack_type()
        Only called when Stage 1 says "malicious".
        Uses a second model to identify the specific attack type:
        DDoS, PortScan, SSH-Patator, DoS Hulk, etc.

  Both models are loaded once with load_pipeline() and reused for every
  subsequent prediction, so disk access only happens once.

  This module is intentionally kept simple so that the Flask dashboard,
  the SHAP explainer, and the risk engine can all call it without
  duplicating any logic.

Usage example:
    from src.predict import load_pipeline, predict_flow, identify_attack_type

    pipeline = load_pipeline()

    result = predict_flow(flow_dict, pipeline)
    print(result["label"])        # "benign" or "malicious"
    print(result["probability"])  # e.g. 0.97

    if result["is_malicious"]:
        attack = identify_attack_type(flow_dict, pipeline)
        print(attack["attack_type"])   # e.g. "DDoS"
        print(attack["confidence"])    # e.g. 0.89
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
DEFAULT_MODEL_PATH        = os.path.join("models", "random_forest_baseline.joblib")
DEFAULT_FEATURE_NAMES_PATH= os.path.join("models", "feature_names.json")
DEFAULT_ATTACK_MODEL_PATH = os.path.join("models", "attack_type_classifier.joblib")
DEFAULT_ENCODER_PATH      = os.path.join("models", "attack_type_label_encoder.joblib")


# ---------------------------------------------------------------------------
# Pipeline loader
# ---------------------------------------------------------------------------

def load_pipeline(
    model_path: str = DEFAULT_MODEL_PATH,
    feature_names_path: str = DEFAULT_FEATURE_NAMES_PATH,
    attack_model_path: str = DEFAULT_ATTACK_MODEL_PATH,
    encoder_path: str = DEFAULT_ENCODER_PATH,
) -> dict:
    """
    Load the trained models and supporting files from disk.

    Returns a dict with four keys:
      "model"          : the binary RandomForestClassifier (benign vs malicious)
      "feature_names"  : ordered list of 77 feature name strings
      "attack_model"   : the multi-class RandomForestClassifier (attack type)
                         — None if the file does not exist yet
      "label_encoder"  : the LabelEncoder that maps numbers back to attack names
                         — None if the file does not exist yet

    The attack_model and label_encoder are optional: if they have not been
    trained yet (train_attack_classifier.py not yet run), load_pipeline()
    still succeeds and predict_flow() still works.  Only identify_attack_type()
    will raise an error if those files are missing.

    Parameters
    ----------
    model_path : str
        Path to the binary classification .joblib file.
    feature_names_path : str
        Path to the feature_names.json file.
    attack_model_path : str
        Path to the multi-class attack type .joblib file.
    encoder_path : str
        Path to the LabelEncoder .joblib file.
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

    # Attack type classifier is optional — load if present
    attack_model  = joblib.load(attack_model_path)  if os.path.exists(attack_model_path)  else None
    label_encoder = joblib.load(encoder_path)        if os.path.exists(encoder_path)        else None

    return {
        "model":         model,
        "feature_names": feature_names,
        "attack_model":  attack_model,
        "label_encoder": label_encoder,
    }


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
# Attack type identification (Stage 2 of the two-stage pipeline)
# ---------------------------------------------------------------------------

def identify_attack_type(
    flow: Union[dict, pd.Series],
    pipeline: dict,
) -> dict:
    """
    Identify the specific type of attack in a flow that has already been
    flagged as malicious by predict_flow().

    Uses the multi-class attack type classifier trained in
    src/train_attack_classifier.py.

    Parameters
    ----------
    flow : dict or pandas.Series
        The same feature dict/Series you passed to predict_flow().

    pipeline : dict
        The dict returned by load_pipeline().  Must contain "attack_model"
        and "label_encoder" (i.e. train_attack_classifier.py must have been
        run first).

    Returns
    -------
    dict with keys:
        "attack_type"  : str  — human-readable attack name, e.g. "DDoS"
        "confidence"   : float — probability assigned to that class (0.0–1.0)
        "all_probs"    : dict  — probability for every class (useful for
                                 the dashboard to show a breakdown)

    Raises
    ------
    RuntimeError
        If the attack type model has not been trained yet.
    """
    attack_model  = pipeline.get("attack_model")
    label_encoder = pipeline.get("label_encoder")
    feature_names = pipeline["feature_names"]

    if attack_model is None or label_encoder is None:
        raise RuntimeError(
            "Attack type classifier not loaded.\n"
            "Run src/train_attack_classifier.py first."
        )

    # Convert to dict
    if isinstance(flow, pd.Series):
        flow_dict = flow.to_dict()
    else:
        flow_dict = dict(flow)

    # Build feature row (same ordering logic as predict_flow)
    row = np.array(
        [float(flow_dict[f]) for f in feature_names], dtype=np.float32
    ).reshape(1, -1)

    # Get predicted class index and its name
    predicted_index = int(attack_model.predict(row)[0])
    attack_name = label_encoder.inverse_transform([predicted_index])[0]

    # Get probability for every class
    proba_array = attack_model.predict_proba(row)[0]
    confidence  = float(proba_array[predicted_index])

    # Build a readable dict of all class probabilities (filter out near-zeros)
    all_probs = {
        label_encoder.classes_[i]: round(float(p), 4)
        for i, p in enumerate(proba_array)
        if p > 0.001
    }

    return {
        "attack_type": attack_name,
        "confidence":  round(confidence, 4),
        "all_probs":   all_probs,
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
