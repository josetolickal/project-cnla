"""
Milestone 7 — Threat Risk Engine
=================================

What this module does (plain English):
  A machine learning model outputs a probability (e.g., 0.98) and an attack
  type (e.g., "DDoS" or "PortScan"). A security team needs an actionable
  risk assessment: Is this LOW, MEDIUM, HIGH, or CRITICAL risk?

  This module calculates a transparent, deterministic risk score from 0.0 to 1.0:
    Risk Score = (P_malicious * 0.60) + (Attack Severity Weight * 0.40)

  Why this formula?
  - P_malicious (60% weight): The model's statistical confidence that the flow
    is truly an attack (from Stage 1 Random Forest).
  - Attack Severity (40% weight): Not all attacks are equally dangerous. A simple
    port scan (probing) has a lower immediate danger than an active DDoS flood
    or a SQL injection attempt.

  Risk Levels:
    - LOW      (0.00 - 0.35) : Normal traffic, benign flows, or low-impact scans.
    - MEDIUM   (0.35 - 0.65) : Brute-force login attempts, reconnaissance, XSS.
    - HIGH     (0.65 - 0.85) : Active DoS floods, Botnet C2 traffic.
    - CRITICAL (0.85 - 1.00) : High-volume DDoS, database SQLi, data exfiltration.

  This scoring is completely transparent and reproducible for viva/presentation.
"""

from typing import Dict, Any, Optional

# Severity weights for known attack categories (0.0 to 1.0 scale)
ATTACK_SEVERITY_WEIGHTS: Dict[str, float] = {
    # Benign
    "Benign": 0.00,

    # Low severity (Reconnaissance / Scans)
    "PortScan": 0.30,

    # Medium severity (Brute-Force & Web Injections)
    "Web Attack - XSS": 0.50,
    "FTP-Patator": 0.55,
    "SSH-Patator": 0.60,
    "Web Attack - Brute Force": 0.60,

    # High severity (Denial of Service & Botnet)
    "Bot": 0.75,
    "DoS Slowhttptest": 0.75,
    "DoS slowloris": 0.75,
    "DoS GoldenEye": 0.80,
    "DoS Hulk": 0.80,

    # Critical severity (Volumetric outage & Remote Exploits)
    "Infiltration": 0.90,
    "DDoS": 0.95,
    "Heartbleed": 0.95,
    "Web Attack - Sql Injection": 0.95,
}

DEFAULT_SEVERITY_WEIGHT = 0.50  # Default fallback for unknown attacks


def get_attack_severity(attack_type: Optional[str]) -> float:
    """Return the base severity weight for a given attack name."""
    if not attack_type:
        return 0.0
    return ATTACK_SEVERITY_WEIGHTS.get(attack_type, DEFAULT_SEVERITY_WEIGHT)


def map_score_to_level(score: float) -> str:
    """Map a continuous risk score (0.0 to 1.0) to a discrete threat level."""
    if score >= 0.85:
        return "CRITICAL"
    elif score >= 0.65:
        return "HIGH"
    elif score >= 0.35:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_risk(
    is_malicious: int,
    probability: float,
    attack_type: Optional[str] = None,
    log_correlation_boost: float = 0.0,
) -> Dict[str, Any]:
    """
    Calculate the risk score and threat level for a network flow.

    Parameters
    ----------
    is_malicious : int
        0 for benign, 1 for malicious (from Stage 1 predict_flow).
    probability : float
        Prediction confidence of being malicious (0.0 to 1.0).
    attack_type : Optional[str]
        Specific attack category (from Stage 2 identify_attack_type).
    log_correlation_boost : float
        Optional risk boost (e.g. +0.10) if Milestone 9 Linux logs correlate.

    Returns
    -------
    dict with keys:
        "risk_score"   : float rounded to 4 decimal places (0.0 to 1.0)
        "risk_level"   : str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        "probability"  : float
        "severity"     : float
        "attack_type"  : str
        "rationale"    : list of explanatory reason strings
    """
    reasons = []

    # If predicted benign with high confidence, risk is minimal
    if is_malicious == 0:
        base_score = probability * 0.30
        risk_score = min(1.0, max(0.0, base_score + log_correlation_boost))
        reasons.append(f"Traffic classified as benign (malicious probability: {probability:.2%}).")
        return {
            "risk_score": round(risk_score, 4),
            "risk_level": "LOW",
            "probability": round(probability, 4),
            "severity": 0.0,
            "attack_type": "Benign",
            "rationale": reasons,
        }

    # Malicious flow risk calculation
    severity = get_attack_severity(attack_type)
    
    # 60% probability weight + 40% attack severity weight
    raw_score = (probability * 0.60) + (severity * 0.40) + log_correlation_boost
    risk_score = min(1.0, max(0.0, raw_score))
    risk_level = map_score_to_level(risk_score)

    reasons.append(f"Model classified flow as malicious with {probability:.1%} confidence.")
    if attack_type:
        reasons.append(f"Stage 2 identified attack type as '{attack_type}' (inherent severity: {severity:.2f}).")
    else:
        reasons.append(f"Attack type undetermined; applied default severity ({DEFAULT_SEVERITY_WEIGHT:.2f}).")

    if log_correlation_boost > 0.0:
        reasons.append(f"System log correlation added +{log_correlation_boost:.2f} risk boost.")

    reasons.append(f"Final composite risk score: {risk_score:.4f} -> Threat Level: {risk_level}.")

    return {
        "risk_score": round(risk_score, 4),
        "risk_level": risk_level,
        "probability": round(probability, 4),
        "severity": round(severity, 4),
        "attack_type": attack_type or "Unknown",
        "rationale": reasons,
    }
