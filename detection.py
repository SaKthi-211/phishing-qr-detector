"""
detection.py
-------------
This is the "brain" of the system. It combines the trained ML model's
(RandomForest) prediction probability with a rule-based heuristic score
to produce a final risk_score (0-100) and verdict (Safe / Suspicious /
Phishing).

Reason for combining ML with heuristics instead of using ML alone: the
ML model is trained on synthetic data, so it may miss edge cases not
represented in training. Heuristic rules fill that gap - together they
give better real-world reliability. This is the "ML & Heuristic
Analysis" combined approach.
"""

import os
import joblib
import pandas as pd
from model.feature_extractor import extract_features, features_to_vector, FEATURE_ORDER

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")

_model = joblib.load(os.path.join(MODEL_DIR, "phishing_model.pkl"))
_scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))

# Heuristic rule weights - each suspicious signal adds risk points.
# Total heuristic score is capped at 100.
HEURISTIC_WEIGHTS = {
    "has_ip_address": 25,
    "is_shortened": 15,
    "count_at": 15,
    "has_double_slash_redirect": 10,
    "has_suspicious_keyword": 10,
    "brand_impersonation": 20,
    "tld_suspicious": 15,
    "count_hyphens": 3,   # per hyphen, capped below
}


def heuristic_score(features: dict) -> float:
    score = 0
    for key, weight in HEURISTIC_WEIGHTS.items():
        value = features.get(key, 0)
        if key == "count_hyphens":
            score += min(value, 4) * weight  # max 12 points from hyphens
        elif value:
            score += weight

    if not features.get("has_https"):
        score += 5

    return min(score, 100)


def analyze_url(url: str) -> dict:
    """Main entry point: takes a URL and returns the full analysis report."""
    features = extract_features(url)
    # Pass as a DataFrame (with column names) - the scaler was fit with
    # named columns during training, so column names must match, otherwise
    # sklearn raises a warning.
    vector_df = pd.DataFrame([features_to_vector(features)], columns=FEATURE_ORDER)
    vector_scaled = _scaler.transform(vector_df)

    ml_proba = _model.predict_proba(vector_scaled)[0][1]  # phishing class probability
    ml_score = round(ml_proba * 100, 2)

    rule_score = heuristic_score(features)

    # Final score: 65% weight to ML, 35% weight to heuristics.
    # ML is strong at pattern recognition, heuristics are strong at
    # catching explicit red flags - so we give ML slightly more trust
    # while still balancing with rule-based signals.
    final_score = round((ml_score * 0.65) + (rule_score * 0.35), 2)

    if final_score >= 60:
        verdict = "Phishing"
    elif final_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    reasons = _explain(features)

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": final_score,
        "ml_score": ml_score,
        "heuristic_score": rule_score,
        "features": features,
        "reasons": reasons,
    }


def _explain(features: dict) -> list:
    """Generates a human-readable list of reasons behind the verdict
    (for display in the UI)."""
    reasons = []
    if features["has_ip_address"]:
        reasons.append("Uses a raw IP address instead of a domain name")
    if features["is_shortened"]:
        reasons.append("Uses a URL shortening service (hides the real destination)")
    if features["count_at"] > 0:
        reasons.append("Contains an '@' symbol in the URL (a common browser-confusion trick)")
    if features["has_double_slash_redirect"]:
        reasons.append("Suspicious redirect pattern ('//') found in the path")
    if features["has_suspicious_keyword"]:
        reasons.append("Contains a suspicious keyword (login/verify/account/etc.)")
    if features["brand_impersonation"]:
        reasons.append("A well-known brand name appears in the subdomain/path but not the real domain")
    if features["tld_suspicious"]:
        reasons.append("Uses a suspicious/free top-level domain (.tk/.xyz/.top/etc.)")
    if features["count_hyphens"] >= 2:
        reasons.append("Domain contains multiple hyphens (a common typosquatting pattern)")
    if not features["has_https"]:
        reasons.append("Uses plain HTTP instead of HTTPS")
    if not reasons:
        reasons.append("No suspicious signals detected - this looks safe")
    return reasons
