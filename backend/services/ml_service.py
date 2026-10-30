"""
SCAMLENS AI — FastAPI ML Service
Thin wrapper around the existing ScamLensPredictor — no duplicate ML logic.
"""

from __future__ import annotations
import sys
from pathlib import Path

# Ensure the project root (parent of backend/) is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone
from src.models.predictor import get_predictor, ScamLensPredictor
from src.utils.logger import get_logger

logger = get_logger("MLService")

# Singleton predictor (loaded once on first call)
_predictor: ScamLensPredictor | None = None


def _get_predictor() -> ScamLensPredictor:
    global _predictor
    if _predictor is None:
        logger.info("Loading ScamLensPredictor for FastAPI backend…")
        _predictor = get_predictor()
    return _predictor


def _build_guidance(risk_level: str) -> str:
    """Return plain-English guidance based on the risk level."""
    if risk_level == "Low":
        return (
            "The risk score is low. Continue to verify the sender before taking important actions. "
            "No automated tool can guarantee a message is completely safe."
        )
    elif risk_level == "Suspicious":
        return (
            "Some suspicious signals were detected. Be careful. Avoid clicking links or sharing "
            "personal information until the message is verified through the original source."
        )
    elif risk_level == "High":
        return (
            "High-risk indicators detected. Do not click links or provide passwords, OTPs, or "
            "financial information. Verify the message through an official channel before responding."
        )
    else:  # Very High
        return (
            "Very high risk detected. Do not click suspicious links or provide passwords, OTPs, or "
            "financial information. Verify through an official source such as the institution's "
            "official website or helpline."
        )


def analyze(text: str) -> dict:
    """
    Run the existing ScamLensPredictor on arbitrary text.

    IMPORTANT: This function never opens, fetches, or visits any URL.
    URLs are analyzed purely as static strings through the existing ML pipeline.
    """
    predictor = _get_predictor()
    result = predictor.predict(text)

    if not result.get("valid", True):
        raise ValueError(result.get("error", "Invalid input"))

    risk_level = result["risk_level"]
    return {
        "prediction":        result["prediction"],
        "risk_level":        risk_level,
        "risk_score":        result["risk_score"],
        "risk_probability":  result["phishing_probability"],
        "indicators":        result.get("indicators", []),
        "guidance":          _build_guidance(risk_level),
        "model":             "Random Forest",
        "scan_id":           result.get("scan_id"),
        "timestamp":         datetime.now(timezone.utc).isoformat(),
    }
