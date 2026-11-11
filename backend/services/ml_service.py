"""
SCAMLENS AI - FastAPI ML Service
Links the existing ScamLensPredictor with Explainable AI, static URL intelligence,
and multilingual script identification.
"""

from __future__ import annotations
import sys
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone

# Ensure the project root (parent of backend/) is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.models.predictor import get_predictor, ScamLensPredictor
from backend.services.explainability import explain_text
from backend.services.url_intelligence import analyze_url_static, extract_urls
from backend.services.language_service import analyze_multilingual_content
from src.utils.logger import get_logger

logger = get_logger("MLService")

# Singleton predictor (loaded once on first call with thread-safe locking)
import threading

_predictor: ScamLensPredictor | None = None
_ml_lock = threading.Lock()


def _get_predictor() -> ScamLensPredictor:
    global _predictor
    if _predictor is None:
        with _ml_lock:
            if _predictor is None:
                logger.info("Loading ScamLensPredictor for FastAPI backend...")
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


def analyze(
    text: str,
    user_id: Optional[str] = None,
    include_explainability: bool = True
) -> Dict[str, Any]:
    """
    Run the existing ScamLensPredictor on arbitrary text with Explainable AI,
    static URL intelligence, and multilingual script detection.

    IMPORTANT: This function never opens, fetches, or visits any URL.
    URLs are analyzed purely as static strings.
    """
    predictor = _get_predictor()
    result = predictor.predict(text, user_id=user_id)

    if not result.get("valid", True):
        raise ValueError(result.get("error", "Invalid input"))

    risk_level = result["risk_level"]
    scam_prob = result["phishing_probability"]

    # 1. Explainable AI: Token Attributions & Highlights
    explainability_data = None
    if include_explainability:
        try:
            explainability_data = explain_text(predictor, text, model_probability=scam_prob)
        except Exception as exc:
            logger.warning(f"Explainability generation failed: {exc}")

    # 2. Multilingual Script Detection & Transliterated Signals
    language_data = None
    try:
        language_data = analyze_multilingual_content(text)
    except Exception as exc:
        logger.warning(f"Language detection failed: {exc}")

    # 3. Static Embedded URL Intelligence (zero network calls)
    embedded_urls = []
    try:
        raw_urls = extract_urls(text, limit=3)
        for u in raw_urls:
            u_info = analyze_url_static(u)
            embedded_urls.append(u_info)
    except Exception as exc:
        logger.warning(f"URL extraction failed: {exc}")

    return {
        "prediction":        result["prediction"],
        "risk_level":        risk_level,
        "risk_score":        result["risk_score"],
        "risk_probability":  scam_prob,
        "indicators":        result.get("indicators", []),
        "guidance":          _build_guidance(risk_level),
        "model":             "Random Forest",
        "scan_id":           result.get("scan_id"),
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "explainability":    explainability_data,
        "language_info":     language_data,
        "embedded_urls":     embedded_urls,
    }
