"""
Production Prediction Engine for SCAMLENS AI
Links trained Random Forest model and training-fitted FeatureExtractor to evaluate new user messages.
Calculates predictions, full-precision probabilities, 0-100 risk scores, application risk levels, and explanatory indicators.
"""

import joblib
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np

from src.config import SAVED_MODELS_DIR, RISK_CONFIG
from src.preprocessing.cleaner import clean_text
from src.features.text_features import extract_text_statistical_features, URL_REGEX
from src.features.url_features import extract_url_lexical_features
from src.utils.database import log_scan_result
from src.utils.logger import get_logger

logger = get_logger("Predictor")

MAX_INPUT_LENGTH = 2000


class ScamLensPredictor:
    """
    ScamLens AI Inference Predictor.
    Loads saved model artifacts and performs leak-free, 100% offline inference.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        extractor_path: Optional[Path] = None
    ):
        self.model_path = model_path or (SAVED_MODELS_DIR / "random_forest.pkl")
        self.extractor_path = extractor_path or (SAVED_MODELS_DIR / "feature_extractor.pkl")

        if not self.model_path.exists():
            raise FileNotFoundError(f"Saved model not found at {self.model_path}")
        if not self.extractor_path.exists():
            raise FileNotFoundError(f"Saved feature extractor not found at {self.extractor_path}")

        logger.info(f"Loading Random Forest model from {self.model_path}...")
        self.model = joblib.load(self.model_path)

        logger.info(f"Loading training-fitted FeatureExtractor from {self.extractor_path}...")
        self.extractor = joblib.load(self.extractor_path)

        # Map binary classes dynamically
        classes = list(self.model.classes_)
        if 1 in classes:
            self.scam_class_idx = classes.index(1)
            self.legit_class_idx = classes.index(0)
        else:
            self.scam_class_idx = 1
            self.legit_class_idx = 0

        logger.info("ScamLensPredictor initialized successfully.")

    def _calculate_risk_level(self, risk_score: float) -> str:
        """Map 0-100 risk score to application-level risk category."""
        low_max = float(RISK_CONFIG.get("low_max", 24.99))
        susp_max = float(RISK_CONFIG.get("suspicious_max", 49.99))
        high_max = float(RISK_CONFIG.get("high_max", 74.99))

        if risk_score <= low_max:
            return "Low"
        elif risk_score <= susp_max:
            return "Suspicious"
        elif risk_score <= high_max:
            return "High"
        else:
            return "Very High"

    def _extract_explanations(self, message: str, cleaned_message: str) -> List[str]:
        """Extract human-readable explanatory indicators based on static feature rules."""
        indicators = []
        text_stats = extract_text_statistical_features(message)

        if text_stats.get("has_urgency_keyword", 0) == 1:
            indicators.append("Urgency-related language detected (e.g., 'urgent', 'immediately', 'expires')")
        if text_stats.get("has_credential_keyword", 0) == 1:
            indicators.append("Credential or account security language detected (e.g., 'verify', 'account', 'password')")
        if text_stats.get("has_financial_keyword", 0) == 1:
            indicators.append("Financial or banking language detected (e.g., 'bank', 'payment', 'cash', 'card')")
        if text_stats.get("has_reward_keyword", 0) == 1:
            indicators.append("Prize or reward language detected (e.g., 'winner', 'won', 'free', 'claim')")
        if text_stats.get("has_action_keyword", 0) == 1:
            indicators.append("Call-to-action request detected (e.g., 'click', 'call', 'reply', 'confirm')")

        if text_stats.get("exclamation_count", 0) > 1:
            indicators.append("High exclamation mark density detected (!)")
        if text_stats.get("currency_symbol_count", 0) > 0:
            indicators.append("Currency symbol detected ($, £, €, ₹)")
        if text_stats.get("uppercase_ratio", 0) > 0.35:
            indicators.append("High uppercase character ratio detected (shouting)")

        # Static URL analysis indicators (zero network calls)
        urls = URL_REGEX.findall(message)
        if urls:
            indicators.append(f"Web URL detected: {urls[0][:40]}...")
            url_feats = extract_url_lexical_features(urls[0])
            
            if url_feats.get("has_https", 0) == 0:
                indicators.append("Insecure URL scheme detected (HTTP instead of HTTPS)")
            if url_feats.get("contains_url_shortener", 0) == 1:
                indicators.append("URL shortener service detected (obfuscated link)")
            if url_feats.get("contains_suspicious_tld", 0) == 1:
                indicators.append("Suspicious Top-Level Domain (TLD) detected")
            if url_feats.get("has_ip_address", 0) == 1:
                indicators.append("Raw IP address host detected in URL")
            if url_feats.get("has_at_symbol", 0) == 1:
                indicators.append("Suspicious '@' symbol detected in URL structure")

        if not indicators:
            indicators.append("No strong predefined indicators detected. Prediction is based on learned ML model patterns.")

        return indicators

    def predict(self, message: str, user_id: Optional[str] = None, skip_logging: bool = False) -> Dict[str, Any]:
        """
        Predict whether a text message is Legitimate or Scam/Phishing.
        """
        # 1. Input Validation
        if message is None or not str(message).strip():
            return {
                "valid": False,
                "error": "Invalid input: Message content cannot be empty or whitespace-only.",
                "prediction": "Error",
                "risk_score": 0.0,
                "risk_level": "Unknown"
            }

        raw_text = str(message).strip()
        if len(raw_text) > MAX_INPUT_LENGTH:
            logger.warning(f"Truncating input exceeding {MAX_INPUT_LENGTH} characters.")
            raw_text = raw_text[:MAX_INPUT_LENGTH]

        # 2. Cleaning & Feature Transformation
        cleaned_text = clean_text(raw_text)
        X_feat = self.extractor.transform([cleaned_text])

        # 3. Model Inference
        pred_class = int(self.model.predict(X_feat)[0])
        probabilities = self.model.predict_proba(X_feat)[0]

        scam_prob = float(probabilities[self.scam_class_idx])
        legit_prob = float(probabilities[self.legit_class_idx])

        # 4. Label Mapping & Risk Score Computation
        pred_label = "Scam/Phishing" if pred_class == 1 else "Legitimate"
        risk_score = round(scam_prob * 100.0, 2)
        risk_level = self._calculate_risk_level(risk_score)

        # 5. Explanatory Indicators
        indicators = self._extract_explanations(raw_text, cleaned_text)

        # Message Preview
        preview = raw_text[:80] + ("..." if len(raw_text) > 80 else "")

        # 6. Database Logging (Safe SQLite recording; skipped for educational sandbox demos)
        scan_id = None
        if not skip_logging:
            try:
                input_type = "url" if raw_text.startswith(("http://", "https://")) else "text"
                scan_id = log_scan_result(
                    input_type=input_type,
                    content=preview,
                    prediction_label=pred_label,
                    scam_probability=round(scam_prob, 4),
                    risk_score=risk_score,
                    risk_level=risk_level,
                    explanation_summary="; ".join(indicators[:3]),
                    user_id=user_id
                )
            except Exception as e:
                logger.warning(f"Database logging failed: {e}")

        return {
            "valid": True,
            "prediction": pred_label,
            "class_id": pred_class,
            "phishing_probability": round(scam_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "message_preview": preview,
            "scan_id": scan_id
        }


# Singleton instance helper (thread-safe double-checked locking)
import threading

_predictor_instance: Optional[ScamLensPredictor] = None
_predictor_lock = threading.Lock()


def get_predictor() -> ScamLensPredictor:
    """Return a singleton instance of ScamLensPredictor without duplicate loading."""
    global _predictor_instance
    if _predictor_instance is None:
        with _predictor_lock:
            if _predictor_instance is None:
                _predictor_instance = ScamLensPredictor()
    return _predictor_instance
