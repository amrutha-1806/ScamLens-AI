"""
SCAMLENS AI - Explainability Service

Two clearly separated sources of explanation are produced:

1. MODEL ATTRIBUTION (Random Forest, perturbation-based)
   Leave-one-word-out occlusion: for each distinct word in the input, the
   word is removed, the text is re-cleaned, re-vectorised with the SAME
   training-fitted FeatureExtractor and scored by the SAME trained Random
   Forest. The change in scam probability is that word's local influence.
   Positive influence -> the word pushed the model towards "Scam/Phishing".
   Negative influence -> the word pushed the model towards "Legitimate".
   This is a genuine measurement of the deployed model's behaviour on this
   input, but it is a *local approximation*: word effects interact, and the
   model also uses character n-grams and statistical features.

2. RULE-BASED INDICATORS (keyword lexicons from config.yaml)
   Deterministic keyword matches. These are NOT model output and do not
   change the model's score.

Perturbation scoring never writes to the scan database.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import CONFIG  # noqa: E402
from src.preprocessing.cleaner import clean_text  # noqa: E402

MAX_EXPLAIN_CHARS = 2000      # mirrors predictor.MAX_INPUT_LENGTH
MAX_UNIQUE_WORDS = 150        # bounds perturbation cost
MIN_INFLUENCE = 0.005         # 0.5 percentage points: below this is treated as negligible
METHOD_NAME = "Leave-one-word-out occlusion on the trained Random Forest"

_WORD_RE = re.compile(r"[A-Za-z0-9\u00C0-\u024F\u0900-\u0DFF][A-Za-z0-9'\u00C0-\u024F\u0900-\u0DFF\u200c\u200d]*")
_URL_RE = re.compile(r"(?i)(?:https?://|www\.)\S+")

CATEGORY_LABELS = {
    "urgency": "Urgency / pressure",
    "credential": "Credential / account security",
    "financial": "Financial / payment",
    "reward": "Prize / reward lure",
    "action": "Call to action",
}

SUSPICIOUS_PHRASE_PATTERNS: List[Tuple[str, str, str]] = [
    (r"act\s+immediately", "urgency", "Pressures you to act before verifying the sender."),
    (r"verify\s+your\s+(?:account|identity|kyc)", "credential", "Attempts to lure you into submitting login or KYC details."),
    (r"(?:your\s+)?account\s+will\s+be\s+(?:blocked|suspended|frozen|closed)", "urgency", "Threatens account loss to trigger panic."),
    (r"share\s+your\s+(?:otp|pin|password|cvv)", "credential", "Directly requests secret authentication codes that banks never ask for."),
    (r"claim\s+your\s+(?:reward|prize|cashback|bonus)", "reward", "Uses an unsolicited reward lure to trick you into clicking."),
    (r"urgent\s+payment\s+required", "financial", "Demands an immediate financial transfer under pressure."),
    (r"within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)", "urgency", "Sets an artificial countdown deadline."),
    (r"electricity\s+connection\s+will\s+be\s+disconnected", "urgency", "Classic utility cutoff threat used in bill scams."),
    (r"(?:aapka|apka)\s+(?:account|khata)\s+(?:block|band|suspend)", "urgency", "Hinglish threat of immediate account suspension."),
    (r"turant\s+(?:kyc|update|verify|call)\s+kare(?:in)?", "urgency", "Hinglish high-pressure directive."),
    (r"otp\s+share\s+kare(?:in)?", "credential", "Hinglish request to hand over a secret OTP."),
    (r"nimma\s+(?:khate|account)\s+(?:block|raddagide)", "urgency", "Kanglish threat of account suspension."),
    (r"खाता\s+(?:ब्लॉक|बंद)|तुरंत\s+(?:अपडेट|वेरीफाई|संपर्क)|ओटीपी\s+साझा", "urgency", "Hindi phrase pressuring urgent account or OTP action."),
    (r"ನಿಮ್ಮ\s+ಖಾತೆ\s+ಬ್ಲಾಕ್|ತಕ್ಷಣ\s+(?:ಅಪ್ಡೇಟ್|ಸಂಪರ್ಕಿಸಿ)|ಒಟಿಪಿ\s+ಹಂಚಿಕೊಳ್ಳಿ", "urgency", "Kannada phrase pressuring urgent account or OTP action."),
]


def _keyword_lexicon() -> Dict[str, List[str]]:
    return {k: [w.lower() for w in v] for k, v in CONFIG.get("features", {}).get("keywords", {}).items()}


def _scam_probabilities(predictor: Any, texts: List[str]) -> List[float]:
    """Score raw texts with the deployed extractor + model. No DB logging."""
    cleaned = [clean_text(t) for t in texts]
    features = predictor.extractor.transform(cleaned)
    probs = predictor.model.predict_proba(features)
    return [float(row[predictor.scam_class_idx]) for row in probs]


def _tokenize(text: str) -> List[Tuple[str, int, int]]:
    """Return (token, start, end). URLs are kept as single tokens."""
    tokens: List[Tuple[str, int, int]] = []
    url_spans = [(m.start(), m.end()) for m in _URL_RE.finditer(text)]
    for start, end in url_spans:
        tokens.append((text[start:end], start, end))
    for m in _WORD_RE.finditer(text):
        if any(s <= m.start() < e for s, e in url_spans):
            continue
        tokens.append((m.group(0), m.start(), m.end()))
    tokens.sort(key=lambda t: t[1])
    return tokens


def rule_based_highlights(text: str) -> List[Dict[str, Any]]:
    """Exact spans matching phrase patterns and configured keyword lexicons (rule-based)."""
    spans: List[Dict[str, Any]] = []
    lowered = text.lower()
    for pattern_str, category, _explanation in SUSPICIOUS_PHRASE_PATTERNS:
        for m in re.finditer(pattern_str, text, flags=re.IGNORECASE):
            spans.append({
                "start": m.start(),
                "end": m.end(),
                "text": text[m.start():m.end()],
                "category": category,
                "category_label": CATEGORY_LABELS.get(category, category.title()),
                "source": "rule",
            })
    for category, words in _keyword_lexicon().items():
        for word in words:
            pattern = re.compile(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])")
            for m in pattern.finditer(lowered):
                spans.append({
                    "start": m.start(),
                    "end": m.end(),
                    "text": text[m.start():m.end()],
                    "category": category,
                    "category_label": CATEGORY_LABELS.get(category, category.title()),
                    "source": "rule",
                })
    spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))
    # Remove overlaps, keeping the earliest / longest match.
    merged: List[Dict[str, Any]] = []
    for span in spans:
        if merged and span["start"] < merged[-1]["end"]:
            continue
        merged.append(span)
    return merged


def explain_text(predictor: Any, text: str, model_probability: float | None = None) -> Dict[str, Any]:
    """
    Build an explanation for ``text``.

    ``model_probability`` should be the scam probability already returned by the
    predictor for the same text; if omitted it is recomputed (identical result).
    """
    raw = (text or "").strip()[:MAX_EXPLAIN_CHARS]
    result: Dict[str, Any] = {
        "method": METHOD_NAME,
        "analyzed_text": raw,
        "truncated": len((text or "").strip()) > MAX_EXPLAIN_CHARS,
        "base_probability": None,
        "token_attributions": [],
        "top_scam_terms": [],
        "top_legitimate_terms": [],
        "rule_highlights": rule_based_highlights(raw) if raw else [],
        "summary": "",
        "limitations": [
            "Model attributions are a local, perturbation-based approximation of how the Random Forest responds to removing each word; they are not the model's internal reasoning.",
            "Words interact, and the model also uses character n-grams and 43 statistical/URL features, so individual word effects do not add up exactly to the final score.",
            "Rule-based keyword highlights come from fixed lexicons and do not change the model's prediction.",
        ],
    }
    if not raw:
        result["summary"] = "No text to explain."
        return result

    tokens = _tokenize(raw)
    unique: Dict[str, List[Tuple[int, int]]] = {}
    for tok, start, end in tokens:
        key = tok.lower()
        if key not in unique and len(unique) >= MAX_UNIQUE_WORDS:
            continue
        unique.setdefault(key, []).append((start, end))

    keys = list(unique.keys())
    variants: List[str] = []
    for key in keys:
        spans = unique[key]
        chars = list(raw)
        for start, end in spans:
            for i in range(start, end):
                chars[i] = " "
        variants.append(re.sub(r"\s+", " ", "".join(chars)).strip())

    scored = _scam_probabilities(predictor, [raw] + variants)
    base = scored[0]
    if model_probability is not None:
        # Same model, same input: should be identical; trust the stored value.
        base = float(model_probability)
    result["base_probability"] = round(base, 4)

    attributions: List[Dict[str, Any]] = []
    for key, prob_without in zip(keys, scored[1:]):
        influence = base - prob_without  # >0: word raised scam probability
        direction = "neutral"
        if influence >= MIN_INFLUENCE:
            direction = "scam"
        elif influence <= -MIN_INFLUENCE:
            direction = "legitimate"
        for start, end in unique[key]:
            attributions.append({
                "text": raw[start:end],
                "start": start,
                "end": end,
                "influence": round(influence, 4),
                "direction": direction,
                "source": "model",
            })
    attributions.sort(key=lambda a: a["start"])
    result["token_attributions"] = attributions

    per_word: Dict[str, float] = {}
    for key, prob_without in zip(keys, scored[1:]):
        per_word[key] = base - prob_without
    first_text = {a["text"].lower(): a["text"] for a in reversed(attributions)}
    scam_terms = sorted(((w, v) for w, v in per_word.items() if v >= MIN_INFLUENCE), key=lambda x: -x[1])[:8]
    legit_terms = sorted(((w, v) for w, v in per_word.items() if v <= -MIN_INFLUENCE), key=lambda x: x[1])[:8]
    result["top_scam_terms"] = [{"text": first_text.get(w, w), "influence": round(v, 4)} for w, v in scam_terms]
    result["top_legitimate_terms"] = [{"text": first_text.get(w, w), "influence": round(v, 4)} for w, v in legit_terms]

    verdict = "Scam/Phishing" if base >= 0.5 else "Legitimate"
    if verdict == "Scam/Phishing":
        if scam_terms:
            names = ", ".join(f"'{first_text.get(w, w)}'" for w, _ in scam_terms[:4])
            result["summary"] = (
                f"The Random Forest assigned a {base * 100:.1f}% scam probability. Removing {names} lowered that "
                f"probability the most, so these words contributed most to the scam classification."
            )
        else:
            result["summary"] = (
                f"The Random Forest assigned a {base * 100:.1f}% scam probability, but no single word changed it by "
                f"more than {MIN_INFLUENCE * 100:.1f} points; the decision reflects combined character-level and statistical patterns."
            )
    else:
        if legit_terms:
            names = ", ".join(f"'{first_text.get(w, w)}'" for w, _ in legit_terms[:4])
            result["summary"] = (
                f"The Random Forest assigned a {base * 100:.1f}% scam probability (classified Legitimate). Words such as {names} "
                f"pulled the score towards Legitimate; removing them would increase the scam probability."
            )
        else:
            result["summary"] = (
                f"The Random Forest assigned a {base * 100:.1f}% scam probability (classified Legitimate). No single word "
                f"strongly drove the result; the text lacks the combined patterns the model associates with scams."
            )
        if scam_terms:
            names = ", ".join(f"'{first_text.get(w, w)}'" for w, _ in scam_terms[:3])
            result["summary"] += f" Some words ({names}) still nudged the score upward, which is worth noting."
    return result
