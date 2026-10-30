"""
Text Feature Extraction Module for SCAMLENS AI
Extracts text statistics, ratios, URL presence, and scam indicator keyword features.
"""

import re
from typing import Dict, Any, List
from src.config import KEYWORD_LISTS

# Currency symbols set
CURRENCY_SYMBOLS = {"$", "£", "€", "₹", "¥", "¢"}

# Safe regex pattern for URL extraction without network calls
URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s/$.?#].[^\s]*|[a-zA-Z0-9.-]+\.(?:com|org|net|gov|edu|uk|xyz|top|info|co|biz|tv|online|site)[^\s]*",
    re.IGNORECASE
)


def extract_text_statistical_features(text: str) -> Dict[str, float]:
    """
    Extract statistical and character-level features from raw text message.
    Guarantees no NaN or infinite values.
    """
    if text is None or not str(text).strip():
        return {
            "character_count": 0.0,
            "word_count": 0.0,
            "digit_count": 0.0,
            "uppercase_count": 0.0,
            "lowercase_count": 0.0,
            "special_character_count": 0.0,
            "exclamation_count": 0.0,
            "question_mark_count": 0.0,
            "currency_symbol_count": 0.0,
            "newline_count": 0.0,
            "uppercase_ratio": 0.0,
            "digit_ratio": 0.0,
            "special_character_ratio": 0.0,
            "url_count": 0.0,
            "has_url": 0.0,
            "http_count": 0.0,
            "https_count": 0.0,
            "urgency_keyword_count": 0.0,
            "has_urgency_keyword": 0.0,
            "credential_keyword_count": 0.0,
            "has_credential_keyword": 0.0,
            "financial_keyword_count": 0.0,
            "has_financial_keyword": 0.0,
            "reward_keyword_count": 0.0,
            "has_reward_keyword": 0.0,
            "action_keyword_count": 0.0,
            "has_action_keyword": 0.0,
        }

    text_str = str(text)
    char_len = float(len(text_str))
    words = text_str.split()
    word_cnt = float(len(words))

    digit_cnt = float(sum(1 for c in text_str if c.isdigit()))
    upper_cnt = float(sum(1 for c in text_str if c.isupper()))
    lower_cnt = float(sum(1 for c in text_str if c.islower()))
    special_cnt = float(sum(1 for c in text_str if not c.isalnum() and not c.isspace()))

    exclamation_cnt = float(text_str.count("!"))
    question_cnt = float(text_str.count("?"))
    currency_cnt = float(sum(text_str.count(sym) for sym in CURRENCY_SYMBOLS))
    newline_cnt = float(text_str.count("\n"))

    # Ratios (safe division)
    safe_char_len = max(char_len, 1.0)
    upper_ratio = round(upper_cnt / safe_char_len, 4)
    digit_ratio = round(digit_cnt / safe_char_len, 4)
    special_ratio = round(special_cnt / safe_char_len, 4)

    # URL presence in text
    urls_found = URL_REGEX.findall(text_str)
    url_cnt = float(len(urls_found))
    has_url = 1.0 if url_cnt > 0 else 0.0
    text_lower = text_str.lower()
    http_cnt = float(text_lower.count("http://"))
    https_cnt = float(text_lower.count("https://"))

    # Indicator keyword counts & flags
    urgency_words = KEYWORD_LISTS.get("urgency", [])
    credential_words = KEYWORD_LISTS.get("credential", [])
    financial_words = KEYWORD_LISTS.get("financial", [])
    reward_words = KEYWORD_LISTS.get("reward", [])
    action_words = KEYWORD_LISTS.get("action", [])

    urgency_cnt = float(sum(1 for kw in urgency_words if kw in text_lower))
    credential_cnt = float(sum(1 for kw in credential_words if kw in text_lower))
    financial_cnt = float(sum(1 for kw in financial_words if kw in text_lower))
    reward_cnt = float(sum(1 for kw in reward_words if kw in text_lower))
    action_cnt = float(sum(1 for kw in action_words if kw in text_lower))

    return {
        "character_count": char_len,
        "word_count": word_cnt,
        "digit_count": digit_cnt,
        "uppercase_count": upper_cnt,
        "lowercase_count": lower_cnt,
        "special_character_count": special_cnt,
        "exclamation_count": exclamation_cnt,
        "question_mark_count": question_cnt,
        "currency_symbol_count": currency_cnt,
        "newline_count": newline_cnt,
        "uppercase_ratio": upper_ratio,
        "digit_ratio": digit_ratio,
        "special_character_ratio": special_ratio,
        "url_count": url_cnt,
        "has_url": has_url,
        "http_count": http_cnt,
        "https_count": https_cnt,
        "urgency_keyword_count": urgency_cnt,
        "has_urgency_keyword": 1.0 if urgency_cnt > 0 else 0.0,
        "credential_keyword_count": credential_cnt,
        "has_credential_keyword": 1.0 if credential_cnt > 0 else 0.0,
        "financial_keyword_count": financial_cnt,
        "has_financial_keyword": 1.0 if financial_cnt > 0 else 0.0,
        "reward_keyword_count": reward_cnt,
        "has_reward_keyword": 1.0 if reward_cnt > 0 else 0.0,
        "action_keyword_count": action_cnt,
        "has_action_keyword": 1.0 if action_cnt > 0 else 0.0,
    }
