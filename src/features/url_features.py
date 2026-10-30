"""
Static Lexical and Structural URL Feature Extraction Module for SCAMLENS AI
Performs 100% offline static string analysis. Never makes network calls or HTTP requests.
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any
from src.config import URL_CONFIG

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
SUSPICIOUS_KEYWORDS = ["login", "verify", "account", "secure", "update", "bank", "claim", "prize", "wp-content", "confirm", "free"]


def extract_url_lexical_features(url: str) -> Dict[str, float]:
    """
    Extract static lexical and structural features from a single URL string.
    Zero network interaction. Pure string operations.
    """
    if url is None or not str(url).strip():
        return {
            "url_length": 0.0,
            "has_https": 0.0,
            "has_ip_address": 0.0,
            "has_at_symbol": 0.0,
            "dot_count": 0.0,
            "hyphen_count": 0.0,
            "underscore_count": 0.0,
            "slash_count": 0.0,
            "question_mark_count": 0.0,
            "ampersand_count": 0.0,
            "equals_count": 0.0,
            "digit_count": 0.0,
            "subdomain_count": 0.0,
            "query_length": 0.0,
            "path_length": 0.0,
            "contains_url_shortener": 0.0,
            "contains_suspicious_tld": 0.0,
            "contains_suspicious_keyword": 0.0,
        }

    url_str = str(url).strip()
    url_lower = url_str.lower()

    # Prepend scheme if missing for clean urlparse parsing
    parse_url = url_str if url_lower.startswith(("http://", "https://")) else f"http://{url_str}"
    try:
        parsed = urlparse(parse_url)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path
        query = parsed.query
    except Exception:
        netloc = url_lower
        path = ""
        query = ""

    url_len = float(len(url_str))
    has_https = 1.0 if url_lower.startswith("https://") else 0.0
    
    # Clean port if present in netloc
    host_only = netloc.split(":")[0]
    has_ip = 1.0 if IP_PATTERN.match(host_only) else 0.0
    has_at = 1.0 if "@" in url_str else 0.0

    dot_cnt = float(url_str.count("."))
    hyphen_cnt = float(url_str.count("-"))
    underscore_cnt = float(url_str.count("_"))
    slash_cnt = float(url_str.count("/"))
    question_cnt = float(url_str.count("?"))
    ampersand_cnt = float(url_str.count("&"))
    equals_cnt = float(url_str.count("="))
    digit_cnt = float(sum(1 for c in url_str if c.isdigit()))

    # Subdomain count calculation
    host_parts = [p for p in host_only.split(".") if p]
    subdomain_cnt = float(max(len(host_parts) - 2, 0)) if not has_ip else 0.0

    query_len = float(len(query))
    path_len = float(len(path))

    # Shorteners & Suspicious TLD check
    shorteners = URL_CONFIG.get("shorteners", [])
    suspicious_tlds = URL_CONFIG.get("suspicious_tlds", [])

    is_shortener = 1.0 if any(s in host_only for s in shorteners) else 0.0
    is_suspicious_tld = 1.0 if any(host_only.endswith(tld) for tld in suspicious_tlds) else 0.0
    has_suspicious_kw = 1.0 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0.0

    return {
        "url_length": url_len,
        "has_https": has_https,
        "has_ip_address": has_ip,
        "has_at_symbol": has_at,
        "dot_count": dot_cnt,
        "hyphen_count": hyphen_cnt,
        "underscore_count": underscore_cnt,
        "slash_count": slash_cnt,
        "question_mark_count": question_cnt,
        "ampersand_count": ampersand_cnt,
        "equals_count": equals_cnt,
        "digit_count": digit_cnt,
        "subdomain_count": subdomain_cnt,
        "query_length": query_len,
        "path_length": path_len,
        "contains_url_shortener": is_shortener,
        "contains_suspicious_tld": is_suspicious_tld,
        "contains_suspicious_keyword": has_suspicious_kw,
    }
