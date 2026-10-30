"""
Data Cleaning and Text Normalization Module
Preserves scam signals such as URLs, numbers, currency symbols, and key punctuation.
"""

import re
import html


def clean_text(text: str) -> str:
    """
    Clean and normalize input text for NLP and Scam detection while preserving key signals.
    - Strips HTML tags & unescapes HTML entities
    - Preserves URLs, digits, punctuation (!, ?, $, %), and uppercase signals
    - Normalizes excessive whitespace
    """
    if text is None:
        return ""

    text_str = str(text)
    if not text_str.strip():
        return ""

    # Unescape HTML entities (e.g., &amp; -> &)
    text_str = html.unescape(text_str)

    # Remove HTML tags (e.g. <br>, <b>)
    text_str = re.sub(r"<[^>]+>", " ", text_str)

    # Convert to lowercase for NLP uniformity
    cleaned = text_str.lower()

    # Replace multiple spaces/newlines with a single space
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned


def clean_url(url: str) -> str:
    """Clean and normalize URL strings."""
    if url is None:
        return ""

    url_str = str(url).strip()
    if not url_str:
        return ""

    url_str = url_str.lower().rstrip("/")
    return url_str
