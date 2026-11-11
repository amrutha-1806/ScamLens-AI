"""
SCAMLENS AI - Multilingual Script Detection & Regional Indicators

TECHNICAL CONTRACT & TRANSPARENCY
----------------------------------
1. Script Detection:
   Purely offline inspection of Unicode code-point ranges.
   Supports Latin (English), Devanagari (Hindi/Marathi), Kannada, and other Indic scripts.
   Computes exact script character ratios.

2. Model Boundary Transparency:
   The primary Scikit-Learn Random Forest model was trained on the English
   UCI SMS Spam Collection (5,574 samples). When native Indic script text is
   analyzed, SCAMLENS AI transparently discloses this limitation. We NEVER
   fabricate fake machine learning predictions or confidence scores on
   languages for which the model was not trained.

3. Transliterated / Romanized Indicators (Hinglish & Kanglish):
   In India, smishing messages frequently use Latin script to spell Hindi
   or Kannada words phonetically (e.g. 'Aapka account block ho gaya hai',
   'Nimma khatege hana jame agide'). We detect these common phonetic
   social engineering triggers through rule-based pattern matching,
   clearly distinguished from model predictions.
"""

from __future__ import annotations
import re
import unicodedata
from typing import Dict, Any, List

# Unicode ranges for relevant scripts
SCRIPT_RANGES = [
    ("Devanagari (Hindi/Marathi)", 0x0900, 0x097F),
    ("Kannada", 0x0C80, 0x0CFF),
    ("Tamil", 0x0B80, 0x0BFF),
    ("Telugu", 0x0C00, 0x0C7F),
    ("Bengali", 0x0980, 0x09FF),
    ("Malayalam", 0x0D00, 0x0D7F),
    ("Gujarati", 0x0A80, 0x0AFF),
    ("Latin (English/Romanized)", 0x0020, 0x024F),
]

# Common Hinglish (Romanized Hindi) scam lures and urgency patterns
HINGLISH_SCAM_PATTERNS = [
    (r"\b(aapka|apka|apke|aapke)\s+(account|bank|khata|pan|aadhaar|debit|credit)\b", "Account reference in Hindi"),
    (r"\b(block|band|suspend|freeze)\s+(ho\s+gaya|kar\s+diya|ho\s+jayega)\b", "Threat of account suspension in Hindi"),
    (r"\b(turant|jaldi|aaj\s+hi)\s+(karein|kare|update|verify|call)\b", "Artificial urgency command in Hindi"),
    (r"\b(paisa|paise|rupya|rupaye|dhanrashi)\s+(jeeta|mila|jama|credit)\b", "Prize or financial lure in Hindi"),
    (r"\b(inam|inaam|lottery|lucky\s+draw|cash\s+reward)\b", "Lottery or reward trigger in Hindi"),
    (r"\b(bijli|electricity)\s+(bill|connection)\s+(kat|katega)\b", "Electricity disconnection threat in Hindi"),
    (r"\b(sampark|sampark\s+karein|call\s+karein|dial\s+karein)\b", "Call-to-action directive in Hindi"),
    (r"\b(kisi\s+ko\s+na\s+bataye|otp\s+share\s+karein)\b", "OTP coercion pattern in Hindi"),
]

# Common Kanglish (Romanized Kannada) scam lures and urgency patterns
KANGLISH_SCAM_PATTERNS = [
    (r"\b(nimma|namma)\s+(khate|account|bank|hana|pan|aadhaar)\b", "Account reference in Kannada"),
    (r"\b(khate|account)\s+(raddagide|block\s+agide|amukisalaagide)\b", "Account block/suspension threat in Kannada"),
    (r"\b(koodale|thakshana|eeegale)\s+(madi|samparkisi|update)\b", "Artificial urgency command in Kannada"),
    (r"\b(inamu|inammannu|bahumaana|hana)\s+(geliddiri|padediddiri)\b", "Prize or reward lure in Kannada"),
    (r"\b(vidyuth|current|bill)\s+(kadtavagide|khandisalaaguvudu)\b", "Electricity disconnection threat in Kannada"),
    (r"\b(samparkisi|kare\s+madi|dial\s+madi)\b", "Call-to-action directive in Kannada"),
    (r"\b(otp\s+heli|hanchikollabedi)\b", "OTP credential request in Kannada"),
]

# Native Devanagari (Hindi) scam lures and urgency patterns
HINDI_NATIVE_SCAM_PATTERNS = [
    (r"(आपका\s+खाता|बैंक\s+खाता|खाता\s+ब्लॉक|खाता\s+बंद)", "Account suspension threat in Hindi (Devanagari)"),
    (r"(तुरंत|अविलंब|आज\s+ही)\s*(अपडेट|वेरीफाई|संपर्क|कॉल)", "Artificial urgency command in Hindi (Devanagari)"),
    (r"(ओटीपी|OTP|पिन|पासवर्ड|केवाईसी|KYC|पैन|आधार)", "Sensitive credential or KYC request in Hindi (Devanagari)"),
    (r"(इनाम|लॉटरी|लकी\s+ड्रॉ|कैशबैक|पुरस्कार|जीता\s+है)", "Prize or lottery lure in Hindi (Devanagari)"),
    (r"(बिजली\s+कनेक्शन|बिजली\s+का\s+बिल|काट\s+दिया\s+जाएगा)", "Utility disconnection threat in Hindi (Devanagari)"),
]

# Native Kannada script scam lures and urgency patterns
KANNADA_NATIVE_SCAM_PATTERNS = [
    (r"(ನಿಮ್ಮ\s+ಖಾತೆ|ಬ್ಯಾಂಕ್\s+ಖಾತೆ|ಖಾತೆ\s+ಬ್ಲಾಕ್|ರದ್ದಾಗಿದೆ)", "Account suspension threat in Kannada script"),
    (r"(ತಕ್ಷಣ|ಕೂಡಲೇ|ಈಗಲೇ)\s*(ಅಪ್ಡೇಟ್|ಸಂಪರ್ಕಿಸಿ|ಕರೆ\s+ಮಾಡಿ)", "Artificial urgency command in Kannada script"),
    (r"(ಒಟಿಪಿ|OTP|ಪಿನ್|ಪಾಸ್ವರ್ಡ್|ಕೆವೈಸಿ|KYC|ಪ್ಯಾನ್|ಆಧಾರ್)", "Sensitive credential or KYC request in Kannada script"),
    (r"(ಬಹುಮಾನ|ಲಾಟರಿ|ಲಕ್ಕಿ\s+ಡ್ರಾ|ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್|ಗೆದ್ದಿದ್ದೀರಿ)", "Prize or lottery lure in Kannada script"),
    (r"(ವಿದ್ಯುತ್\s+ಸಂಪರ್ಕ|ಕರೆಂಟ್\s+ಬಿಲ್|ಕಡಿತಗೊಳಿಸಲಾಗುವುದು)", "Utility disconnection threat in Kannada script"),
]


def detect_scripts(text: str) -> Dict[str, Any]:
    """
    Statically detect Unicode scripts in the provided text and compute percentage breakdown.
    Zero external network calls.
    """
    if not text or not str(text).strip():
        return {
            "primary_script": "None",
            "scripts_detected": [],
            "is_multilingual": False,
            "has_indic_script": False,
            "has_latin": False,
            "indic_script_name": None,
            "character_counts": {},
        }

    cleaned = str(text).strip()
    counts: Dict[str, int] = {}
    total_letters = 0

    for ch in cleaned:
        if ch.isspace() or unicodedata.category(ch).startswith("P") or ch.isdigit():
            continue
        cp = ord(ch)
        matched_script = "Other"
        for name, start, end in SCRIPT_RANGES:
            if start <= cp <= end:
                matched_script = name
                break
        counts[matched_script] = counts.get(matched_script, 0) + 1
        total_letters += 1

    if total_letters == 0:
        return {
            "primary_script": "Punctuation/Numeric",
            "scripts_detected": ["Numeric/Symbols"],
            "is_multilingual": False,
            "has_indic_script": False,
            "has_latin": False,
            "indic_script_name": None,
            "character_counts": counts,
        }

    # Calculate proportions
    proportions = {k: round(v / total_letters, 4) for k, v in counts.items()}
    sorted_scripts = sorted(proportions.items(), key=lambda x: -x[1])
    primary_script = sorted_scripts[0][0] if sorted_scripts else "Unknown"

    has_indic = any(
        name in proportions and proportions[name] > 0.05
        for name in ["Devanagari (Hindi/Marathi)", "Kannada", "Tamil", "Telugu", "Bengali", "Malayalam", "Gujarati"]
    )
    indic_names = [
        name for name in ["Devanagari (Hindi/Marathi)", "Kannada", "Tamil", "Telugu", "Bengali", "Malayalam", "Gujarati"]
        if name in proportions and proportions[name] > 0.05
    ]
    indic_name = indic_names[0] if indic_names else None
    has_latin = "Latin (English/Romanized)" in proportions and proportions["Latin (English/Romanized)"] > 0.05

    return {
        "primary_script": primary_script,
        "scripts_detected": [k for k, v in sorted_scripts if v > 0.05],
        "is_multilingual": len([k for k, v in sorted_scripts if v > 0.10]) > 1,
        "has_indic_script": has_indic,
        "has_latin": has_latin,
        "indic_script_name": indic_name,
        "proportions": proportions,
        "character_counts": counts,
    }


def analyze_multilingual_content(text: str) -> Dict[str, Any]:
    """
    Perform script detection and rule-based transliterated (Hinglish/Kanglish) pattern checks.
    Provides transparent notices regarding English-trained ML model coverage.
    """
    script_info = detect_scripts(text)
    lowered = text.lower() if text else ""

    hinglish_hits: List[Dict[str, str]] = []
    for pattern, description in HINGLISH_SCAM_PATTERNS:
        match = re.search(pattern, lowered, re.IGNORECASE)
        if match:
            hinglish_hits.append({
                "matched_text": match.group(0),
                "pattern_type": "Hinglish (Romanized Hindi)",
                "description": description,
            })

    kanglish_hits: List[Dict[str, str]] = []
    for pattern, description in KANGLISH_SCAM_PATTERNS:
        match = re.search(pattern, lowered, re.IGNORECASE)
        if match:
            kanglish_hits.append({
                "matched_text": match.group(0),
                "pattern_type": "Kanglish (Romanized Kannada)",
                "description": description,
            })

    if text:
        for pattern, description in HINDI_NATIVE_SCAM_PATTERNS:
            match = re.search(pattern, text)
            if match:
                hinglish_hits.append({
                    "matched_text": match.group(0),
                    "pattern_type": "Hindi (Devanagari)",
                    "description": description,
                })
        for pattern, description in KANNADA_NATIVE_SCAM_PATTERNS:
            match = re.search(pattern, text)
            if match:
                kanglish_hits.append({
                    "matched_text": match.group(0),
                    "pattern_type": "Kannada (Native Script)",
                    "description": description,
                })

    # Transparency notes
    transparency_notes: List[str] = []
    if script_info["has_indic_script"]:
        indic_name = script_info["indic_script_name"] or "Indic"
        transparency_notes.append(
            f"Native {indic_name} script detected. Note: The core Random Forest classifier was trained on English SMS. "
            "Native script content is evaluated using static lexical and indicator heuristics (phone numbers, URLs, currency symbols) "
            "without claiming native NLP training."
        )

    if hinglish_hits or kanglish_hits:
        transparency_notes.append(
            f"Detected {len(hinglish_hits) + len(kanglish_hits)} regional Indian transliterated scam signal(s) "
            "(phonetic Hindi/Kannada spelled in Latin characters)."
        )

    return {
        "script_info": script_info,
        "regional_signals": {
            "hinglish_signals": hinglish_hits,
            "kanglish_signals": kanglish_hits,
            "total_regional_signals": len(hinglish_hits) + len(kanglish_hits),
        },
        "transparency_notes": transparency_notes,
    }
