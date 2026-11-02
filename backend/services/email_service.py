"""
SCAMLENS AI - Email Phishing Analyzer Service

SECURITY & TRANSPARENCY CONTRACT
---------------------------------
1. Zero Network Access:
   Never contacts mail servers, never resolves MX/SPF records, and never
   opens or visits any links found in the email.
2. Static Header & Content Analysis:
   - Parses Sender display name and email address.
   - Detects Display Name Spoofing (e.g., display name claims to be "SBI Bank",
     but the email domain is "@freemail.xyz").
   - Identifies Free Webmail abuse for corporate/banking claims.
   - Evaluates Subject line urgency and bait.
   - Extracts all embedded URLs and executes static zero-visit URL intelligence.
3. Model & Heuristics Separation:
   - Random Forest ML model scores the body + subject text.
   - Email-specific heuristic checks are explicitly labeled as rule-based indicators.
"""

from __future__ import annotations
import email.utils
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.services.ml_service import _get_predictor, _build_guidance
from backend.services.url_intelligence import analyze_url_static, extract_urls, BRAND_DOMAINS, registrable_domain
from backend.services.explainability import explain_text
from backend.services.language_service import analyze_multilingual_content
from src.utils.database import log_scan_result
from src.utils.logger import get_logger

logger = get_logger("EmailService")

# Common free webmail domains that should not originate official enterprise/bank notices
FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "icloud.com", "mail.com", "zoho.com", "protonmail.com", "proton.me"
}

# High-risk brand names to check for display name impersonation
HIGH_RISK_BRANDS = [
    ("state bank of india", "State Bank of India", ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in")),
    ("sbi", "State Bank of India / SBI", ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in")),
    ("hdfc", "HDFC Bank", ("hdfcbank.com", "hdfc.com")),
    ("icici", "ICICI Bank", ("icicibank.com",)),
    ("axis", "Axis Bank", ("axisbank.com",)),
    ("kotak", "Kotak Mahindra Bank", ("kotak.com",)),
    ("punjab national bank", "Punjab National Bank / PNB", ("pnbindia.in", "pnb.bank.in")),
    ("pnb", "Punjab National Bank / PNB", ("pnbindia.in", "pnb.bank.in")),
    ("paypal", "PayPal", ("paypal.com",)),
    ("amazon", "Amazon", ("amazon.in", "amazon.com")),
    ("flipkart", "Flipkart", ("flipkart.com",)),
    ("apple", "Apple Security", ("apple.com", "icloud.com")),
    ("microsoft", "Microsoft Security", ("microsoft.com", "office.com", "live.com")),
    ("google", "Google Account", ("google.com",)),
    ("netflix", "Netflix Billing", ("netflix.com",)),
    ("income tax", "Income Tax Department", ("incometax.gov.in",)),
    ("india post", "India Post", ("indiapost.gov.in",)),
]


def analyze_email_phishing(
    sender: str,
    subject: str,
    body: str,
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Perform a comprehensive, 100% offline static analysis on an email.
    """
    sender_clean = (sender or "").strip()
    subject_clean = (subject or "").strip()
    body_clean = (body or "").strip()

    if not body_clean and not subject_clean:
        raise ValueError("Email analysis requires at least a subject or body content.")

    # 1. Parse Sender Address and Display Name
    display_name, email_address = email.utils.parseaddr(sender_clean)
    email_address = email_address.lower().strip()
    sender_domain = email_address.split("@")[-1] if "@" in email_address else ""
    sender_reg_domain = registrable_domain(sender_domain) if sender_domain else ""

    header_findings: List[Dict[str, str]] = []

    # Check: Display Name Spoofing with Brand Names
    spoofed_brand = None
    if display_name:
        display_lower = display_name.lower()
        for brand_key, brand_label, official_domains in HIGH_RISK_BRANDS:
            if brand_key in display_lower:
                # Check if sender email address domain matches the official brand domains
                if not any(sender_reg_domain == o or sender_domain.endswith("." + o) for o in official_domains):
                    spoofed_brand = brand_label
                    header_findings.append({
                        "code": "display_name_spoofing",
                        "severity": "high",
                        "title": f"Display Name Impersonation: {brand_label}",
                        "detail": (
                            f"The sender display name claims to represent '{brand_label}', but the email "
                            f"address is '{email_address}' (domain: '{sender_domain}'). Legitimate {brand_label} "
                            f"emails originate from official domains ({', '.join(official_domains)})."
                        )
                    })
                    break

        # Check if display name is an email address designed to confuse the user
        if "@" in display_name and display_name.lower() != email_address:
            header_findings.append({
                "code": "email_in_display_name",
                "severity": "medium",
                "title": "Email Address in Display Name",
                "detail": (
                    f"The display name '{display_name}' contains an '@' symbol that mimics an email address, "
                    f"while the actual transmitting address is '{email_address}'."
                )
            })

    # Check: Free Webmail service claiming corporate / banking authority
    if sender_reg_domain in FREE_WEBMAIL_DOMAINS:
        combined_text_low = (subject_clean + " " + body_clean).lower()
        bank_keywords = ["bank", "account", "kyc", "security team", "fraud alert", "income tax", "billing department"]
        if any(kw in combined_text_low for kw in bank_keywords):
            header_findings.append({
                "code": "free_webmail_for_official_notice",
                "severity": "high",
                "title": f"Free Public Webmail ({sender_reg_domain}) Used for Security/Banking Notice",
                "detail": (
                    f"The sender uses a free public email provider ({sender_reg_domain}), but the content discusses "
                    "banking, account security, or official administrative matters."
                )
            })

    # Check: Subject Line Urgency / Coercion
    subject_lower = subject_clean.lower()
    urgent_subject_words = ["urgent", "immediately", "account suspended", "action required", "locked", "unauthorized", "verify now"]
    has_urgent_subject = any(w in subject_lower for w in urgent_subject_words)
    if has_urgent_subject:
        header_findings.append({
            "code": "urgent_subject_line",
            "severity": "medium",
            "title": "Artificial Urgency in Subject Line",
            "detail": f"Subject line contains high-urgency keywords ('{subject_clean}'), a standard phishing psychological trigger."
        })

    # 2. Extract and Statically Analyze Embedded Links
    extracted_urls = extract_urls(body_clean, limit=5)
    url_analyses: List[Dict[str, Any]] = []
    risky_url_count = 0

    for u in extracted_urls:
        u_res = analyze_url_static(u)
        url_analyses.append(u_res)
        if u_res.get("heuristic_level") in ("High", "Elevated"):
            risky_url_count += 1

    # 3. Model Inference on Combined Email Content
    combined_content = f"Subject: {subject_clean}\n\n{body_clean}" if subject_clean else body_clean
    predictor = _get_predictor()
    ml_result = predictor.predict(combined_content)

    base_scam_prob = ml_result.get("phishing_probability", 0.0)
    base_risk_score = ml_result.get("risk_score", 0.0)

    # 4. Explainable AI: Token Attributions & Highlights
    explanation_data = explain_text(predictor, combined_content, model_probability=base_scam_prob)

    # 5. Multilingual and Regional Indicators
    language_data = analyze_multilingual_content(combined_content)

    # 6. Composite Email Risk Calculation
    # Starts with ML score; adjusted additively by header and URL risks
    email_risk_score = base_risk_score
    if spoofed_brand:
        email_risk_score = max(email_risk_score, 85.0)
    elif risky_url_count > 0:
        email_risk_score = min(100.0, email_risk_score + (15.0 * risky_url_count))

    if email_risk_score <= 24.99:
        email_risk_level = "Low"
    elif email_risk_score <= 49.99:
        email_risk_level = "Suspicious"
    elif email_risk_score <= 74.99:
        email_risk_level = "High"
    else:
        email_risk_level = "Very High"

    # Prediction label
    email_prediction = "Scam/Phishing" if email_risk_score >= 50.0 else "Legitimate"

    # Combined indicator list
    indicators = list(ml_result.get("indicators", []))
    for hf in header_findings:
        indicators.insert(0, f"[Header] {hf['title']}")
    for u_res in url_analyses:
        for f in u_res.get("findings", [])[:2]:
            indicators.append(f"[Link] {f['title']}")

    # 7. Safe SQLite Database Logging
    scan_id = None
    try:
        preview_text = f"From: {sender_clean[:40]} | Sub: {subject_clean[:40]}"
        scan_id = log_scan_result(
            input_type="email",
            content=preview_text,
            prediction_label=email_prediction,
            scam_probability=round(email_risk_score / 100.0, 4),
            risk_score=round(email_risk_score, 2),
            risk_level=email_risk_level,
            explanation_summary="; ".join(indicators[:4]),
            user_id=user_id
        )
    except Exception as exc:
        logger.warning(f"Email database logging skipped: {exc}")

    return {
        "prediction": email_prediction,
        "risk_level": email_risk_level,
        "risk_score": round(email_risk_score, 2),
        "risk_probability": round(email_risk_score / 100.0, 4),
        "model_probability": base_scam_prob,
        "model_risk_score": base_risk_score,
        "guidance": _build_guidance(email_risk_level),
        "indicators": indicators,
        "model": "Random Forest + Static Email Forensic Heuristics",
        "sender_analysis": {
            "raw_sender": sender_clean,
            "display_name": display_name,
            "email_address": email_address,
            "domain": sender_domain,
            "registrable_domain": sender_reg_domain,
            "is_free_webmail": sender_reg_domain in FREE_WEBMAIL_DOMAINS,
            "header_findings": header_findings,
            "spoofed_brand": spoofed_brand,
        },
        "subject_analysis": {
            "subject": subject_clean,
            "has_urgency": has_urgent_subject,
        },
        "embedded_urls": url_analyses,
        "url_count": len(extracted_urls),
        "risky_url_count": risky_url_count,
        "explainability": explanation_data,
        "language_info": language_data,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
