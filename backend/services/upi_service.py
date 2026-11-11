"""
SCAMLENS AI — Static QR Code & UPI Payment Safety Inspector (Feature 7)

SECURITY & ACCURACY CONTRACT:
- Operates 100% statically on the decoded QR payload or UPI ID string.
- NEVER initiates a payment, contacts a payment gateway, or opens a UPI app.
- NEVER stores or logs sensitive payment details in SQLite or application logs.
- NEVER claims that a UPI ID or QR code recipient is "verified" or "safe" based
  solely on valid syntax. Always reminds the user that a syntactically valid QR
  code does not guarantee a trustworthy recipient and that entering a UPI PIN
  always deducts money (never receives money).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, unquote, urlsplit

from backend.services.url_intelligence import levenshtein

# Well-known NPCI UPI PSP / Bank Handle suffixes (for syntax & typo detection only;
# matching a known handle does NOT verify the account owner).
KNOWN_UPI_HANDLES: Dict[str, str] = {
    "okaxis": "Google Pay (Axis Bank PSP)",
    "okhdfcbank": "Google Pay (HDFC Bank PSP)",
    "okicici": "Google Pay (ICICI Bank PSP)",
    "oksbi": "Google Pay (SBI PSP)",
    "ybl": "PhonePe (Yes Bank PSP)",
    "ibl": "PhonePe (ICICI Bank PSP)",
    "axl": "PhonePe (Axis Bank PSP)",
    "paytm": "Paytm Payments Bank / PSP",
    "ptyes": "Paytm (Yes Bank PSP)",
    "ptaxis": "Paytm (Axis Bank PSP)",
    "pthdfc": "Paytm (HDFC Bank PSP)",
    "ptsbi": "Paytm (SBI PSP)",
    "apl": "Amazon Pay (Axis Bank PSP)",
    "yapl": "Amazon Pay (Yes Bank PSP)",
    "rapl": "Amazon Pay (RBL Bank PSP)",
    "upi": "BHIM / NPCI Standard Handle",
    "sbi": "State Bank of India",
    "hdfcbank": "HDFC Bank",
    "icici": "ICICI Bank",
    "axisbank": "Axis Bank",
    "kotak": "Kotak Mahindra Bank",
    "pnb": "Punjab National Bank",
    "cnrb": "Canara Bank",
    "barodampay": "Bank of Baroda",
    "indus": "IndusInd Bank",
    "federal": "Federal Bank",
    "idfcbank": "IDFC First Bank",
    "rbl": "RBL Bank",
    "yesbank": "Yes Bank",
    "aubank": "AU Small Finance Bank",
    "sliceaxis": "slice (Axis Bank PSP)",
    "naviaxis": "Navi (Axis Bank PSP)",
    "jupiteraxis": "Jupiter (Axis Bank PSP)",
    "fbl": "Freed / Federal Bank PSP",
    "freecharge": "Freecharge PSP",
    "mobikwik": "MobiKwik PSP",
}

# Deceptive keywords commonly used in fake "Receive Money / Refund / KYC" UPI scams
DECEPTIVE_UPI_KEYWORDS = {
    "refund": "Claims to process a 'refund' — scammers trick users into approving a payment thinking they are receiving a refund.",
    "cashback": "Mentions 'cashback' — entering a UPI PIN never receives cashback; it only sends money out.",
    "reward": "Mentions 'reward' — prize/reward QR codes are a common trap to deduct money from your account.",
    "prize": "Mentions 'prize' — unsolicited prize QR codes deduct funds instead of crediting them.",
    "lottery": "Mentions 'lottery' — high-risk advance-fee or collect-request scam pattern.",
    "claim": "Uses 'claim' — scanning a payment QR code to 'claim' money will actually debit your bank account.",
    "receive": "Uses 'receive' — you never scan a UPI QR code or enter a PIN to receive money.",
    "credit": "Uses 'credit' — deceptive wording designed to make a debit look like an incoming credit.",
    "kyc": "References 'KYC' — banks and telecom providers never verify KYC through UPI transfers.",
    "verify": "References 'verify' — legitimate verification does not require a UPI payment.",
    "unblock": "References 'unblock' — coercive threat pattern used in account-freeze scams.",
    "helpline": "Impersonates a customer support helpline inside a payment VPA.",
    "customercare": "Impersonates customer care inside a payment VPA.",
    "support": "Uses 'support' — official support teams do not collect funds via personal UPI IDs.",
    "rbi": "References 'RBI' — the Reserve Bank of India does not collect individual payments via UPI QR codes.",
    "pmcare": "References 'PM Cares' — historically abused in lookalike charity UPI scams; verify only on official .gov.in portals.",
    "electricity": "References 'electricity' — utility disconnection scams often use personal UPI IDs.",
    "olx": "References marketplace buyer/seller payment — common vector for QR-code 'scan to receive payment' fraud.",
}

_VPA_REGEX = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$")


def inspect_upi_or_qr_payload(raw_input: str, source_type: str = "manual") -> Dict[str, Any]:
    """
    Parse and statically inspect a UPI ID or decoded QR code payload string.
    Never logs sensitive fields or claims recipient identity verification.
    """
    cleaned = (raw_input or "").strip()
    if not cleaned:
        raise ValueError("Please provide a UPI ID or decoded QR code text to inspect.")
    if len(cleaned) > 2048:
        raise ValueError("Input exceeds maximum safe length (2,048 characters).")

    warnings: List[Dict[str, str]] = []
    extracted: Dict[str, Optional[str]] = {
        "raw_type": "upi_id",
        "scheme": None,
        "upi_id": None,
        "payee_name": None,
        "amount": None,
        "min_amount": None,
        "currency": "INR",
        "note": None,
        "merchant_code": None,
        "mode": None,
        "psp_handle": None,
        "psp_provider_hint": None,
    }

    lower = cleaned.lower()

    # Case 1: QR code decoded to a Web URL (http/https) instead of a UPI payment URI
    if lower.startswith("http://") or lower.startswith("https://") or lower.startswith("www."):
        extracted["raw_type"] = "web_url_in_qr"
        extracted["scheme"] = "https" if lower.startswith("https://") else "http"
        warnings.append({
            "code": "qr_contains_web_url",
            "severity": "high",
            "title": "QR Code Opens a Website Instead of a UPI Payment",
            "explanation": (
                "This QR code does not contain a standard 'upi://pay' payment address. Instead, it directs to a web link, "
                "which scammers frequently use to open fake banking login pages or download malicious APK files."
            ),
        })
        return _build_upi_response(extracted, warnings, syntax_valid=False)

    # Case 2: Full UPI URI (upi://pay?... or upi://mandate?...)
    if lower.startswith("upi://"):
        extracted["raw_type"] = "upi_qr_uri"
        parts = urlsplit(cleaned)
        host_action = (parts.netloc or parts.path.lstrip("/")).lower()
        extracted["scheme"] = f"upi://{host_action}"

        if "mandate" in host_action:
            warnings.append({
                "code": "upi_mandate_autodebit",
                "severity": "high",
                "title": "Recurring Auto-Debit Mandate Detected (upi://mandate)",
                "explanation": (
                    "This QR code sets up a recurring UPI AutoPay mandate rather than a one-time payment. "
                    "Approving it allows periodic automatic deductions from your bank account."
                ),
            })

        params = {k.lower(): unquote(v).strip() for k, v in parse_qsl(parts.query, keep_blank_values=True)}
        extracted["upi_id"] = params.get("pa") or None
        extracted["payee_name"] = params.get("pn") or None
        extracted["amount"] = params.get("am") or None
        extracted["min_amount"] = params.get("mam") or None
        extracted["currency"] = params.get("cu") or "INR"
        extracted["note"] = params.get("tn") or None
        extracted["merchant_code"] = params.get("mc") or None
        extracted["mode"] = params.get("mode") or None

        if not extracted["upi_id"]:
            warnings.append({
                "code": "missing_pa_parameter",
                "severity": "high",
                "title": "Missing Payee UPI Address (pa)",
                "explanation": "The UPI QR code URI is malformed because it does not specify a payee UPI ID ('pa=').",
            })
            return _build_upi_response(extracted, warnings, syntax_valid=False)
    else:
        # Case 3: Manual UPI ID or plain text
        extracted["raw_type"] = "upi_id"
        extracted["upi_id"] = cleaned

    upi_id = (extracted["upi_id"] or "").strip()
    syntax_valid = bool(_VPA_REGEX.match(upi_id))

    if not syntax_valid:
        warnings.append({
            "code": "malformed_upi_syntax",
            "severity": "high",
            "title": "Invalid UPI ID Format",
            "explanation": (
                f"'{upi_id[:60]}' is not a valid Virtual Payment Address (expected format: 'username@bankhandle' "
                "using letters, digits, dots, hyphens, or underscores without spaces)."
            ),
        })
        return _build_upi_response(extracted, warnings, syntax_valid=False)

    user_part, handle_part = upi_id.split("@", 1)
    user_lower = user_part.lower()
    handle_lower = handle_part.lower()
    extracted["psp_handle"] = handle_lower
    extracted["psp_provider"] = KNOWN_UPI_HANDLES.get(handle_lower)
    extracted["psp_provider_hint"] = KNOWN_UPI_HANDLES.get(handle_lower)

    # Check 1: Handle typo / unrecognized PSP suffix
    if handle_lower not in KNOWN_UPI_HANDLES:
        closest_handle: Optional[str] = None
        for known in KNOWN_UPI_HANDLES:
            if levenshtein(handle_lower, known) == 1:
                closest_handle = known
                break
        if closest_handle:
            warnings.append({
                "code": "handle_typosquat",
                "severity": "high",
                "title": f"Suspicious Bank Handle Typo (@{handle_lower})",
                "explanation": (
                    f"The handle '@{handle_lower}' is 1 character away from the standard '@{closest_handle}' "
                    f"({KNOWN_UPI_HANDLES[closest_handle]}). Verify carefully before proceeding."
                ),
            })
        else:
            warnings.append({
                "code": "uncommon_psp_handle",
                "severity": "medium",
                "title": f"Unrecognized UPI Handle Suffix (@{handle_lower})",
                "explanation": (
                    f"The suffix '@{handle_lower}' is not in the standard list of major retail UPI handles. "
                    "Double-check the spelling with the intended recipient."
                ),
            })

    # Check 2: Deceptive / Refund / Cashback / KYC keywords in UPI ID, Payee Name, or Note
    combined_text = " ".join(
        filter(None, [user_lower, (extracted["payee_name"] or "").lower(), (extracted["note"] or "").lower()])
    )
    if any(k in combined_text for k in ("receive", "claim", "refund", "cashback", "reward", "prize", "lottery")):
        warnings.append({
            "code": "RECEIVE_MONEY_PIN_SCAM_LURE",
            "severity": "high",
            "title": "Deceptive 'Scan to Receive / Refund / Cashback' Lure Detected",
            "explanation": (
                "This payment request mentions receiving, claiming, or refunding money. "
                "In UPI, scanning a QR code and entering your PIN ALWAYS SENDS money out of your bank account."
            ),
        })
    for kw, reason in DECEPTIVE_UPI_KEYWORDS.items():
        if kw in combined_text:
            warnings.append({
                "code": f"deceptive_keyword_{kw}",
                "severity": "high",
                "title": f"Suspicious Payment Lure Keyword Detected ('{kw.upper()}')",
                "explanation": reason,
            })

    # Check 3: Misleading Payee Name vs UPI ID mismatch or numeric-heavy burner VPA
    if extracted["payee_name"]:
        pn_lower = extracted["payee_name"].lower()
        if any(term in pn_lower for term in ("verified", "official", "govt", "rbi", "npci", "refund desk", "cashback")):
            warnings.append({
                "code": "misleading_payee_name",
                "severity": "high",
                "title": "Self-Declared 'Official / Verified' Payee Name",
                "explanation": (
                    f"The QR code sets the display name to '{extracted['payee_name']}'. Anyone generating a QR code "
                    "can type any display name they want in the 'pn=' field; it is NOT verified by a bank."
                ),
            })

    # Check 4: Pre-filled Amount checks
    if extracted["amount"]:
        try:
            amt_val = float(extracted["amount"])
            if amt_val <= 0:
                warnings.append({
                    "code": "invalid_amount",
                    "severity": "high",
                    "title": "Malformed Pre-Filled Amount",
                    "explanation": f"The QR code specifies a non-positive payment amount ({extracted['amount']}).",
                })
            elif amt_val >= 10000:
                warnings.append({
                    "code": "high_prefilled_amount",
                    "severity": "high",
                    "title": f"High Pre-Filled Transfer Amount (₹{amt_val:,.2f})",
                    "explanation": (
                        f"This QR code automatically pre-fills a payment of ₹{amt_val:,.2f}. "
                        "Scammers often embed high amounts hoping you will enter your PIN without noticing."
                    ),
                })
            else:
                warnings.append({
                    "code": "PREFILLED_DEBIT_AMOUNT",
                    "severity": "low",
                    "title": f"Pre-Filled Debit Amount (₹{amt_val:,.2f})",
                    "explanation": (
                        f"Scanning this QR code requests an outgoing payment of ₹{amt_val:,.2f} from your account. "
                        "Remember: You NEVER enter your UPI PIN to receive money."
                    ),
                })
        except ValueError:
            warnings.append({
                "code": "non_numeric_amount",
                "severity": "high",
                "title": "Malformed Amount Parameter",
                "explanation": f"The amount parameter ('{extracted['amount']}') is not a valid number.",
            })

    return _build_upi_response(extracted, warnings, syntax_valid=True)


def _build_upi_response(
    extracted: Dict[str, Optional[str]],
    warnings: List[Dict[str, str]],
    syntax_valid: bool,
) -> Dict[str, Any]:
    high_count = sum(1 for w in warnings if w["severity"] == "high")
    med_count = sum(1 for w in warnings if w["severity"] == "medium")

    if not syntax_valid or high_count >= 2:
        risk_level = "Very High" if high_count >= 2 else "High"
        risk_score = min(98, 75 + high_count * 10)
        verdict = "High-Risk / Suspicious Payment Request"
    elif high_count == 1:
        risk_level = "High"
        risk_score = 72
        verdict = "Suspicious Payment Pattern Detected"
    elif med_count >= 1:
        risk_level = "Suspicious"
        risk_score = 48
        verdict = "Caution — Unverified UPI Handle / Pattern"
    else:
        # IMPORTANT: Never claim a UPI ID or QR code is "Safe" or "Verified Legitimate" based only on syntax!
        risk_level = "Low"
        risk_score = 15
        verdict = "Syntax Valid — Recipient Identity Unverified"

    safety_checklist = [
        "Remember the #1 UPI Rule: You NEVER need to scan a QR code or enter your UPI PIN to RECEIVE money, refunds, or cashback.",
        "A syntactically valid UPI ID or QR code only means the address format is valid — it does NOT guarantee the recipient is trustworthy.",
        "Anyone can type any Payee Name ('pn=') into a custom QR code generator. Verify the banking name shown inside your official UPI app before entering your PIN.",
        "Never scan payment QR codes sent by strangers on WhatsApp, Telegram, OLX, or social media.",
        "If you were tricked into transferring money, immediately call the National Cybercrime Helpline at 1930 and report at https://cybercrime.gov.in/.",
    ]

    prediction = "Scam/Phishing" if risk_score >= 30 else "Legitimate"
    indicators = (
        [f"{w['title']}: {w['explanation']}" for w in warnings]
        if warnings
        else ["Valid UPI VPA syntax; no explicit refund/cashback scam lure keywords detected."]
    )

    return {
        "valid": True,
        "syntax_valid": syntax_valid,
        "source_type": "qr" if extracted.get("raw_type") == "upi_qr_uri" else "manual",
        "prediction": prediction,
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "extracted": extracted,
        "extracted_details": {
            "raw_payload": extracted.get("upi_id") or "",
            "payload_type": extracted.get("raw_type") or "upi_id",
            "upi_id": extracted.get("upi_id"),
            "payee_name": extracted.get("payee_name"),
            "amount": extracted.get("amount"),
            "currency": extracted.get("currency") or "INR",
            "note": extracted.get("note"),
            "merchant_code": extracted.get("merchant_code"),
            "transaction_ref": None,
            "psp_handle": extracted.get("psp_handle"),
            "psp_provider": extracted.get("psp_provider"),
            "is_mandate": "mandate" in str(extracted.get("scheme") or ""),
            "mode": extracted.get("mode"),
        },
        "warnings": warnings,
        "indicators": indicators,
        "guidance": verdict,
        "safety_checklist": safety_checklist,
        "safety_disclaimers": safety_checklist,
        "verification_limitation_notice": (
            "Important Limitation: SCAMLENS AI inspects UPI ID and QR code syntax, parameters, and scam lure patterns "
            "offline. It cannot query live NPCI bank servers to verify the real-world account holder's identity. "
            "A valid format never guarantees a safe recipient."
        ),
    }
