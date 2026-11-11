"""
Unit and FastAPI integration tests for the 8 new additive SCAMLENS AI features:
- Feature 2: Explainable Risk Score & Multi-Word Phrase Highlighting
- Feature 3: Advanced Link Checker (Shorteners, Character Substitutions, Punycode, SSRF Protection)
- Feature 5: Try a Sample Scam (sandbox_demo=True / skip_logging=True SQLite History Isolation)
- Feature 6: Regional Language Support (English, Hindi Devanagari, Hinglish, Kannada)
- Feature 7: QR Code & UPI Payment Safety Checker
"""

import unittest

from backend.main import (
    analyze_message,
    analyze_upi_payload,
    resolve_url_advanced,
    scan_history,
)
from backend.schemas import MessageRequest, UpiInspectRequest, UrlResolveRequest
from backend.services.explainability import rule_based_highlights
from backend.services.language_service import analyze_multilingual_content
from backend.services.upi_service import inspect_upi_or_qr_payload
from backend.services.url_resolver import (
    detect_lookalike_and_homograph_warnings,
    inspect_url_advanced,
    is_ip_public_and_safe,
    validate_and_resolve_host,
)


class TestEightNewFeatures(unittest.TestCase):
    # ------------------------------------------------------------------
    # Feature 2: Explainable Risk Score & Multi-Word Phrase Highlighting
    # ------------------------------------------------------------------
    def test_multi_word_suspicious_phrase_highlighting(self):
        sample_text = (
            "URGENT: Your account will be blocked today. Act immediately to verify your account "
            "or share your OTP. Claim your reward now! Urgent payment required."
        )
        highlights = rule_based_highlights(sample_text)
        matched_phrases_lower = [h["text"].lower() for h in highlights]

        self.assertTrue(any("your account will be blocked" in p for p in matched_phrases_lower))
        self.assertTrue(any("act immediately" in p for p in matched_phrases_lower))
        self.assertTrue(any("verify your account" in p for p in matched_phrases_lower))
        self.assertTrue(any("share your otp" in p for p in matched_phrases_lower))
        self.assertTrue(any("claim your reward" in p for p in matched_phrases_lower))
        self.assertTrue(any("urgent payment required" in p for p in matched_phrases_lower))

        for h in highlights:
            self.assertEqual(h["source"], "rule")

    # ------------------------------------------------------------------
    # Feature 3: Advanced Link Checker & SSRF Protection
    # ------------------------------------------------------------------
    def test_ssrf_ip_validation_blocks_private_loopback_and_metadata(self):
        for unsafe_ip in [
            "127.0.0.1",
            "127.0.1.1",
            "0.0.0.0",
            "10.0.0.1",
            "172.16.0.5",
            "192.168.1.100",
            "169.254.169.254",
            "::1",
            "fe80::1",
        ]:
            safe, reason = is_ip_public_and_safe(unsafe_ip)
            self.assertFalse(safe, f"Expected {unsafe_ip} to be blocked, got safe=True")
            self.assertTrue(len(reason) > 0)

        safe_pub, _ = is_ip_public_and_safe("93.184.216.34")
        self.assertTrue(safe_pub)

        host_ok, _, host_err = validate_and_resolve_host("localhost", 80)
        self.assertFalse(host_ok)
        self.assertIn("blocked", host_err.lower())

    def test_lookalike_character_substitution_and_punycode_detection(self):
        # 1 -> l substitution for PayPal
        w_paypal = detect_lookalike_and_homograph_warnings("http://paypa1-account-verify.com/login")
        codes_paypal = [w["code"] for w in w_paypal]
        self.assertIn("CHARACTER_SUBSTITUTION_SPOOF", codes_paypal)

        # 0 -> o substitution for Google
        w_google = detect_lookalike_and_homograph_warnings("https://g00gle-security-check.com/signin")
        codes_google = [w["code"] for w in w_google]
        self.assertIn("CHARACTER_SUBSTITUTION_SPOOF", codes_google)

        # rn -> m substitution for Amazon
        w_amazon = detect_lookalike_and_homograph_warnings("http://arnazon-order-update.com/track")
        codes_amazon = [w["code"] for w in w_amazon]
        self.assertIn("CHARACTER_SUBSTITUTION_SPOOF", codes_amazon)

        # Punycode xn-- detection
        w_puny = detect_lookalike_and_homograph_warnings("https://xn--pple-43d.com/id")
        codes_puny = [w["code"] for w in w_puny]
        self.assertIn("PUNYCODE_IDN_HOMOGRAPH", codes_puny)

    def test_advanced_url_resolve_endpoint_and_ssrf_blocking(self):
        # 1. Attempting to resolve a loopback URL must be blocked by SSRF protection
        data_ssrf = resolve_url_advanced(
            UrlResolveRequest(url="http://127.0.0.1:8001/api/health", resolve_redirects=True)
        )
        self.assertFalse(data_ssrf["destination_verified"])
        self.assertEqual(data_ssrf["resolution_status"], "blocked_ssrf")
        self.assertIn("safe", data_ssrf["safety_disclaimer"].lower())

        # 2. Disallowed scheme (file:// or javascript:) must be blocked
        res_scheme = inspect_url_advanced("file:///etc/passwd", resolve_redirects=True)
        self.assertEqual(res_scheme["resolution_status"], "blocked_scheme")

        # 3. Shortener + static mode check
        data_short = resolve_url_advanced(
            UrlResolveRequest(url="https://bit.ly/3xYz99ClaimReward", resolve_redirects=False)
        )
        self.assertTrue(data_short["is_shortened"])
        warning_codes = [w["code"] for w in data_short["advanced_warnings"]]
        self.assertIn("URL_SHORTENER_DETECTED", warning_codes)

    # ------------------------------------------------------------------
    # Feature 5: Try a Sample Scam — Sandbox History Isolation
    # ------------------------------------------------------------------
    def test_sandbox_demo_does_not_pollute_scan_history(self):
        hist_before = scan_history(limit=500, user_id=None).count

        res = analyze_message(
            MessageRequest(
                message="URGENT: Your SBI account will be blocked today. Share your OTP immediately to verify your account!",
                sandbox_demo=True,
            )
        )
        self.assertEqual(res.prediction, "Scam/Phishing")
        self.assertIsNone(res.scan_id)

        hist_after = scan_history(limit=500, user_id=None).count
        self.assertEqual(hist_before, hist_after)

    # ------------------------------------------------------------------
    # Feature 6: Regional Language Support (Hindi, Hinglish, Kannada)
    # ------------------------------------------------------------------
    def test_regional_language_detection_and_transparency(self):
        # Hindi (Devanagari)
        hindi_msg = "तुरंत ध्यान दें: आपका खाता बंद हो जाएगा क्योंकि आपका केवाईसी अपडेट अधूरा है। अपना ओटीपी साझा करें।"
        hi_info = analyze_multilingual_content(hindi_msg)
        self.assertTrue(hi_info["script_info"]["has_indic_script"])
        self.assertGreater(len(hi_info["regional_signals"]["hinglish_signals"]), 0)
        self.assertTrue(
            any("english" in note.lower() for note in hi_info["transparency_notes"]),
            "Must honestly disclose English training scope of the ML model",
        )

        # Kannada
        kannada_msg = "ತುರ್ತು ಸೂಚನೆ: ನಿಮ್ಮ ಖಾತೆ ಬ್ಲಾಕ್ ಆಗಿದೆ. ತಕ್ಷಣ ಕೆವೈಸಿ ಅಪ್ಡೇಟ್ ಮಾಡಿ ಅಥವಾ ನಿಮ್ಮ ಒಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ."
        kn_info = analyze_multilingual_content(kannada_msg)
        self.assertTrue(kn_info["script_info"]["has_indic_script"])
        self.assertGreater(len(kn_info["regional_signals"]["kanglish_signals"]), 0)

        # Hinglish
        hinglish_msg = "URGENT: Aapka bank khata aaj band ho jayega. Turant verify karein aur OTP share karein."
        hg_info = analyze_multilingual_content(hinglish_msg)
        self.assertGreater(len(hg_info["regional_signals"]["hinglish_signals"]), 0)

    # ------------------------------------------------------------------
    # Feature 7: QR Code & UPI Payment Safety Checker
    # ------------------------------------------------------------------
    def test_upi_and_qr_safety_checker_endpoint(self):
        # 1. Deceptive "Scan to receive refund" QR URI
        scam_uri = (
            "upi://pay?pa=refund.claim.desk@ybl&pn=Customer%20Cashback%20Refund"
            "&am=4999.00&cu=INR&tn=Scan%20and%20enter%20PIN%20to%20receive%20Rs%204999%20refund"
        )
        data = analyze_upi_payload(UpiInspectRequest(payload=scam_uri, source_type="qr"))
        self.assertTrue(data["valid"])
        self.assertEqual(data["prediction"], "Scam/Phishing")
        self.assertGreaterEqual(data["risk_score"], 60)

        details = data["extracted_details"]
        self.assertEqual(details["upi_id"], "refund.claim.desk@ybl")
        self.assertEqual(details["payee_name"], "Customer Cashback Refund")
        self.assertEqual(details["amount"], "4999.00")
        self.assertIn("receive", details["note"].lower())

        warning_codes = [w["code"] for w in data["warnings"]]
        self.assertIn("RECEIVE_MONEY_PIN_SCAM_LURE", warning_codes)
        self.assertIn("PREFILLED_DEBIT_AMOUNT", warning_codes)

        # 2. Syntactically valid merchant VPA must still carry non-verification disclaimer
        valid_res = inspect_upi_or_qr_payload("bookshop.counter12@okicici", source_type="manual")
        self.assertTrue(valid_res["valid"])
        self.assertEqual(valid_res["extracted_details"]["psp_handle"], "okicici")
        self.assertTrue(
            any("not guarantee" in d.lower() for d in valid_res["safety_disclaimers"]),
            "Must state that a syntactically valid UPI ID does not guarantee a trustworthy recipient",
        )


if __name__ == "__main__":
    unittest.main()
