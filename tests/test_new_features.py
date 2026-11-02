"""
Tests for SCAMLENS AI upgraded features:
1. Explainable AI with token-level highlights
2. Static URL Intelligence (zero execution, entropy, typosquatting)
3. Email Phishing Analyzer (sender display-name spoofing, embedded URLs)
4. Security Alert Center & Incident Dossier PDF
5. Multilingual script detection & transliterated dialect indicators
"""

import unittest
from backend.services.url_intelligence import (
    analyze_url_static,
    shannon_entropy,
    levenshtein,
    extract_urls,
)
from backend.services.explainability import (
    explain_text,
    rule_based_highlights,
)
from backend.services.language_service import (
    detect_scripts,
    analyze_multilingual_content,
)
from backend.services.email_service import (
    analyze_email_phishing,
)
from backend.services.report_service import (
    generate_incident_report_pdf,
)
from src.utils.database import (
    fetch_security_alerts,
    update_alert_review,
    fetch_scan_by_id,
)


class TestUrlIntelligence(unittest.TestCase):
    """Test suite for static URL intelligence."""

    def test_shannon_entropy(self):
        """Entropy of a uniform single character is 0; random strings have higher entropy."""
        self.assertEqual(shannon_entropy("aaaaaa"), 0.0)
        self.assertGreater(shannon_entropy("a8f93kd92x-sec"), 3.0)

    def test_levenshtein_distance(self):
        """Test edit distance calculation."""
        self.assertEqual(levenshtein("paypal", "paypal"), 0)
        self.assertEqual(levenshtein("paypal", "paypa1"), 1)
        self.assertEqual(levenshtein("bank", "back"), 1)

    def test_ip_address_host_detection(self):
        """Detect IP address used as hostname without DNS lookup."""
        res = analyze_url_static("http://192.168.1.100/login/update")
        self.assertTrue(res["valid"])
        self.assertTrue(res["components"]["is_ip_address"])
        self.assertEqual(res["heuristic_level"], "High")
        finding_codes = [f["code"] for f in res["findings"]]
        self.assertIn("ip_host", finding_codes)

    def test_url_shortener_detection(self):
        """Detect known URL shortener domains."""
        res = analyze_url_static("https://bit.ly/3xY79aZ")
        self.assertTrue(res["metrics"]["is_shortener"])
        finding_codes = [f["code"] for f in res["findings"]]
        self.assertIn("url_shortener", finding_codes)

    def test_typosquatting_detection(self):
        """Detect suspicious brand impersonation / typosquatting in hostname."""
        res = analyze_url_static("https://secure-paypa1-update.com/verify")
        self.assertIsNotNone(res["brand_match"])
        self.assertIn(res["brand_match"]["type"], ["typosquat", "impersonation"])
        self.assertIn(res["heuristic_level"], ["Elevated", "High"])

    def test_url_extraction(self):
        """Extract URLs from unstructured body text."""
        text = "Please check https://account-update.info/login and also http://bit.ly/secure for info."
        urls = extract_urls(text)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://account-update.info/login", urls)
        self.assertIn("http://bit.ly/secure", urls)

    def test_structural_checks_complete_dimensions(self):
        """Verify that exactly 9 structural dimensions are returned with valid statuses."""
        res = analyze_url_static("https://docs.python.org/3/library/index.html")
        checks = res.get("structural_checks", [])
        self.assertEqual(len(checks), 9)
        expected_ids = [
            "https_protocol",
            "url_length_depth",
            "domain_structure",
            "subdomain_count",
            "raw_ip_hostname",
            "at_symbol_obfuscation",
            "phishing_keywords",
            "url_shortener_service",
            "special_character_density",
        ]
        self.assertEqual([c["id"] for c in checks], expected_ids)
        for c in checks:
            self.assertIn(c["status"], ["Detected", "Not Detected", "Unable to Evaluate"])
            self.assertTrue(len(c["explanation"]) > 10)

    def test_5_sample_urls_evaluation(self):
        """Test URL Analyzer logic on the 5 required sample URLs."""
        # 1. Normal HTTPS URL
        res_https = analyze_url_static("https://docs.python.org/3/library/index.html")
        checks_https = {c["id"]: c for c in res_https["structural_checks"]}
        self.assertEqual(checks_https["https_protocol"]["status"], "Not Detected")
        self.assertIn("does NOT prove", checks_https["https_protocol"]["explanation"])
        self.assertEqual(checks_https["raw_ip_hostname"]["status"], "Not Detected")

        # 2. HTTP URL
        res_http = analyze_url_static("http://example.com/login")
        checks_http = {c["id"]: c for c in res_http["structural_checks"]}
        self.assertEqual(checks_http["https_protocol"]["status"], "Detected")
        self.assertEqual(checks_http["phishing_keywords"]["status"], "Detected")

        # 3. URL containing suspicious keywords
        res_kw = analyze_url_static("https://secure-account-verify-login.com/update")
        checks_kw = {c["id"]: c for c in res_kw["structural_checks"]}
        self.assertEqual(checks_kw["domain_structure"]["status"], "Detected")
        self.assertEqual(checks_kw["phishing_keywords"]["status"], "Detected")

        # 4. Raw IP address URL
        res_ip = analyze_url_static("http://192.168.1.1/admin")
        checks_ip = {c["id"]: c for c in res_ip["structural_checks"]}
        self.assertEqual(checks_ip["raw_ip_hostname"]["status"], "Detected")
        self.assertEqual(checks_ip["domain_structure"]["status"], "Unable to Evaluate")
        self.assertEqual(checks_ip["subdomain_count"]["status"], "Unable to Evaluate")
        self.assertEqual(checks_ip["url_shortener_service"]["status"], "Unable to Evaluate")

        # 5. Shortened URL
        res_short = analyze_url_static("https://bit.ly/3xY79aZ")
        checks_short = {c["id"]: c for c in res_short["structural_checks"]}
        self.assertEqual(checks_short["url_shortener_service"]["status"], "Detected")


class TestExplainableAI(unittest.TestCase):
    """Test suite for explainable AI and token attribution."""

    def test_rule_highlights(self):
        """Verify keyword highlights with exact start and end offsets."""
        text = "URGENT: Your bank account is locked! Click link to claim your prize now."
        highlights = rule_based_highlights(text)
        self.assertIsInstance(highlights, list)
        self.assertGreater(len(highlights), 0)
        for h in highlights:
            start, end = h["start"], h["end"]
            self.assertEqual(text[start:end].lower(), h["text"].lower())
            self.assertIn("category", h)
            self.assertEqual(h["source"], "rule")

    def test_token_attributions_with_model(self):
        """Verify leave-one-word-out perturbation attribution on ScamLensPredictor."""
        from src.models.predictor import ScamLensPredictor
        predictor = ScamLensPredictor()
        text = "Congratulations! You won a $1000 prize. Call now."
        explanation = explain_text(predictor, text, model_probability=0.92)
        self.assertIsInstance(explanation, dict)
        self.assertIn("token_attributions", explanation)
        self.assertIn("rule_highlights", explanation)
        self.assertIn("summary", explanation)
        self.assertIn("limitations", explanation)
        attributions = explanation["token_attributions"]
        self.assertGreater(len(attributions), 0)
        for attr in attributions:
            self.assertIn("text", attr)
            self.assertIn("start", attr)
            self.assertIn("end", attr)
            self.assertIn("influence", attr)
            start, end = attr["start"], attr["end"]
            self.assertEqual(text[start:end].lower(), attr["text"].lower())


class TestLanguageDetection(unittest.TestCase):
    """Test suite for Unicode script detection and transliteration heuristics."""

    def test_kannada_script_detection(self):
        """Detect Kannada script and provide honest transparency note."""
        text = "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆಯನ್ನು ತಕ್ಷಣ ನವೀಕರಿಸಿ"
        res = analyze_multilingual_content(text)
        self.assertEqual(res["script_info"]["primary_script"], "Kannada")
        self.assertTrue(res["script_info"]["has_indic_script"])
        self.assertGreater(len(res["transparency_notes"]), 0)
        self.assertIn("Kannada", res["transparency_notes"][0])

    def test_devanagari_script_detection(self):
        """Detect Devanagari script and provide honest transparency note."""
        text = "आपका बैंक खाता तुरंत ब्लॉक कर दिया जाएगा"
        res = analyze_multilingual_content(text)
        self.assertEqual(res["script_info"]["primary_script"], "Devanagari (Hindi/Marathi)")
        self.assertTrue(res["script_info"]["has_indic_script"])
        self.assertGreater(len(res["transparency_notes"]), 0)
        self.assertIn("Devanagari", res["transparency_notes"][0])

    def test_hinglish_detection(self):
        """Detect transliterated Hindi (Hinglish) patterns in Latin script."""
        text = "Aapka account block ho gaya hai, turant update karein."
        res = analyze_multilingual_content(text)
        self.assertEqual(res["script_info"]["primary_script"], "Latin (English/Romanized)")
        self.assertGreater(len(res["regional_signals"]["hinglish_signals"]), 0)

    def test_kanglish_detection(self):
        """Detect transliterated Kannada (Kanglish) patterns in Latin script."""
        text = "Nimma account block agide, thakshana samparkisi."
        res = analyze_multilingual_content(text)
        self.assertEqual(res["script_info"]["primary_script"], "Latin (English/Romanized)")
        self.assertGreater(len(res["regional_signals"]["kanglish_signals"]), 0)


class TestEmailPhishingAnalyzer(unittest.TestCase):
    """Test suite for email phishing analyzer."""

    def test_display_name_spoofing(self):
        """Detect display name impersonating a brand while using an untrusted sender domain."""
        res = analyze_email_phishing(
            sender="PayPal Security Team <support@mail-update-verify.com>",
            subject="Action Required: Unauthorized Transaction Detected",
            body="Dear customer, someone tried to log into your account. Click http://192.168.1.1/login to verify.",
        )
        self.assertEqual(res["prediction"], "Scam/Phishing")
        self.assertIn(res["risk_level"], ["High", "Very High"])
        self.assertGreater(res["risk_score"], 70.0)

        # Check indicators for spoofing & embedded URL
        indicators_str = " ".join(res["indicators"])
        self.assertTrue("Spoofing" in indicators_str or "Display Name" in indicators_str or "PayPal" in indicators_str)
        self.assertGreater(len(res["embedded_urls"]), 0)

    def test_legitimate_email(self):
        """Test a clean email without deceptive indicators."""
        res = analyze_email_phishing(
            sender="Alice Smith <alice@example.com>",
            subject="Team lunch tomorrow at 12:30",
            body="Hi team, let's meet at the cafeteria tomorrow for lunch. See you all then!",
        )
        self.assertEqual(res["prediction"], "Legitimate")
        self.assertIn(res["risk_level"], ["Low", "Suspicious"])
        self.assertLess(res["risk_score"], 50.0)


class TestSecurityAlertCenterAndIncidentPdf(unittest.TestCase):
    """Test suite for alert center triage and incident forensic dossier generation."""

    def test_database_alerts_and_review(self):
        """Verify querying alerts and updating review status in database."""
        alerts = fetch_security_alerts(limit=5, status_filter="all")
        self.assertIsInstance(alerts, list)
        if len(alerts) > 0:
            sample_id = alerts[0]["id"]
            # Test updating review
            update_success = update_alert_review(
                scan_id=sample_id,
                review_status="investigating",
                review_notes="Forensic analyst is reviewing token weights.",
            )
            self.assertTrue(update_success)

            # Test retrieving updated record
            record = fetch_scan_by_id(sample_id)
            self.assertIsNotNone(record)
            self.assertEqual(record["review_status"], "investigating")
            self.assertEqual(record["review_notes"], "Forensic analyst is reviewing token weights.")

    def test_generate_incident_report_pdf(self):
        """Verify generating a 1-page vector PDF incident dossier."""
        sample_record = {
            "id": 999,
            "timestamp": "2026-11-02 21:00:00",
            "input_type": "email",
            "content": "Subject: URGENT: Your PayPal account has been suspended! Click http://paypa1-update.com/login",
            "prediction_label": "Scam/Phishing",
            "risk_level": "Very High",
            "scam_probability": 0.965,
            "risk_score": 96.5,
            "explanation_summary": "Detected display name spoofing, high-risk typosquatted domain, and urgency triggers.",
            "review_status": "investigating",
            "review_notes": "Confirmed phishing domain targeting PayPal credentials.",
            "reviewed_at": "2026-11-02 21:15:00",
        }
        pdf_bytes = generate_incident_report_pdf(sample_record)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 500)


if __name__ == "__main__":
    unittest.main()
