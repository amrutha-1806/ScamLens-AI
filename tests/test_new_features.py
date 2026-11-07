"""
Tests for SCAMLENS AI upgraded features:
1. Explainable AI with token-level highlights
2. Static URL Intelligence (zero execution, entropy, typosquatting)
3. Email Phishing Analyzer (sender display-name spoofing, embedded URLs)
4. Security Alert Center & Incident Dossier PDF
5. Multilingual script detection & transliterated dialect indicators
"""

import unittest
from fastapi import HTTPException
from backend.services.url_intelligence import (
    analyze_url_static,
    shannon_entropy,
    levenshtein,
    extract_urls,
    calculate_url_risk_verdict,
)
from backend.main import analyze_url
from backend.schemas import UrlRequest
from backend.services.ml_service import analyze
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

    def test_url_component_offsets_and_bounds(self):
        """Verify accurate character offsets for normal HTTPS, subdomains, ports, and query parameters."""
        test_cases = [
            ("https://docs.python.org/3/library/index.html", {
                "scheme": "https",
                "subdomain": "docs",
                "registrable_domain": "python.org",
                "tld": "org",
                "path": "/3/library/index.html",
            }),
            ("http://192.168.1.1:8080/admin?auth=true", {
                "scheme": "http",
                "host": "192.168.1.1",
                "port": "8080",
                "path": "/admin",
                "query": "auth=true",
            }),
            ("https://sbi.secure-banking.xyz/update-kyc?ref=sms", {
                "scheme": "https",
                "subdomain": "sbi",
                "registrable_domain": "secure-banking.xyz",
                "tld": "xyz",
                "path": "/update-kyc",
                "query": "ref=sms",
            }),
            ("http://example.com/login", {
                "scheme": "http",
                "registrable_domain": "example.com",
                "tld": "com",
                "path": "/login",
            }),
        ]

        for url, expected in test_cases:
            res = analyze_url_static(url)
            self.assertTrue(res["valid"])
            comps = res["components"]
            self.assertIn("offsets", comps)
            offsets = comps["offsets"]

            for comp_name, expected_substr in expected.items():
                self.assertIn(comp_name, offsets, f"Missing offset for '{comp_name}' in URL: {url}")
                start, end = offsets[comp_name]
                # Offset bounds rule: 0 <= start < end <= len(url)
                self.assertGreaterEqual(start, 0)
                self.assertLess(start, end)
                self.assertLessEqual(end, len(url))
                # Text slice matches expected substring
                self.assertEqual(url[start:end].lower(), expected_substr.lower())

    def test_url_findings_component_association(self):
        """Verify that suspicious indicators link to the correct URL components."""
        # 1. Suspicious TLD
        res_tld = analyze_url_static("https://bank-portal.xyz/account")
        tld_finding = next((f for f in res_tld["findings"] if f["code"] == "suspicious_tld"), None)
        self.assertIsNotNone(tld_finding)
        self.assertEqual(tld_finding.get("component"), "tld")

        # 2. Insecure HTTP scheme
        res_http = analyze_url_static("http://example.com/test")
        http_finding = next((f for f in res_http["findings"] if f["code"] == "no_https"), None)
        self.assertIsNotNone(http_finding)
        self.assertEqual(http_finding.get("component"), "scheme")

        # 3. Raw IP Host
        res_ip = analyze_url_static("http://10.0.0.1/login")
        ip_finding = next((f for f in res_ip["findings"] if f["code"] == "ip_host"), None)
        self.assertIsNotNone(ip_finding)
        self.assertEqual(ip_finding.get("component"), "host")

        # 4. Brand impersonation on subdomain
        res_brand = analyze_url_static("https://sbi.fake-portal.com/kyc")
        brand_finding = next((f for f in res_brand["findings"] if f["code"] == "brand_impersonation"), None)
        self.assertIsNotNone(brand_finding)
        self.assertEqual(brand_finding.get("component"), "subdomain")

        # 5. Non-standard port
        res_port = analyze_url_static("https://example.com:8443/login")
        port_finding = next((f for f in res_port["findings"] if f["code"] == "non_standard_port"), None)
        self.assertIsNotNone(port_finding)
        self.assertEqual(port_finding.get("component"), "port")

    def test_url_no_false_suspicious_highlighting(self):
        """Benign HTTPS URLs should not have false danger findings."""
        res_safe = analyze_url_static("https://docs.python.org/3/library/index.html")
        self.assertTrue(res_safe["valid"])
        self.assertEqual(res_safe["heuristic_level"], "No notable indicators")
        high_sev_findings = [f for f in res_safe["findings"] if f["severity"] in ["high", "medium"]]
        self.assertEqual(len(high_sev_findings), 0)

    def test_url_malformed_and_incomplete_safety(self):
        """Malformed or incomplete URLs should fail gracefully without unhandled exceptions."""
        empty_res = analyze_url_static("")
        self.assertFalse(empty_res["valid"])
        self.assertIn("No URL provided", empty_res["error"])

        none_res = analyze_url_static(None)
        self.assertFalse(none_res["valid"])

        whitespace_res = analyze_url_static("https://example .com/page")
        self.assertFalse(whitespace_res["valid"])
        self.assertIn("whitespace", whitespace_res["error"])

        unsupported_res = analyze_url_static("javascript://alert(1)")
        self.assertFalse(unsupported_res["valid"])
        self.assertIn("Unsupported scheme", unsupported_res["error"])

        unsupported_no_slashes = analyze_url_static("javascript:alert(1)")
        self.assertFalse(unsupported_no_slashes["valid"])
        self.assertIsNotNone(unsupported_no_slashes["error"])

    def test_url_zero_network_calls(self):
        """Verify that network_access remains strictly False (offline static inspection)."""
        res = analyze_url_static("https://example.com/test")
        self.assertFalse(res["network_access"])


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


class TestUrlAnalysisAccuracy(unittest.TestCase):
    """
    Regression and accuracy tests for SCAMLENS AI URL Analysis Accuracy Correction:
    - Decoupling URL analysis from SMS-trained Random Forest model
    - Honest benign control handling (https://www.google.com -> Legitimate, Low risk)
    - IP address and brand impersonation threat detection
    - Non-suppression of suspicious paths/queries on official domains
    - Synchronization of risk_score and risk_probability
    - Preservation of Message Analyzer behavior
    """

    def test_google_com_benign_control(self):
        """
        Verify that https://www.google.com is classified as Legitimate with Low risk,
        0.0 risk score, 0.0 risk probability, official domain match, and zero structural findings.
        """
        intel = analyze_url_static("https://www.google.com")
        self.assertTrue(intel["valid"])
        self.assertIsNotNone(intel["brand_match"])
        self.assertEqual(intel["brand_match"]["type"], "official_domain")
        self.assertEqual(intel["brand_match"]["brand"], "google")
        self.assertEqual(intel["heuristic_score"], 0)
        self.assertEqual(intel["heuristic_level"], "No notable indicators")
        self.assertEqual(len(intel["findings"]), 0)

        verdict = calculate_url_risk_verdict(intel)
        self.assertEqual(verdict["prediction"], "Legitimate")
        self.assertEqual(verdict["risk_level"], "Low")
        self.assertEqual(verdict["risk_score"], 0.0)
        self.assertEqual(verdict["risk_probability"], 0.0)
        self.assertEqual(verdict["model"], "Static URL Heuristic Engine")

        # Test through FastAPI endpoint
        endpoint_res = analyze_url(UrlRequest(url="https://www.google.com"))
        self.assertEqual(endpoint_res.prediction, "Legitimate")
        self.assertEqual(endpoint_res.risk_level, "Low")
        self.assertEqual(endpoint_res.risk_score, 0.0)
        self.assertEqual(endpoint_res.risk_probability, 0.0)
        self.assertEqual(endpoint_res.model, "Static URL Heuristic Engine")
        self.assertIn("GOOGLE", " ".join(endpoint_res.indicators))

    def test_raw_ip_address_host(self):
        """
        Verify that raw IP hosts (http://192.168.1.1/login) trigger elevated/high risk,
        are flagged with ip_host, and synchronize score and probability.
        """
        endpoint_res = analyze_url(UrlRequest(url="http://192.168.1.1/login"))
        self.assertEqual(endpoint_res.prediction, "Scam/Phishing")
        self.assertIn(endpoint_res.risk_level, ["High", "Suspicious"])
        self.assertEqual(endpoint_res.risk_level, "High")
        self.assertEqual(endpoint_res.risk_score, 68.0)
        self.assertEqual(endpoint_res.risk_probability, 0.68)
        self.assertEqual(endpoint_res.model, "Static URL Heuristic Engine")

        intel = endpoint_res.url_intelligence
        self.assertTrue(intel["components"]["is_ip_address"])
        codes = [f["code"] for f in intel["findings"]]
        self.assertIn("ip_host", codes)
        self.assertIn("no_https", codes)

    def test_sbi_brand_impersonation(self):
        """
        Verify that deceptive brand impersonation (https://secure-sbi.kyc-update.xyz/login.php)
        is classified as Scam/Phishing with High risk, deceptive domain flag, and suspicious TLD.
        """
        endpoint_res = analyze_url(UrlRequest(url="https://secure-sbi.kyc-update.xyz/login.php"))
        self.assertEqual(endpoint_res.prediction, "Scam/Phishing")
        self.assertIn(endpoint_res.risk_level, ["High", "Very High"])
        self.assertEqual(endpoint_res.risk_level, "High")
        self.assertGreaterEqual(endpoint_res.risk_score, 70.0)
        self.assertEqual(endpoint_res.risk_probability, round(endpoint_res.risk_score / 100.0, 4))

        intel = endpoint_res.url_intelligence
        self.assertIsNotNone(intel["brand_match"])
        self.assertEqual(intel["brand_match"]["type"], "impersonation")
        codes = [f["code"] for f in intel["findings"]]
        self.assertIn("brand_impersonation", codes)
        self.assertIn("suspicious_tld", codes)

    def test_official_domain_with_suspicious_path_not_suppressed(self):
        """
        Verify that official domain recognition does NOT grant unconditional immunity
        when a suspicious executable download or redirect parameter is present.
        """
        # Test 1: Executable download on official domain
        res_exe = analyze_url(UrlRequest(url="https://google.com/login.exe"))
        self.assertIsNotNone(res_exe.url_intelligence["brand_match"])
        self.assertEqual(res_exe.url_intelligence["brand_match"]["type"], "official_domain")
        codes_exe = [f["code"] for f in res_exe.url_intelligence["findings"]]
        self.assertIn("risky_download", codes_exe)
        self.assertEqual(res_exe.prediction, "Scam/Phishing")
        self.assertIn(res_exe.risk_level, ["High", "Very High"])
        self.assertGreaterEqual(res_exe.risk_score, 50.0)

        # Test 2: Embedded redirect parameter on official domain
        res_red = analyze_url(UrlRequest(url="https://paypal.com/test?redirect=https://evil.com"))
        self.assertIsNotNone(res_red.url_intelligence["brand_match"])
        self.assertEqual(res_red.url_intelligence["brand_match"]["type"], "official_domain")
        codes_red = [f["code"] for f in res_red.url_intelligence["findings"]]
        self.assertIn("embedded_redirect", codes_red)
        self.assertGreater(res_red.risk_score, 0.0)

    def test_empty_and_malformed_urls(self):
        """
        Verify that empty, whitespace-only, and malformed URLs are rejected safely
        with HTTP 422 or valid=False without raising uncaught exceptions.
        """
        for bad_url in ["", "   ", "http://", "ftp://invalid-scheme.com", "not a url with spaces"]:
            intel = analyze_url_static(bad_url)
            self.assertFalse(intel["valid"])
            self.assertIsNotNone(intel["error"])

        # Test endpoint raises 422 for malformed URL
        with self.assertRaises(HTTPException) as ctx:
            analyze_url(UrlRequest(url="ftp://files.example.com/test"))
        self.assertEqual(ctx.exception.status_code, 422)

    def test_risk_score_and_probability_synchronization(self):
        """
        Verify that risk_probability is strictly equal to round(risk_score / 100.0, 4)
        across all test URLs and cannot contradict each other.
        """
        test_urls = [
            "https://www.google.com",
            "http://192.168.1.1/login",
            "https://secure-sbi.kyc-update.xyz/login.php",
            "https://google.com/login.exe",
            "https://paypal.com/test?redirect=https://evil.com",
            "http://bit.ly/3xYz99ClaimReward",
            "https://docs.python.org/3/library/index.html",
            "http://paypa1-update.com/login",
            "https://github.com/torvalds/linux",
            "http://10.0.0.1:8080/admin/reset",
        ]
        for u in test_urls:
            res = analyze_url(UrlRequest(url=u))
            expected_prob = round(res.risk_score / 100.0, 4)
            self.assertAlmostEqual(
                res.risk_probability,
                expected_prob,
                places=4,
                msg=f"Score {res.risk_score} and Prob {res.risk_probability} desynchronized for {u}",
            )
            self.assertEqual(res.model, "Static URL Heuristic Engine")

    def test_message_analyzer_behavior_preserved(self):
        """
        Verify that the Message Analyzer continues to use the Random Forest model
        with token-level explainability and unchanged prediction behavior.
        """
        # Phishing SMS lure
        scam_text = "URGENT: You have won a cash prize of $50,000! Claim immediately at http://win.example.com"
        scam_res = analyze(scam_text, include_explainability=True)
        self.assertEqual(scam_res["model"], "Random Forest")
        self.assertEqual(scam_res["prediction"], "Scam/Phishing")
        self.assertIsNotNone(scam_res["explainability"])
        self.assertGreater(len(scam_res["indicators"]), 0)

        # Benign routine message
        legit_text = "Hey team, let's catch up tomorrow for our weekly project progress sync."
        legit_res = analyze(legit_text, include_explainability=True)
        self.assertEqual(legit_res["model"], "Random Forest")
        self.assertEqual(legit_res["prediction"], "Legitimate")
        self.assertEqual(legit_res["risk_level"], "Low")
        self.assertLess(legit_res["risk_score"], 25.0)


class TestBatchCsvUrlRouting(unittest.IsolatedAsyncioTestCase):
    """
    Regression test suite for Batch CSV Scanner URL routing.
    Verifies that URL rows route strictly to the Static URL Heuristic Engine
    while message/text rows continue to route to the Random Forest model.
    """

    async def test_mixed_csv_messages_and_urls(self):
        """
        Verify that a CSV containing both messages and URLs correctly
        evaluates messages via Random Forest and URLs via Static URL Heuristic Engine.
        """
        import io
        from fastapi import UploadFile
        from backend.main import analyze_batch

        csv_content = (
            "message\n"
            '"Hey team, are we still meeting today at 2pm?"\n'
            '"URGENT: Your account has been suspended! Verify immediately at http://claim.xyz"\n'
            '"https://www.google.com"\n'
            '"http://192.168.1.1/login"\n'
            '"https://google.com/installer/update.exe"\n'
        ).encode("utf-8")

        upload = UploadFile(filename="mixed_test.csv", file=io.BytesIO(csv_content))
        response = await analyze_batch(file=upload)

        self.assertEqual(response.total_rows, 5)
        self.assertEqual(response.processed_rows, 5)
        self.assertEqual(response.failed_rows, 0)
        self.assertEqual(len(response.results), 5)

        res = response.results

        # Row 0: Legitimate message -> Random Forest
        self.assertEqual(res[0].input_type, "message")
        self.assertEqual(res[0].model, "Random Forest")
        self.assertEqual(res[0].prediction, "Legitimate")
        self.assertLess(res[0].risk_score, 25.0)

        # Row 1: Phishing message -> Random Forest
        self.assertEqual(res[1].input_type, "message")
        self.assertEqual(res[1].model, "Random Forest")
        self.assertEqual(res[1].prediction, "Scam/Phishing")
        self.assertGreater(res[1].risk_score, 50.0)

        # Row 2: Benign URL (https://www.google.com) -> Static URL Heuristic Engine (NOT Random Forest!)
        self.assertEqual(res[2].input_type, "url")
        self.assertEqual(res[2].model, "Static URL Heuristic Engine")
        self.assertEqual(res[2].prediction, "Legitimate")
        self.assertEqual(res[2].risk_score, 0.0)
        self.assertEqual(res[2].risk_probability, 0.0)
        self.assertNotEqual(res[2].model, "Random Forest")

        # Row 3: Raw IP URL (http://192.168.1.1/login) -> Static URL Heuristic Engine
        self.assertEqual(res[3].input_type, "url")
        self.assertEqual(res[3].model, "Static URL Heuristic Engine")
        self.assertEqual(res[3].prediction, "Scam/Phishing")
        self.assertEqual(res[3].risk_score, 68.0)
        self.assertEqual(res[3].risk_probability, 0.68)
        self.assertNotEqual(res[3].model, "Random Forest")

        # Row 4: Official domain with .exe download -> Static URL Heuristic Engine
        self.assertEqual(res[4].input_type, "url")
        self.assertEqual(res[4].model, "Static URL Heuristic Engine")
        self.assertEqual(res[4].prediction, "Scam/Phishing")
        self.assertEqual(res[4].risk_score, 56.0)
        self.assertEqual(res[4].risk_probability, 0.56)

        # Verify risk score & probability synchronization across all URL rows
        for item in res[2:]:
            expected_p = round(item.risk_score / 100.0, 4)
            self.assertEqual(item.risk_probability, expected_p)

    async def test_csv_with_explicit_type_column(self):
        """
        Verify that a CSV with an explicit 'type' column correctly routes
        each row even if the URL doesn't have an http/https prefix or message contains links.
        """
        import io
        from fastapi import UploadFile
        from backend.main import analyze_batch

        csv_content = (
            "type,content\n"
            'url,"https://www.google.com"\n'
            'message,"Your one-time pass code is 482103"\n'
            'url,"http://192.168.1.1/login"\n'
        ).encode("utf-8")

        upload = UploadFile(filename="typed_batch.csv", file=io.BytesIO(csv_content))
        response = await analyze_batch(file=upload)

        self.assertEqual(response.processed_rows, 3)
        self.assertEqual(response.results[0].input_type, "url")
        self.assertEqual(response.results[0].model, "Static URL Heuristic Engine")
        self.assertEqual(response.results[0].prediction, "Legitimate")

        self.assertEqual(response.results[1].input_type, "message")
        self.assertEqual(response.results[1].model, "Random Forest")
        self.assertEqual(response.results[1].prediction, "Legitimate")

        self.assertEqual(response.results[2].input_type, "url")
        self.assertEqual(response.results[2].model, "Static URL Heuristic Engine")
        self.assertEqual(response.results[2].prediction, "Scam/Phishing")

    async def test_csv_with_url_header_column(self):
        """
        Verify that a CSV with a column named 'url' is auto-detected
        and routes strictly to the Static URL Heuristic Engine.
        """
        import io
        from fastapi import UploadFile
        from backend.main import analyze_batch

        csv_content = (
            "url\n"
            '"https://www.google.com"\n'
            '"http://192.168.1.1/login"\n'
        ).encode("utf-8")

        upload = UploadFile(filename="urls_only.csv", file=io.BytesIO(csv_content))
        response = await analyze_batch(file=upload)

        self.assertEqual(response.processed_rows, 2)
        for item in response.results:
            self.assertEqual(item.input_type, "url")
            self.assertEqual(item.model, "Static URL Heuristic Engine")

    async def test_batch_csv_malformed_url_handled_gracefully(self):
        """
        Verify that an invalid URL in a batch reports an informative error
        in failed_rows / errors without crashing the entire batch.
        """
        import io
        from fastapi import UploadFile
        from backend.main import analyze_batch

        csv_content = (
            "type,content\n"
            'message,"Valid normal message here"\n'
            'url,"ftp://unsupported-scheme.com"\n'
        ).encode("utf-8")

        upload = UploadFile(filename="malformed.csv", file=io.BytesIO(csv_content))
        response = await analyze_batch(file=upload)

        self.assertEqual(response.processed_rows, 1)
        self.assertEqual(response.failed_rows, 1)
        self.assertIn("invalid URL", response.errors[0])
        self.assertEqual(response.results[0].input_type, "message")


class TestUrlGuidanceConsistency(unittest.TestCase):
    """
    Guidance text must agree with the static heuristic findings, without changing
    scores or classifications.
    """

    NO_INDICATORS_PHRASE = "no suspicious structural indicators"

    def test_clean_google_url_has_no_findings_and_clean_guidance(self):
        """A URL with zero findings may state that no suspicious indicators were found."""
        res = analyze_url(UrlRequest(url="https://www.google.com"))
        self.assertEqual(res.url_intelligence["findings"], [])
        self.assertEqual(res.model, "Static URL Heuristic Engine")
        self.assertEqual(res.prediction, "Legitimate")
        self.assertEqual(res.risk_level, "Low")
        self.assertEqual(res.risk_score, 0.0)
        self.assertIn(self.NO_INDICATORS_PHRASE, res.guidance.lower())
        self.assertIn("official domain", res.guidance.lower())

    def test_embedded_redirect_on_google_url_guidance_mentions_warning(self):
        """A medium finding must be called out in guidance even though overall risk stays Low."""
        res = analyze_url(UrlRequest(url="https://google.com/url?q=abc&redirect=http://evil.com"))
        findings = res.url_intelligence["findings"]
        codes = [f["code"] for f in findings]
        self.assertIn("embedded_redirect", codes)
        self.assertTrue(any(f["severity"] == "medium" for f in findings))
        self.assertEqual(res.url_intelligence["brand_match"]["type"], "official_domain")

        # Scoring/classification is the existing engine output, unchanged by the guidance fix.
        self.assertEqual(res.risk_level, "Low")
        self.assertEqual(res.prediction, "Legitimate")
        self.assertEqual(res.risk_score, 15.0)
        self.assertEqual(res.risk_probability, 0.15)

        guidance = res.guidance.lower()
        self.assertNotIn(self.NO_INDICATORS_PHRASE, guidance)
        self.assertIn("suspicious indicator", guidance)
        self.assertIn("embedded redirect parameter", guidance)
        self.assertIn("remains low", guidance)
        # Official domain is supporting evidence only, not a safety guarantee.
        self.assertIn("does not make the path or query content", guidance)

    def test_low_severity_only_finding_is_noted_without_alarm(self):
        """Low-severity-only findings are noted as minor, never described as 'no indicators'."""
        res = analyze_url(UrlRequest(url="https://example.com/login"))
        codes = [f["code"] for f in res.url_intelligence["findings"]]
        self.assertEqual(codes, ["credential_keywords"])
        self.assertEqual(res.risk_level, "Low")
        guidance = res.guidance.lower()
        self.assertNotIn(self.NO_INDICATORS_PHRASE, guidance)
        self.assertIn("minor", guidance)
        self.assertNotIn("a suspicious indicator was detected", guidance)

    def test_high_risk_phishing_url_guidance_is_high_risk(self):
        """High-risk URLs keep their high-risk guidance and never claim a clean result."""
        for url in ("https://secure-sbi.kyc-update.xyz/login.php", "http://192.168.1.1/login"):
            res = analyze_url(UrlRequest(url=url))
            self.assertEqual(res.prediction, "Scam/Phishing", msg=url)
            self.assertIn(res.risk_level, ("High", "Very High"), msg=url)
            self.assertGreaterEqual(res.risk_score, 50.0, msg=url)
            self.assertGreater(len(res.url_intelligence["findings"]), 0, msg=url)
            guidance = res.guidance.lower()
            self.assertNotIn(self.NO_INDICATORS_PHRASE, guidance, msg=url)
            self.assertTrue("high-risk" in guidance or "critical" in guidance, msg=url)
            self.assertIn("do not", guidance, msg=url)

    def test_guidance_never_claims_clean_when_findings_exist(self):
        """Across a spread of URLs, 'no suspicious indicators' guidance implies zero findings."""
        urls = [
            "https://www.google.com",
            "https://google.com/url?q=abc&redirect=http://evil.com",
            "https://google.com/installer/update.exe",
            "http://bit.ly/3xYz99ClaimReward",
            "https://docs.python.org/3/library/index.html",
            "http://paypa1-update.com/login",
            "www.example.org/page",
            "https://github.com/torvalds/linux",
        ]
        for url in urls:
            res = analyze_url(UrlRequest(url=url))
            if self.NO_INDICATORS_PHRASE in res.guidance.lower():
                self.assertEqual(res.url_intelligence["findings"], [], msg=url)


if __name__ == "__main__":
    unittest.main()
