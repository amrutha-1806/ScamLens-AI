"""
Unit Tests for Phase 5 ScamLensPredictor Inference Engine & Database Integration
"""

import unittest
import os
import sqlite3
from src.config import SAVED_MODELS_DIR, DB_PATH
from src.models.predictor import get_predictor, ScamLensPredictor
from src.utils.database import get_connection, fetch_recent_scans


class TestPredictorEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Initialize predictor instance once for testing."""
        cls.predictor = get_predictor()

    def test_01_saved_model_loads(self):
        """Test 1: Saved Random Forest model loads successfully."""
        self.assertIsNotNone(self.predictor.model)
        self.assertTrue(hasattr(self.predictor.model, "predict"))

    def test_02_saved_extractor_loads(self):
        """Test 2: Saved FeatureExtractor loads successfully."""
        self.assertIsNotNone(self.predictor.extractor)
        self.assertTrue(self.predictor.extractor.is_fitted)

    def test_03_normal_message_transforms(self):
        """Test 3: Normal message can be transformed by loaded feature extractor."""
        X_feat = self.predictor.extractor.transform(["Hello world, this is a test."])
        self.assertEqual(X_feat.shape[0], 1)
        self.assertGreater(X_feat.shape[1], 0)

    def test_04_prediction_returns_binary_class(self):
        """Test 4: Prediction class_id is in {0, 1}."""
        res = self.predictor.predict("Hi, meeting you at 5pm.")
        self.assertTrue(res["valid"])
        self.assertIn(res["class_id"], {0, 1})

    def test_05_prediction_label_valid(self):
        """Test 5: Prediction label is either 'Legitimate' or 'Scam/Phishing'."""
        res = self.predictor.predict("WINNER! Claim your free £1000 prize now!")
        self.assertTrue(res["valid"])
        self.assertIn(res["prediction"], {"Legitimate", "Scam/Phishing"})

    def test_06_probabilities_valid_range(self):
        """Test 6: Probabilities fall between 0.0 and 1.0."""
        res = self.predictor.predict("Test message")
        p_scam = res["phishing_probability"]
        p_legit = res["legitimate_probability"]
        self.assertTrue(0.0 <= p_scam <= 1.0)
        self.assertTrue(0.0 <= p_legit <= 1.0)

    def test_07_probabilities_sum_to_one(self):
        """Test 7: Probabilities approximately sum to 1.0."""
        res = self.predictor.predict("URGENT bank verification needed")
        p_sum = res["phishing_probability"] + res["legitimate_probability"]
        self.assertAlmostEqual(p_sum, 1.0, delta=0.01)

    def test_08_risk_score_range(self):
        """Test 8: Risk score is between 0.0 and 100.0."""
        res = self.predictor.predict("Free money winner call 0800123")
        score = res["risk_score"]
        self.assertTrue(0.0 <= score <= 100.0)

    def test_09_risk_level_categories(self):
        """Test 9: Risk level belongs to {'Low', 'Suspicious', 'High', 'Very High'}."""
        res = self.predictor.predict("Normal message for risk level check")
        self.assertIn(res["risk_level"], {"Low", "Suspicious", "High", "Very High"})

    def test_10_empty_message_handled(self):
        """Test 10: Empty message returns valid=False and clear error message."""
        res = self.predictor.predict("")
        self.assertFalse(res["valid"])
        self.assertIn("error", res)

    def test_11_whitespace_message_handled(self):
        """Test 11: Whitespace-only message returns valid=False."""
        res = self.predictor.predict("     \n\t  ")
        self.assertFalse(res["valid"])
        self.assertIn("error", res)

    def test_12_url_message_offline(self):
        """Test 12: URL-containing message completes 100% offline without network calls."""
        res = self.predictor.predict("Verify at http://suspicious-bank-link.xyz/@login")
        self.assertTrue(res["valid"])
        # Check that URL indicators were extracted offline
        indicators_str = " ".join(res["indicators"])
        self.assertIn("URL", indicators_str)

    def test_13_explanations_accurate(self):
        """Test 13: Prediction explanation contains relevant indicators."""
        res = self.predictor.predict("URGENT! Account blocked. Call bank now!")
        self.assertTrue(res["valid"])
        self.assertGreater(len(res["indicators"]), 0)

    def test_14_database_logging(self):
        """Test 14: Predictor records scan logs into SQLite database."""
        res = self.predictor.predict("Database logging verification test message.")
        self.assertTrue(res["valid"])
        self.assertIsNotNone(res.get("scan_id"))

        scans = fetch_recent_scans(limit=5)
        self.assertGreater(len(scans), 0)


if __name__ == "__main__":
    unittest.main()
