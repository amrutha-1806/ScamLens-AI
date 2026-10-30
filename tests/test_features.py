"""
Unit Tests for Phase 3 Feature Extraction & Pipeline
"""

import unittest
import numpy as np
import scipy.sparse as sp
from src.features.text_features import extract_text_statistical_features
from src.features.url_features import extract_url_lexical_features
from src.features.extractor import FeatureExtractor


class TestFeatureEngineering(unittest.TestCase):

    def test_01_text_features_empty_and_normal(self):
        """Test text statistical feature extraction on empty and normal strings."""
        empty_feats = extract_text_statistical_features("")
        self.assertEqual(empty_feats["character_count"], 0.0)
        self.assertEqual(empty_feats["word_count"], 0.0)

        normal_feats = extract_text_statistical_features("Hello world, this is normal text.")
        self.assertEqual(normal_feats["word_count"], 6.0)
        self.assertGreater(normal_feats["character_count"], 0.0)

    def test_02_text_features_scam_signals(self):
        """Test text statistical feature extraction for numbers, URLs, punctuation, and currency."""
        text = "URGENT! You won $5000 cash! Claim at http://scam.xyz or call 0800123456 now?"
        feats = extract_text_statistical_features(text)
        
        self.assertGreater(feats["exclamation_count"], 0.0)
        self.assertGreater(feats["question_mark_count"], 0.0)
        self.assertGreater(feats["currency_symbol_count"], 0.0)
        self.assertGreater(feats["digit_count"], 0.0)
        self.assertEqual(feats["has_url"], 1.0)
        self.assertEqual(feats["has_urgency_keyword"], 1.0)
        self.assertEqual(feats["has_reward_keyword"], 1.0)

    def test_03_url_static_features(self):
        """Test static URL lexical analysis on sample URLs (100% offline, zero network calls)."""
        # Test 1: Clean HTTPS URL
        url1 = "https://example.com"
        f1 = extract_url_lexical_features(url1)
        self.assertEqual(f1["has_https"], 1.0)
        self.assertEqual(f1["has_ip_address"], 0.0)

        # Test 2: IP Address URL
        url2 = "http://192.168.1.1/login"
        f2 = extract_url_lexical_features(url2)
        self.assertEqual(f2["has_ip_address"], 1.0)
        self.assertEqual(f2["contains_suspicious_keyword"], 1.0)

        # Test 3: Suspicious TLD & @ symbol
        url3 = "http://suspicious-site.xyz/@login"
        f3 = extract_url_lexical_features(url3)
        self.assertEqual(f3["has_at_symbol"], 1.0)
        self.assertEqual(f3["contains_suspicious_tld"], 1.0)
        self.assertEqual(f3["contains_suspicious_keyword"], 1.0)

    def test_04_feature_extractor_lifecycle(self):
        """Test FeatureExtractor fit, transform, dimensions, and feature names API."""
        corpus = [
            "Urgent action required! Verify your bank account at http://secure-bank.xyz",
            "Hey buddy, are we still meeting for lunch today?",
            "WINNER! Claim your free £1000 prize now!"
        ]

        extractor = FeatureExtractor()
        
        # Test error before fit
        with self.assertRaises(RuntimeError):
            extractor.transform(["test"])
        with self.assertRaises(RuntimeError):
            extractor.get_feature_names_out()

        # Fit and transform corpus
        X = extractor.fit_transform(corpus)
        
        self.assertTrue(sp.issparse(X), "Output feature matrix must be scipy sparse matrix.")
        self.assertEqual(X.shape[0], len(corpus))
        
        feature_names = extractor.get_feature_names_out()
        self.assertEqual(X.shape[1], len(feature_names))

        # Test transformation of new unseen message
        new_msg = ["Call this number 080012345 to claim $500"]
        X_new = extractor.transform(new_msg)
        
        self.assertEqual(X_new.shape[0], 1)
        self.assertEqual(X_new.shape[1], X.shape[1], "Dimension mismatch on transform.")

    def test_05_feature_extractor_empty_input(self):
        """Test pipeline safety on empty or null inputs."""
        extractor = FeatureExtractor()
        extractor.fit(["sample message for fitting"])
        
        X_empty = extractor.transform(["", None])
        self.assertEqual(X_empty.shape[0], 2)
        self.assertFalse(np.isnan(X_empty.data).any(), "NaN values found in feature matrix.")


if __name__ == "__main__":
    unittest.main()
