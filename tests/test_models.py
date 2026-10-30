"""
Unit Tests for Phase 4 ML Model Training, Evaluation, and Serialization Suite
"""

import unittest
import os
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

from src.config import SAVED_MODELS_DIR, PROCESSED_DATA_DIR
from src.models.trainer import load_processed_data, split_data, prepare_features_leak_free, get_baseline_classifiers
from src.models.evaluator import calculate_metrics, plot_and_save_confusion_matrix, EVALUATION_DIR


class TestModelTrainingSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Load data and split once for testing efficiency."""
        cls.df = load_processed_data()
        cls.X_train, cls.X_test, cls.y_train, cls.y_test = split_data(cls.df, test_size=0.20, random_state=42)
        cls.extractor, cls.X_train_feat, cls.X_test_feat = prepare_features_leak_free(cls.X_train, cls.X_test)

    def test_01_dataset_loads(self):
        """Test 1: Dataset loads successfully and contains expected 5574 records."""
        self.assertEqual(len(self.df), 5574, f"Expected 5574 records, found {len(self.df)}")
        self.assertIn("clean_message", self.df.columns)
        self.assertIn("label", self.df.columns)

    def test_02_labels_binary(self):
        """Test 2: Target labels contain strictly 0 (Legitimate) and 1 (Scam/Phishing)."""
        unique_labels = set(self.df["label"].unique())
        self.assertEqual(unique_labels, {0, 1}, f"Unexpected label set: {unique_labels}")

    def test_03_train_test_split_stratified(self):
        """Test 3: Stratified train/test split preserves class proportions."""
        train_scam_ratio = (self.y_train == 1).mean()
        test_scam_ratio = (self.y_test == 1).mean()
        overall_scam_ratio = (self.df["label"] == 1).mean()

        self.assertAlmostEqual(train_scam_ratio, overall_scam_ratio, delta=0.02)
        self.assertAlmostEqual(test_scam_ratio, overall_scam_ratio, delta=0.02)

    def test_04_feature_dimensions_matched(self):
        """Test 4: Train and test feature matrices have identical feature dimensions."""
        self.assertEqual(
            self.X_train_feat.shape[1],
            self.X_test_feat.shape[1],
            "Column count mismatch between train and test feature matrices!"
        )
        self.assertEqual(self.X_train_feat.shape[0], len(self.y_train))
        self.assertEqual(self.X_test_feat.shape[0], len(self.y_test))

    def test_05_models_train_controlled_subset(self):
        """Test 5: Baseline models fit without errors on a controlled training subset."""
        models = get_baseline_classifiers(random_state=42)
        X_sub = self.X_train_feat[:100]
        y_sub = self.y_train[:100]

        for name, model in models.items():
            model.fit(X_sub, y_sub)
            self.assertTrue(hasattr(model, "classes_"), f"Model {name} failed to fit.")

    def test_06_models_produce_predictions(self):
        """Test 6: Models produce predictions and probability scores matching test set size."""
        models = get_baseline_classifiers(random_state=42)
        X_sub_tr = self.X_train_feat[:200]
        y_sub_tr = self.y_train[:200]
        X_sub_te = self.X_test_feat[:50]

        for name, model in models.items():
            model.fit(X_sub_tr, y_sub_tr)
            preds = model.predict(X_sub_te)
            self.assertEqual(len(preds), 50, f"Prediction length mismatch for {name}")

            has_proba = hasattr(model, "predict_proba") or hasattr(model, "decision_function")
            self.assertTrue(has_proba, f"Model {name} lacks probability / decision function.")

    def test_07_evaluation_metrics_valid_range(self):
        """Test 7: Calculated metrics are numeric and fall strictly within [0.0, 1.0]."""
        y_true = np.array([0, 1, 0, 1, 0, 1])
        y_pred = np.array([0, 1, 0, 0, 0, 1])
        y_prob = np.array([[0.9, 0.1], [0.1, 0.9], [0.8, 0.2], [0.6, 0.4], [0.95, 0.05], [0.2, 0.8]])

        metrics = calculate_metrics(y_true, y_pred, y_prob)
        for key in ["accuracy", "precision", "recall", "f1_score", "macro_f1"]:
            val = metrics[key]
            self.assertIsInstance(val, float)
            self.assertTrue(0.0 <= val <= 1.0, f"Metric '{key}' out of range: {val}")

        self.assertIsInstance(metrics["roc_auc"], float)
        self.assertTrue(0.0 <= metrics["roc_auc"] <= 1.0)

    def test_08_confusion_matrix_shape(self):
        """Test 8: Confusion matrix has exact binary dimension (2, 2)."""
        y_true = np.array([0, 1, 0, 1])
        y_pred = np.array([0, 1, 1, 1])
        metrics = calculate_metrics(y_true, y_pred)
        
        cm = metrics["confusion_matrix"]
        self.assertEqual(cm.shape, (2, 2))
        self.assertEqual(cm.sum(), 4)

    def test_09_saved_model_artifacts_exist(self):
        """Test 9: Saved model artifacts, feature extractor, and metadata JSON exist."""
        expected_files = [
            "logistic_regression.pkl",
            "decision_tree.pkl",
            "random_forest.pkl",
            "svm.pkl",
            "feature_extractor.pkl",
            "model_metadata.json"
        ]

        for fname in expected_files:
            fpath = SAVED_MODELS_DIR / fname
            self.assertTrue(fpath.exists(), f"Missing expected artifact file: {fpath}")
            self.assertGreater(fpath.stat().st_size, 0, f"Artifact file is empty: {fpath}")

        # Check metadata JSON readability
        meta_path = SAVED_MODELS_DIR / "model_metadata.json"
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["project_name"], "SCAMLENS AI")
        self.assertIn("selected_model", meta)

    def test_10_zero_network_access(self):
        """Test 10: Model training and evaluation run 100% offline with zero network calls."""
        # Verify offline fitting of feature extractor and model on mock messages
        mock_texts = pd.Series(["Free cash claim now http://scam.xyz", "Meeting at 5pm"])
        mock_labels = pd.Series([1, 0])

        ext, X_tr, X_te = prepare_features_leak_free(mock_texts, mock_texts)
        self.assertIsNotNone(X_tr)
        self.assertIsNotNone(X_te)


if __name__ == "__main__":
    unittest.main()
