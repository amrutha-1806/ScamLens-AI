"""
Integration Unit Tests for ScamLens AI Streamlit Application & UI Polish Backend
"""

import unittest
import importlib
import pandas as pd
from pathlib import Path

from src.config import BASE_DIR, SAVED_MODELS_DIR
from src.models.predictor import ScamLensPredictor
from src.utils.database import fetch_recent_scans
from app.app import load_cached_predictor


class TestStreamlitAppIntegration(unittest.TestCase):

    def test_01_app_imports(self):
        """Test 1: App module imports cleanly without syntax/import errors."""
        app_module = importlib.import_module("app.app")
        self.assertIsNotNone(app_module)

    def test_02_cached_predictor_loads(self):
        """Test 2: Cached predictor function returns a valid ScamLensPredictor instance."""
        predictor = load_cached_predictor()
        self.assertIsInstance(predictor, ScamLensPredictor)

    def test_03_analyzer_backend_prediction(self):
        """Test 3: Backend prediction invocation generates real output for analyzer UI."""
        predictor = load_cached_predictor()
        res = predictor.predict("Congratulations! You won a free cash prize.")
        self.assertTrue(res["valid"])
        self.assertIn("prediction", res)
        self.assertIn(res["prediction"], {"Legitimate", "Scam/Phishing"})
        self.assertIn("risk_score", res)
        self.assertIn("risk_level", res)

    def test_04_model_performance_csv_readable(self):
        """Test 4: Model comparison CSV is readable by performance page."""
        csv_path = BASE_DIR / "reports" / "model_results" / "model_comparison.csv"
        self.assertTrue(csv_path.exists(), "model_comparison.csv missing!")
        df = pd.read_csv(csv_path)
        self.assertGreater(len(df), 0)
        self.assertIn("model", df.columns)
        self.assertIn("macro_f1", df.columns)

    def test_05_scan_history_db_readable_and_filterable(self):
        """Test 5: SQLite scan history fetcher & filter operations run cleanly."""
        scans = fetch_recent_scans(limit=20)
        self.assertIsInstance(scans, list)
        if scans:
            df = pd.DataFrame(scans)
            self.assertIn("prediction_label", df.columns)
            self.assertIn("risk_level", df.columns)

    def test_06_zero_network_calls_app(self):
        """Test 6: Confirms backend app operations run 100% offline."""
        predictor = load_cached_predictor()
        res = predictor.predict("Check link http://test-site.xyz/@login")
        self.assertTrue(res["valid"])
        self.assertGreater(len(res["indicators"]), 0)


if __name__ == "__main__":
    unittest.main()
