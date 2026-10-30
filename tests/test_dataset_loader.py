"""
Unit Tests for Dataset Loader Module
"""

import unittest
import os
import pandas as pd
from pathlib import Path

from src.config import RAW_DATA_DIR, PROCESSED_DATA_DIR
from src.preprocessing.dataset_loader import load_and_preprocess_dataset, download_raw_dataset


class TestDatasetLoader(unittest.TestCase):

    def test_01_download_raw_dataset(self):
        """Test raw dataset file exists or can be downloaded."""
        raw_file = download_raw_dataset()
        self.assertTrue(raw_file.exists(), "Raw dataset file SMSSpamCollection does not exist.")
        self.assertGreater(raw_file.stat().st_size, 0, "Raw dataset file is empty.")

    def test_02_load_and_preprocess(self):
        """Test dataset loading, label mapping, and processed file output."""
        df = load_and_preprocess_dataset()
        
        # Check DataFrame shape
        self.assertEqual(len(df), 5574, f"Expected 5574 rows, got {len(df)}")
        
        # Check required columns
        expected_cols = ["message", "label", "label_name", "clean_message", "char_length", "word_count"]
        for col in expected_cols:
            self.assertIn(col, df.columns, f"Missing required column '{col}' in processed DataFrame.")

        # Check label mapping values
        unique_labels = set(df["label"].unique())
        self.assertEqual(unique_labels, {0, 1}, f"Labels should be {{0, 1}}, found {unique_labels}")

        unique_label_names = set(df["label_name"].unique())
        self.assertEqual(unique_label_names, {"Legitimate", "Scam/Phishing"}, f"Label names mismatch: {unique_label_names}")

        # Check null values
        self.assertEqual(df["label"].isnull().sum(), 0, "Found null values in label column.")
        self.assertEqual(df["clean_message"].isnull().sum(), 0, "Found null values in clean_message column.")

    def test_03_processed_file_creation(self):
        """Test processed CSV file creation in data/processed."""
        processed_csv = PROCESSED_DATA_DIR / "sms_processed.csv"
        self.assertTrue(processed_csv.exists(), "Processed CSV file sms_processed.csv was not created.")
        self.assertGreater(processed_csv.stat().st_size, 0, "Processed CSV file is empty.")


if __name__ == "__main__":
    unittest.main()
