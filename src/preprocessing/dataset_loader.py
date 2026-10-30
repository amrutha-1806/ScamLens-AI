"""
Dataset Ingestion, Download, Validation, and Preprocessing Loader for SCAMLENS AI.
Primary Dataset: UCI SMS Spam Collection
"""

import os
import urllib.request
import zipfile
import io
import pandas as pd
from pathlib import Path
from typing import Tuple, Dict, Any

from src.config import RAW_DATA_DIR, PROCESSED_DATA_DIR
from src.preprocessing.cleaner import clean_text
from src.utils.logger import get_logger

logger = get_logger("DatasetLoader")

UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
RAW_FILE_PATH = RAW_DATA_DIR / "SMSSpamCollection"
PROCESSED_FILE_PATH = PROCESSED_DATA_DIR / "sms_processed.csv"


def download_raw_dataset() -> Path:
    """Download and extract UCI SMS Spam Collection if missing."""
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    if RAW_FILE_PATH.exists():
        logger.info(f"Raw dataset already exists at {RAW_FILE_PATH}")
        return RAW_FILE_PATH

    logger.info(f"Downloading UCI SMS Spam Collection from {UCI_ZIP_URL}...")
    try:
        req = urllib.request.Request(UCI_ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as resp:
            zip_bytes = resp.read()
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                z.extractall(RAW_DATA_DIR)
        logger.info(f"Successfully extracted dataset to {RAW_DATA_DIR}")
    except Exception as e:
        logger.error(f"Failed to download dataset automatically: {e}")
        raise RuntimeError(
            f"Dataset download failed. Please manually place the file 'SMSSpamCollection' in '{RAW_DATA_DIR}'."
        ) from e

    return RAW_FILE_PATH


def validate_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
    """Perform dataset validation and print summary metrics."""
    total_rows = len(df)
    total_cols = len(df.columns)
    missing_vals = int(df.isnull().sum().sum())
    dup_rows = int(df.duplicated(subset=["message"]).sum())
    empty_msgs = int((df["message"].astype(str).str.strip() == "").sum())
    
    label_col = "label" if "label" in df.columns else "raw_label"
    label_counts = df[label_col].value_counts().to_dict()
    legit_count = label_counts.get(0, label_counts.get("ham", 0))
    scam_count = label_counts.get(1, label_counts.get("spam", 0))

    val_summary = {
        "total_rows": total_rows,
        "total_cols": total_cols,
        "missing_values": missing_vals,
        "duplicate_messages": dup_rows,
        "empty_messages": empty_msgs,
        "legitimate_count": int(legit_count),
        "scam_count": int(scam_count),
        "data_types": df.dtypes.astype(str).to_dict()
    }

    print("\nDataset Validation")
    print("------------------")
    print(f"Rows:               {total_rows}")
    print(f"Columns:            {total_cols}")
    print(f"Missing values:     {missing_vals}")
    print(f"Duplicate rows:     {dup_rows}")
    print(f"Empty messages:     {empty_msgs}")
    print(f"Legitimate (ham):   {legit_count}")
    print(f"Scam/Phishing (spam): {scam_count}")
    print("------------------\n")

    logger.info("Dataset validation completed successfully.")
    return val_summary


def load_and_preprocess_dataset(force_reload: bool = False) -> pd.DataFrame:
    """
    Main loader function. Downloads, validates, cleans, and exports the dataset.
    Returns the processed Pandas DataFrame.
    """
    raw_path = download_raw_dataset()

    if not raw_path.exists():
        raise FileNotFoundError(f"Raw dataset file not found at {raw_path}")

    # Load raw tab-separated file
    logger.info(f"Loading raw dataset from {raw_path}")
    df = pd.read_csv(raw_path, sep="\t", names=["raw_label", "message"], encoding="utf-8", quoting=3)

    # Validate raw data structure
    if len(df) == 0:
        raise ValueError("Loaded raw dataset is empty!")

    # Perform initial raw data validation
    validate_dataframe(df)

    # Map ham -> 0, spam -> 1
    df["label"] = df["raw_label"].map({"ham": 0, "spam": 1})
    if df["label"].isnull().any():
        raise ValueError("Invalid labels detected in dataset!")

    df["label_name"] = df["label"].map({0: "Legitimate", 1: "Scam/Phishing"})

    # Apply text cleaner
    logger.info("Applying text cleaning and normalization...")
    df["clean_message"] = df["message"].apply(clean_text)

    # Calculate basic length metrics
    df["char_length"] = df["message"].astype(str).apply(len)
    df["word_count"] = df["message"].astype(str).apply(lambda x: len(x.split()))

    # Ensure output directory exists
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Save to processed CSV
    cols_to_save = ["message", "label", "label_name", "clean_message", "char_length", "word_count"]
    df[cols_to_save].to_csv(PROCESSED_FILE_PATH, index=False, encoding="utf-8")
    logger.info(f"Saved processed dataset to {PROCESSED_FILE_PATH}")

    return df


if __name__ == "__main__":
    load_and_preprocess_dataset()
