"""
Exploratory Data Analysis (EDA) Pipeline for SCAMLENS AI
Generates dataset visualizations, text statistics, duplicate analysis, and summary reports.
"""

import os
from pathlib import Path
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import re

from src.config import BASE_DIR, PROCESSED_DATA_DIR
from src.preprocessing.dataset_loader import load_and_preprocess_dataset
from src.utils.logger import get_logger

logger = get_logger("EDA")

# Output directory setup
REPORTS_DIR = BASE_DIR / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"
MODEL_RESULTS_DIR = REPORTS_DIR / "model_results"
EVALUATION_DIR = REPORTS_DIR / "evaluation"

for d in [REPORTS_DIR, FIGURES_DIR, MODEL_RESULTS_DIR, EVALUATION_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def plot_class_distribution(df: pd.DataFrame) -> Path:
    """Generate and save class distribution bar chart."""
    plt.figure(figsize=(7, 5))
    counts = df["label_name"].value_counts()
    colors = ["#2ecc71", "#e74c3c"]
    
    ax = sns.barplot(x=counts.index, y=counts.values, palette=colors, hue=counts.index, legend=False)
    plt.title("SCAMLENS AI — Class Distribution (UCI SMS Dataset)", fontsize=13, fontweight="bold")
    plt.xlabel("Class", fontsize=11)
    plt.ylabel("Message Count", fontsize=11)

    # Annotate bar values & percentages
    total = len(df)
    for p in ax.patches:
        height = p.get_height()
        pct = (height / total) * 100
        ax.annotate(f"{int(height)}\n({pct:.1f}%)",
                    (p.get_x() + p.get_width() / 2., height / 2),
                    ha="center", va="center", fontsize=11, color="white", fontweight="bold")

    plt.tight_layout()
    out_path = FIGURES_DIR / "class_distribution.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    logger.info(f"Saved class distribution chart to {out_path}")
    return out_path


def plot_message_length_distribution(df: pd.DataFrame) -> Path:
    """Generate and save character length distribution chart."""
    plt.figure(figsize=(9, 5))
    
    sns.histplot(
        data=df,
        x="char_length",
        hue="label_name",
        bins=50,
        kde=True,
        element="step",
        palette={"Legitimate": "#2ecc71", "Scam/Phishing": "#e74c3c"}
    )
    plt.title("Message Character Length Distribution by Class", fontsize=13, fontweight="bold")
    plt.xlabel("Character Length", fontsize=11)
    plt.ylabel("Frequency", fontsize=11)
    plt.xlim(0, 500)
    plt.tight_layout()

    out_path = FIGURES_DIR / "message_length_distribution.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    logger.info(f"Saved message length chart to {out_path}")
    return out_path


def plot_word_count_distribution(df: pd.DataFrame) -> Path:
    """Generate and save word count distribution chart."""
    plt.figure(figsize=(9, 5))
    
    sns.histplot(
        data=df,
        x="word_count",
        hue="label_name",
        bins=40,
        kde=True,
        element="step",
        palette={"Legitimate": "#2ecc71", "Scam/Phishing": "#e74c3c"}
    )
    plt.title("Word Count Distribution by Class", fontsize=13, fontweight="bold")
    plt.xlabel("Word Count", fontsize=11)
    plt.ylabel("Frequency", fontsize=11)
    plt.xlim(0, 100)
    plt.tight_layout()

    out_path = FIGURES_DIR / "word_count_distribution.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    logger.info(f"Saved word count distribution chart to {out_path}")
    return out_path


def get_top_keywords(series: pd.Series, top_n: int = 15):
    """Extract most frequent words from a pandas Series of text."""
    stop_words = {"i", "me", "my", "myself", "we", "our", "ours", "you", "your", "yours", "he", "him", "his",
                  "she", "her", "it", "its", "they", "them", "their", "what", "which", "who", "whom", "this",
                  "that", "these", "those", "am", "is", "are", "was", "were", "be", "been", "being", "have",
                  "has", "had", "do", "does", "did", "doing", "a", "an", "the", "and", "but", "if", "or",
                  "because", "as", "until", "while", "of", "at", "by", "for", "with", "about", "against",
                  "between", "into", "through", "during", "before", "after", "above", "below", "to", "from",
                  "up", "down", "in", "out", "on", "off", "over", "under", "again", "further", "then", "once",
                  "to", "u", "ur", "2", "4", "n", "call", "get", "go", "got"}
    
    words = []
    for text in series.dropna():
        tokens = re.findall(r"\b[a-z]{2,}\b", str(text).lower())
        words.extend([t for t in tokens if t not in stop_words])
    
    return Counter(words).most_common(top_n)


def run_eda() -> Dict[str, Any]:
    """Execute full EDA pipeline and output eda_summary.txt."""
    processed_csv = PROCESSED_DATA_DIR / "sms_processed.csv"
    if not processed_csv.exists():
        df = load_and_preprocess_dataset()
    else:
        df = pd.read_csv(processed_csv)

    total_rows = len(df)
    total_cols = len(df.columns)

    counts = df["label_name"].value_counts()
    legit_cnt = int(counts.get("Legitimate", 0))
    scam_cnt = int(counts.get("Scam/Phishing", 0))

    legit_pct = (legit_cnt / total_rows) * 100
    scam_pct = (scam_cnt / total_rows) * 100

    missing_vals = int(df.isnull().sum().sum())
    dup_cnt = int(df.duplicated(subset=["message"]).sum())
    dup_pct = (dup_cnt / total_rows) * 100

    # Message Length Stats
    len_mean = float(df["char_length"].mean())
    len_median = float(df["char_length"].median())
    len_min = int(df["char_length"].min())
    len_max = int(df["char_length"].max())

    # Word Count Stats
    word_mean = float(df["word_count"].mean())
    word_median = float(df["word_count"].median())
    word_min = int(df["word_count"].min())
    word_max = int(df["word_count"].max())

    # Class-specific length stats
    legit_df = df[df["label"] == 0]
    scam_df = df[df["label"] == 1]

    legit_len_mean = float(legit_df["char_length"].mean())
    scam_len_mean = float(scam_df["char_length"].mean())

    legit_words_mean = float(legit_df["word_count"].mean())
    scam_words_mean = float(scam_df["word_count"].mean())

    # Generate Figures
    plot_class_distribution(df)
    plot_message_length_distribution(df)
    plot_word_count_distribution(df)

    # Keywords Analysis
    top_legit_words = get_top_keywords(legit_df["clean_message"], 10)
    top_scam_words = get_top_keywords(scam_df["clean_message"], 10)

    # Build Summary Text Report
    summary_text = f"""SCAMLENS AI — EDA SUMMARY
=========================

Dataset: UCI SMS Spam Collection
Total Rows: {total_rows}
Total Columns: {total_cols}

Class Distribution:
-------------------
Legitimate (ham):    {legit_cnt} ({legit_pct:.2f}%)
Scam/Phishing (spam): {scam_cnt} ({scam_pct:.2f}%)

Data Quality & Cleanliness:
---------------------------
Missing Values: {missing_vals}
Duplicate Messages: {dup_cnt} ({dup_pct:.2f}%)

Overall Message Length (Characters):
-----------------------------------
Mean:    {len_mean:.2f}
Median:  {len_median:.2f}
Minimum: {len_min}
Maximum: {len_max}

Overall Word Count:
-------------------
Mean:    {word_mean:.2f}
Median:  {word_median:.2f}
Minimum: {word_min}
Maximum: {word_max}

Class Comparison Statistics:
----------------------------
Legitimate Avg Char Length:  {legit_len_mean:.2f}
Scam/Phishing Avg Char Length: {scam_len_mean:.2f}
Legitimate Avg Word Count:    {legit_words_mean:.2f}
Scam/Phishing Avg Word Count:  {scam_words_mean:.2f}

Frequent Keywords (Legitimate):
{', '.join([w for w, _ in top_legit_words])}

Frequent Keywords (Scam/Phishing):
{', '.join([w for w, _ in top_scam_words])}
"""

    summary_file = REPORTS_DIR / "eda_summary.txt"
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(summary_text)

    logger.info(f"EDA Summary written to {summary_file}")
    print(summary_text)

    return {
        "total_rows": total_rows,
        "legit_cnt": legit_cnt,
        "scam_cnt": scam_cnt,
        "len_mean": len_mean,
        "word_mean": word_mean,
        "dup_cnt": dup_cnt
    }


if __name__ == "__main__":
    run_eda()
