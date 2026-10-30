"""
Model Evaluation and Metrics Module for SCAMLENS AI
Computes Accuracy, Precision, Recall, F1, Macro F1, ROC-AUC, Confusion Matrix plots, and comparison reports.
"""

import os
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

from src.config import BASE_DIR
from src.utils.logger import get_logger

logger = get_logger("Evaluator")

# Directory setup for evaluation outputs
REPORTS_DIR = BASE_DIR / "reports"
EVALUATION_DIR = REPORTS_DIR / "evaluation"
MODEL_RESULTS_DIR = REPORTS_DIR / "model_results"

for d in [REPORTS_DIR, EVALUATION_DIR, MODEL_RESULTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: Optional[np.ndarray] = None) -> Dict[str, Any]:
    """
    Calculate comprehensive evaluation metrics for binary scam detection.
    Positive class: 1 = Scam/Phishing
    """
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    rec = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    roc_auc = "N/A"
    if y_prob is not None:
        try:
            # Handle 2D probability array or 1D decision function values
            scores = y_prob[:, 1] if y_prob.ndim == 2 else y_prob
            roc_auc = float(roc_auc_score(y_true, scores))
        except Exception as e:
            logger.warning(f"Could not compute ROC-AUC: {e}")
            roc_auc = "N/A"

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "macro_f1": macro_f1,
        "roc_auc": roc_auc,
        "confusion_matrix": cm
    }


def plot_and_save_confusion_matrix(cm: np.ndarray, model_name: str, save_path: Path) -> Path:
    """Plot and save confusion matrix heatmap."""
    plt.figure(figsize=(6, 5))
    labels = ["Legitimate", "Scam/Phishing"]
    
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels,
        cbar=False,
        annot_kws={"size": 14, "weight": "bold"}
    )
    plt.title(f"Confusion Matrix — {model_name}", fontsize=12, fontweight="bold")
    plt.xlabel("Predicted Label", fontsize=11)
    plt.ylabel("Actual Label", fontsize=11)
    plt.tight_layout()

    plt.savefig(save_path, dpi=300)
    plt.close()
    logger.info(f"Saved confusion matrix for {model_name} to {save_path}")
    return save_path


def export_model_comparison_report(
    eval_results: Dict[str, Dict[str, Any]],
    csv_path: Path = MODEL_RESULTS_DIR / "model_comparison.csv",
    txt_path: Path = MODEL_RESULTS_DIR / "model_comparison.txt",
    selection_metric: str = "macro_f1"
) -> Tuple[str, pd.DataFrame]:
    """
    Format evaluation results, export CSV & TXT reports, and identify the best model by selection metric.
    """
    rows = []
    for model_name, metrics in eval_results.items():
        roc_val = metrics["roc_auc"]
        roc_str = f"{roc_val:.4f}" if isinstance(roc_val, float) else str(roc_val)

        rows.append({
            "model": model_name,
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "macro_f1": metrics["macro_f1"],
            "roc_auc": roc_str,
            "training_time_seconds": metrics.get("training_time_seconds", 0.0)
        })

    df_results = pd.DataFrame(rows)
    
    # Sort models deterministically: Primary metric (macro_f1), Secondary metric (roc_auc float), Tertiary (f1_score)
    df_results["roc_auc_num"] = pd.to_numeric(df_results["roc_auc"], errors="coerce").fillna(-1.0)
    df_results = df_results.sort_values(
        by=[selection_metric, "roc_auc_num", "f1_score"],
        ascending=[False, False, False]
    ).reset_index(drop=True)
    df_results = df_results.drop(columns=["roc_auc_num"])
    df_results.to_csv(csv_path, index=False)
    logger.info(f"Saved model comparison CSV to {csv_path}")

    selected_model_name = str(df_results.iloc[0]["model"])
    selected_score = float(df_results.iloc[0][selection_metric])

    # Build readable comparison table text report
    table_lines = [
        "SCAMLENS AI — MODEL COMPARISON REPORT",
        "========================================",
        f"Primary Selection Metric: {selection_metric.upper()}",
        f"Selected Best Model: {selected_model_name} ({selection_metric.upper()} = {selected_score:.4f})",
        "",
        f"{'Model Name':<24} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'Macro F1':<10} {'ROC-AUC':<10} {'Time(s)':<8}",
        "-" * 92
    ]

    for _, r in df_results.iterrows():
        table_lines.append(
            f"{r['model']:<24} {r['accuracy']:<10.4f} {r['precision']:<10.4f} {r['recall']:<10.4f} {r['f1_score']:<10.4f} {r['macro_f1']:<10.4f} {str(r['roc_auc']):<10} {r['training_time_seconds']:<8.3f}"
        )

    table_lines.extend([
        "-" * 92,
        "",
        "Evaluation Note: All metrics evaluated on held-out 20% test dataset.",
        "Data Leakage Safeguard: Feature extractor fit strictly on training set."
    ])

    report_txt = "\n".join(table_lines)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(report_txt)

    logger.info(f"Saved model comparison text report to {txt_path}")
    print("\n" + report_txt + "\n")

    return selected_model_name, df_results
