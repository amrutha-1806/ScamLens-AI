"""
Centralized Configuration Loader for SCAMLENS AI
Exposes paths, hyperparams, feature configs, keyword lists, URL settings, model settings, and risk thresholds.
"""

import os
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Base Directory Path
BASE_DIR = Path(__file__).resolve().parent.parent

# Path to config.yaml
CONFIG_PATH = BASE_DIR / "config.yaml"


def load_config():
    """Load configuration from config.yaml or return defaults."""
    if HAS_YAML and CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception:
            pass
    return {
        "project": {
            "name": "SCAMLENS AI",
            "version": "1.0.0"
        },
        "paths": {
            "raw_data_dir": "data/raw",
            "processed_data_dir": "data/processed",
            "saved_models_dir": "saved_models",
            "logs_dir": "logs",
            "db_path": "scamlens.db"
        },
        "data": {
            "test_size": 0.2,
            "random_state": 42
        },
        "features": {
            "tfidf_word": {
                "ngram_range": [1, 2],
                "min_df": 2,
                "max_df": 0.95,
                "sublinear_tf": True,
                "max_features": 5000
            },
            "tfidf_char": {
                "ngram_range": [3, 5],
                "min_df": 2,
                "sublinear_tf": True,
                "max_features": 5000
            },
            "keywords": {
                "urgency": ["urgent", "immediately", "hurry", "act now", "expires", "limited time", "action required", "alert", "locked"],
                "credential": ["account", "verify", "verification", "password", "login", "suspended", "security"],
                "financial": ["bank", "payment", "money", "cash", "refund", "transaction", "credit", "debit"],
                "reward": ["winner", "won", "prize", "reward", "claim", "free", "gift"],
                "action": ["click", "call", "contact", "reply", "confirm", "verify"]
            },
            "url": {
                "shorteners": ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly"],
                "suspicious_tlds": [".zip", ".xyz", ".top", ".work", ".gq", ".cf", ".ml", ".ga", ".fit", ".icu", ".country"]
            }
        },
        "model_training": {
            "test_size": 0.20,
            "random_state": 42,
            "selection_metric": "macro_f1",
            "class_weight": "balanced"
        },
        "risk": {
            "low_max": 24.99,
            "suspicious_max": 49.99,
            "high_max": 74.99,
            "very_high_min": 75.00
        }
    }


# Exported Configuration Object
CONFIG = load_config()

# Resolved Absolute Paths
RAW_DATA_DIR = BASE_DIR / CONFIG["paths"]["raw_data_dir"]
PROCESSED_DATA_DIR = BASE_DIR / CONFIG["paths"]["processed_data_dir"]
SAVED_MODELS_DIR = BASE_DIR / CONFIG["paths"]["saved_models_dir"]
LOGS_DIR = BASE_DIR / CONFIG["paths"]["logs_dir"]
DB_PATH = BASE_DIR / CONFIG["paths"]["db_path"]

# Feature & Model Exports
TFIDF_WORD_CONFIG = CONFIG.get("features", {}).get("tfidf_word", {})
TFIDF_CHAR_CONFIG = CONFIG.get("features", {}).get("tfidf_char", {})
KEYWORD_LISTS = CONFIG.get("features", {}).get("keywords", {})
URL_CONFIG = CONFIG.get("features", {}).get("url", {})
MODEL_TRAINING_CONFIG = CONFIG.get("model_training", {})
RISK_CONFIG = CONFIG.get("risk", {
    "low_max": 24.99,
    "suspicious_max": 49.99,
    "high_max": 74.99,
    "very_high_min": 75.00
})

# Ensure essential directories exist
RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
