"""
SCAMLENS AI — FastAPI History Service
Thin wrapper around the existing SQLite database utilities.
"""

from __future__ import annotations
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.database import fetch_recent_scans
from src.utils.logger import get_logger

logger = get_logger("HistoryService")


def get_history(limit: int = 100) -> list[dict]:
    """Return real scan records from the existing SQLite database."""
    records = fetch_recent_scans(limit=limit)
    # Normalise: ensure timestamp is always a string
    for r in records:
        if r.get("timestamp") is None:
            r["timestamp"] = ""
    return records
