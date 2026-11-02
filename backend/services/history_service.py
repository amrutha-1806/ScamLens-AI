"""
SCAMLENS AI - FastAPI History & Security Alert Service
Wrapper around SQLite database operations for history, alert triage, and feedback.
"""

from __future__ import annotations
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.database import (
    fetch_recent_scans,
    fetch_security_alerts,
    update_alert_review,
    fetch_scan_by_id,
    record_user_feedback,
)
from src.utils.logger import get_logger

logger = get_logger("HistoryService")


def get_history(limit: int = 100, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return real scan records from the SQLite database."""
    records = fetch_recent_scans(limit=limit, user_id=user_id)
    for r in records:
        if r.get("timestamp") is None:
            r["timestamp"] = ""
    return records


def get_alerts(
    limit: int = 50,
    status_filter: Optional[str] = None,
    user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Return high-risk scans for the Security Alert Center."""
    records = fetch_security_alerts(limit=limit, status_filter=status_filter, user_id=user_id)
    for r in records:
        if r.get("timestamp") is None:
            r["timestamp"] = ""
    return records


def update_alert(
    scan_id: int,
    review_status: str,
    review_notes: Optional[str] = None,
    user_id: Optional[str] = None
) -> bool:
    """Update review status and analyst notes for an alert."""
    return update_alert_review(
        scan_id=scan_id,
        review_status=review_status,
        review_notes=review_notes,
        user_id=user_id
    )


def get_scan(scan_id: int, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return a single scan record with associated feedback."""
    return fetch_scan_by_id(scan_id=scan_id, user_id=user_id)


def save_feedback(scan_id: int, actual_label: str, user_comment: str = "") -> int:
    """Save user verification feedback."""
    return record_user_feedback(scan_id=scan_id, actual_label=actual_label, user_comment=user_comment)
