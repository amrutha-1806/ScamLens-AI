"""
SQLite Database Operations for SCAMLENS AI
Manages database creation, scan log recording, user feedback, and Security Alert reviews.
"""

import sqlite3
from typing import List, Tuple, Dict, Any, Optional
from datetime import datetime, timezone
from src.config import DB_PATH
from src.utils.logger import get_logger

logger = get_logger("Database")


_DB_INITIALIZED = False


def _create_tables(conn: sqlite3.Connection) -> None:
    """Create tables and execute non-destructive migrations."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            input_type TEXT NOT NULL, -- 'text', 'url', 'email', 'csv'
            content TEXT NOT NULL,
            prediction_label TEXT NOT NULL, -- 'Legitimate' or 'Scam/Phishing'
            scam_probability REAL NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL, -- 'Low', 'Suspicious', 'High', 'Very High'
            explanation_summary TEXT,
            user_id TEXT DEFAULT NULL,
            review_status TEXT DEFAULT 'unreviewed', -- 'unreviewed', 'reviewed', 'flagged_fp', 'investigating'
            review_notes TEXT DEFAULT NULL,
            reviewed_at DATETIME DEFAULT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            actual_label TEXT NOT NULL,
            user_comment TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scan_logs (id)
        )
    """)

    existing_cols = [r[1] for r in cursor.execute("PRAGMA table_info(scan_logs)").fetchall()]
    migrations = [
        ("user_id", "TEXT DEFAULT NULL"),
        ("review_status", "TEXT DEFAULT 'unreviewed'"),
        ("review_notes", "TEXT DEFAULT NULL"),
        ("reviewed_at", "DATETIME DEFAULT NULL"),
    ]
    for col_name, col_sql in migrations:
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE scan_logs ADD COLUMN {col_name} {col_sql}")
            logger.info(f"Migrated scan_logs table: added column {col_name}")

    conn.commit()


def get_connection() -> sqlite3.Connection:
    """Create and return a database connection, ensuring tables exist."""
    global _DB_INITIALIZED
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if not _DB_INITIALIZED:
        try:
            cursor = conn.cursor()
            table_check = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_logs'").fetchone()
            if table_check is None:
                _create_tables(conn)
            _DB_INITIALIZED = True
        except Exception:
            pass
    return conn


def init_db() -> None:
    """Explicitly initialize the SQLite database schema and run migrations."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _create_tables(conn)
    conn.close()
    logger.info(f"Database initialized successfully at {DB_PATH}")


def log_scan_result(
    input_type: str,
    content: str,
    prediction_label: str,
    scam_probability: float,
    risk_score: float,
    risk_level: str,
    explanation_summary: str = "",
    user_id: Optional[str] = None
) -> int:
    """Insert a scan result into scan_logs table and return the new scan_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_logs 
        (input_type, content, prediction_label, scam_probability, risk_score, risk_level, explanation_summary, user_id, review_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unreviewed')
    """, (input_type, content, prediction_label, scam_probability, risk_score, risk_level, explanation_summary, user_id))
    
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    logger.info(f"Scan log saved with ID: {scan_id}")
    return scan_id


def fetch_recent_scans(limit: int = 50, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch recent scan logs, optionally scoped to a specific authenticated user."""
    conn = get_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("""
            SELECT * FROM scan_logs WHERE user_id = ? OR user_id IS NULL ORDER BY timestamp DESC LIMIT ?
        """, (user_id, limit))
    else:
        cursor.execute("""
            SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_security_alerts(
    limit: int = 50,
    status_filter: Optional[str] = None,
    user_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fetch high-risk detections (risk_level in 'High', 'Very High' or risk_score >= 70)
    for the Security Alert Center, with optional review status filtering.
    """
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        SELECT * FROM scan_logs 
        WHERE (risk_level IN ('High', 'Very High') OR risk_score >= 70.0)
    """
    params: List[Any] = []

    if status_filter and status_filter.lower() != "all":
        query += " AND review_status = ?"
        params.append(status_filter.lower())

    if user_id:
        query += " AND (user_id = ? OR user_id IS NULL)"
        params.append(user_id)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def update_alert_review(
    scan_id: int,
    review_status: str,
    review_notes: Optional[str] = None,
    user_id: Optional[str] = None
) -> bool:
    """
    Update the triage/review status and analyst notes for a specific scan alert.
    """
    valid_statuses = {"unreviewed", "reviewed", "flagged_fp", "investigating"}
    status = review_status.lower().strip()
    if status not in valid_statuses:
        raise ValueError(f"Invalid review status: '{review_status}'. Must be one of {valid_statuses}")

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    cursor = conn.cursor()

    if user_id:
        cursor.execute("""
            UPDATE scan_logs
            SET review_status = ?, review_notes = ?, reviewed_at = ?
            WHERE id = ? AND (user_id = ? OR user_id IS NULL)
        """, (status, review_notes, now_iso, scan_id, user_id))
    else:
        cursor.execute("""
            UPDATE scan_logs
            SET review_status = ?, review_notes = ?, reviewed_at = ?
            WHERE id = ?
        """, (status, review_notes, now_iso, scan_id))

    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0


def fetch_scan_by_id(scan_id: int, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch a single scan record with associated feedback if available."""
    conn = get_connection()
    cursor = conn.cursor()
    if user_id:
        cursor.execute("""
            SELECT * FROM scan_logs WHERE id = ? AND (user_id = ? OR user_id IS NULL)
        """, (scan_id, user_id))
    else:
        cursor.execute("""
            SELECT * FROM scan_logs WHERE id = ?
        """, (scan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    result = dict(row)

    # Attach feedback
    cursor.execute("SELECT * FROM user_feedback WHERE scan_id = ? ORDER BY timestamp DESC", (scan_id,))
    fb_rows = cursor.fetchall()
    result["feedback"] = [dict(fb) for fb in fb_rows]

    conn.close()
    return result


def record_user_feedback(scan_id: int, actual_label: str, user_comment: str = "") -> int:
    """Record user verification feedback for a scan."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO user_feedback (scan_id, actual_label, user_comment)
        VALUES (?, ?, ?)
    """, (scan_id, actual_label, user_comment))
    conn.commit()
    fb_id = cursor.lastrowid
    conn.close()
    return fb_id
