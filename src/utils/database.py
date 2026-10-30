"""
SQLite Database Operations for SCAMLENS AI
Manages database creation, scan log recording, and user feedback history.
"""

import sqlite3
from typing import List, Tuple, Dict, Any, Optional
from src.config import DB_PATH
from src.utils.logger import get_logger

logger = get_logger("Database")


def get_connection() -> sqlite3.Connection:
    """Create and return a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the SQLite database schema if tables do not exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # Table for recording detection history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            input_type TEXT NOT NULL, -- 'text' or 'url'
            content TEXT NOT NULL,
            prediction_label TEXT NOT NULL, -- 'Legitimate' or 'Phishing/Scam'
            scam_probability REAL NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL, -- 'Low Risk', 'Medium Risk', 'High Risk'
            explanation_summary TEXT
        )
    """)

    # Table for user feedback/reporting
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

    conn.commit()
    conn.close()
    logger.info(f"Database initialized successfully at {DB_PATH}")


def log_scan_result(
    input_type: str,
    content: str,
    prediction_label: str,
    scam_probability: float,
    risk_score: float,
    risk_level: str,
    explanation_summary: str = ""
) -> int:
    """Insert a scan result into scan_logs table and return the new scan_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_logs 
        (input_type, content, prediction_label, scam_probability, risk_score, risk_level, explanation_summary)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (input_type, content, prediction_label, scam_probability, risk_score, risk_level, explanation_summary))
    
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    logger.info(f"Scan log saved with ID: {scan_id}")
    return scan_id


def fetch_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetch recent scan logs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
