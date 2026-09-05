"""
db.py
------
Handles the MySQL connection and scan history saving/fetching.

Important: A local MySQL server must be running (XAMPP / WAMP / native
MySQL install) - run database/db_setup.sql first to create the schema.
If MySQL can't be reached, the app doesn't crash - it automatically
falls back to in-memory storage (convenient for a demo, but history is
lost on restart - so set up MySQL properly for your actual submission).
"""

import mysql.connector
from mysql.connector import Error
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",          # <-- put your MySQL root password here
    "database": "phishing_qr_db",
}

# Fallback in-memory list used when MySQL isn't reachable
_fallback_history = []


def get_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error:
        return None


def init_db_if_needed():
    """When the app starts, check whether the table exists and create it
    if not (a safety net in case db_setup.sql wasn't run manually)."""
    conn = get_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                scan_type VARCHAR(20) NOT NULL,
                input_value TEXT NOT NULL,
                verdict VARCHAR(20) NOT NULL,
                risk_score FLOAT NOT NULL,
                scanned_at DATETIME NOT NULL
            )
            """
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error:
        return False


def save_scan(scan_type: str, input_value: str, verdict: str, risk_score: float):
    """Saves a scan result to the DB. If the DB is unavailable, it falls
    back to in-memory storage (app doesn't crash)."""
    conn = get_connection()
    record = {
        "scan_type": scan_type,
        "input_value": input_value,
        "verdict": verdict,
        "risk_score": risk_score,
        "scanned_at": datetime.now(),
    }
    if conn is None:
        _fallback_history.insert(0, record)
        return

    try:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO scan_history (scan_type, input_value, verdict, risk_score, scanned_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (scan_type, input_value, verdict, risk_score, record["scanned_at"]),
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Error:
        _fallback_history.insert(0, record)


def get_history(limit: int = 50):
    """Fetches recent scan history (DB first, fallback if unavailable)."""
    conn = get_connection()
    if conn is None:
        return _fallback_history[:limit]

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT %s", (limit,)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows if rows else _fallback_history[:limit]
    except Error:
        return _fallback_history[:limit]
