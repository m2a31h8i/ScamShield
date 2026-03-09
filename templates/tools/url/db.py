"""
database/db.py
SQLite database initialization and helper functions for storing scan results.
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


def get_connection():
    """Return a new SQLite connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create tables if they don't exist.
    Called once at application startup.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            scanned_at  TEXT    NOT NULL,
            risk_level  TEXT    NOT NULL,
            technologies TEXT   NOT NULL,   -- JSON blob
            vulnerabilities TEXT NOT NULL,  -- JSON blob
            recommendations TEXT NOT NULL,  -- JSON blob
            ssl_info    TEXT    NOT NULL,   -- JSON blob
            headers_info TEXT   NOT NULL,   -- JSON blob
            ports_info   TEXT   NOT NULL    -- JSON blob
        )
    """)

    conn.commit()
    conn.close()


def save_scan(url: str, result: dict) -> int:
    """
    Persist a scan result to the database.
    Returns the new row id.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans
            (url, scanned_at, risk_level, technologies, vulnerabilities,
             recommendations, ssl_info, headers_info, ports_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        datetime.utcnow().isoformat(),
        result.get("risk_level", "Unknown"),
        json.dumps(result.get("technologies", {})),
        json.dumps(result.get("vulnerabilities", [])),
        json.dumps(result.get("recommendations", [])),
        json.dumps(result.get("ssl_info", {})),
        json.dumps(result.get("headers_info", {})),
        json.dumps(result.get("ports_info", {})),
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans() -> list:
    """Return a lightweight list of all scans (no heavy JSON blobs)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, scanned_at, risk_level
        FROM scans
        ORDER BY id DESC
    """)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_scan_by_id(scan_id: int) -> dict | None:
    """Return full scan details for the given id, or None if not found."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    data = dict(row)
    # Deserialise JSON blobs
    for field in ("technologies", "vulnerabilities", "recommendations",
                  "ssl_info", "headers_info", "ports_info"):
        data[field] = json.loads(data[field])

    return data


def delete_scan(scan_id: int) -> bool:
    """Delete a scan by id. Returns True if deleted, False if not found."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted