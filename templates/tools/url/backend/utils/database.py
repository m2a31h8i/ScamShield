"""
utils/database.py
=================
SQLite persistence layer for scan history.
All JSON fields are serialised as TEXT columns.
"""

import sqlite3
import json
import logging
import os
from typing import Optional, List

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Thread-safe SQLite wrapper for storing scan results."""

    def __init__(self, db_path: str = "scans.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_db()

    # ── Schema ─────────────────────────────────────────────────────────────────

    def init_db(self):
        """Create tables if they don't already exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    url             TEXT    NOT NULL,
                    scanned_at      TEXT,
                    risk_level      TEXT,
                    risk_score      INTEGER DEFAULT 0,
                    technologies    TEXT,   -- JSON blob
                    security        TEXT,   -- JSON blob
                    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        logger.info(f"Database initialised at {self.db_path}")

    # ── CRUD ───────────────────────────────────────────────────────────────────

    def save_scan(self, result: dict) -> int:
        """Persist a scan result. Returns the new scan ID."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scans (url, scanned_at, risk_level, risk_score, technologies, security)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.get("url"),
                    result.get("scanned_at"),
                    result.get("risk_level"),
                    result.get("risk_score", 0),
                    json.dumps(result.get("technologies", {})),
                    json.dumps(result.get("security", {})),
                )
            )
            conn.commit()
            return cur.lastrowid

    def get_scan(self, scan_id: int) -> Optional[dict]:
        """Retrieve a single scan record by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()

        return self._row_to_dict(row) if row else None

    def get_history(self, limit: int = 50) -> List[dict]:
        """Return the most recent `limit` scans."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()

        return [self._row_to_dict(r) for r in rows]

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan. Returns True if a row was deleted."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cur.rowcount > 0

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        # Deserialise JSON blobs
        for key in ("technologies", "security"):
            if isinstance(d.get(key), str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d