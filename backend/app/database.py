"""
database.py
------------
Sets up the SQLite "threat graph" database.

Two tables:
  1. entities        - every phone number / UPI ID / domain we've ever seen,
                        with a running count of how many times it's been
                        reported and the last time it was seen.
  2. submissions      - a log of every message analyzed (for the demo's
                        "recent activity" feed and for debugging).

SQLite is intentionally chosen over Postgres here: zero setup, single file,
perfect for a 48-hour hackathon build. Swapping to Postgres later only
touches this file.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "raksha.db"


def init_db():
    """Create tables if they don't already exist. Safe to call every startup."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,      -- 'phone', 'upi_id', 'domain', 'bank_name'
                entity_value TEXT NOT NULL,
                report_count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(entity_type, entity_value)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_text TEXT NOT NULL,
                source TEXT NOT NULL,           -- 'text', 'url', 'screenshot', 'qr', 'forward'
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,          -- 'safe', 'suspicious', 'dangerous'
                triggered_rules TEXT,           -- JSON-encoded list of rule names that fired
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.commit()


@contextmanager
def get_connection():
    """Context-managed SQLite connection so callers don't leak connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
