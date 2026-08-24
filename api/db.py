"""
SentinelClip — SQLite Database Layer

Handles database initialization, schema creation, WAL mode activation,
and seed data loading. Provides thread-safe connection management.

IMPORTANT: This module is the ONLY code that touches SQLite directly.
All other components go through the Flask API.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sentinelclip.db")
_connection = None


def get_db(db_path: str = None) -> sqlite3.Connection:
    """
    Get a SQLite connection with WAL mode and row factory enabled.
    
    Args:
        db_path: Optional override for the database path (used in testing).
    """
    path = db_path or DB_PATH
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """
    Create tables if they don't exist and seed default policy rules.
    """
    cursor = conn.cursor()

    # Create policies table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            pattern TEXT NOT NULL,
            pattern_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            action TEXT NOT NULL,
            replacement_value TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # Create audit_log table (hash-chained)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            domain TEXT,
            rule_name TEXT,
            severity TEXT,
            action_taken TEXT,
            detection_summary TEXT,
            previous_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL
        )
    """)

    # Create allowed/blocked domains table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS allowed_blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            list_type TEXT NOT NULL
        )
    """)

    conn.commit()

    # Seed default policies if table is empty
    count = cursor.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
    if count == 0:
        _seed_default_policies(conn)


def _seed_default_policies(conn: sqlite3.Connection) -> None:
    """Load default policy rules from config/default_policy.json."""
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "config", "default_policy.json"
    )

    if not os.path.exists(config_path):
        print(f"[WARNING] Default policy file not found at {config_path}")
        return

    with open(config_path, "r") as f:
        rules = json.load(f)

    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.cursor()

    for rule in rules:
        cursor.execute(
            """
            INSERT INTO policies (rule_name, pattern, pattern_type, severity,
                                  action, replacement_value, enabled,
                                  created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule["rule_name"],
                rule["pattern"],
                rule["pattern_type"],
                rule["severity"],
                rule["action"],
                rule.get("replacement_value"),
                1 if rule.get("enabled", True) else 0,
                now,
                now,
            ),
        )

    conn.commit()
    print(f"[INFO] Seeded {len(rules)} default policy rules.")
