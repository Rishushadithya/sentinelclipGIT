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
            scope_type TEXT NOT NULL DEFAULT 'global',
            scope_target TEXT,
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
            pc_user_name TEXT,
            domain TEXT,
            rule_name TEXT,
            severity TEXT,
            action_taken TEXT,
            detection_summary TEXT,
            previous_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL
        )
    """)

    _ensure_audit_log_columns(conn)
    _ensure_policy_scope_columns(conn)

    # Device identity and one-time enrollment state for LAN agents.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            os_user TEXT NOT NULL,
            ip_address TEXT,
            group_name TEXT,
            enrolled_at TEXT NOT NULL,
            last_seen TEXT,
            status TEXT NOT NULL DEFAULT 'offline',
            device_token_hash TEXT NOT NULL UNIQUE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS enrollment_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
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

    _migrate_default_policy_patterns(conn)


def _ensure_audit_log_columns(conn: sqlite3.Connection) -> None:
    """Add the pc_user_name column to existing audit_log tables."""
    columns = conn.execute("PRAGMA table_info(audit_log)").fetchall()
    existing = {row[1] for row in columns}

    if "pc_user_name" not in existing:
        conn.execute("ALTER TABLE audit_log ADD COLUMN pc_user_name TEXT")
        conn.commit()


def _ensure_policy_scope_columns(conn: sqlite3.Connection) -> None:
    """Add policy scoping columns to databases created before fleet support."""
    columns = conn.execute("PRAGMA table_info(policies)").fetchall()
    existing = {row[1] for row in columns}

    if "scope_type" not in existing:
        conn.execute(
            "ALTER TABLE policies ADD COLUMN scope_type TEXT NOT NULL DEFAULT 'global'"
        )
    if "scope_target" not in existing:
        conn.execute("ALTER TABLE policies ADD COLUMN scope_target TEXT")
    conn.commit()


def _migrate_default_policy_patterns(conn: sqlite3.Connection) -> None:
    """Migrate specific legacy seed patterns without overwriting custom rules."""
    legacy_password_pattern = r'(?i)(password|passwd|pwd)["\'\s:=]+\S+'
    prior_expanded_password_pattern = (
        r'(?i)(?:\b(?:password|passwd|pwd|pass|pw)\b\s*["\']?\s*(?:[:=])\s*["\']?\S+'
        r'|<\s*(?:password|passwd|pwd|pass|pw)\s*>\s*[^<\r\n]+\s*<\s*/\s*(?:password|passwd|pwd|pass|pw)\s*>)'
    )
    expanded_password_pattern = (
        r'(?i)(?:\b(?:password|passwd|pwd|pass|pw|passcode|passphrase|userpass|loginpass|dbpass|db_password|authpass)\b\s*["\']?\s*(?:[:=])\s*["\']?\S+'
        r'|<\s*(?:password|passwd|pwd|pass|pw|passcode|passphrase|userpass|loginpass|dbpass|db_password|authpass)\s*>\s*[^<\r\n]+\s*<\s*/\s*(?:password|passwd|pwd|pass|pw|passcode|passphrase|userpass|loginpass|dbpass|db_password|authpass)\s*>)'
    )

    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE policies
        SET pattern = ?, updated_at = ?
        WHERE rule_name = ? AND (pattern = ? OR pattern = ?)
        """,
        (
            expanded_password_pattern,
            datetime.now(timezone.utc).isoformat(),
            "Password Assignment",
            legacy_password_pattern,
            prior_expanded_password_pattern,
        ),
    )
    if cursor.rowcount > 0:
        conn.commit()


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
                                  scope_type, scope_target,
                                  created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'global', NULL, ?, ?)
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
