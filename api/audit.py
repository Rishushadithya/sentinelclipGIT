"""
SentinelClip — Hash-Chained Audit Log

Implements SHA-256 hash chaining for tamper-evident audit logging.
Each event's hash includes the previous event's hash, creating an
immutable chain that can be verified to detect any modifications.

The GENESIS hash is used as the initial previous_hash for the first entry.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone


GENESIS_HASH = "GENESIS"


def compute_hash(event_data: dict, previous_hash: str) -> str:
    """
    Compute SHA-256 hash of event data concatenated with previous hash.
    
    Args:
        event_data: Dictionary of event fields (deterministically serialized).
        previous_hash: Hash of the previous audit log entry.
        
    Returns:
        Hex-encoded SHA-256 hash string.
    """
    serialized = json.dumps(event_data, sort_keys=True)
    return hashlib.sha256((serialized + previous_hash).encode("utf-8")).hexdigest()


def get_latest_audit_hash(conn: sqlite3.Connection) -> str:
    """
    Get the current_hash of the most recent audit log entry.
    Returns GENESIS_HASH if the log is empty.
    """
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()

    if row is None:
        return GENESIS_HASH
    return row["current_hash"]


def record_audit_event(
    conn: sqlite3.Connection,
    timestamp: str,
    source: str,
    domain: str | None,
    pc_user_name: str | None,
    rule_name: str | None,
    severity: str | None,
    action_taken: str | None,
    detection_summary: str,
) -> tuple[int, str]:
    """
    Record a new audit event with hash chaining.
    
    Args:
        conn: SQLite connection.
        timestamp: ISO 8601 timestamp.
        source: Event source ('clipboard' | 'browser_upload').
        domain: Target AI domain (if applicable).
        rule_name: Name of the matched rule.
        severity: Severity level.
        action_taken: Action that was applied.
        detection_summary: JSON string with detection metadata (no raw values).
        
    Returns:
        Tuple of (event_id, current_hash).
    """
    # Build the event data dict for hashing
    event_data = {
        "timestamp": timestamp,
        "source": source,
        "pc_user_name": pc_user_name,
        "domain": domain,
        "rule_name": rule_name,
        "severity": severity,
        "action_taken": action_taken,
        "detection_summary": detection_summary,
    }

    previous_hash = get_latest_audit_hash(conn)
    current_hash = compute_hash(event_data, previous_hash)

    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO audit_log (timestamp, source, pc_user_name, domain, rule_name, severity,
                               action_taken, detection_summary,
                               previous_hash, current_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            source,
            pc_user_name,
            domain,
            rule_name,
            severity,
            action_taken,
            detection_summary,
            previous_hash,
            current_hash,
        ),
    )
    conn.commit()

    event_id = cursor.lastrowid
    return event_id, current_hash


def verify_chain(conn: sqlite3.Connection) -> dict:
    """
    Walk the entire audit_log table in order, recomputing each hash and
    comparing to the stored value.
    
    Returns:
        {
            "valid": bool,
            "total_entries": int,
            "verified_entries": int,
            "first_mismatch_id": int | None,
            "message": str,
        }
    """
    if conn.row_factory is None:
        conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT * FROM audit_log ORDER BY id ASC"
    ).fetchall()

    if not rows:
        return {
            "valid": True,
            "total_entries": 0,
            "verified_entries": 0,
            "first_mismatch_id": None,
            "message": "Audit log is empty — nothing to verify.",
        }

    expected_previous = GENESIS_HASH
    verified = 0

    for row in rows:
        event_data = {
            "timestamp": row["timestamp"],
            "source": row["source"],
            "pc_user_name": row["pc_user_name"] if "pc_user_name" in row.keys() else None,
            "domain": row["domain"],
            "rule_name": row["rule_name"],
            "severity": row["severity"],
            "action_taken": row["action_taken"],
            "detection_summary": row["detection_summary"],
        }

        # Check previous_hash link
        if row["previous_hash"] != expected_previous:
            return {
                "valid": False,
                "total_entries": len(rows),
                "verified_entries": verified,
                "first_mismatch_id": row["id"],
                "message": (
                    f"Chain broken at entry ID {row['id']}: "
                    f"expected previous_hash '{expected_previous[:16]}...' "
                    f"but found '{row['previous_hash'][:16]}...'"
                ),
            }

        # Recompute and verify current hash
        recomputed = compute_hash(event_data, row["previous_hash"])
        if recomputed != row["current_hash"]:
            # Check legacy format if pc_user_name is None
            legacy_data = {
                "timestamp": row["timestamp"],
                "source": row["source"],
                "domain": row["domain"],
                "rule_name": row["rule_name"],
                "severity": row["severity"],
                "action_taken": row["action_taken"],
                "detection_summary": row["detection_summary"],
            }
            recomputed_legacy = compute_hash(legacy_data, row["previous_hash"])
            if recomputed_legacy == row["current_hash"]:
                recomputed = recomputed_legacy
            else:
                return {
                    "valid": False,
                    "total_entries": len(rows),
                    "verified_entries": verified,
                    "first_mismatch_id": row["id"],
                    "message": (
                        f"Hash mismatch at entry ID {row['id']}: "
                        f"stored '{row['current_hash'][:16]}...' "
                        f"does not match recomputed '{recomputed[:16]}...'. "
                        f"Data may have been tampered with."
                    ),
                }

        expected_previous = row["current_hash"]
        verified += 1

    return {
        "valid": True,
        "total_entries": len(rows),
        "verified_entries": verified,
        "first_mismatch_id": None,
        "message": f"All {verified} entries verified — audit chain is intact.",
    }
