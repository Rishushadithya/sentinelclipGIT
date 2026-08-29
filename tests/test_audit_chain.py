"""
SentinelClip — Audit Chain Tests

Tests hash-chain creation, integrity verification, and tamper detection.
Intentionally modifies rows to confirm verify_chain() catches tampering.
"""

import sys
import os
import json
import sqlite3
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.audit import (
    compute_hash,
    get_latest_audit_hash,
    record_audit_event,
    verify_chain,
    GENESIS_HASH,
)
from api.db import get_db, init_db


@pytest.fixture
def db(tmp_path):
    """Create a temporary test database."""
    db_path = str(tmp_path / "test_audit.db")
    conn = get_db(db_path)
    init_db(conn)
    yield conn
    conn.close()


def _record_test_event(conn, rule_name="Test Rule", severity="HIGH", source="clipboard"):
    """Helper to record a test event."""
    return record_audit_event(
        conn=conn,
        timestamp="2026-08-19T10:00:00Z",
        source=source,
        domain=None,
        pc_user_name=None,
        rule_name=rule_name,
        severity=severity,
        action_taken="BLOCK",
        detection_summary=json.dumps([{
            "rule_name": rule_name,
            "severity": severity,
            "action": "BLOCK",
        }]),
    )


# ===========================================================================
# Hash computation tests
# ===========================================================================

class TestHashComputation:
    def test_deterministic(self):
        """Same input should always produce same hash."""
        data = {"key": "value", "number": 42}
        h1 = compute_hash(data, "prev")
        h2 = compute_hash(data, "prev")
        assert h1 == h2

    def test_different_data_different_hash(self):
        data1 = {"key": "value1"}
        data2 = {"key": "value2"}
        assert compute_hash(data1, "prev") != compute_hash(data2, "prev")

    def test_different_previous_different_hash(self):
        data = {"key": "value"}
        assert compute_hash(data, "prev1") != compute_hash(data, "prev2")

    def test_hash_is_hex_sha256(self):
        h = compute_hash({"test": True}, "genesis")
        assert len(h) == 64  # SHA-256 hex digest length
        assert all(c in "0123456789abcdef" for c in h)


# ===========================================================================
# Chain recording tests
# ===========================================================================

class TestChainRecording:
    def test_first_event_uses_genesis(self, db):
        """First event should have GENESIS as previous_hash."""
        event_id, current_hash = _record_test_event(db)
        row = db.execute(
            "SELECT previous_hash FROM audit_log WHERE id = ?", (event_id,)
        ).fetchone()
        assert row["previous_hash"] == GENESIS_HASH

    def test_chain_links_correctly(self, db):
        """Each event's previous_hash should match the prior event's current_hash."""
        _, hash1 = _record_test_event(db, "Rule 1")
        _, hash2 = _record_test_event(db, "Rule 2")
        _, hash3 = _record_test_event(db, "Rule 3")

        rows = db.execute(
            "SELECT previous_hash, current_hash FROM audit_log ORDER BY id ASC"
        ).fetchall()

        assert rows[0]["previous_hash"] == GENESIS_HASH
        assert rows[0]["current_hash"] == hash1
        assert rows[1]["previous_hash"] == hash1
        assert rows[1]["current_hash"] == hash2
        assert rows[2]["previous_hash"] == hash2
        assert rows[2]["current_hash"] == hash3

    def test_get_latest_hash_empty(self, db):
        assert get_latest_audit_hash(db) == GENESIS_HASH

    def test_get_latest_hash_after_events(self, db):
        _, hash1 = _record_test_event(db)
        assert get_latest_audit_hash(db) == hash1
        _, hash2 = _record_test_event(db)
        assert get_latest_audit_hash(db) == hash2


# ===========================================================================
# Chain verification tests
# ===========================================================================

class TestChainVerification:
    def test_empty_chain_valid(self, db):
        result = verify_chain(db)
        assert result["valid"] is True
        assert result["total_entries"] == 0

    def test_single_event_valid(self, db):
        _record_test_event(db)
        result = verify_chain(db)
        assert result["valid"] is True
        assert result["total_entries"] == 1

    def test_multiple_events_valid(self, db):
        for i in range(10):
            _record_test_event(db, f"Rule {i}")
        result = verify_chain(db)
        assert result["valid"] is True
        assert result["total_entries"] == 10
        assert result["verified_entries"] == 10

    def test_tamper_detection_modified_data(self, db):
        """Modifying event data should break the chain."""
        for i in range(5):
            _record_test_event(db, f"Rule {i}")

        # Verify chain is intact before tampering
        assert verify_chain(db)["valid"] is True

        # Tamper: modify the rule_name of the 3rd entry
        db.execute(
            "UPDATE audit_log SET rule_name = 'TAMPERED' WHERE id = 3"
        )
        db.commit()

        result = verify_chain(db)
        assert result["valid"] is False
        assert result["first_mismatch_id"] == 3
        assert "tampered" in result["message"].lower() or "mismatch" in result["message"].lower()

    def test_tamper_detection_modified_hash(self, db):
        """Modifying a stored hash should break the chain."""
        for i in range(3):
            _record_test_event(db, f"Rule {i}")

        # Tamper: modify the current_hash of the 2nd entry
        db.execute(
            "UPDATE audit_log SET current_hash = 'fakehash' WHERE id = 2"
        )
        db.commit()

        result = verify_chain(db)
        assert result["valid"] is False

    def test_tamper_detection_modified_previous_hash(self, db):
        """Modifying a previous_hash link should break the chain."""
        for i in range(3):
            _record_test_event(db, f"Rule {i}")

        # Tamper: modify the previous_hash of the 2nd entry
        db.execute(
            "UPDATE audit_log SET previous_hash = 'broken_link' WHERE id = 2"
        )
        db.commit()

        result = verify_chain(db)
        assert result["valid"] is False
        assert result["first_mismatch_id"] == 2
