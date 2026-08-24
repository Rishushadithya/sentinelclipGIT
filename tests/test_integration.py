"""
SentinelClip — Integration Tests

End-to-end tests that exercise the full pipeline:
Flask API → Detection → Sanitization → Audit logging → Verification.
"""

import sys
import os
import json
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.app import create_app
from api.audit import verify_chain
from api.db import get_db
from detection.patterns import scan, SEED_RULES
from clipboard_engine.sanitizer import sanitize_payload


@pytest.fixture
def app(tmp_path):
    db_path = str(tmp_path / "integration_test.db")
    app = create_app(db_path=db_path)
    app.config["TESTING"] = True
    app.config["DB_PATH"] = db_path
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    conn = get_db(app.config.get("DB_PATH"))
    yield conn
    conn.close()


class TestFullPipeline:
    """Test the complete detection → sanitization → logging → verification flow."""

    def test_clipboard_detection_and_logging(self, client):
        """Simulate clipboard engine detecting and logging an AWS key."""
        # Step 1: Fetch policy rules from API
        resp = client.get("/api/v1/policy")
        assert resp.status_code == 200
        rules_data = resp.get_json()["rules"]
        assert len(rules_data) > 0

        # Step 2: Detect sensitive content
        from detection.patterns import rules_from_dicts
        rules = rules_from_dicts(rules_data)
        test_text = "Deploy with key AKIAIOSFODNN7EXAMPLE to production"
        detections = scan(test_text, rules)
        assert len(detections) > 0
        assert any(d.rule_name == "AWS Access Key" for d in detections)

        # Step 3: Sanitize
        sanitized, det_log = sanitize_payload(test_text, rules)
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "[BLOCKED" in sanitized

        # Step 4: Log event
        rule_entries = [d for d in det_log if "rule_name" in d]
        resp = client.post("/api/v1/log", json={
            "source": "clipboard",
            "detections": rule_entries,
            "action_taken": "BLOCK",
        })
        assert resp.status_code == 201
        log_data = resp.get_json()
        assert log_data["status"] == "logged"
        assert "current_hash" in log_data

        # Step 5: Verify event appears in audit log
        resp = client.get("/api/v1/events?severity=HIGH")
        events = resp.get_json()["events"]
        assert len(events) > 0
        assert events[0]["rule_name"] == "AWS Access Key"

        # Step 6: Verify audit chain integrity
        resp = client.get("/api/v1/audit/verify")
        verify = resp.get_json()
        assert verify["valid"] is True

    def test_browser_upload_detection_flow(self, client):
        """Simulate browser extension detecting sensitive content in a file upload."""
        # Load test fixture
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "sample.json"
        )
        with open(fixture_path, "r") as f:
            file_content = f.read()

        # Detect
        from detection.patterns import rules_from_dicts
        resp = client.get("/api/v1/policy")
        rules = rules_from_dicts(resp.get_json()["rules"])
        sanitized, det_log = sanitize_payload(file_content, rules)

        # Should detect multiple issues
        rule_entries = [d for d in det_log if "rule_name" in d]
        assert len(rule_entries) > 0

        # Log as browser upload
        resp = client.post("/api/v1/log", json={
            "source": "browser_upload",
            "domain": "chat.openai.com",
            "detections": rule_entries,
            "action_taken": "BLOCK",
        })
        assert resp.status_code == 201

        # Verify in events
        resp = client.get("/api/v1/events?source=browser_upload")
        events = resp.get_json()["events"]
        assert len(events) > 0
        assert events[0]["domain"] == "chat.openai.com"

    def test_multiple_events_chain_integrity(self, client):
        """Log multiple events and verify the full chain is intact."""
        test_cases = [
            {
                "source": "clipboard",
                "detections": [
                    {"rule_name": "AWS Access Key", "severity": "HIGH", "action": "BLOCK"}
                ],
                "action_taken": "BLOCK",
            },
            {
                "source": "browser_upload",
                "domain": "gemini.google.com",
                "detections": [
                    {"rule_name": "Private IP Address", "severity": "MEDIUM", "action": "OBFUSCATE"}
                ],
                "action_taken": "OBFUSCATE",
            },
            {
                "source": "clipboard",
                "detections": [
                    {"rule_name": "Email Address", "severity": "LOW", "action": "WARN"}
                ],
                "action_taken": "WARN",
            },
            {
                "source": "clipboard",
                "detections": [
                    {"rule_name": "JWT Token", "severity": "HIGH", "action": "BLOCK"}
                ],
                "action_taken": "BLOCK",
            },
        ]

        for tc in test_cases:
            resp = client.post("/api/v1/log", json=tc)
            assert resp.status_code == 201

        # Verify chain
        resp = client.get("/api/v1/audit/verify")
        verify = resp.get_json()
        assert verify["valid"] is True
        assert verify["total_entries"] == 4

    def test_policy_crud_flow(self, client):
        """Test the full policy create → read → update → delete lifecycle."""
        # Read admin token
        from api.auth import get_or_create_admin_token
        token = get_or_create_admin_token()
        headers = {"Authorization": f"Bearer {token}"}

        # Create
        resp = client.post("/api/v1/policy/update", json={
            "rule_name": "GitHub Token",
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
            "pattern_type": "regex",
            "severity": "HIGH",
            "action": "BLOCK",
        }, headers=headers)
        assert resp.status_code == 201
        rule_id = resp.get_json()["id"]

        # Read — should be in active rules
        resp = client.get("/api/v1/policy")
        rules = resp.get_json()["rules"]
        names = [r["rule_name"] for r in rules]
        assert "GitHub Token" in names

        # Update
        resp = client.post("/api/v1/policy/update", json={
            "id": rule_id,
            "rule_name": "GitHub Token (Updated)",
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
            "pattern_type": "regex",
            "severity": "HIGH",
            "action": "REDACT",
        }, headers=headers)
        assert resp.status_code == 200

        # Delete
        resp = client.delete(f"/api/v1/policy/{rule_id}", headers=headers)
        assert resp.status_code == 200

        # Verify deleted
        resp = client.get("/api/v1/policy")
        rules = resp.get_json()["rules"]
        names = [r["rule_name"] for r in rules]
        assert "GitHub Token (Updated)" not in names

    def test_stats_endpoint_accuracy(self, client):
        """Verify stats endpoint reflects logged events correctly."""
        # Log events of different types
        client.post("/api/v1/log", json={
            "source": "clipboard",
            "detections": [{"rule_name": "Test", "severity": "HIGH", "action": "BLOCK"}],
            "action_taken": "BLOCK",
        })
        client.post("/api/v1/log", json={
            "source": "clipboard",
            "detections": [{"rule_name": "Test", "severity": "LOW", "action": "WARN"}],
            "action_taken": "WARN",
        })
        client.post("/api/v1/log", json={
            "source": "browser_upload",
            "domain": "claude.ai",
            "detections": [{"rule_name": "Test", "severity": "MEDIUM", "action": "REDACT"}],
            "action_taken": "REDACT",
        })

        resp = client.get("/api/v1/stats")
        stats = resp.get_json()
        assert stats["total_events"] == 3
        assert "clipboard" in stats["by_source"]
        assert "browser_upload" in stats["by_source"]
        assert stats["by_source"]["clipboard"] == 2
        assert stats["by_source"]["browser_upload"] == 1


class TestFixtureFileScan:
    """Test scanning fixture files as if they were uploaded."""

    def test_scan_sample_secrets(self, client):
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "sample_secrets.txt"
        )
        with open(fixture_path, "r") as f:
            content = f.read()

        from detection.patterns import rules_from_dicts
        resp = client.get("/api/v1/policy")
        rules = rules_from_dicts(resp.get_json()["rules"])

        sanitized, det_log = sanitize_payload(content, rules)
        rule_entries = [d for d in det_log if "rule_name" in d]

        # Should detect multiple types
        rule_names = set(d["rule_name"] for d in rule_entries)
        assert "AWS Access Key" in rule_names
        assert "Private IP Address" in rule_names
        assert "Email Address" in rule_names

    def test_scan_csv_fixture(self, client):
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "sample.csv"
        )
        with open(fixture_path, "r") as f:
            content = f.read()

        from detection.patterns import rules_from_dicts
        resp = client.get("/api/v1/policy")
        rules = rules_from_dicts(resp.get_json()["rules"])

        _, det_log = sanitize_payload(content, rules)
        rule_entries = [d for d in det_log if "rule_name" in d]
        assert len(rule_entries) > 0

    def test_scan_json_fixture(self, client):
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "sample.json"
        )
        with open(fixture_path, "r") as f:
            content = f.read()

        from detection.patterns import rules_from_dicts
        resp = client.get("/api/v1/policy")
        rules = rules_from_dicts(resp.get_json()["rules"])

        _, det_log = sanitize_payload(content, rules)
        rule_entries = [d for d in det_log if "rule_name" in d]
        assert len(rule_entries) > 0
        rule_names = set(d["rule_name"] for d in rule_entries)
        assert "Private IP Address" in rule_names
