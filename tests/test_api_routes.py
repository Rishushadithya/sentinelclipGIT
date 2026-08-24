"""
SentinelClip — API Route Tests

Tests all Flask API endpoints with a test client and in-memory SQLite DB.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.app import create_app
from api.auth import TOKEN_FILE


@pytest.fixture
def app(tmp_path):
    """Create a Flask app with a temporary test database."""
    db_path = str(tmp_path / "test.db")
    app = create_app(db_path=db_path)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def admin_token():
    """Read the admin token from config file."""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            return f.read().strip()
    return "test_token"


@pytest.fixture
def auth_headers(admin_token):
    """Authorization headers for authenticated requests."""
    return {"Authorization": f"Bearer {admin_token}"}


# ===========================================================================
# Health Check
# ===========================================================================

class TestHealth:
    def test_health_check(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "SentinelClip API Hub"


# ===========================================================================
# Policy Routes
# ===========================================================================

class TestPolicyRoutes:
    def test_get_policies_returns_seed_rules(self, client):
        """Default seed rules should be loaded on first run."""
        response = client.get("/api/v1/policy")
        assert response.status_code == 200
        data = response.get_json()
        assert "rules" in data
        assert len(data["rules"]) > 0
        # Check seed rules are present
        rule_names = [r["rule_name"] for r in data["rules"]]
        assert "AWS Access Key" in rule_names
        assert "JWT Token" in rule_names

    def test_get_policies_has_required_fields(self, client):
        response = client.get("/api/v1/policy")
        data = response.get_json()
        for rule in data["rules"]:
            assert "rule_name" in rule
            assert "pattern" in rule
            assert "pattern_type" in rule
            assert "severity" in rule
            assert "action" in rule

    def test_update_policy_requires_auth(self, client):
        """POST /policy/update should require authentication."""
        response = client.post(
            "/api/v1/policy/update",
            json={
                "rule_name": "Test Rule",
                "pattern": "test",
                "pattern_type": "keyword",
                "severity": "LOW",
                "action": "WARN",
            },
        )
        assert response.status_code == 401

    def test_create_new_policy(self, client, auth_headers):
        response = client.post(
            "/api/v1/policy/update",
            json={
                "rule_name": "Custom Rule",
                "pattern": "custom_secret_\\w+",
                "pattern_type": "regex",
                "severity": "MEDIUM",
                "action": "OBFUSCATE",
                "replacement_value": "[CUSTOM]",
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "created"
        assert "id" in data

    def test_update_existing_policy(self, client, auth_headers):
        # Create first
        resp = client.post(
            "/api/v1/policy/update",
            json={
                "rule_name": "To Update",
                "pattern": "original",
                "pattern_type": "keyword",
                "severity": "LOW",
                "action": "WARN",
            },
            headers=auth_headers,
        )
        rule_id = resp.get_json()["id"]

        # Update
        response = client.post(
            "/api/v1/policy/update",
            json={
                "id": rule_id,
                "rule_name": "Updated Rule",
                "pattern": "updated",
                "pattern_type": "keyword",
                "severity": "HIGH",
                "action": "BLOCK",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "updated"

    def test_update_validates_fields(self, client, auth_headers):
        response = client.post(
            "/api/v1/policy/update",
            json={
                "rule_name": "Bad Rule",
                "pattern": "test",
                "pattern_type": "invalid_type",
                "severity": "LOW",
                "action": "WARN",
            },
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_delete_policy(self, client, auth_headers):
        # Create
        resp = client.post(
            "/api/v1/policy/update",
            json={
                "rule_name": "To Delete",
                "pattern": "delete_me",
                "pattern_type": "keyword",
                "severity": "LOW",
                "action": "WARN",
            },
            headers=auth_headers,
        )
        rule_id = resp.get_json()["id"]

        # Delete
        response = client.delete(
            f"/api/v1/policy/{rule_id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.get_json()["status"] == "deleted"


# ===========================================================================
# Log Routes
# ===========================================================================

class TestLogRoutes:
    def test_log_event(self, client):
        response = client.post(
            "/api/v1/log",
            json={
                "source": "clipboard",
                "detections": [
                    {
                        "rule_name": "AWS Access Key",
                        "severity": "HIGH",
                        "action": "BLOCK",
                    }
                ],
                "action_taken": "BLOCK",
            },
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "logged"
        assert "event_id" in data
        assert "current_hash" in data

    def test_log_browser_upload(self, client):
        response = client.post(
            "/api/v1/log",
            json={
                "source": "browser_upload",
                "domain": "chat.openai.com",
                "detections": [
                    {
                        "rule_name": "Private IP Address",
                        "severity": "MEDIUM",
                        "action": "OBFUSCATE",
                    }
                ],
                "action_taken": "OBFUSCATE",
            },
        )
        assert response.status_code == 201

    def test_log_requires_source(self, client):
        response = client.post(
            "/api/v1/log",
            json={"detections": [], "action_taken": "NONE"},
        )
        assert response.status_code == 400

    def test_log_validates_source(self, client):
        response = client.post(
            "/api/v1/log",
            json={"source": "invalid_source"},
        )
        assert response.status_code == 400


# ===========================================================================
# Event Routes
# ===========================================================================

class TestEventRoutes:
    def _log_events(self, client, count=5):
        """Helper to create test events."""
        for i in range(count):
            client.post(
                "/api/v1/log",
                json={
                    "source": "clipboard" if i % 2 == 0 else "browser_upload",
                    "domain": "chat.openai.com" if i % 2 else None,
                    "detections": [
                        {
                            "rule_name": f"Test Rule {i}",
                            "severity": ["LOW", "MEDIUM", "HIGH"][i % 3],
                            "action": "WARN",
                        }
                    ],
                    "action_taken": "WARN",
                },
            )

    def test_get_events_default(self, client):
        self._log_events(client, 3)
        response = client.get("/api/v1/events")
        assert response.status_code == 200
        data = response.get_json()
        assert "events" in data
        assert "total" in data
        assert len(data["events"]) == 3

    def test_get_events_pagination(self, client):
        self._log_events(client, 5)
        response = client.get("/api/v1/events?limit=2&offset=0")
        data = response.get_json()
        assert len(data["events"]) == 2
        assert data["total"] == 5

    def test_get_events_filter_severity(self, client):
        self._log_events(client, 6)
        response = client.get("/api/v1/events?severity=HIGH")
        data = response.get_json()
        for event in data["events"]:
            assert event["severity"] == "HIGH"

    def test_get_events_filter_source(self, client):
        self._log_events(client, 4)
        response = client.get("/api/v1/events?source=clipboard")
        data = response.get_json()
        for event in data["events"]:
            assert event["source"] == "clipboard"

    def test_verify_audit_empty(self, client):
        response = client.get("/api/v1/audit/verify")
        assert response.status_code == 200
        data = response.get_json()
        assert data["valid"] is True
        assert data["total_entries"] == 0

    def test_verify_audit_after_events(self, client):
        self._log_events(client, 5)
        response = client.get("/api/v1/audit/verify")
        data = response.get_json()
        assert data["valid"] is True
        assert data["total_entries"] == 5

    def test_stats(self, client):
        self._log_events(client, 3)
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.get_json()
        assert "total_events" in data
        assert "events_today" in data
        assert "by_severity" in data
        assert "by_source" in data
