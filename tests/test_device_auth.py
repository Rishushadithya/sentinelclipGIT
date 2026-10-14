"""Tests for LAN device enrollment and scoped policy access."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.app import create_app
from api.auth import TOKEN_FILE


@pytest.fixture
def app(tmp_path):
    app = create_app(db_path=str(tmp_path / "device_test.db"))
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_headers():
    with open(TOKEN_FILE, "r") as token_file:
        return {"Authorization": f"Bearer {token_file.read().strip()}"}


def enroll(client, admin_headers, hostname, group_name=None):
    code_response = client.post(
        "/api/v1/devices/enrollment-codes",
        json={},
        headers=admin_headers,
    )
    assert code_response.status_code == 201
    response = client.post(
        "/api/v1/devices/enroll",
        json={
            "code": code_response.get_json()["code"],
            "hostname": hostname,
            "os_user": f"user-{hostname}",
            "group_name": group_name,
        },
    )
    assert response.status_code == 201
    data = response.get_json()
    return data["device_id"], {"Authorization": f"Bearer {data['device_token']}"}


def create_policy(client, admin_headers, name, scope_type="global", scope_target=None):
    response = client.post(
        "/api/v1/policy/update",
        json={
            "rule_name": name,
            "pattern": name.lower().replace(" ", "_"),
            "pattern_type": "keyword",
            "severity": "LOW",
            "action": "WARN",
            "scope_type": scope_type,
            "scope_target": scope_target,
        },
        headers=admin_headers,
    )
    assert response.status_code == 201


def policy_names(client, device_headers):
    response = client.get("/api/v1/policy", headers=device_headers)
    assert response.status_code == 200
    return {rule["rule_name"] for rule in response.get_json()["rules"]}


def test_enrollment_code_is_one_time(client, admin_headers):
    code_response = client.post(
        "/api/v1/devices/enrollment-codes",
        json={},
        headers=admin_headers,
    )
    code = code_response.get_json()["code"]
    payload = {"code": code, "hostname": "PC-1", "os_user": "alice"}

    first = client.post("/api/v1/devices/enroll", json=payload)
    second = client.post("/api/v1/devices/enroll", json=payload)

    assert first.status_code == 201
    assert second.status_code == 403
    assert first.get_json()["device_id"]
    assert first.get_json()["device_token"]


def test_policy_and_log_reject_missing_or_invalid_device_token(client):
    assert client.get("/api/v1/policy").status_code == 401
    assert client.get(
        "/api/v1/policy",
        headers={"Authorization": "Bearer invalid-token"},
    ).status_code == 403
    assert client.post(
        "/api/v1/log",
        json={"source": "clipboard"},
    ).status_code == 401


def test_policy_scope_global_and_device(client, admin_headers):
    device_id, device_headers = enroll(client, admin_headers, "PC-DEVICE")
    _, other_headers = enroll(client, admin_headers, "PC-OTHER")
    create_policy(client, admin_headers, "Global Rule")
    create_policy(client, admin_headers, "Device Rule", "device", device_id)

    assert "Global Rule" in policy_names(client, device_headers)
    assert "Device Rule" in policy_names(client, device_headers)
    assert "Global Rule" in policy_names(client, other_headers)
    assert "Device Rule" not in policy_names(client, other_headers)


def test_policy_scope_global_and_group(client, admin_headers):
    _, group_headers = enroll(client, admin_headers, "PC-GROUP", "finance")
    _, other_headers = enroll(client, admin_headers, "PC-OTHER", "engineering")
    create_policy(client, admin_headers, "Global Group Rule")
    create_policy(client, admin_headers, "Finance Rule", "group", "finance")

    assert {"Global Group Rule", "Finance Rule"}.issubset(
        policy_names(client, group_headers)
    )
    assert "Finance Rule" not in policy_names(client, other_headers)


def test_policy_device_scope_does_not_apply_to_other_device(client, admin_headers):
    first_id, first_headers = enroll(client, admin_headers, "PC-FIRST")
    _, second_headers = enroll(client, admin_headers, "PC-SECOND")
    create_policy(client, admin_headers, "Only First Device", "device", first_id)

    assert "Only First Device" in policy_names(client, first_headers)
    assert "Only First Device" not in policy_names(client, second_headers)


def test_admin_device_list_handles_authenticated_last_seen(client, admin_headers):
    enroll(client, admin_headers, "PC-LIST")

    response = client.get("/api/v1/devices", headers=admin_headers)

    assert response.status_code == 200
    devices = response.get_json()["devices"]
    assert devices[0]["hostname"] == "PC-LIST"
    assert devices[0]["status"] == "online"


def test_enrollment_code_changes_when_device_enrolled(client, admin_headers):
    """Verify that enrolling a device consumes the code and changes it for the next device."""
    # 1. Fetch current active code
    get_res = client.get("/api/v1/devices/enrollment-code", headers=admin_headers)
    assert get_res.status_code == 200
    first_code = get_res.get_json()["code"]
    assert first_code

    # 2. Enroll a device with the first code
    enroll_res = client.post(
        "/api/v1/devices/enroll",
        json={
            "code": first_code,
            "hostname": "PC-NEW-1",
            "os_user": "user1",
        },
    )
    assert enroll_res.status_code == 201

    # 3. Old code cannot be reused
    reused_res = client.post(
        "/api/v1/devices/enroll",
        json={
            "code": first_code,
            "hostname": "PC-REUSE",
            "os_user": "user-bad",
        },
    )
    assert reused_res.status_code == 403

    # 4. Active enrollment code must have CHANGED to a fresh new one!
    get_new_res = client.get("/api/v1/devices/enrollment-code", headers=admin_headers)
    assert get_new_res.status_code == 200
    second_code = get_new_res.get_json()["code"]
    assert second_code != first_code, "Enrollment code should have changed after device enrollment"

    # 5. Next device can enroll using the new changed code
    enroll_second_res = client.post(
        "/api/v1/devices/enroll",
        json={
            "code": second_code,
            "hostname": "PC-NEW-2",
            "os_user": "user2",
        },
    )
    assert enroll_second_res.status_code == 201
