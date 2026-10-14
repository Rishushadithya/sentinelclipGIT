"""Enrollment and device-management endpoints."""

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, g, request

from api.auth import require_auth
from api.device_auth import hash_device_token


device_bp = Blueprint("devices", __name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse stored timestamps and normalize legacy naive values to UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@device_bp.route("/api/v1/devices/enrollment-codes", methods=["POST"])
@require_auth
def create_enrollment_code():
    """Generate a short-lived, one-time enrollment code for an agent."""
    data = request.get_json(silent=True) or {}
    try:
        expires_minutes = int(data.get("expires_minutes", 10))
    except (TypeError, ValueError):
        return jsonify({"error": "expires_minutes must be an integer."}), 400

    if not 1 <= expires_minutes <= 60:
        return jsonify({"error": "expires_minutes must be between 1 and 60."}), 400

    code = secrets.token_urlsafe(12)
    now = _utc_now()
    expires_at = now + timedelta(minutes=expires_minutes)
    g.db.execute(
        "INSERT INTO enrollment_codes (code_hash, created_at, expires_at) VALUES (?, ?, ?)",
        (hash_device_token(code), now.isoformat(), expires_at.isoformat()),
    )
    g.db.commit()
    return jsonify({"code": code, "expires_at": expires_at.isoformat()}), 201


@device_bp.route("/api/v1/devices/enroll", methods=["POST"])
def enroll_device():
    """Exchange an unused enrollment code for a permanent device token."""
    data = request.get_json(silent=True) or {}
    required = ("code", "hostname", "os_user")
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing required field: {missing[0]}"}), 400

    now = _utc_now()
    code_row = g.db.execute(
        "SELECT * FROM enrollment_codes WHERE code_hash = ? AND used_at IS NULL",
        (hash_device_token(data["code"]),),
    ).fetchone()
    if code_row is None:
        return jsonify({"error": "Invalid or already-used enrollment code."}), 403

    try:
        expires_at = datetime.fromisoformat(code_row["expires_at"])
    except ValueError:
        return jsonify({"error": "Enrollment code has invalid expiry."}), 500
    if expires_at <= now:
        return jsonify({"error": "Enrollment code has expired."}), 403

    device_id = str(uuid.uuid4())
    device_token = secrets.token_urlsafe(32)
    g.db.execute(
        """
        INSERT INTO devices (
            id, hostname, os_user, ip_address, group_name,
            enrolled_at, last_seen, status, device_token_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?)
        """,
        (
            device_id,
            data["hostname"],
            data["os_user"],
            data.get("ip_address") or request.remote_addr,
            data.get("group_name"),
            now.isoformat(),
            now.isoformat(),
            hash_device_token(device_token),
        ),
    )
    g.db.execute(
        "UPDATE enrollment_codes SET used_at = ? WHERE id = ?",
        (now.isoformat(), code_row["id"]),
    )
    g.db.commit()

    return jsonify({
        "device_id": device_id,
        "device_token": device_token,
        "group_name": data.get("group_name"),
    }), 201


@device_bp.route("/api/v1/devices", methods=["GET"])
@require_auth
def list_devices():
    """List enrolled devices for the administrator dashboard."""
    rows = g.db.execute("SELECT * FROM devices ORDER BY enrolled_at DESC").fetchall()
    devices = []
    now = _utc_now()
    for row in rows:
        last_seen = row["last_seen"]
        online = False
        seen_at = _parse_timestamp(last_seen)
        if seen_at is not None:
            online = now - seen_at <= timedelta(minutes=2)
        devices.append({
            "id": row["id"],
            "hostname": row["hostname"],
            "os_user": row["os_user"],
            "ip_address": row["ip_address"],
            "group_name": row["group_name"],
            "enrolled_at": row["enrolled_at"],
            "last_seen": last_seen,
            "status": "online" if online else "offline",
        })
    return jsonify({"devices": devices})
