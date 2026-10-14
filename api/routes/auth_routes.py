"""
SentinelClip — Admin Authentication Routes

POST /api/v1/admin/login        — Exchange username/password for the admin bearer token.
POST /api/v1/admin/credentials  — Change username/password (requires current admin token).
GET  /api/v1/admin/whoami       — Return the current admin username (requires admin token).
"""

from flask import Blueprint, jsonify, request
from api.admin_credentials import (
    verify_credentials,
    update_credentials,
    get_current_username,
)
from api.auth import get_or_create_admin_token, require_auth

auth_routes_bp = Blueprint("admin_auth", __name__)


@auth_routes_bp.route("/api/v1/admin/login", methods=["POST"])
def admin_login():
    """
    Exchange valid admin credentials for the bearer token used by all
    protected API endpoints.

    Request body (JSON):
        {"username": "admin", "password": "..."}

    Response (200):
        {"token": "<bearer_token>", "username": "admin"}

    Response (401):
        {"error": "Invalid username or password."}
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required."}), 400

    if not verify_credentials(username, password):
        return jsonify({"error": "Invalid username or password."}), 401

    token = get_or_create_admin_token()
    return jsonify({"token": token, "username": username})


@auth_routes_bp.route("/api/v1/admin/credentials", methods=["POST"])
@require_auth
def change_credentials():
    """
    Update the admin username and/or password.
    Requires the current admin bearer token in the Authorization header.

    Request body (JSON):
        {"new_username": "admin", "new_password": "new_pass_min8"}

    Response (200):
        {"status": "updated", "username": "admin"}
    """
    data = request.get_json(silent=True) or {}
    new_username = data.get("new_username", "").strip()
    new_password = data.get("new_password", "")

    if not new_username or not new_password:
        return jsonify({"error": "new_username and new_password are required."}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    update_credentials(new_username, new_password)
    return jsonify({"status": "updated", "username": new_username})


@auth_routes_bp.route("/api/v1/admin/whoami", methods=["GET"])
@require_auth
def whoami():
    """Return the current admin username (identity check for the dashboard)."""
    return jsonify({"username": get_current_username()})
