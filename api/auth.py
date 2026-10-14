"""
SentinelClip — Local Authentication

Simple token-based authentication for dashboard-only write operations.
On first run, generates a random admin token stored in config/.admin_token.
Flask routes that mutate policy require Authorization: Bearer <token>.
"""

import os
import secrets
import functools
from flask import request, jsonify


TOKEN_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", ".admin_token"
)


def get_or_create_admin_token() -> str:
    """
    Get the admin token from config/.admin_token.
    If the file doesn't exist, generate a new token and save it.
    """
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            token = f.read().strip()
            if token:
                return token

    # Generate new token
    token = secrets.token_urlsafe(32)

    # Ensure config directory exists
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)

    with open(TOKEN_FILE, "w") as f:
        f.write(token)

    print(f"[INFO] Admin token generated and saved to {TOKEN_FILE}")

    return token


def require_auth(f):
    """
    Flask route decorator that requires a valid admin token.
    Checks for Authorization: Bearer <token> header.
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Missing or invalid Authorization header. "
                         "Expected: Bearer <admin_token>"
            }), 401

        provided_token = auth_header[7:]  # Strip "Bearer "
        expected_token = get_or_create_admin_token()

        if not secrets.compare_digest(provided_token, expected_token):
            return jsonify({"error": "Invalid admin token."}), 403

        return f(*args, **kwargs)
    return decorated
