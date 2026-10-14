"""Device-token authentication for enrolled LAN agents."""

import functools
import hashlib
from datetime import datetime, timezone
from flask import g, jsonify, request


def hash_device_token(token: str) -> str:
    """Return the SHA-256 digest stored for a device token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_device_auth(view):
    """Require a valid enrolled-device bearer token and update its liveness."""
    @functools.wraps(view)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Device bearer token required."}), 401

        token = auth_header[7:].strip()
        if not token:
            return jsonify({"error": "Device bearer token required."}), 401

        row = g.db.execute(
            "SELECT * FROM devices WHERE device_token_hash = ?",
            (hash_device_token(token),),
        ).fetchone()
        if row is None:
            return jsonify({"error": "Invalid device token."}), 403

        g.device = row
        last_seen = datetime.now(timezone.utc).isoformat()
        g.db.execute(
            "UPDATE devices SET last_seen = ?, status = 'online' WHERE id = ?",
            (last_seen, row["id"]),
        )
        g.db.commit()
        return view(*args, **kwargs)

    return decorated
