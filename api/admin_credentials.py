"""
SentinelClip — Admin Credential Management

Stores the dashboard admin username + PBKDF2-SHA256 hashed password in
config/.admin_credentials (JSON, mode 0600).

On first run, default credentials are:
    username : admin
    password : sentinelclip

Override the defaults before first launch via environment variables:
    SENTINELCLIP_ADMIN_USER   — desired username
    SENTINELCLIP_ADMIN_PASS   — desired password

Change at any time via the dashboard Settings page or the
POST /api/v1/admin/credentials endpoint (requires current admin bearer token).
"""

import hashlib
import json
import os
import secrets

# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------

CREDENTIALS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", ".admin_credentials"
)

DEFAULT_USERNAME = os.getenv("SENTINELCLIP_ADMIN_USER", "admin")
DEFAULT_PASSWORD = os.getenv("SENTINELCLIP_ADMIN_PASS", "sentinelclip")

# PBKDF2-SHA256 iteration count (OWASP 2023 recommendation)
PBKDF2_ITERATIONS = 260_000


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str, salt: str) -> str:
    """Derive a PBKDF2-SHA256 key from *password* + hex-encoded *salt*."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    )
    return dk.hex()


def _persist_credentials(username: str, password: str) -> dict:
    """Hash *password* and write credentials to disk; return the stored dict."""
    salt = secrets.token_hex(32)
    data = {
        "username": username,
        "password_hash": _hash_password(password, salt),
        "salt": salt,
    }
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)
    try:
        os.chmod(CREDENTIALS_FILE, 0o600)
    except OSError:
        pass  # Windows — skip chmod
    return data


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_or_create_credentials() -> dict:
    """
    Load stored credentials from disk.

    On first run (no credential file, or corrupted file) the defaults are
    written, printed to stdout, and returned.
    """
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if {"username", "password_hash", "salt"}.issubset(data):
                return data
        except (json.JSONDecodeError, OSError, ValueError):
            pass  # Fall through to create defaults

    data = _persist_credentials(DEFAULT_USERNAME, DEFAULT_PASSWORD)
    print(
        f"[INFO] Admin credentials initialised — "
        f"username: {DEFAULT_USERNAME}  "
        f"default password: {DEFAULT_PASSWORD}  "
        f"(change via dashboard Settings page after first login)"
    )
    return data


def verify_credentials(username: str, password: str) -> bool:
    """
    Return True if *username* / *password* match the stored credentials.

    Both comparisons use constant-time digests to prevent timing attacks.
    """
    creds = get_or_create_credentials()
    username_ok = secrets.compare_digest(
        username.encode("utf-8"),
        creds["username"].encode("utf-8"),
    )
    computed = _hash_password(password, creds["salt"])
    password_ok = secrets.compare_digest(computed, creds["password_hash"])
    return username_ok and password_ok


def update_credentials(new_username: str, new_password: str) -> None:
    """Replace stored credentials with *new_username* / *new_password*."""
    _persist_credentials(new_username, new_password)
    print(f"[INFO] Admin credentials updated — new username: {new_username}")


def get_current_username() -> str:
    """Return the stored admin username (does not expose hash/salt)."""
    return get_or_create_credentials()["username"]
