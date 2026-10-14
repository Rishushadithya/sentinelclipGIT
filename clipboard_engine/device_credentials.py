"""Persistent credentials and first-run enrollment for a SentinelClip agent."""

import getpass
import json
import os
import platform
from pathlib import Path

import requests


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DEVICE_ID_FILE = CONFIG_DIR / ".device_id"
DEVICE_TOKEN_FILE = CONFIG_DIR / ".device_token"
ENROLLMENT_CODE_ENV = "SENTINELCLIP_ENROLLMENT_CODE"
DEVICE_GROUP_ENV = "SENTINELCLIP_DEVICE_GROUP"


def load_device_credentials() -> dict:
    """Load locally stored device credentials, if enrolled."""
    if not DEVICE_ID_FILE.exists() or not DEVICE_TOKEN_FILE.exists():
        return {}
    device_id = DEVICE_ID_FILE.read_text(encoding="utf-8").strip()
    device_token = DEVICE_TOKEN_FILE.read_text(encoding="utf-8").strip()
    if not device_id or not device_token:
        return {}
    return {"device_id": device_id, "device_token": device_token}


def save_device_credentials(device_id: str, device_token: str) -> None:
    """Persist the device identity and secret with restrictive file permissions where supported."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DEVICE_ID_FILE.write_text(device_id, encoding="utf-8")
    DEVICE_TOKEN_FILE.write_text(device_token, encoding="utf-8")
    try:
        os.chmod(DEVICE_ID_FILE, 0o600)
        os.chmod(DEVICE_TOKEN_FILE, 0o600)
    except OSError:
        pass


def enroll_from_environment(api_base: str) -> dict:
    """Exchange SENTINELCLIP_ENROLLMENT_CODE and save returned credentials."""
    code = os.getenv(ENROLLMENT_CODE_ENV, "").strip()
    if not code:
        return {}

    response = requests.post(
        f"{api_base}/devices/enroll",
        json={
            "code": code,
            "hostname": platform.node() or "unknown-host",
            "os_user": getpass.getuser(),
            "group_name": os.getenv(DEVICE_GROUP_ENV) or None,
        },
        timeout=5,
    )
    response.raise_for_status()
    data = response.json()
    save_device_credentials(data["device_id"], data["device_token"])
    return {
        "device_id": data["device_id"],
        "device_token": data["device_token"],
    }


def get_device_token(api_base: str) -> str | None:
    """Return the stored token, enrolling once when an enrollment code is configured."""
    credentials = load_device_credentials()
    if credentials:
        return credentials["device_token"]
    try:
        return enroll_from_environment(api_base).get("device_token")
    except (requests.RequestException, KeyError, json.JSONDecodeError) as exc:
        return None
