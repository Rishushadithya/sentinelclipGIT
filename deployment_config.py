"""Load the installed SentinelClip role and expose its service settings."""

import json
from pathlib import Path


VALID_ROLES = {"server", "agent", "both"}
DEFAULTS = {
    "role": "both",
    "api_base": "http://127.0.0.1:5000/api/v1",
    "api_host": "0.0.0.0",
    "api_port": 5000,
    "dashboard_host": "127.0.0.1",
    "dashboard_port": 8501,
}


def load_deployment_config(path: str | Path) -> dict:
    """Load deployment settings, retaining source-checkout defaults if absent."""
    config_path = Path(path)
    if not config_path.exists():
        return DEFAULTS.copy()

    with config_path.open(encoding="utf-8") as config_file:
        config = {**DEFAULTS, **json.load(config_file)}

    role = config.get("role")
    if role not in VALID_ROLES:
        raise ValueError(f"Unsupported SentinelClip role: {role!r}")
    config["api_port"] = int(config["api_port"])
    config["dashboard_port"] = int(config["dashboard_port"])
    return config


def services_for_role(role: str) -> tuple[bool, bool, bool]:
    """Return whether the API, clipboard engine, and dashboard should run."""
    if role not in VALID_ROLES:
        raise ValueError(f"Unsupported SentinelClip role: {role!r}")
    runs_server = role in {"server", "both"}
    runs_clipboard = role in {"agent", "both"}
    return runs_server, runs_clipboard, runs_server