"""
SentinelClip — Clipboard Reporter

Reports detection events to the Flask API hub via POST /api/v1/log.
Handles fail-closed/fail-open logic based on severity when the API
is unreachable.
"""

import logging
import getpass
import requests
from datetime import datetime, timezone

logger = logging.getLogger("sentinelclip.reporter")

API_BASE = "http://127.0.0.1:5000/api/v1"


def report_detection(
    detections: list[dict],
    source: str = "clipboard",
    domain: str | None = None,
    action_taken: str = "NONE",
    api_base: str = API_BASE,
    pc_user_name: str | None = None,
) -> bool:
    """
    Report a detection event to the Flask API.
    
    Args:
        detections: List of detection metadata dicts (safe for logging).
        source: Event source ('clipboard' or 'browser_upload').
        domain: Target AI domain if applicable.
        action_taken: The action that was applied.
        api_base: Base URL of the Flask API.
        
    Returns:
        True if the event was logged successfully, False otherwise.
    """
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "pc_user_name": pc_user_name or getpass.getuser(),
        "domain": domain,
        "detections": detections,
        "action_taken": action_taken,
    }

    try:
        resp = requests.post(
            f"{api_base}/log",
            json=payload,
            timeout=3,
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info(
            f"Event logged: ID={data.get('event_id')}, "
            f"hash={data.get('current_hash', '')[:16]}..."
        )
        return True
    except requests.RequestException as e:
        logger.error(f"Failed to report event to API: {e}")
        return False


def check_api_health(api_base: str = API_BASE) -> bool:
    """
    Check if the Flask API hub is reachable.
    
    Returns:
        True if the API responds to /health, False otherwise.
    """
    try:
        resp = requests.get(f"{api_base}/health", timeout=2)
        return resp.status_code == 200
    except requests.RequestException:
        return False
