"""
SentinelClip — Native Messaging Host

Bridge between the Chromium browser extension and the Flask API hub.
Reads length-prefixed JSON from stdin (Chrome native messaging protocol),
runs content through the shared detection engine, and writes the verdict
back to stdout.

Protocol:
  - Input:  4-byte little-endian length prefix + JSON message
  - Output: 4-byte little-endian length prefix + JSON response
"""

import sys
import os
import json
import struct
import logging
import requests

# Ensure project root is on path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_ROOT)

from detection.patterns import scan, rules_from_dicts
from clipboard_engine.sanitizer import sanitize_payload

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_BASE = "http://127.0.0.1:5000/api/v1"
LOG_FILE = os.path.join(SCRIPT_DIR, "native_host.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("sentinelclip.native_host")


# ---------------------------------------------------------------------------
# Native messaging I/O (Chrome protocol)
# ---------------------------------------------------------------------------

def read_message():
    """Read a length-prefixed JSON message from stdin."""
    # Read the 4-byte message length
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length or len(raw_length) < 4:
        return None

    message_length = struct.unpack('<I', raw_length)[0]
    if message_length == 0:
        return None

    # Read the JSON message
    raw_message = sys.stdin.buffer.read(message_length)
    if not raw_message:
        return None

    return json.loads(raw_message.decode('utf-8'))


def write_message(message):
    """Write a length-prefixed JSON message to stdout."""
    encoded = json.dumps(message).encode('utf-8')
    length = struct.pack('<I', len(encoded))
    sys.stdout.buffer.write(length)
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


# ---------------------------------------------------------------------------
# Policy rules fetching
# ---------------------------------------------------------------------------

_cached_rules = None
_cached_rules_raw = None


def get_policy_rules():
    """Fetch policy rules from the Flask API (with simple caching)."""
    global _cached_rules, _cached_rules_raw

    try:
        resp = requests.get(f"{API_BASE}/policy", timeout=3)
        resp.raise_for_status()
        data = resp.json()
        rule_dicts = data.get("rules", [])
        _cached_rules_raw = rule_dicts
        _cached_rules = rules_from_dicts(rule_dicts)
        return _cached_rules
    except requests.RequestException as e:
        logger.warning(f"Could not fetch rules from API: {e}")
        if _cached_rules:
            return _cached_rules
        return []


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------

def scan_content(domain, filename, content):
    """
    Scan file content against policy rules.
    
    Returns:
        dict with verdict (ALLOW/BLOCK/WARN), detections, and message.
    """
    rules = get_policy_rules()
    if not rules:
        logger.warning("No policy rules available")
        return {
            "verdict": "ALLOW",
            "reason": "no_rules",
            "message": "No policy rules configured.",
        }

    # Run sanitization (includes detection)
    sanitized, detections_log = sanitize_payload(content, rules)

    # Filter actual rule detections
    rule_detections = [d for d in detections_log if "rule_name" in d]

    if not rule_detections:
        return {
            "verdict": "ALLOW",
            "reason": "clean",
            "message": f"No sensitive content detected in {filename}.",
        }

    # Determine verdict
    has_block = any(d.get("type") == "block_required" for d in detections_log)
    has_warn = any(d.get("type") == "warning_required" for d in detections_log)
    has_redact = any(d.get("action") in ("REDACT", "OBFUSCATE") for d in rule_detections)

    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_severity = max(
        (d.get("severity", "LOW") for d in rule_detections),
        key=lambda s: severity_order.get(s, 0),
    )

    if has_block:
        verdict = "BLOCK"
    elif max_severity == "HIGH" or has_redact:
        verdict = "BLOCK"
    elif has_warn:
        verdict = "WARN"
    else:
        verdict = "WARN"

    # Build detection summary for reporting
    detection_names = ", ".join(set(d["rule_name"] for d in rule_detections))

    # Report to Flask API
    try:
        action_taken = verdict
        requests.post(
            f"{API_BASE}/log",
            json={
                "source": "browser_upload",
                "domain": domain,
                "detections": rule_detections,
                "action_taken": action_taken,
            },
            timeout=3,
        )
        logger.info(f"Event logged for {filename} on {domain}: {verdict}")
    except requests.RequestException as e:
        logger.error(f"Failed to log event: {e}")

    return {
        "verdict": verdict,
        "detections": detection_names,
        "message": (
            f"Detected {len(rule_detections)} sensitive item(s) in {filename}: "
            f"{detection_names}. Max severity: {max_severity}."
        ),
    }


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    """Main native messaging host loop."""
    logger.info("Native messaging host started")

    while True:
        try:
            message = read_message()
            if message is None:
                break

            logger.info(f"Received message: action={message.get('action')}")

            if message.get("action") == "scan":
                result = scan_content(
                    domain=message.get("domain", "unknown"),
                    filename=message.get("filename", "unknown"),
                    content=message.get("content", ""),
                )
                write_message(result)
            elif message.get("action") == "health":
                write_message({"status": "ok", "service": "SentinelClip Native Host"})
            else:
                write_message({"error": f"Unknown action: {message.get('action')}"})

        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
            try:
                write_message({"error": str(e), "verdict": "ALLOW"})
            except Exception:
                break

    logger.info("Native messaging host stopped")


if __name__ == "__main__":
    main()
