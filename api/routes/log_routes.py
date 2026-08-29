"""
SentinelClip — Log Routes

POST /api/v1/log — Record a detection event with hash chain.
"""

import json
import getpass
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, g
from api.audit import record_audit_event

log_bp = Blueprint("log", __name__)


@log_bp.route("/api/v1/log", methods=["POST"])
def log_event():
    """
    Record a detection event from the clipboard engine or browser extension.
    
    Body (JSON):
    {
        "timestamp": "2026-08-19T10:22:00Z",   (optional — server generates if missing)
        "source": "clipboard",                   ('clipboard' | 'browser_upload')
        "domain": null,                           (AI domain, if applicable)
        "detections": [
            {"rule_name": "AWS Access Key", "severity": "HIGH", "action": "BLOCK"}
        ],
        "action_taken": "BLOCK"
    }
    
    Response:
    {"status": "logged", "event_id": 42, "current_hash": "..."}
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    # Validate required fields
    if "source" not in data:
        return jsonify({"error": "Missing required field: source"}), 400
    if data["source"] not in ("clipboard", "browser_upload"):
        return jsonify({
            "error": "source must be 'clipboard' or 'browser_upload'"
        }), 400

    # Use provided timestamp or generate one
    timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    pc_user_name = data.get("pc_user_name") or getpass.getuser()

    # Extract detection info
    detections = data.get("detections", [])
    action_taken = data.get("action_taken", "NONE")

    # Determine primary rule info (highest severity detection)
    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    rule_entries = [d for d in detections if "rule_name" in d]

    primary_rule_name = None
    primary_severity = None

    if rule_entries:
        # Sort by severity descending
        rule_entries.sort(
            key=lambda d: severity_order.get(d.get("severity", "LOW"), 0),
            reverse=True,
        )
        primary_rule_name = rule_entries[0].get("rule_name")
        primary_severity = rule_entries[0].get("severity")

    # Build detection summary (safe for storage — no raw values)
    detection_summary = json.dumps(detections, sort_keys=True)

    # Record with hash chain
    db = g.db
    event_id, current_hash = record_audit_event(
        conn=db,
        timestamp=timestamp,
        source=data["source"],
        domain=data.get("domain"),
        pc_user_name=pc_user_name,
        rule_name=primary_rule_name,
        severity=primary_severity,
        action_taken=action_taken,
        detection_summary=detection_summary,
    )

    return jsonify({
        "status": "logged",
        "event_id": event_id,
        "current_hash": current_hash,
    }), 201
