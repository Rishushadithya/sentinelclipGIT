"""
SentinelClip — Policy Routes

GET /api/v1/policy      — Return active policy rules
POST /api/v1/policy/update — Create/update/disable rules (auth required)
"""

from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, g
from api.auth import require_auth
from api.models import PolicyRuleModel

policy_bp = Blueprint("policy", __name__)


@policy_bp.route("/api/v1/policy", methods=["GET"])
def get_policies():
    """Return all active (enabled) policy rules."""
    db = g.db
    cursor = db.cursor()
    rows = cursor.execute(
        "SELECT * FROM policies WHERE enabled = 1 ORDER BY id ASC"
    ).fetchall()

    rules = []
    for row in rows:
        model = PolicyRuleModel.from_row(row)
        rules.append({
            "rule_name": model.rule_name,
            "pattern": model.pattern,
            "pattern_type": model.pattern_type,
            "severity": model.severity,
            "action": model.action,
            "replacement_value": model.replacement_value,
            "enabled": model.enabled,
        })

    return jsonify({"rules": rules})


@policy_bp.route("/api/v1/policy/all", methods=["GET"])
@require_auth
def get_all_policies():
    """Return ALL policy rules (including disabled) — for dashboard admin."""
    db = g.db
    cursor = db.cursor()
    rows = cursor.execute(
        "SELECT * FROM policies ORDER BY id ASC"
    ).fetchall()

    rules = [PolicyRuleModel.from_row(row).to_dict() for row in rows]
    return jsonify({"rules": rules})


@policy_bp.route("/api/v1/policy/update", methods=["POST"])
@require_auth
def update_policy():
    """
    Create or update a policy rule.
    
    If 'id' is provided, updates that rule. Otherwise creates a new rule.
    
    Body (JSON):
    {
        "id": 1,                    (optional — omit to create new)
        "rule_name": "...",
        "pattern": "...",
        "pattern_type": "regex",
        "severity": "HIGH",
        "action": "BLOCK",
        "replacement_value": null,
        "enabled": true
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON."}), 400

    required_fields = ["rule_name", "pattern", "pattern_type", "severity", "action"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Validate enum values
    if data["pattern_type"] not in ("regex", "keyword"):
        return jsonify({"error": "pattern_type must be 'regex' or 'keyword'"}), 400
    if data["severity"] not in ("LOW", "MEDIUM", "HIGH"):
        return jsonify({"error": "severity must be 'LOW', 'MEDIUM', or 'HIGH'"}), 400
    if data["action"] not in ("WARN", "OBFUSCATE", "REDACT", "BLOCK"):
        return jsonify({"error": "action must be WARN, OBFUSCATE, REDACT, or BLOCK"}), 400

    db = g.db
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()

    if "id" in data and data["id"] is not None:
        # Update existing rule
        cursor.execute(
            """
            UPDATE policies SET
                rule_name = ?, pattern = ?, pattern_type = ?,
                severity = ?, action = ?, replacement_value = ?,
                enabled = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                data["rule_name"],
                data["pattern"],
                data["pattern_type"],
                data["severity"],
                data["action"],
                data.get("replacement_value"),
                1 if data.get("enabled", True) else 0,
                now,
                data["id"],
            ),
        )
        db.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": f"Policy ID {data['id']} not found."}), 404

        return jsonify({
            "status": "updated",
            "id": data["id"],
            "updated_at": now,
        })
    else:
        # Create new rule
        cursor.execute(
            """
            INSERT INTO policies (rule_name, pattern, pattern_type, severity,
                                  action, replacement_value, enabled,
                                  created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["rule_name"],
                data["pattern"],
                data["pattern_type"],
                data["severity"],
                data["action"],
                data.get("replacement_value"),
                1 if data.get("enabled", True) else 0,
                now,
                now,
            ),
        )
        db.commit()

        return jsonify({
            "status": "created",
            "id": cursor.lastrowid,
            "created_at": now,
        }), 201


@policy_bp.route("/api/v1/policy/<int:policy_id>", methods=["DELETE"])
@require_auth
def delete_policy(policy_id: int):
    """Delete a policy rule by ID."""
    db = g.db
    cursor = db.cursor()
    cursor.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
    db.commit()

    if cursor.rowcount == 0:
        return jsonify({"error": f"Policy ID {policy_id} not found."}), 404

    return jsonify({"status": "deleted", "id": policy_id})
