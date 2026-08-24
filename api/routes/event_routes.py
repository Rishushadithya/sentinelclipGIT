"""
SentinelClip — Event & Health Routes

GET /api/v1/events         — Paginated/filterable audit log
GET /api/v1/health         — Liveness check
GET /api/v1/audit/verify   — Chain integrity verification
GET /api/v1/stats          — Summary statistics for dashboard
"""

import json
from flask import Blueprint, jsonify, request, g
from api.audit import verify_chain
from api.models import AuditEventModel

event_bp = Blueprint("events", __name__)


@event_bp.route("/api/v1/health", methods=["GET"])
def health_check():
    """Simple liveness check — confirms Flask API hub is running."""
    return jsonify({
        "status": "ok",
        "service": "SentinelClip API Hub",
        "version": "1.0.0",
    })


@event_bp.route("/api/v1/events", methods=["GET"])
def get_events():
    """
    Return paginated/filterable audit log entries.
    
    Query parameters:
        limit:    Max entries to return (default 100, max 1000)
        offset:   Offset for pagination (default 0)
        severity: Filter by severity (LOW | MEDIUM | HIGH)
        source:   Filter by source (clipboard | browser_upload)
        from:     Filter events after this ISO timestamp
        to:       Filter events before this ISO timestamp
    """
    db = g.db
    cursor = db.cursor()

    # Parse query parameters
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    source = request.args.get("source")
    date_from = request.args.get("from")
    date_to = request.args.get("to")

    # Build query dynamically
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if source:
        query += " AND source = ?"
        params.append(source)
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from)
    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to)

    # Get total count for pagination
    count_query = query.replace("SELECT *", "SELECT COUNT(*)")
    total = cursor.execute(count_query, params).fetchone()[0]

    # Add ordering and pagination
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = cursor.execute(query, params).fetchall()
    events = [AuditEventModel.from_row(row).to_dict() for row in rows]

    return jsonify({
        "events": events,
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@event_bp.route("/api/v1/audit/verify", methods=["GET"])
def verify_audit():
    """Verify the integrity of the hash-chained audit log."""
    db = g.db
    result = verify_chain(db)
    return jsonify(result)


@event_bp.route("/api/v1/stats", methods=["GET"])
def get_stats():
    """
    Return summary statistics for the dashboard.
    
    Returns counts of events by severity and source,
    total events today, and recent event count.
    """
    db = g.db
    cursor = db.cursor()

    # Total events
    total = cursor.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

    # Events today (UTC)
    from datetime import datetime, timezone
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    today_count = cursor.execute(
        "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?",
        (today_start,),
    ).fetchone()[0]

    # By severity
    severity_rows = cursor.execute(
        "SELECT severity, COUNT(*) as count FROM audit_log "
        "GROUP BY severity ORDER BY count DESC"
    ).fetchall()
    by_severity = {row["severity"]: row["count"] for row in severity_rows if row["severity"]}

    # By source
    source_rows = cursor.execute(
        "SELECT source, COUNT(*) as count FROM audit_log "
        "GROUP BY source ORDER BY count DESC"
    ).fetchall()
    by_source = {row["source"]: row["count"] for row in source_rows}

    # By action
    action_rows = cursor.execute(
        "SELECT action_taken, COUNT(*) as count FROM audit_log "
        "GROUP BY action_taken ORDER BY count DESC"
    ).fetchall()
    by_action = {row["action_taken"]: row["count"] for row in action_rows if row["action_taken"]}

    # Recent events (last 10)
    recent_rows = cursor.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 10"
    ).fetchall()
    recent = [AuditEventModel.from_row(row).to_dict() for row in recent_rows]

    return jsonify({
        "total_events": total,
        "events_today": today_count,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_action": by_action,
        "recent_events": recent,
    })
