"""
SentinelClip — Data Models

Data classes for policy rules and audit events, matching the SQLite schema.
Used for type-safe data passing between API layers.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class PolicyRuleModel:
    """Represents a policy rule from the policies table."""
    id: Optional[int] = None
    rule_name: str = ""
    pattern: str = ""
    pattern_type: str = "regex"       # 'regex' | 'keyword'
    severity: str = "LOW"             # 'LOW' | 'MEDIUM' | 'HIGH'
    action: str = "WARN"              # 'WARN' | 'OBFUSCATE' | 'REDACT' | 'BLOCK'
    replacement_value: Optional[str] = None
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "action": self.action,
            "replacement_value": self.replacement_value,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_row(cls, row) -> "PolicyRuleModel":
        return cls(
            id=row["id"],
            rule_name=row["rule_name"],
            pattern=row["pattern"],
            pattern_type=row["pattern_type"],
            severity=row["severity"],
            action=row["action"],
            replacement_value=row["replacement_value"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


@dataclass
class AuditEventModel:
    """Represents an audit log entry from the audit_log table."""
    id: Optional[int] = None
    timestamp: str = ""
    source: str = ""                   # 'clipboard' | 'browser_upload'
    pc_user_name: Optional[str] = None
    domain: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    action_taken: Optional[str] = None
    detection_summary: Optional[str] = None  # JSON string
    previous_hash: str = ""
    current_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "pc_user_name": self.pc_user_name,
            "domain": self.domain,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "action_taken": self.action_taken,
            "detection_summary": self.detection_summary,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
        }

    @classmethod
    def from_row(cls, row) -> "AuditEventModel":
        return cls(
            id=row["id"],
            timestamp=row["timestamp"],
            source=row["source"],
            pc_user_name=row["pc_user_name"] if "pc_user_name" in row.keys() else None,
            domain=row["domain"],
            rule_name=row["rule_name"],
            severity=row["severity"],
            action_taken=row["action_taken"],
            detection_summary=row["detection_summary"],
            previous_hash=row["previous_hash"],
            current_hash=row["current_hash"],
        )
