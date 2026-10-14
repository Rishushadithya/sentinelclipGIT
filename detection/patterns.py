"""
SentinelClip Detection Engine — Shared Pattern Library

Contains seed regex/keyword patterns for detecting sensitive data.
All patterns are pre-compiled at import time for performance.
The SEED_RULES list populates config/default_policy.json on first run.
At runtime, rules are fetched from the Flask API (policies table).
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PolicyRule:
    """A single detection policy rule."""
    rule_name: str
    pattern: str
    pattern_type: str  # 'regex' | 'keyword'
    severity: str      # 'LOW' | 'MEDIUM' | 'HIGH'
    action: str        # 'WARN' | 'OBFUSCATE' | 'REDACT' | 'BLOCK'
    replacement_value: Optional[str] = None
    enabled: bool = True
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compiled_pattern(self) -> re.Pattern:
        """Return a compiled regex pattern, caching the result."""
        if self._compiled is None:
            if self.pattern_type == 'keyword':
                # Escape keyword for literal match, case-insensitive
                self._compiled = re.compile(re.escape(self.pattern), re.IGNORECASE)
            else:
                self._compiled = re.compile(self.pattern)
        return self._compiled


@dataclass
class Detection:
    """
    A single detection result.
    
    IMPORTANT: Does NOT contain the raw matched string — only metadata.
    This ensures the detection result itself is safe for logging without
    becoming a leak vector.
    """
    rule_name: str
    severity: str       # 'LOW' | 'MEDIUM' | 'HIGH'
    action: str         # 'WARN' | 'OBFUSCATE' | 'REDACT' | 'BLOCK'
    match_start: int    # start position in the input text
    match_end: int      # end position in the input text
    matched_len: int    # length of the matched string


# ---------------------------------------------------------------------------
# Seed rules — these are the default detection patterns from the spec.
# They populate config/default_policy.json and the policies DB table on
# first run. At runtime, rules come from the Flask API.
# ---------------------------------------------------------------------------

SEED_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_name="AWS Access Key",
        pattern=r"AKIA[0-9A-Z]{16}",
        pattern_type="regex",
        severity="HIGH",
        action="BLOCK",
    ),
    PolicyRule(
        rule_name="Generic API Key",
        pattern=r'(?i)(api[_\-]?key)["\'\s:=]+[A-Za-z0-9_\-]{16,}',
        pattern_type="regex",
        severity="HIGH",
        action="REDACT",
    ),
    PolicyRule(
        rule_name="Private IP Address",
        pattern=(
            r"\b("
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r")\b"
        ),
        pattern_type="regex",
        severity="MEDIUM",
        action="OBFUSCATE",
        replacement_value="[PRIVATE_IP]",
    ),
    PolicyRule(
        rule_name="Public IP Address",
        pattern=(
            r"\b(?:"
            r"(?!(?:10|127|169\.254|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))(?:\.\d{1,3}){2})"
            r"(?:\d{1,3}\.){3}\d{1,3}"
            r")\b"
        ),
        pattern_type="regex",
        severity="LOW",
        action="WARN",
        replacement_value="[PUBLIC_IP]",
    ),
    PolicyRule(
        rule_name="Email Address",
        pattern=r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        pattern_type="regex",
        severity="LOW",
        action="WARN",
    ),
    PolicyRule(
        rule_name="NIC / National ID (LK)",
        pattern=r"\b\d{9}[vVxX]\b|\b\d{12}\b",
        pattern_type="regex",
        severity="MEDIUM",
        action="REDACT",
    ),
    PolicyRule(
        rule_name="Credit Card Number",
        pattern=r"\b(?:\d[ \-]*?){13,16}\b",
        pattern_type="regex",
        severity="HIGH",
        action="BLOCK",
    ),
    PolicyRule(
        rule_name="JWT Token",
        pattern=r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        pattern_type="regex",
        severity="HIGH",
        action="BLOCK",
    ),
    PolicyRule(
        rule_name="Password Assignment",
        pattern=(
            r'(?i)(?:'
            r'\b(?:password|passwd|pwd|pass|pw|passcode|passphrase|userpass|loginpass|dbpass|db_password|authpass)\b\s*["\']?\s*(?:[:=])\s*["\']?\S+'
            r'|<\s*(?:password|passwd|pwd|pass|pw|passcode|passphrase|userpass|loginpass|dbpass|db_password|authpass)\s*>\s*[^<\r\n]+\s*<\s*/\s*(?:password|passwd|pwd|pass|pw|passcode|passphrase|userpass|loginpass|dbpass|db_password|authpass)\s*>'
            r')'
        ),
        pattern_type="regex",
        severity="HIGH",
        action="REDACT",
    ),
    PolicyRule(
        rule_name="RSA Private Key",
        pattern=r"-----BEGIN (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----",
        pattern_type="regex",
        severity="HIGH",
        action="BLOCK",
    ),
    PolicyRule(
        rule_name="Database Connection URI",
        pattern=r"(?i)\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis)://[^\s\"']+",
        pattern_type="regex",
        severity="HIGH",
        action="REDACT",
    ),
    PolicyRule(
        rule_name="GCP API Key",
        pattern=r"AIza[0-9A-Za-z_\-]{35}",
        pattern_type="regex",
        severity="HIGH",
        action="BLOCK",
    ),
]


def scan(text: str, rules: list[PolicyRule] = None) -> list[Detection]:
    """
    Scan the input text against all enabled policy rules.
    """
    if rules is None:
        rules = SEED_RULES
    detections: list[Detection] = []

    for rule in rules:
        if not rule.enabled:
            continue

        compiled = rule.compiled_pattern()
        for match in compiled.finditer(text):
            detections.append(Detection(
                rule_name=rule.rule_name,
                severity=rule.severity,
                action=rule.action,
                match_start=match.start(),
                match_end=match.end(),
                matched_len=match.end() - match.start(),
            ))

    return detections


def sanitize_payload(input_text: str, policy_rules: list[PolicyRule] = None) -> tuple[str, list[dict]]:
    """
    Appendix B.1 Implementation Pseudocode Function.
    
    Sanitizes input text by applying REDACT, OBFUSCATE, WARN, or BLOCK actions
    based on configured policy rules.
    
    Returns:
        tuple (sanitized_text, list_of_detections)
    """
    if policy_rules is None:
        policy_rules = SEED_RULES
        
    sanitized_text = input_text
    detections_list = []

    for rule in policy_rules:
        if not rule.enabled:
            continue
            
        compiled = rule.compiled_pattern()
        matches = list(compiled.finditer(sanitized_text))
        
        if matches:
            action = rule.action
            if action == "REDACT":
                sanitized_text = compiled.sub("[REDACTED]", sanitized_text)
            elif action == "OBFUSCATE":
                replacement = rule.replacement_value or "[OBFUSCATED]"
                sanitized_text = compiled.sub(replacement, sanitized_text)
            elif action == "WARN":
                detections_list.append({"rule": rule.rule_name, "severity": rule.severity, "action": "WARN"})
            elif action == "BLOCK":
                detections_list.append({"rule": rule.rule_name, "severity": rule.severity, "action": "BLOCK"})
                
            detections_list.append({
                "rule_name": rule.rule_name,
                "severity": rule.severity,
                "action": action
            })

    return sanitized_text, detections_list


def rules_from_dicts(rule_dicts: list[dict]) -> list[PolicyRule]:
    """
    Convert a list of rule dictionaries (e.g. from JSON or API response)
    into PolicyRule objects.
    """
    rules = []
    for d in rule_dicts:
        rules.append(PolicyRule(
            rule_name=d["rule_name"],
            pattern=d["pattern"],
            pattern_type=d["pattern_type"],
            severity=d["severity"],
            action=d["action"],
            replacement_value=d.get("replacement_value"),
            enabled=d.get("enabled", True),
        ))
    return rules
