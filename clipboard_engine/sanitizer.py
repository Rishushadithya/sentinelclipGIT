"""
SentinelClip Sanitizer — Redact / Obfuscate / Block / Warn logic

Applies policy actions to detected sensitive content in text.
Works with Detection objects from the detection engine.
"""

import re
from typing import Optional
from detection.patterns import PolicyRule, Detection, scan


def sanitize_payload(
    input_text: str,
    policy_rules: list[PolicyRule],
) -> tuple[str, list[dict]]:
    """
    Scan input text against policy rules and apply sanitization actions.
    
    Actions:
      - REDACT:    Replace matched content with [REDACTED]
      - OBFUSCATE: Replace matched content with the rule's replacement_value
      - WARN:      Flag for user warning but do not modify text
      - BLOCK:     Flag for blocking the entire operation
    
    Args:
        input_text:    The raw text to sanitize.
        policy_rules:  List of active PolicyRule objects.
        
    Returns:
        Tuple of:
          - sanitized_text: The text after applying REDACT/OBFUSCATE actions
          - detections_log: List of detection metadata dicts (safe for audit logging)
    """
    detections_log: list[dict] = []
    block_required = False
    warning_required = False

    # Collect all matches with their actions, sorted by position (reverse)
    # so we can replace from end to start without shifting indices
    all_replacements: list[dict] = []

    for rule in policy_rules:
        if not rule.enabled:
            continue

        compiled = rule.compiled_pattern()
        for match in compiled.finditer(input_text):
            detection_entry = {
                "rule_name": rule.rule_name,
                "severity": rule.severity,
                "action": rule.action,
                "match_start": match.start(),
                "match_end": match.end(),
                "matched_len": match.end() - match.start(),
            }

            if rule.rule_name == "Public IP Address":
                detection_entry["classification"] = "public_ip"
            elif rule.rule_name == "Private IP Address":
                detection_entry["classification"] = "private_ip"

            detections_log.append(detection_entry)

            if rule.action == "REDACT":
                all_replacements.append({
                    "start": match.start(),
                    "end": match.end(),
                    "replacement": "[REDACTED]",
                })
            elif rule.action == "OBFUSCATE":
                replacement = rule.replacement_value or "[OBFUSCATED]"
                all_replacements.append({
                    "start": match.start(),
                    "end": match.end(),
                    "replacement": replacement,
                })
            elif rule.action == "BLOCK":
                block_required = True
            elif rule.action == "WARN":
                warning_required = True

    # Sort replacements by start position descending to preserve indices
    all_replacements.sort(key=lambda r: r["start"], reverse=True)

    # Remove overlapping replacements (keep the one with earlier start)
    # Since sorted descending, we process from end to start
    sanitized_text = input_text
    used_ranges: list[tuple[int, int]] = []

    for repl in all_replacements:
        start, end = repl["start"], repl["end"]
        # Check for overlap with already-applied replacements
        overlaps = False
        for used_start, used_end in used_ranges:
            if start < used_end and end > used_start:
                overlaps = True
                break
        if not overlaps:
            sanitized_text = (
                sanitized_text[:start] + repl["replacement"] + sanitized_text[end:]
            )
            used_ranges.append((start, end))

    # If BLOCK is required, replace entire content
    if block_required:
        sanitized_text = "[BLOCKED — Sensitive content detected by SentinelClip]"

    # Add meta flags to detections log
    if block_required:
        detections_log.insert(0, {"type": "block_required"})
    if warning_required:
        detections_log.insert(0, {"type": "warning_required"})

    return sanitized_text, detections_log
