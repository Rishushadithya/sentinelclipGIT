"""
SentinelClip — User Notification Helper

Shows user-facing Data Loss Prevention (DLP) notifications.
Uses custom high-contrast Windows 11 style DLP toast card (matching enterprise
endpoint DLP alerts), with fallback to plyer/logging if GUI is unavailable.
"""

from __future__ import annotations

import logging
from typing import Optional

from clipboard_engine.dlp_toast import show_dlp_toast

logger = logging.getLogger("sentinelclip.notifier")


def show_dlp_notification(
    rule_name: str,
    action: str = "BLOCK",
    source_filename: Optional[str] = None,
    detail: Optional[str] = None,
    timeout: int = 8,
) -> None:
    """
    Show a dedicated modern DLP toast card mentioning the specific violation.
    
    Args:
        rule_name: Triggered policy rule name (e.g. 'Credit Card Number').
        action: Action taken ('BLOCK', 'WARN', 'REDACT', 'OBFUSCATE').
        source_filename: Optional file name if the content originated from a file.
        detail: Optional extra violation context or match snippet.
        timeout: Auto-dismiss delay in seconds.
    """
    try:
        show_dlp_toast(
            rule_name=rule_name,
            action=action,
            source_filename=source_filename,
            detail=detail,
            timeout=timeout,
        )
    except Exception as exc:
        logger.warning("Custom DLP toast unavailable: %s", exc)
        show_warning_notification(
            title=f"SentinelClip DLP: {rule_name}",
            message=f"Action: {action}. Copy detected from {source_filename or 'clipboard'}.",
            timeout=timeout,
        )


def show_warning_notification(title: str, message: str, timeout: int = 6) -> None:
    """Show a warning notification using plyer as secondary fallback."""
    try:
        from plyer import notification

        notification.notify(
            title=title,
            message=message,
            app_name="SentinelClip",
            timeout=timeout,
        )
    except Exception as exc:
        logger.warning("Desktop notification unavailable: %s", exc)
        logger.warning("%s -- %s", title, message)
