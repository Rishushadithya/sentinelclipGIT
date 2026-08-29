"""
SentinelClip — User Notification Helper

Shows user-facing warning notifications. Uses plyer when available and falls
back to console output if desktop notifications are unavailable.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("sentinelclip.notifier")


def show_warning_notification(title: str, message: str, timeout: int = 6) -> None:
    """Show a warning notification without raising errors to callers."""
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
