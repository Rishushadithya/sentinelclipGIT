"""
SentinelClip — Clipboard Watcher

Polls the OS clipboard at regular intervals, detects changes by hashing,
and dispatches new content through the detection → sanitization → reporting
pipeline.

Uses pyperclip for cross-platform clipboard access.
On Windows, uses a 200ms polling interval for sub-150ms effective latency.
"""

import hashlib
import time
import logging
import pyperclip

logger = logging.getLogger("sentinelclip.watcher")


class ClipboardWatcher:
    """
    Polls the clipboard for changes and calls a callback with new content.
    
    Args:
        on_change: Callback function(text: str) called when clipboard changes.
        poll_interval: Seconds between polls (default 0.2 = 200ms).
    """

    def __init__(self, on_change, poll_interval: float = 0.2):
        self.on_change = on_change
        self.poll_interval = poll_interval
        self._last_hash: str = ""
        self._running: bool = False

    def _hash_text(self, text: str) -> str:
        """Hash clipboard text for change detection."""
        return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()

    def _get_clipboard(self) -> str:
        """Safely read clipboard content."""
        try:
            text = pyperclip.paste()
            return text if isinstance(text, str) else ""
        except Exception as e:
            logger.debug(f"Clipboard read failed: {e}")
            return ""

    def start(self):
        """Start the clipboard polling loop (blocking)."""
        self._running = True
        logger.info(
            f"Clipboard watcher started (poll interval: {self.poll_interval}s)"
        )

        # Initialize with current clipboard content (don't trigger on startup)
        current = self._get_clipboard()
        self._last_hash = self._hash_text(current) if current else ""

        while self._running:
            try:
                current = self._get_clipboard()
                if not current:
                    time.sleep(self.poll_interval)
                    continue

                current_hash = self._hash_text(current)
                if current_hash != self._last_hash:
                    self._last_hash = current_hash
                    logger.debug(f"Clipboard change detected ({len(current)} chars)")
                    try:
                        self.on_change(current)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                time.sleep(self.poll_interval)

            except KeyboardInterrupt:
                logger.info("Clipboard watcher stopped by user.")
                break
            except Exception as e:
                logger.error(f"Watcher loop error: {e}")
                time.sleep(self.poll_interval)

    def stop(self):
        """Stop the polling loop."""
        self._running = False
        logger.info("Clipboard watcher stopping...")
