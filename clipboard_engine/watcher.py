"""
SentinelClip — Clipboard Watcher

Polls the OS clipboard at regular intervals, detects changes by hashing,
and dispatches new content through the detection → sanitization → reporting
pipeline.

Supports:
  1. Plain text clipboard content (CF_UNICODETEXT)
  2. File clipboard content when files are copied in Windows Explorer (CF_HDROP)
     extracting content from documents (.docx, .txt, .csv, .json, .py, etc.)
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
import zipfile
import xml.etree.ElementTree as ET
from typing import Callable, Optional, Tuple

import pyperclip

logger = logging.getLogger("sentinelclip.watcher")

# Try to import win32clipboard for Windows CF_HDROP support
try:
    import win32clipboard
    HAS_WIN32 = True
except ImportError:
    win32clipboard = None
    HAS_WIN32 = False


def extract_file_content(file_path: str, max_size: int = 5 * 1024 * 1024) -> str:
    """Safely extract scannable text from a file (up to max_size)."""
    if not os.path.isfile(file_path):
        return ""
    try:
        if os.path.getsize(file_path) > max_size:
            return ""
    except OSError:
        return ""

    ext = os.path.splitext(file_path)[1].lower()

    # Word .docx extraction (OpenXML standard library parser)
    if ext == ".docx":
        try:
            with zipfile.ZipFile(file_path, "r") as z:
                xml_data = z.read("word/document.xml")
                root = ET.fromstring(xml_data)
                texts = [elem.text for elem in root.iter() if elem.text]
                return " ".join(texts)
        except Exception as e:
            logger.debug("Failed to parse docx %s: %s", file_path, e)

    # Standard UTF-8 / ASCII text file reading
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        logger.debug("Failed to read text file %s: %s", file_path, e)

    return ""


class ClipboardWatcher:
    """
    Polls the clipboard for changes (text and copied files) and invokes on_change.
    
    Args:
        on_change: Callback function(text: str, source_filename: Optional[str] = None)
        poll_interval: Seconds between polls (default 0.2 = 200ms).
    """

    def __init__(self, on_change: Callable, poll_interval: float = 0.2):
        self.on_change = on_change
        self.poll_interval = poll_interval
        self._last_hash: str = ""
        self._running: bool = False

    def _hash_payload(self, text: str, source_filename: Optional[str] = None) -> str:
        """Hash clipboard payload for change detection."""
        key = f"{source_filename or ''}:{text}"
        return hashlib.md5(key.encode("utf-8", errors="replace")).hexdigest()

    def _get_clipboard_data(self) -> Tuple[str, Optional[str]]:
        """
        Safely read clipboard content.
        Returns:
            Tuple of (content_text, source_filename)
        """
        # Try win32clipboard first on Windows for CF_HDROP & CF_UNICODETEXT
        if HAS_WIN32:
            for _ in range(3):  # Retry briefly if clipboard is momentarily locked
                try:
                    win32clipboard.OpenClipboard()
                    try:
                        # 1. Check if files were copied in Windows Explorer (CF_HDROP)
                        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_HDROP):
                            file_paths = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)
                            if file_paths and len(file_paths) > 0:
                                target_path = file_paths[0]
                                filename = os.path.basename(target_path)
                                content = extract_file_content(target_path)
                                if content:
                                    return content, filename
                                return "", filename

                        # 2. Check if text is available (CF_UNICODETEXT)
                        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                            text = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                            if isinstance(text, str):
                                return text, None
                    finally:
                        win32clipboard.CloseClipboard()
                    break
                except Exception:
                    time.sleep(0.015)

        # Fallback to pyperclip for cross-platform text reading
        try:
            text = pyperclip.paste()
            if isinstance(text, str):
                return text, None
        except Exception as e:
            logger.debug(f"Clipboard read failed: {e}")

        return "", None

    def _dispatch_change(self, text: str, source_filename: Optional[str] = None):
        """Invoke on_change callback with backwards-compatible argument handling."""
        try:
            # Try passing both text and source_filename
            self.on_change(text, source_filename)
        except TypeError:
            # Fallback to single argument (text)
            self.on_change(text)

    def start(self):
        """Start the clipboard polling loop (blocking)."""
        self._running = True
        logger.info(
            f"Clipboard watcher started (poll interval: {self.poll_interval}s)"
        )

        # Initialize with current clipboard content (don't trigger on startup)
        current_text, current_file = self._get_clipboard_data()
        self._last_hash = self._hash_payload(current_text, current_file) if current_text else ""

        while self._running:
            try:
                current_text, current_file = self._get_clipboard_data()
                if not current_text:
                    time.sleep(self.poll_interval)
                    continue

                current_hash = self._hash_payload(current_text, current_file)
                if current_hash != self._last_hash:
                    self._last_hash = current_hash
                    desc = f"from '{current_file}'" if current_file else f"({len(current_text)} chars)"
                    logger.debug(f"Clipboard change detected {desc}")
                    try:
                        self._dispatch_change(current_text, current_file)
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
