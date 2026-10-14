"""
Tests for SentinelClip DLP Desktop Toast Notifications and Watcher file support.
"""

import os
import zipfile
import xml.etree.ElementTree as ET
import pytest

from clipboard_engine.dlp_toast import get_violation_category, show_dlp_toast
from clipboard_engine.notifier import show_dlp_notification
from clipboard_engine.watcher import extract_file_content, ClipboardWatcher


def test_violation_categories():
    """Verify friendly categories for DLP policy rules."""
    assert get_violation_category("Credit Card Number") == "Financial data"
    assert get_violation_category("Password Assignment") == "Credentials / Passwords"
    assert get_violation_category("AWS Access Key") == "Cloud API credentials"
    assert get_violation_category("Generic API Key") == "Secret API keys"
    assert get_violation_category("JWT Token") == "Authentication tokens"
    assert get_violation_category("NIC / National ID (LK)") == "Government identification"
    assert get_violation_category("NonExistentRule") == "Sensitive data"


def test_extract_file_content_plain_text(tmp_path):
    """Verify extracting content from a plain text file."""
    text_file = tmp_path / "sample.txt"
    text_file.write_text("Password = 'Secret123'", encoding="utf-8")

    content = extract_file_content(str(text_file))
    assert "Password = 'Secret123'" in content


def test_extract_file_content_docx(tmp_path):
    """Verify extracting text from a .docx file structure."""
    docx_file = tmp_path / "Cards.docx"
    
    # Create minimal docx zip structure
    xml_content = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>James Smith 4929-3813-3266-4295</w:t></w:r></w:p></w:body>'
        '</w:document>'
    )
    
    with zipfile.ZipFile(docx_file, "w") as z:
        z.writestr("word/document.xml", xml_content)

    content = extract_file_content(str(docx_file))
    assert "James Smith 4929-3813-3266-4295" in content


def test_show_dlp_toast_does_not_crash(monkeypatch):
    """Verify show_dlp_notification does not raise errors."""
    called = []
    monkeypatch.setattr(
        "clipboard_engine.dlp_toast._run_toast_window",
        lambda rule, action, src, detail, to: called.append((rule, action, src)),
    )

    show_dlp_notification(
        rule_name="Credit Card Number",
        action="BLOCK",
        source_filename="Cards.docx",
        detail="Financial data copy to clipboard detected",
    )

    assert len(called) == 1
    assert called[0] == ("Credit Card Number", "BLOCK", "Cards.docx")
