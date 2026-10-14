"""
Unit tests for SentinelClip browser extension files and native messaging host.
"""

import json
import os
import pytest
from pathlib import Path

from native_host.native_host import scan_content


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXT_DIR = PROJECT_ROOT / "browser_extension"


def test_manifest_structure():
    """Verify manifest.json is valid MV3 with main-world and isolated-world content scripts."""
    manifest_path = EXT_DIR / "manifest.json"
    assert manifest_path.exists(), "manifest.json does not exist"

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("manifest_version") == 3
    assert "nativeMessaging" in data.get("permissions", [])

    content_scripts = data.get("content_scripts", [])
    assert len(content_scripts) >= 2, "Expected both main-world and isolated-world scripts"

    # Check main-world interceptor
    main_world_scripts = [
        cs for cs in content_scripts
        if cs.get("world") == "MAIN" and "page_interceptor.js" in cs.get("js", [])
    ]
    assert len(main_world_scripts) == 1, "Missing page_interceptor.js with world=MAIN"
    assert main_world_scripts[0].get("run_at") == "document_start"

    # Check isolated content script
    isolated_scripts = [
        cs for cs in content_scripts
        if "content_script.js" in cs.get("js", [])
    ]
    assert len(isolated_scripts) == 1, "Missing content_script.js"
    assert isolated_scripts[0].get("run_at") == "document_start"

    # Check web_accessible_resources
    war = data.get("web_accessible_resources", [])
    assert any("page_interceptor.js" in r.get("resources", []) for r in war)


def test_extension_scripts_exist():
    """Verify all required extension script files exist and have non-trivial content."""
    for filename in ["page_interceptor.js", "content_script.js", "background.js", "rules.json"]:
        file_path = EXT_DIR / filename
        assert file_path.exists(), f"Missing {filename}"
        assert file_path.stat().st_size > 100, f"{filename} is too small"


def test_native_host_scan_blocks_sample_secrets():
    """Verify scan_content blocks content matching Password Assignment in sample_secrets.txt."""
    secrets_file = PROJECT_ROOT / "sample_secrets.txt"
    assert secrets_file.exists(), "sample_secrets.txt not found"
    content = secrets_file.read_text(encoding="utf-8")

    result = scan_content(
        domain="chatgpt.com",
        filename="sample_secrets.txt",
        content=content,
    )

    assert result["verdict"] == "BLOCK"
    assert "Password Assignment" in result.get("detections", "")


def test_native_host_scan_allows_benign_content():
    """Verify scan_content allows ordinary text with no sensitive data."""
    benign_text = "This is a simple meeting summary for tomorrow's standup."
    result = scan_content(
        domain="claude.ai",
        filename="notes.txt",
        content=benign_text,
    )

    assert result["verdict"] == "ALLOW"
    assert result.get("reason") == "clean"
