"""Register the SentinelClip native host for Chrome and/or Edge on Windows."""

import json
import re
import winreg
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
HOST_NAME = "com.sentinelclip.host"
MANIFEST_PATH = APP_ROOT / "native_host" / "com.sentinelclip.host.json"
HOST_PATH = APP_ROOT / "native_host" / "SentinelClipNativeHost.exe"
BROWSER_REGISTRY_KEYS = {
    "Chrome": r"Software\Google\Chrome\NativeMessagingHosts\com.sentinelclip.host",
    "Edge": r"Software\Microsoft\Edge\NativeMessagingHosts\com.sentinelclip.host",
}


def register_native_host(chrome_id: str = "", edge_id: str = "") -> list[str]:
    """Write the native-host manifest and per-user browser registry entries."""
    browser_ids = {"Chrome": chrome_id.strip(), "Edge": edge_id.strip()}
    browser_ids = {name: value for name, value in browser_ids.items() if value}
    if not browser_ids:
        raise ValueError("Enter at least one Chrome or Edge extension ID.")

    for browser, extension_id in browser_ids.items():
        if not re.fullmatch(r"[a-p]{32}", extension_id):
            raise ValueError(f"The {browser} extension ID must be 32 letters from a to p.")

    manifest = {
        "name": HOST_NAME,
        "description": "SentinelClip native upload scanner",
        "path": str(HOST_PATH),
        "type": "stdio",
        "allowed_origins": [
            f"chrome-extension://{extension_id}/"
            for extension_id in browser_ids.values()
        ],
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    for browser in browser_ids:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, BROWSER_REGISTRY_KEYS[browser]) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(MANIFEST_PATH))

    return list(browser_ids)