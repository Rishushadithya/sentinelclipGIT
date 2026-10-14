"""
SentinelClip — Windows Desktop Application & System Tray App

Runs as a native Windows tray app without open console windows (using pythonw.exe).
Manages the services selected during setup and provides a system tray menu.
"""

import os
import sys
import time
import subprocess
import threading
import ctypes
import webbrowser
import requests
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item
from deployment_config import load_deployment_config, services_for_role

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
DEPLOYMENT = load_deployment_config(os.path.join(PROJECT_ROOT, "config", "deployment.json"))
RUN_API, RUN_CLIPBOARD, RUN_DASHBOARD = services_for_role(DEPLOYMENT["role"])
os.environ["SENTINELCLIP_API_BASE"] = DEPLOYMENT["api_base"]
os.environ["SENTINELCLIP_HOST"] = DEPLOYMENT["api_host"]
os.environ["SENTINELCLIP_PORT"] = str(DEPLOYMENT["api_port"])
os.environ["SENTINELCLIP_DASHBOARD_HOST"] = DEPLOYMENT["dashboard_host"]
os.environ["SENTINELCLIP_DASHBOARD_PORT"] = str(DEPLOYMENT["dashboard_port"])

PYTHON_EXE = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")
PYTHONW_EXE = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "pythonw.exe")
STREAMLIT_EXE = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "streamlit.exe")
STREAMLIT_HOST = os.environ["SENTINELCLIP_DASHBOARD_HOST"]
STREAMLIT_PORT = os.environ["SENTINELCLIP_DASHBOARD_PORT"]
LOCAL_API_BASE = f"http://127.0.0.1:{DEPLOYMENT['api_port']}/api/v1"
ADMIN_TOKEN_FILE = os.path.join(PROJECT_ROOT, "config", ".admin_token")

if not os.path.exists(PYTHON_EXE):
    PYTHON_EXE = sys.executable
if not os.path.exists(PYTHONW_EXE):
    PYTHONW_EXE = sys.executable

# Process handles
processes = {
    "api": None,
    "clipboard": None,
    "dashboard": None,
}


class SingleInstance:
    """Coordinate one launcher instance and support restart-on-second-launch."""

    MUTEX_NAME = "Global\\SentinelClip.DesktopLauncher"
    RESTART_EVENT_NAME = "Global\\SentinelClip.DesktopLauncher.Restart"

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.mutex = self.kernel32.CreateMutexW(None, True, self.MUTEX_NAME)
        self.already_running = self.kernel32.GetLastError() == 183
        self.restart_event = self.kernel32.CreateEventW(
            None, False, False, self.RESTART_EVENT_NAME
        )

    def request_restart(self):
        """Ask the active launcher to stop so this new launch can replace it."""
        existing_event = self.kernel32.OpenEventW(0x0002, False, self.RESTART_EVENT_NAME)
        if existing_event:
            self.kernel32.SetEvent(existing_event)
            self.kernel32.CloseHandle(existing_event)

        # Wait until the old launcher releases its mutex before taking over.
        self.kernel32.WaitForSingleObject(self.mutex, 10000)
        self.kernel32.CloseHandle(self.mutex)
        if self.restart_event:
            self.kernel32.CloseHandle(self.restart_event)

    def watch_for_restart(self, on_restart):
        """Run a lightweight wait loop that stops the active launcher on request."""
        def wait_loop():
            result = self.kernel32.WaitForSingleObject(self.restart_event, 1000)
            if result == 0:
                on_restart()

        threading.Thread(target=wait_loop, daemon=True).start()

    def close(self):
        """Release the named synchronization handles."""
        if self.restart_event:
            self.kernel32.CloseHandle(self.restart_event)
            self.restart_event = None
        if self.mutex:
            self.kernel32.ReleaseMutex(self.mutex)
            self.kernel32.CloseHandle(self.mutex)
            self.mutex = None


def create_tray_icon_image() -> Image.Image:
    """Create a 64x64 shield icon for system tray if image asset isn't found."""
    icon_path = os.path.join(PROJECT_ROOT, "browser_extension", "icons", "icon48.png")
    if os.path.exists(icon_path):
        return Image.open(icon_path)

    # Fallback generated icon
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Background circle
    draw.ellipse((4, 4, 60, 60), fill=(26, 26, 46, 255), outline=(0, 212, 255, 255), width=3)
    # Shield shape
    draw.polygon([(32, 14), (50, 22), (50, 40), (32, 54), (14, 40), (14, 22)], fill=(0, 212, 255, 255))
    return img


def start_services():
    """Start only the background services selected by the installed role."""
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    if RUN_API and (processes["api"] is None or processes["api"].poll() is not None):
        processes["api"] = subprocess.Popen(
            [PYTHON_EXE, "-m", "api.app"],
            cwd=PROJECT_ROOT,
            creationflags=creation_flags,
        )

    if RUN_API:
        time.sleep(1.5)

    if RUN_CLIPBOARD and (processes["clipboard"] is None or processes["clipboard"].poll() is not None):
        processes["clipboard"] = subprocess.Popen(
            [PYTHON_EXE, "-m", "clipboard_engine.main"],
            cwd=PROJECT_ROOT,
            creationflags=creation_flags,
        )

    if RUN_DASHBOARD and (processes["dashboard"] is None or processes["dashboard"].poll() is not None):
        if os.path.exists(STREAMLIT_EXE):
            cmd = [STREAMLIT_EXE, "run", "dashboard/Home.py", "--server.address", STREAMLIT_HOST, "--server.port", STREAMLIT_PORT, "--server.headless", "true"]
        else:
            cmd = [PYTHON_EXE, "-m", "streamlit", "run", "dashboard/Home.py", "--server.address", STREAMLIT_HOST, "--server.port", STREAMLIT_PORT, "--server.headless", "true"]

        processes["dashboard"] = subprocess.Popen(
            cmd,
            cwd=PROJECT_ROOT,
            creationflags=creation_flags,
        )


def stop_services():
    """Gracefully terminate all background services."""
    for name, proc in processes.items():
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            processes[name] = None


def open_dashboard(icon=None, item=None):
    """Open Streamlit Dashboard in default browser."""
    webbrowser.open(f"http://localhost:{STREAMLIT_PORT}")


def verify_audit_integrity(icon=None, item=None):
    """Call API to verify audit chain integrity and show a notification."""
    try:
        api_base = os.environ["SENTINELCLIP_API_BASE"]
        resp = requests.get(f"{api_base}/audit/verify", timeout=5)
        data = resp.json()
        if data.get("valid"):
            msg = f"Audit Chain Valid! All {data.get('verified_entries', 0)} entries verified."
            title = "SentinelClip Integrity OK"
        else:
            msg = f"TAMPERING DETECTED! First mismatch at ID {data.get('first_mismatch_id')}."
            title = "SentinelClip Integrity Warning!"

        icon.notify(msg, title)
    except Exception as e:
        icon.notify(f"Could not connect to API: {e}", "SentinelClip Error")


def create_agent_enrollment_code(icon=None, item=None):
    """Create a short-lived enrollment code and copy it for the administrator."""
    try:
        with open(ADMIN_TOKEN_FILE, "r", encoding="utf-8") as token_file:
            admin_token = token_file.read().strip()
        response = requests.post(
            f"{LOCAL_API_BASE}/devices/enrollment-codes",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"expires_minutes": 10},
            timeout=5,
        )
        response.raise_for_status()
        code = response.json()["code"]
        import pyperclip

        pyperclip.copy(code)
        icon.notify("One-time code copied. It expires in 10 minutes.", "SentinelClip Enrollment")
    except Exception as exc:
        icon.notify(f"Could not create enrollment code: {exc}", "SentinelClip Error")


def main():
    instance = SingleInstance()
    if instance.already_running:
        instance.request_restart()
        return

    # Start background services
    start_services()

    # Create system tray icon
    image = create_tray_icon_image()
    menu = pystray.Menu(
        item(f"SentinelClip DLP ({DEPLOYMENT['role'].title()})", lambda icon, item: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item("Open Dashboard", open_dashboard, default=True, enabled=RUN_DASHBOARD),
        item(
            "Copy Agent Enrollment Code",
            create_agent_enrollment_code,
            enabled=RUN_API,
        ),
        item("Verify Audit Chain Integrity", verify_audit_integrity),
    )

    icon = pystray.Icon("SentinelClip", image, "SentinelClip DLP Middleware", menu)

    def restart_current_instance():
        stop_services()
        icon.stop()

    instance.watch_for_restart(restart_current_instance)
    
    if RUN_DASHBOARD:
        threading.Thread(
            target=lambda: (time.sleep(2), open_dashboard()), daemon=True
        ).start()

    try:
        icon.run()
    finally:
        instance.close()


if __name__ == "__main__":
    main()
