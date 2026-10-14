"""
SentinelClip — Windows Desktop Application & System Tray App

Runs as a native Windows tray app without open console windows (using pythonw.exe).
Auto-elevates to Administrator if required, manages all 3 background services
(Flask API, Clipboard Engine, Streamlit Dashboard), and provides a system tray
menu with quick actions.
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

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

PYTHON_EXE = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")
PYTHONW_EXE = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "pythonw.exe")
STREAMLIT_EXE = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "streamlit.exe")
STREAMLIT_HOST = os.getenv("SENTINELCLIP_DASHBOARD_HOST", "0.0.0.0")
STREAMLIT_PORT = os.getenv("SENTINELCLIP_DASHBOARD_PORT", "8501")

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


def is_admin() -> bool:
    """Check if the current process has Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_as_admin():
    """Relaunch current script with Administrator elevation via UAC."""
    script = os.path.abspath(sys.argv[0])
    params = f'"{script}"'
    # Use pythonw if available to prevent black CMD window
    executable = PYTHONW_EXE if os.path.exists(PYTHONW_EXE) else sys.executable

    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, params, PROJECT_ROOT, 1
    )
    sys.exit(0)


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
    """Start all 3 background services."""
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    # 1. Flask API Hub
    if processes["api"] is None or processes["api"].poll() is not None:
        processes["api"] = subprocess.Popen(
            [PYTHON_EXE, "-m", "api.app"],
            cwd=PROJECT_ROOT,
            creationflags=creation_flags,
        )

    # Give API a moment to spin up
    time.sleep(1.5)

    # 2. Clipboard Sentinel Engine
    if processes["clipboard"] is None or processes["clipboard"].poll() is not None:
        processes["clipboard"] = subprocess.Popen(
            [PYTHON_EXE, "-m", "clipboard_engine.main"],
            cwd=PROJECT_ROOT,
            creationflags=creation_flags,
        )

    # 3. Streamlit Dashboard
    if processes["dashboard"] is None or processes["dashboard"].poll() is not None:
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
    webbrowser.open("http://localhost:8501")


def verify_audit_integrity(icon=None, item=None):
    """Call API to verify audit chain integrity and show a notification."""
    try:
        resp = requests.get("http://127.0.0.1:5000/api/v1/audit/verify", timeout=5)
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


def quit_app(icon, item):
    """Exit the system tray application and stop services."""
    stop_services()
    icon.stop()


def main():
    instance = SingleInstance()
    if instance.already_running:
        instance.request_restart()
        return

    # Enforce elevation if not admin (ensures registry & low-level clipboard access)
    if not is_admin():
        run_as_admin()
        return

    # Start background services
    start_services()

    # Create system tray icon
    image = create_tray_icon_image()
    menu = pystray.Menu(
        item("🛡️ SentinelClip DLP (Active)", lambda icon, item: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item("📊 Open Dashboard", open_dashboard, default=True),
        item("🔍 Verify Audit Chain Integrity", verify_audit_integrity),
        pystray.Menu.SEPARATOR,
        item("🚪 Exit SentinelClip", quit_app),
    )

    icon = pystray.Icon("SentinelClip", image, "SentinelClip DLP Middleware", menu)

    def restart_current_instance():
        stop_services()
        icon.stop()

    instance.watch_for_restart(restart_current_instance)
    
    # Auto open dashboard on start
    threading.Thread(target=lambda: (time.sleep(2), webbrowser.open("http://localhost:8501")), daemon=True).start()

    try:
        icon.run()
    finally:
        instance.close()


if __name__ == "__main__":
    main()
