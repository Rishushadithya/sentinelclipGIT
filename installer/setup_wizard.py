"""Configure a SentinelClip Server, Agent, or combined installation."""

import ctypes
import getpass
import json
import platform
import socket
import sys
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path

import requests


APP_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_ROOT))
CONFIG_DIR = APP_ROOT / "config"
DEPLOYMENT_FILE = CONFIG_DIR / "deployment.json"
LOCAL_API_BASE = "http://127.0.0.1:5000/api/v1"


def get_lan_ip() -> str:
    """Return the IPv4 address selected for outbound LAN traffic."""
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        connection.connect(("192.0.2.1", 80))
        return connection.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        connection.close()


def request_firewall_rule() -> bool:
    """Ask Windows for elevation to allow the API from the local subnet."""
    command = (
        "New-NetFirewallRule -DisplayName 'SentinelClip API (Private LAN)' "
        "-Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 "
        "-RemoteAddress LocalSubnet -Profile Private -ErrorAction SilentlyContinue"
    )
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        "powershell.exe",
        f'-NoProfile -ExecutionPolicy Bypass -Command "{command}"',
        None,
        0,
    )
    return result > 32


def create_initial_enrollment_code(enroll_local_agent: bool) -> str:
    """Initialize the server database and mint a one-time enrollment code."""
    from api.app import create_app
    from api.auth import get_or_create_admin_token
    from clipboard_engine.device_credentials import save_device_credentials

    app = create_app()
    token = get_or_create_admin_token()
    with app.test_client() as client:
        response = client.post(
            "/api/v1/devices/enrollment-codes",
            headers={"Authorization": f"Bearer {token}"},
            json={"expires_minutes": 10},
        )
        if response.status_code != 201:
            raise RuntimeError(response.get_json().get("error", "Could not create enrollment code."))
        code = response.get_json()["code"]

        if enroll_local_agent:
            enrollment = client.post(
                "/api/v1/devices/enroll",
                json={
                    "code": code,
                    "hostname": platform.node() or "unknown-host",
                    "os_user": getpass.getuser(),
                    "ip_address": get_lan_ip(),
                },
            )
            if enrollment.status_code != 201:
                raise RuntimeError(enrollment.get_json().get("error", "Could not enroll the local agent."))
            credentials = enrollment.get_json()
            save_device_credentials(credentials["device_id"], credentials["device_token"])

            response = client.post(
                "/api/v1/devices/enrollment-codes",
                headers={"Authorization": f"Bearer {token}"},
                json={"expires_minutes": 10},
            )
            if response.status_code != 201:
                raise RuntimeError(response.get_json().get("error", "Could not create remote enrollment code."))
            code = response.get_json()["code"]
    return code


class SetupWizard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SentinelClip Setup")
        self.root.resizable(False, False)
        self.role = tk.StringVar(value="Server")
        self.server_url = tk.StringVar(value=f"http://{get_lan_ip()}:5000/api/v1")
        self.enrollment_code = tk.StringVar()
        self.create_firewall = tk.BooleanVar(value=True)
        self._build_form()

    def _build_form(self):
        self.root.columnconfigure(1, weight=1)
        ttk.Label(self.root, text="Choose how this PC will run SentinelClip.").grid(
            row=0, column=0, columnspan=2, padx=18, pady=(18, 12), sticky="w"
        )
        ttk.Label(self.root, text="PC role").grid(row=1, column=0, padx=18, pady=5, sticky="w")
        role_box = ttk.Combobox(
            self.root,
            textvariable=self.role,
            values=("Server", "Agent", "Both"),
            state="readonly",
            width=34,
        )
        role_box.grid(row=1, column=1, padx=18, pady=5, sticky="ew")
        role_box.bind("<<ComboboxSelected>>", self._update_role_fields)

        self.url_label = ttk.Label(self.root, text="Server API URL")
        self.url_label.grid(row=2, column=0, padx=18, pady=5, sticky="w")
        self.url_entry = ttk.Entry(self.root, textvariable=self.server_url, width=48)
        self.url_entry.grid(row=2, column=1, padx=18, pady=5, sticky="ew")

        self.code_label = ttk.Label(self.root, text="One-time enrollment code")
        self.code_label.grid(row=3, column=0, padx=18, pady=5, sticky="w")
        self.code_entry = ttk.Entry(self.root, textvariable=self.enrollment_code, width=48)
        self.code_entry.grid(row=3, column=1, padx=18, pady=5, sticky="ew")

        self.firewall_box = ttk.Checkbutton(
            self.root,
            text="Allow API access from this private LAN (administrator approval required)",
            variable=self.create_firewall,
        )
        self.firewall_box.grid(row=4, column=0, columnspan=2, padx=18, pady=10, sticky="w")

        buttons = ttk.Frame(self.root)
        buttons.grid(row=5, column=0, columnspan=2, padx=18, pady=(4, 18), sticky="e")
        ttk.Button(buttons, text="Finish Setup", command=self.finish).pack(side="right")
        self._update_role_fields()

    def _update_role_fields(self, _event=None):
        is_agent = self.role.get() == "Agent"
        is_server = self.role.get() in {"Server", "Both"}
        for widget in (self.url_label, self.url_entry, self.code_label, self.code_entry):
            widget.grid_remove()
        if is_agent:
            self.url_label.grid(row=2, column=0, padx=18, pady=5, sticky="w")
            self.url_entry.grid(row=2, column=1, padx=18, pady=5, sticky="ew")
            self.code_label.grid(row=3, column=0, padx=18, pady=5, sticky="w")
            self.code_entry.grid(row=3, column=1, padx=18, pady=5, sticky="ew")
        self.firewall_box.grid() if is_server else self.firewall_box.grid_remove()

    def finish(self):
        role = self.role.get().lower()
        server_url = self.server_url.get().strip().rstrip("/")
        code = self.enrollment_code.get().strip()
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        enrollment_code = ""

        try:
            if role == "agent":
                if not server_url.startswith(("http://", "https://")) or not code:
                    raise ValueError("Enter a valid server API URL and enrollment code.")
                response = requests.post(
                    f"{server_url}/devices/enroll",
                    json={
                        "code": code,
                        "hostname": platform.node() or "unknown-host",
                        "os_user": getpass.getuser(),
                    },
                    timeout=10,
                )
                response.raise_for_status()
                credentials = response.json()
                from clipboard_engine.device_credentials import save_device_credentials

                save_device_credentials(credentials["device_id"], credentials["device_token"])
                api_base = server_url
            else:
                api_base = LOCAL_API_BASE
                enrollment_code = create_initial_enrollment_code(role == "both")

            settings = {
                "role": role,
                "api_base": api_base,
                "api_host": "0.0.0.0" if role in {"server", "both"} else "127.0.0.1",
                "api_port": 5000,
                "dashboard_host": "127.0.0.1",
                "dashboard_port": 8501,
            }
            DEPLOYMENT_FILE.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        except (OSError, ValueError, RuntimeError, requests.RequestException, KeyError) as exc:
            messagebox.showerror("Setup failed", str(exc), parent=self.root)
            return

        firewall_message = ""
        if role in {"server", "both"} and self.create_firewall.get():
            if not request_firewall_rule():
                firewall_message = "\nWindows did not approve the firewall rule. Add a Private-profile TCP 5000 rule for LocalSubnet before remote agents connect."

        if enrollment_code:
            self.root.clipboard_clear()
            self.root.clipboard_append(enrollment_code)
            message = (
                f"Server ready at http://{get_lan_ip()}:5000/api/v1\n\n"
                f"Initial one-time enrollment code (expires in 10 minutes):\n{enrollment_code}\n\n"
                "The code was copied to the clipboard. Use the tray menu to create later codes."
            )
        else:
            message = "Agent enrolled successfully. Its device credentials were saved on this PC."
        messagebox.showinfo("SentinelClip is configured", message + firewall_message, parent=self.root)
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    SetupWizard().run()