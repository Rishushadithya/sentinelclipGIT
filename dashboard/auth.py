"""
SentinelClip Dashboard — Login Gate & Session Authentication

Enforces credential authentication on every dashboard page via PBKDF2-SHA256.
Respects node deployment role from deployment.json or environment:
    - server / both → full dashboard with login gate
    - agent         → info page: "Use the server dashboard at <url>"

Zero emojis, TryHackMe cyber-console styling.
"""

import os
from pathlib import Path
import json
import requests
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Helpers for role & host detection
# ---------------------------------------------------------------------------

def _get_deployment_config() -> dict:
    """Read config/deployment.json if present; fallback to environment."""
    config_file = _PROJECT_ROOT / "config" / "deployment.json"
    if config_file.exists():
        try:
            with open(config_file, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _get_deployment_role() -> str:
    """Return 'both', 'server', or 'agent'."""
    cfg = _get_deployment_config()
    return os.getenv("SENTINELCLIP_DEPLOY_ROLE", cfg.get("role", "both")).lower()


def _get_server_api_base() -> str:
    """Return the base URL of the central server API."""
    cfg = _get_deployment_config()
    return os.getenv(
        "SENTINELCLIP_API_BASE",
        cfg.get("api_base", "http://127.0.0.1:5000/api/v1"),
    )


def _is_agent_mode() -> bool:
    """Return True if this node is configured strictly as a client agent."""
    return _get_deployment_role() == "agent"


# ---------------------------------------------------------------------------
# Authentication logic
# ---------------------------------------------------------------------------

def _do_login(username: str, password: str) -> tuple[bool, str]:
    """
    Call POST /admin/login on the local/configured API.
    Returns (success, error_message_or_token).
    """
    api_base = _get_server_api_base()
    url = f"{api_base}/admin/login"

    try:
        resp = requests.post(
            url,
            json={"username": username, "password": password},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token", "")
            st.session_state["authenticated"] = True
            st.session_state["token"] = token
            st.session_state["admin_token"] = token
            st.session_state["logged_in_user"] = username
            return True, ""
        elif resp.status_code == 401:
            return False, "Invalid username or password."
        else:
            detail = resp.json().get("error", f"HTTP {resp.status_code}")
            return False, detail
    except requests.ConnectionError:
        return False, "Cannot reach the SentinelClip API daemon. Is it running?"
    except requests.Timeout:
        return False, "API request timed out."
    except requests.RequestException as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------

_LOGIN_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background-color: #0d1117 !important;
    background-image: radial-gradient(circle at 50% 20%, rgba(16, 185, 129, 0.05) 0%, transparent 60%) !important;
}

#MainMenu, footer, header { visibility: hidden; }

div[data-testid="stForm"] {
    background: #161c24 !important;
    border: 1px solid #283548 !important;
    border-radius: 8px !important;
    padding: 36px 32px 28px !important;
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7) !important;
}

div[data-testid="stForm"] label {
    color: #8b949e !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
}

div[data-testid="stForm"] input {
    background: #0d1117 !important;
    border: 1px solid #283548 !important;
    border-radius: 4px !important;
    color: #e6edf3 !important;
    font-family: 'Inter', sans-serif !important;
}

div[data-testid="stForm"] input:focus {
    border-color: #10b981 !important;
    box-shadow: 0 0 0 1px #10b981 !important;
}

div[data-testid="stForm"] button[kind="primaryFormSubmit"] {
    background: #10b981 !important;
    border: 1.5px solid #10b981 !important;
    border-radius: 4px !important;
    color: #04100b !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 800 !important;
    letter-spacing: 0.5px !important;
    text-transform: uppercase !important;
    transition: all 0.2s ease !important;
    min-height: 2.6rem !important;
}

div[data-testid="stForm"] button[kind="primaryFormSubmit"] * {
    color: #04100b !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 800 !important;
    letter-spacing: 0.5px !important;
    text-transform: uppercase !important;
}

div[data-testid="stForm"] button[kind="primaryFormSubmit"]:hover {
    background: #059669 !important;
    border-color: #059669 !important;
    color: #ffffff !important;
    box-shadow: 0 0 14px rgba(16, 185, 129, 0.5) !important;
}

div[data-testid="stForm"] button[kind="primaryFormSubmit"]:hover * {
    color: #ffffff !important;
}

.sc-login-logo {
    text-align: center;
    margin-bottom: 28px;
}
.sc-login-category {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: #10b981;
    font-weight: 700;
    letter-spacing: 1.5px;
    margin-bottom: 6px;
}
.sc-login-logo h1 {
    color: #ffffff;
    font-size: 22px;
    font-weight: 700;
    margin: 0;
    letter-spacing: -0.02em;
}
.sc-login-logo p {
    color: #8b949e;
    font-size: 13px;
    margin: 6px 0 0;
}

.sc-login-hint {
    color: #8b949e;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    text-align: center;
    margin-top: 18px;
    line-height: 1.6;
}
</style>
"""

_AGENT_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: #0d1117; }
#MainMenu, footer, header { visibility: hidden; }
.sc-agent-card {
    max-width: 520px;
    margin: 80px auto 0;
    background: #161c24;
    border: 1px solid #283548;
    border-radius: 8px;
    padding: 48px 40px;
    box-shadow: 0 24px 64px rgba(0,0,0,0.6);
    text-align: center;
}
.sc-agent-card h1 { color: #ffffff; font-size: 20px; font-weight: 700; margin: 0 0 12px; }
.sc-agent-card p  { color: #8b949e; font-size: 14px; line-height: 1.7; margin: 0; }
.sc-agent-card a  { color: #10b981; text-decoration: none; font-family: 'JetBrains Mono', monospace; }
.sc-agent-badge {
    display: inline-block;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.35);
    border-radius: 4px;
    padding: 4px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    color: #10b981;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 20px;
}
</style>
"""


def _render_login_page():
    """Render the full-screen username/password login form."""
    st.markdown(_LOGIN_CSS, unsafe_allow_html=True)

    _, center, _ = st.columns([1, 1.4, 1])
    with center:
        st.markdown("""
<div class="sc-login-logo">
    <div class="sc-login-category">// ACCESS CONTROL</div>
    <h1>SentinelClip SOC</h1>
    <p>Administrative Console Authentication</p>
</div>
""", unsafe_allow_html=True)

        with st.form("sc_login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="admin", autocomplete="username")
            password = st.text_input("Password", type="password",
                                     placeholder="Enter your password",
                                     autocomplete="current-password")
            submitted = st.form_submit_button(
                "Authenticate", type="primary", use_container_width=True
            )

            if submitted:
                if not username.strip() or not password:
                    st.error("Please enter both username and password.")
                else:
                    with st.spinner("Authenticating credentials..."):
                        ok, err = _do_login(username.strip(), password)
                    if ok:
                        st.rerun()
                    else:
                        st.error(f"[AUTH ERROR] {err}")

        st.markdown("""
<div class="sc-login-hint">
    DEFAULT: <code>admin</code> / <code>sentinelclip</code><br>
    Credential rotation available under Settings.
</div>
""", unsafe_allow_html=True)


def _render_agent_mode_page():
    """Info screen shown when this node is an agent (no local dashboard)."""
    api_base = _get_server_api_base()
    server_origin = api_base.replace("/api/v1", "")
    dashboard_url = server_origin.replace(":5000", ":8501")

    st.markdown(_AGENT_CSS, unsafe_allow_html=True)
    st.markdown(f"""
<div class="sc-agent-card">
    <div class="sc-agent-badge">[AGENT MODE ACTIVE]</div>
    <h1>Dashboard Not Hosted Locally</h1>
    <p>
        This endpoint is operating as a <strong>SentinelClip Endpoint Agent</strong>
        and streams telemetry to the central server.<br><br>
        Access the centralized SOC console at:<br>
        <a href="{dashboard_url}" target="_blank">{dashboard_url}</a>
    </p>
</div>
""", unsafe_allow_html=True)
    st.stop()


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def require_login() -> bool:
    """
    Enforce the authentication gate. Must be called at the top of every
    dashboard page (after st.set_page_config).
    """
    if _is_agent_mode():
        _render_agent_mode_page()
        return False

    if not st.session_state.get("authenticated"):
        _render_login_page()
        st.stop()
        return False

    return True


def render_user_sidebar():
    """
    Render the logged-in user chip and Logout button in the sidebar.
    """
    user = st.session_state.get("logged_in_user", "admin")
    role = _get_deployment_role().upper()
    st.sidebar.markdown(
        f'<div style="color:#8b949e;font-family:\'JetBrains Mono\', monospace;font-size:10px;font-weight:600;'
        f'text-transform:uppercase;letter-spacing:.8px;margin-bottom:3px;">'
        f'// OPERATOR SESSION</div>'
        f'<div style="color:#ffffff;font-family:\'JetBrains Mono\', monospace;font-size:13px;font-weight:700;'
        f'margin-bottom:2px;">USER: {user}</div>'
        f'<div style="color:#8b949e;font-family:\'JetBrains Mono\', monospace;font-size:11px;">NODE ROLE: [{role}]</div>',
        unsafe_allow_html=True,
    )
    if st.sidebar.button("Sign Out", use_container_width=True):
        for key in ("authenticated", "token", "admin_token", "logged_in_user"):
            st.session_state.pop(key, None)
        st.rerun()
