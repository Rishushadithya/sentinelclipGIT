"""
SentinelClip — Settings Page

Change admin username and password.
Requires the current admin bearer token (obtained via login).
"""

import os
import sys
import requests
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import SentinelClipAPI
from dashboard.auth import require_login, render_user_sidebar
from dashboard.styles import inject_css, render_page_header

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SentinelClip — Settings",
    layout="wide",
)

require_login()
inject_css()

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    render_user_sidebar()

# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

API_BASE = os.getenv("SENTINELCLIP_API_BASE", "http://127.0.0.1:5000/api/v1")
token = st.session_state.get("token", "")
api = SentinelClipAPI(admin_token=token)

render_page_header(
    title="System Configuration",
    subtitle="Rotate administrator access credentials and inspect node runtime topology.",
    category="ADMINISTRATION",
)

# ---------------------------------------------------------------------------
# Change credentials
# ---------------------------------------------------------------------------

st.markdown("### Rotate Administrator Credentials")
st.markdown(
    "Update the username and password used to access this console.  \n"
    "Password requires a minimum length of **8 characters**."
)

with st.form("change_credentials_form"):
    col1, col2 = st.columns(2)

    with col1:
        new_username = st.text_input(
            "New Username",
            value=st.session_state.get("logged_in_user", "admin"),
            placeholder="admin",
        )
        new_password = st.text_input(
            "New Password",
            type="password",
            placeholder="Minimum 8 characters",
        )

    with col2:
        confirm_password = st.text_input(
            "Confirm New Password",
            type="password",
            placeholder="Repeat new password",
        )
        st.markdown("")  # spacing

    submitted = st.form_submit_button("Update Credentials", type="primary")

    if submitted:
        # Validate
        if not new_username.strip():
            st.error("Username cannot be empty.")
        elif not new_password:
            st.error("Password cannot be empty.")
        elif len(new_password) < 8:
            st.error("Password must be at least 8 characters.")
        elif new_password != confirm_password:
            st.error("Passwords do not match.")
        elif not token:
            st.error("No admin token in session. Please sign out and sign in again.")
        else:
            try:
                resp = requests.post(
                    f"{API_BASE}/admin/credentials",
                    json={"new_username": new_username.strip(), "new_password": new_password},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5,
                )
                if resp.status_code == 200:
                    st.success(
                        f"[SUCCESS] Credentials updated. New username: {new_username.strip()}. "
                        "Terminating session for re-authentication..."
                    )
                    # Sign out so the user re-authenticates with new credentials
                    for key in ("authenticated", "token", "admin_token", "logged_in_user"):
                        st.session_state.pop(key, None)
                    st.rerun()
                else:
                    error = resp.json().get("error", f"HTTP {resp.status_code}")
                    st.error(f"Failed to update credentials: {error}")
            except requests.RequestException as exc:
                st.error(f"Cannot reach API daemon: {exc}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Deployment information
# ---------------------------------------------------------------------------

st.markdown("### Deployment Node Topology")

try:
    import json
    from pathlib import Path
    project_root = Path(__file__).resolve().parent.parent.parent
    config_path = project_root / "config" / "deployment.json"
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            deployment = json.load(f)
    else:
        deployment = {"role": "both (default)", "api_base": API_BASE}

    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.metric("Node Role", deployment.get("role", "both").upper())
        st.metric("API Host", deployment.get("api_host", "0.0.0.0"))
    with info_col2:
        st.metric("API Port", str(deployment.get("api_port", 5000)))
        st.metric("Dashboard Port", str(deployment.get("dashboard_port", 8501)))

    st.caption(f"Configured API Target: `{API_BASE}`")

except Exception as exc:
    st.warning(f"Could not load deployment configuration: {exc}")

st.markdown("---")

# ---------------------------------------------------------------------------
# API health check
# ---------------------------------------------------------------------------

st.markdown("### API Service Health")

try:
    health = api.health()
    if health.get("status") == "ok":
        st.success(f"[ONLINE] API daemon responsive — version {health.get('version', '?')}")
    else:
        st.error("[ERROR] API daemon returned an unexpected status code.")
except Exception:
    st.error("[OFFLINE] Cannot establish connection with the SentinelClip API daemon.")
    st.info("Start daemon via: `py -m api.app`")
