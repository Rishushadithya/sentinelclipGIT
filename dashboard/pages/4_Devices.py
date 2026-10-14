"""SentinelClip — Enrolled Devices & Agent Enrollment Page"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import SentinelClipAPI
from dashboard.auth import require_login, render_user_sidebar
from dashboard.styles import inject_css, render_page_header

st.set_page_config(page_title="SentinelClip — Devices", layout="wide")

require_login()
inject_css()

with st.sidebar:
    render_user_sidebar()

render_page_header(
    title="Fleet Management & Enrollment",
    subtitle="Monitor connected endpoint agents and rotate cryptographic enrollment codes.",
    category="FLEET OPERATIONS",
)

token = st.session_state.get("token", "")
api = SentinelClipAPI(admin_token=token)

# ---------------------------------------------------------------------------
# Agent Add / Enroll Code Card
# ---------------------------------------------------------------------------
st.subheader("Agent Enrollment Token")
st.caption(
    "Provide this one-time token to a client agent during initial setup. "
    "Once the agent pairs with the server, this token is automatically rotated."
)

try:
    enroll_info = api.get_enrollment_code()
    current_code = enroll_info.get("code", "")
    expires_at_raw = enroll_info.get("expires_at", "")
except Exception as exc:
    st.error(f"Could not fetch enrollment token: {exc}")
    current_code = ""
    expires_at_raw = ""

if current_code:
    code_col, action_col = st.columns([3, 1])

    with code_col:
        st.code(current_code, language="text")
        st.markdown(
            "**[ACTIVE TOKEN]** One-time enrollment token consumed on first device pairing. "
            "A fresh token is automatically issued upon successful agent registration."
        )

    with action_col:
        st.write("")  # vertical spacing
        if st.button("Rotate Token", use_container_width=True, help="Manually rotate to a fresh enrollment code"):
            try:
                new_info = api.create_enrollment_code()
                st.success("New enrollment token generated.")
                st.rerun()
            except Exception as exc:
                st.error(f"Failed to rotate token: {exc}")

    with st.expander("Agent Pairing Instructions"):
        server_host = os.getenv("SENTINELCLIP_SERVER_HOST", "http://<SERVER-IP>:5000/api/v1")
        st.markdown(
            f"""
            **Method A: Interactive Setup Wizard**
            1. Launch the **SentinelClip Setup Wizard** on the target client workstation.
            2. Select **Client Agent** installation role.
            3. Supply the Central Server URL (`{server_host}`) and provide this enrollment token.
            
            **Method B: Headless Terminal / Scripted Deployment**
            Execute in PowerShell on the endpoint workstation:
            ```powershell
            $env:SENTINELCLIP_API_BASE = "{server_host}"
            $env:SENTINELCLIP_ENROLLMENT_CODE = "{current_code}"
            python -m clipboard_engine.main
            ```
            
            *Upon initial contact, the agent will authenticate, store its paired certificate, and this token will cycle immediately.*
            """
        )

st.markdown("---")

# ---------------------------------------------------------------------------
# Enrolled Devices List
# ---------------------------------------------------------------------------
st.subheader("Active Fleet Roster")

try:
    devices = api.get_devices()
except Exception as exc:
    st.error(f"Could not fetch devices: {exc}")
    st.stop()

if not devices:
    st.info("No endpoint devices registered. Use the enrollment token above to connect an endpoint agent.")
    st.stop()

online_count = sum(device.get("status") == "online" for device in devices)
col1, col2, col3 = st.columns(3)
col1.metric("Total Endpoints", len(devices))
col2.metric("Online", online_count)
col3.metric("Offline", len(devices) - online_count)

rows = []
for device in devices:
    last_seen = device.get("last_seen")
    if last_seen:
        try:
            seen_at = datetime.fromisoformat(last_seen)
            if seen_at.tzinfo is None:
                seen_at = seen_at.replace(tzinfo=timezone.utc)
            status = "Online" if datetime.now(timezone.utc) - seen_at <= timedelta(minutes=2) else "Offline"
        except ValueError:
            status = "Offline"
    else:
        status = "Offline"
    rows.append({
        "Status": "[ONLINE]" if status == "Online" else "[OFFLINE]",
        "Hostname": device.get("hostname", ""),
        "OS User": device.get("os_user", ""),
        "IP Address": device.get("ip_address", ""),
        "Group": device.get("group_name") or "Unassigned",
        "Last Seen": last_seen or "Never",
        "Enrolled": device.get("enrolled_at", ""),
        "Device ID": device.get("id", ""),
    })

st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
