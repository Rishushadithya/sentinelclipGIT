"""SentinelClip — Enrolled Devices Page"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import SentinelClipAPI

st.set_page_config(page_title="SentinelClip — Devices", page_icon="🖥️", layout="wide")

st.title("🖥️ Enrolled Devices")
st.caption("LAN agents enrolled with the central SentinelClip server.")

token = st.session_state.get("token", "")
if not token:
    st.warning("Enter the admin token on the Home page to view enrolled devices.")
    st.stop()

api = SentinelClipAPI(admin_token=token)
try:
    devices = api.get_devices()
except Exception as exc:
    st.error(f"Could not fetch devices: {exc}")
    st.stop()

if not devices:
    st.info("No devices have been enrolled yet.")
    st.stop()

online_count = sum(device.get("status") == "online" for device in devices)
col1, col2, col3 = st.columns(3)
col1.metric("Total Devices", len(devices))
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
        "Status": status,
        "Hostname": device.get("hostname", ""),
        "OS User": device.get("os_user", ""),
        "IP Address": device.get("ip_address", ""),
        "Group": device.get("group_name") or "Unassigned",
        "Last Seen": last_seen or "Never",
        "Enrolled": device.get("enrolled_at", ""),
        "Device ID": device.get("id", ""),
    })

st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
