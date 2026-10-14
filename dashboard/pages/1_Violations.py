"""
SentinelClip — Violations Page

Filterable/searchable table of audit log entries.
Filters: severity, source, date range. Pagination included.
"""

import os
import sys
import json
import streamlit as st
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import SentinelClipAPI


def format_detection_summary(value: str) -> str:
    """Turn stored detection JSON into a compact, readable table value."""
    if not value:
        return "No detection details"

    try:
        detections = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return "Detection details unavailable"

    rule_detections = [
        detection for detection in detections
        if isinstance(detection, dict) and detection.get("rule_name")
    ]
    if not rule_detections:
        return "No rule details"

    labels = []
    for detection in rule_detections:
        label = detection["rule_name"]
        action = detection.get("action")
        if action:
            label = f"{label} ({action})"
        labels.append(label)

    visible_labels = labels[:2]
    summary = ", ".join(visible_labels)
    if len(labels) > len(visible_labels):
        summary += f" +{len(labels) - len(visible_labels)} more"
    return f"{len(labels)} detection{'s' if len(labels) != 1 else ''} · {summary}"

st.set_page_config(
    page_title="SentinelClip — Violations",
    page_icon="🔍",
    layout="wide",
)

# Reuse custom CSS from Home
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    .stApp { background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%); }
    h1, h2, h3 { color: #e0e0ff !important; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Initialize
# ---------------------------------------------------------------------------

token = st.session_state.get("token", "")
api = SentinelClipAPI(admin_token=token)

st.markdown("# 🔍 Violations Log")
st.markdown("Browse and filter all detected security events.")
st.markdown("---")

# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)

with filter_col1:
    severity_filter = st.selectbox(
        "Severity",
        options=["All", "HIGH", "MEDIUM", "LOW"],
        index=0,
    )

with filter_col2:
    source_filter = st.selectbox(
        "Source",
        options=["All", "clipboard", "browser_upload"],
        index=0,
    )

with filter_col3:
    date_from = st.date_input("From Date", value=None)

with filter_col4:
    date_to = st.date_input("To Date", value=None)

# Pagination
page_size = st.selectbox("Results per page", [25, 50, 100, 250], index=1)
page_num = st.number_input("Page", min_value=1, value=1, step=1)
offset = (page_num - 1) * page_size

# ---------------------------------------------------------------------------
# Fetch and display
# ---------------------------------------------------------------------------

try:
    params = {
        "limit": page_size,
        "offset": offset,
    }
    if severity_filter != "All":
        params["severity"] = severity_filter
    if source_filter != "All":
        params["source"] = source_filter
    if date_from:
        params["date_from"] = date_from.isoformat()
    if date_to:
        params["date_to"] = date_to.isoformat()

    data = api.get_events(**params)
    events = data.get("events", [])
    total = data.get("total", 0)

    st.markdown(f"**{total}** total events matching filters | Showing page {page_num}")
    st.markdown("---")

    if events:
        df = pd.DataFrame(events)

        # Format display
        display_cols = [
            "id", "timestamp", "source", "pc_user_name", "domain", "rule_name",
            "severity", "action_taken", "detection_summary",
        ]
        available_cols = [c for c in display_cols if c in df.columns]

        if "detection_summary" in df.columns:
            df["detection_summary"] = df["detection_summary"].apply(
                format_detection_summary
            )

        # Color-code severity
        def style_severity(val):
            colors = {
                "HIGH": "color: #e94560; font-weight: bold",
                "MEDIUM": "color: #f0a500; font-weight: bold",
                "LOW": "color: #00d4ff; font-weight: bold",
            }
            return colors.get(val, "")

        st.dataframe(
            df[available_cols],
            use_container_width=True,
            hide_index=True,
            height=600,
            column_config={
                "id": st.column_config.NumberColumn("ID", width="small"),
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "pc_user_name": st.column_config.TextColumn("PC User", width="small"),
                "detection_summary": st.column_config.TextColumn(
                    "Detection Summary", width="large"
                ),
            },
        )

        # Pagination info
        total_pages = max(1, (total + page_size - 1) // page_size)
        st.caption(f"Page {page_num} of {total_pages}")

    else:
        st.info("No events found matching the selected filters.")

except Exception as e:
    st.error(f"Could not fetch events: {e}")
    st.info("Make sure the Flask API hub is running.")
