"""
SentinelClip — Admin Dashboard (Home)

Summary metrics: total events, severity breakdown, source breakdown,
and recent activity feed.

Run with: streamlit run dashboard/Home.py
"""

import os
import sys
import streamlit as st

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.api_client import SentinelClipAPI
from dashboard.auth import require_login, render_user_sidebar
from dashboard.styles import (
    inject_css,
    render_page_header,
    online_badge,
)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SentinelClip — Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Authentication gate
# ---------------------------------------------------------------------------

require_login()
inject_css()

# ---------------------------------------------------------------------------
# Sidebar — Auth & API status
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## SentinelClip SOC")
    st.caption("Endpoint DLP Monitoring Console")
    st.markdown("---")

    # User info and logout button
    render_user_sidebar()

    st.markdown("---")

    # Initialize API client using token from login session
    token = st.session_state.get("token", "")
    api = SentinelClipAPI(admin_token=token)

    # API status
    st.markdown("### API Daemon Status")
    try:
        health = api.health()
        if health.get("status") == "ok":
            st.markdown(online_badge(True), unsafe_allow_html=True)
            st.caption(f"Engine Core v{health.get('version', '?')}")
        else:
            st.markdown(online_badge(False), unsafe_allow_html=True)
    except Exception:
        st.markdown(online_badge(False), unsafe_allow_html=True)
        st.caption("Daemon offline: `py -m api.app`")

    st.markdown("---")
    try:
        enroll_data = api.get_enrollment_code()
        quick_code = enroll_data.get("code")
        if quick_code:
            st.markdown("**Agent Enrollment Code**")
            st.code(quick_code, language="text")
            st.caption("One-time token to pair next endpoint device.")
    except Exception:
        pass

    if st.button("Refresh Feed", use_container_width=True):
        st.rerun()


# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

render_page_header(
    title="Security Operations Console",
    subtitle="Real-time telemetry, threat mitigation metrics, and endpoint audit activity.",
    category="OVERVIEW",
)

try:
    stats = api.get_stats()

    # Summary metrics row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Total Events",
            value=stats.get("total_events", 0),
        )

    with col2:
        st.metric(
            label="Events Today",
            value=stats.get("events_today", 0),
        )

    with col3:
        high_count = stats.get("by_severity", {}).get("HIGH", 0)
        st.metric(
            label="High Severity",
            value=high_count,
        )

    with col4:
        blocked = stats.get("by_action", {}).get("BLOCK", 0)
        st.metric(
            label="Blocked Actions",
            value=blocked,
        )

    st.markdown("---")

    # Charts row
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("### Severity Distribution")
        by_severity = stats.get("by_severity", {})
        if by_severity:
            import pandas as pd
            df_severity = pd.DataFrame(
                list(by_severity.items()),
                columns=["Severity", "Count"],
            )
            st.bar_chart(df_severity.set_index("Severity"))
        else:
            st.info("No events recorded yet.")

    with chart_col2:
        st.markdown("### Detection Vectors")
        by_source = stats.get("by_source", {})
        if by_source:
            import pandas as pd
            df_source = pd.DataFrame(
                list(by_source.items()),
                columns=["Source", "Count"],
            )
            st.bar_chart(df_source.set_index("Source"))
        else:
            st.info("No events recorded yet.")

    # Action breakdown
    st.markdown("### Enforcement Actions")
    by_action = stats.get("by_action", {})
    if by_action:
        action_cols = st.columns(len(by_action))
        for i, (action, count) in enumerate(by_action.items()):
            with action_cols[i]:
                st.metric(label=action or "N/A", value=count)

    st.markdown("---")

    # Recent events
    st.markdown("### Recent Incident Stream")
    recent = stats.get("recent_events", [])
    if recent:
        import pandas as pd
        df_recent = pd.DataFrame(recent)
        display_cols = [
            "id", "timestamp", "source", "domain", "rule_name",
            "severity", "action_taken",
        ]
        available_cols = [c for c in display_cols if c in df_recent.columns]
        st.dataframe(
            df_recent[available_cols],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No incidents detected. Active monitoring is listening on endpoint clipboards.")

except Exception as e:
    st.error(f"Could not connect to SentinelClip API daemon: {e}")
    st.info(
        "Make sure the Flask API hub is running:\n\n"
        "```\npy -m api.app\n```"
    )
