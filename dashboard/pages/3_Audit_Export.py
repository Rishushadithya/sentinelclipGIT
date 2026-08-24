"""
SentinelClip — Audit Export Page

CSV export of audit log and "Verify Audit Integrity" button.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import SentinelClipAPI

st.set_page_config(
    page_title="SentinelClip — Audit Export",
    page_icon="📊",
    layout="wide",
)

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

st.markdown("# 📊 Audit Export & Integrity")
st.markdown("Export audit data and verify chain integrity.")
st.markdown("---")

# ---------------------------------------------------------------------------
# Audit Chain Verification
# ---------------------------------------------------------------------------

st.markdown("### 🔗 Audit Chain Integrity")
st.markdown(
    "The audit log uses SHA-256 hash chaining to ensure tamper-evidence. "
    "Each entry's hash incorporates the previous entry's hash, creating an "
    "immutable chain. Verification recomputes all hashes and checks for mismatches."
)

col1, col2 = st.columns([1, 3])

with col1:
    verify_btn = st.button("🔍 Verify Integrity", type="primary", use_container_width=True)

if verify_btn:
    with st.spinner("Verifying audit chain integrity..."):
        try:
            result = api.verify_audit()

            if result.get("valid"):
                st.success(f"✅ {result.get('message', 'Chain is intact.')}")
                st.markdown(
                    f"**Entries verified:** {result.get('verified_entries', 0)} / "
                    f"{result.get('total_entries', 0)}"
                )
            else:
                st.error(f"🚨 {result.get('message', 'Chain verification failed!')}")
                if result.get("first_mismatch_id"):
                    st.warning(
                        f"First mismatch detected at entry ID: "
                        f"**{result['first_mismatch_id']}**"
                    )
                st.markdown(
                    f"**Verified before failure:** "
                    f"{result.get('verified_entries', 0)} / "
                    f"{result.get('total_entries', 0)}"
                )

        except Exception as e:
            st.error(f"Verification failed: {e}")

st.markdown("---")

# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

st.markdown("### 📥 Export Audit Log")
st.markdown("Download the full audit log as a CSV file.")

export_col1, export_col2, export_col3 = st.columns(3)

with export_col1:
    export_severity = st.selectbox(
        "Filter by Severity",
        options=["All", "HIGH", "MEDIUM", "LOW"],
        index=0,
        key="export_severity",
    )

with export_col2:
    export_source = st.selectbox(
        "Filter by Source",
        options=["All", "clipboard", "browser_upload"],
        index=0,
        key="export_source",
    )

with export_col3:
    export_limit = st.number_input(
        "Max Records",
        min_value=10,
        max_value=10000,
        value=1000,
        step=100,
        key="export_limit",
    )

if st.button("📥 Generate CSV Export", type="primary"):
    with st.spinner("Generating export..."):
        try:
            params = {"limit": export_limit}
            if export_severity != "All":
                params["severity"] = export_severity
            if export_source != "All":
                params["source"] = export_source

            csv_data = api.export_events_csv(**params)

            if csv_data:
                st.download_button(
                    label="⬇️ Download CSV",
                    data=csv_data,
                    file_name="sentinelclip_audit_log.csv",
                    mime="text/csv",
                    type="primary",
                )
                st.success(f"Export ready — click Download to save.")

                # Preview
                import pandas as pd
                import io
                df = pd.read_csv(io.StringIO(csv_data))
                st.markdown(f"**Preview** ({len(df)} records)")
                st.dataframe(df.head(20), use_container_width=True, hide_index=True)
            else:
                st.info("No events found matching the selected filters.")

        except Exception as e:
            st.error(f"Export failed: {e}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Audit stats summary
# ---------------------------------------------------------------------------

st.markdown("### 📈 Audit Summary")

try:
    stats = api.get_stats()

    stat_col1, stat_col2, stat_col3 = st.columns(3)

    with stat_col1:
        st.metric("Total Events", stats.get("total_events", 0))

    with stat_col2:
        st.metric("Events Today", stats.get("events_today", 0))

    with stat_col3:
        by_action = stats.get("by_action", {})
        blocked = by_action.get("BLOCK", 0)
        st.metric("Total Blocked", blocked)

except Exception as e:
    st.error(f"Could not fetch stats: {e}")
