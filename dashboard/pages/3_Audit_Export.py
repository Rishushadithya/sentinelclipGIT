"""
SentinelClip — Audit Export Page

CSV export of audit log and "Verify Audit Integrity" button.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import SentinelClipAPI
from dashboard.auth import require_login, render_user_sidebar
from dashboard.styles import inject_css, render_page_header

st.set_page_config(
    page_title="SentinelClip — Audit Export",
    layout="wide",
)

require_login()
inject_css()

# ---------------------------------------------------------------------------
# Initialize
# ---------------------------------------------------------------------------

with st.sidebar:
    render_user_sidebar()

token = st.session_state.get("token", "")
api = SentinelClipAPI(admin_token=token)

render_page_header(
    title="Audit Ledger & Export",
    subtitle="Export audit events and cryptographically verify SHA-256 tamper-evident integrity.",
    category="COMPLIANCE",
)

# ---------------------------------------------------------------------------
# Audit Chain Verification
# ---------------------------------------------------------------------------

st.markdown("### Cryptographic Ledger Verification")
st.markdown(
    "The audit log employs SHA-256 hash chaining to ensure tamper-evidence. "
    "Each entry incorporates the hash of its preceding record, forming an immutable sequence. "
    "Verification recomputes all hashes from genesis to head."
)

col1, col2 = st.columns([1.5, 3.5])

with col1:
    verify_btn = st.button("Verify Chain Integrity", type="primary", use_container_width=True)

if verify_btn:
    with st.spinner("Computing SHA-256 hash sequence..."):
        try:
            result = api.verify_audit()

            if result.get("valid"):
                st.success(f"[INTEGRITY CONFIRMED] {result.get('message', 'Audit chain is intact.')}")
                st.markdown(
                    f"**Entries verified:** `{result.get('verified_entries', 0)} / "
                    f"{result.get('total_entries', 0)}`"
                )
            else:
                st.error(f"[TAMPER DETECTED] {result.get('message', 'Chain verification failed!')}")
                if result.get("first_mismatch_id"):
                    st.warning(
                        f"First mismatch detected at entry ID: "
                        f"**{result['first_mismatch_id']}**"
                    )
                st.markdown(
                    f"**Verified before failure:** `{result.get('verified_entries', 0)} / "
                    f"{result.get('total_entries', 0)}`"
                )

        except Exception as e:
            st.error(f"Verification request failed: {e}")

st.markdown("---")

# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

st.markdown("### Export Audit Log")
st.markdown("Download full historical telemetry and DLP incident records.")

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

if st.button("Generate CSV Export", type="primary"):
    with st.spinner("Generating dataset export..."):
        try:
            params = {"limit": export_limit}
            if export_severity != "All":
                params["severity"] = export_severity
            if export_source != "All":
                params["source"] = export_source

            csv_data = api.export_events_csv(**params)

            if csv_data:
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name="sentinelclip_audit_log.csv",
                    mime="text/csv",
                    type="primary",
                )
                st.success("Export generated. Click Download CSV to save.")

                # Preview
                import pandas as pd
                import io
                df = pd.read_csv(io.StringIO(csv_data))
                st.markdown(f"**Dataset Preview** (`{len(df)} records`)")
                st.dataframe(df.head(20), use_container_width=True, hide_index=True)
            else:
                st.info("No events found matching the specified parameters.")

        except Exception as e:
            st.error(f"Export failed: {e}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Audit stats summary
# ---------------------------------------------------------------------------

st.markdown("### Audit Ledger Metrics")

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
        st.metric("Blocked Events", blocked)

except Exception as e:
    st.error(f"Could not load summary metrics: {e}")
