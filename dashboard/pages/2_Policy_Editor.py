"""
SentinelClip — Policy Editor Page

CRUD UI for managing detection policy rules.
Add new rules, edit existing ones, enable/disable, delete.
Requires admin token authentication.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import SentinelClipAPI

st.set_page_config(
    page_title="SentinelClip — Policy Editor",
    page_icon="📋",
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

st.markdown("# 📋 Policy Editor")
st.markdown("Manage detection rules for sensitive content patterns.")
st.markdown("---")

if not token:
    st.warning("⚠️ Enter your admin token in the sidebar on the Home page to edit policies.")

# ---------------------------------------------------------------------------
# Add New Rule
# ---------------------------------------------------------------------------

with st.expander("➕ Add New Rule", expanded=False):
    with st.form("new_rule_form"):
        col1, col2 = st.columns(2)

        with col1:
            new_name = st.text_input("Rule Name *", placeholder="e.g., GitHub Token")
            new_pattern = st.text_area(
                "Pattern *",
                placeholder="Regex or keyword pattern",
                height=80,
            )
            new_type = st.selectbox(
                "Pattern Type",
                options=["regex", "keyword"],
                index=0,
            )

        with col2:
            new_severity = st.selectbox(
                "Severity",
                options=["LOW", "MEDIUM", "HIGH"],
                index=2,
            )
            new_action = st.selectbox(
                "Action",
                options=["WARN", "OBFUSCATE", "REDACT", "BLOCK"],
                index=3,
            )
            new_replacement = st.text_input(
                "Replacement Value",
                placeholder="Used when action is OBFUSCATE",
            )

        submitted = st.form_submit_button("Create Rule", type="primary")

        if submitted:
            if not new_name or not new_pattern:
                st.error("Rule name and pattern are required.")
            elif not token:
                st.error("Admin token is required. Enter it on the Home page sidebar.")
            else:
                try:
                    result = api.update_policy({
                        "rule_name": new_name,
                        "pattern": new_pattern,
                        "pattern_type": new_type,
                        "severity": new_severity,
                        "action": new_action,
                        "replacement_value": new_replacement or None,
                        "enabled": True,
                    })
                    st.success(f"✅ Rule created (ID: {result.get('id')})")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to create rule: {e}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Existing Rules
# ---------------------------------------------------------------------------

st.markdown("### Current Rules")

try:
    if token:
        rules = api.get_all_policies()
    else:
        rules = api.get_policies()

    if not rules:
        st.info("No policy rules configured.")
    else:
        for rule in rules:
            rule_id = rule.get("id", "?")
            enabled = rule.get("enabled", True)
            severity = rule.get("severity", "?")

            # Severity color
            severity_colors = {
                "HIGH": "🔴",
                "MEDIUM": "🟡",
                "LOW": "🔵",
            }
            severity_icon = severity_colors.get(severity, "⚪")

            # Status indicator
            status = "✅" if enabled else "❌"

            with st.expander(
                f"{severity_icon} {rule.get('rule_name', 'Unnamed')} — "
                f"{rule.get('action', '?')} | {status} {'Enabled' if enabled else 'Disabled'}"
            ):
                with st.form(f"edit_rule_{rule_id}"):
                    edit_col1, edit_col2 = st.columns(2)

                    with edit_col1:
                        edit_name = st.text_input(
                            "Rule Name",
                            value=rule.get("rule_name", ""),
                            key=f"name_{rule_id}",
                        )
                        edit_pattern = st.text_area(
                            "Pattern",
                            value=rule.get("pattern", ""),
                            height=80,
                            key=f"pattern_{rule_id}",
                        )
                        edit_type = st.selectbox(
                            "Pattern Type",
                            options=["regex", "keyword"],
                            index=0 if rule.get("pattern_type") == "regex" else 1,
                            key=f"type_{rule_id}",
                        )

                    with edit_col2:
                        severity_options = ["LOW", "MEDIUM", "HIGH"]
                        edit_severity = st.selectbox(
                            "Severity",
                            options=severity_options,
                            index=severity_options.index(severity)
                            if severity in severity_options else 0,
                            key=f"severity_{rule_id}",
                        )
                        action_options = ["WARN", "OBFUSCATE", "REDACT", "BLOCK"]
                        current_action = rule.get("action", "WARN")
                        edit_action = st.selectbox(
                            "Action",
                            options=action_options,
                            index=action_options.index(current_action)
                            if current_action in action_options else 0,
                            key=f"action_{rule_id}",
                        )
                        edit_replacement = st.text_input(
                            "Replacement Value",
                            value=rule.get("replacement_value", "") or "",
                            key=f"replacement_{rule_id}",
                        )
                        edit_enabled = st.checkbox(
                            "Enabled",
                            value=enabled,
                            key=f"enabled_{rule_id}",
                        )

                    btn_col1, btn_col2, _ = st.columns([1, 1, 4])

                    with btn_col1:
                        update_btn = st.form_submit_button("💾 Save", type="primary")

                    with btn_col2:
                        delete_btn = st.form_submit_button("🗑️ Delete")

                    if update_btn:
                        if not token:
                            st.error("Admin token required.")
                        else:
                            try:
                                api.update_policy({
                                    "id": rule_id,
                                    "rule_name": edit_name,
                                    "pattern": edit_pattern,
                                    "pattern_type": edit_type,
                                    "severity": edit_severity,
                                    "action": edit_action,
                                    "replacement_value": edit_replacement or None,
                                    "enabled": edit_enabled,
                                })
                                st.success("✅ Rule updated")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Update failed: {e}")

                    if delete_btn:
                        if not token:
                            st.error("Admin token required.")
                        else:
                            try:
                                api.delete_policy(rule_id)
                                st.success("✅ Rule deleted")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Delete failed: {e}")

except Exception as e:
    st.error(f"Could not fetch policies: {e}")
    st.info("Make sure the Flask API hub is running.")
