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
from dashboard.auth import require_login, render_user_sidebar
from dashboard.styles import (
    inject_css,
    render_page_header,
    severity_badge,
    status_badge,
    action_badge,
)

st.set_page_config(
    page_title="SentinelClip — Policy Editor",
    layout="wide",
)

require_login()
inject_css()

# ---------------------------------------------------------------------------
# Initialize
# ---------------------------------------------------------------------------

with st.sidebar:
    render_user_sidebar()

def _rule_key(rule_id, fallback_index):
    """Return a unique Streamlit key for a rule row even when the API omits an ID."""
    if rule_id is None or str(rule_id).strip() in ("", "?"):
        return f"rule_{fallback_index}"
    return f"rule_{rule_id}"


token = st.session_state.get("token", "")
api = SentinelClipAPI(admin_token=token)

try:
    enrolled_devices = api.get_devices() if token else []
except Exception:
    enrolled_devices = []

device_scope_options = {
    device["id"]: f"{device['hostname']} ({device['id'][:8]})"
    for device in enrolled_devices
}
group_scope_options = sorted({
    device["group_name"] for device in enrolled_devices if device.get("group_name")
})

render_page_header(
    title="Policy Rule Definitions",
    subtitle="Configure real-time regex and keyword inspection rules for endpoint DLP agents.",
    category="POLICY ENGINE",
)

# Display persistent flash notification if an action was just completed
if "policy_flash_message" in st.session_state:
    flash = st.session_state.pop("policy_flash_message")
    st.toast(flash["text"])
    st.success(flash["text"])

if not token:
    st.warning("Admin authorization token is required to modify policy rules.")

# ---------------------------------------------------------------------------
# Add New Rule
# ---------------------------------------------------------------------------

with st.expander("+ ADD POLICY RULE", expanded=False):
    with st.form("new_rule_form"):
        col1, col2 = st.columns(2)

        with col1:
            new_name = st.text_input("Rule Name *", placeholder="e.g. AWS Access Key")
            new_pattern = st.text_area(
                "Pattern *",
                placeholder="Regular expression pattern or keyword sequence",
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
            new_scope_type = st.selectbox(
                "Policy Scope",
                options=["global", "device", "group"],
                format_func=lambda value: "All Devices" if value == "global" else value.title(),
            )
            if new_scope_type == "device" and device_scope_options:
                new_scope_target = st.selectbox(
                    "Target Device", list(device_scope_options),
                    format_func=lambda value: device_scope_options[value],
                )
            elif new_scope_type == "group" and group_scope_options:
                new_scope_target = st.selectbox("Target Group", group_scope_options)
            else:
                new_scope_target = None
            new_replacement = st.text_input(
                "Replacement Value",
                placeholder="Required when action is set to OBFUSCATE",
            )

        submitted = st.form_submit_button("Deploy Rule", type="primary")

        if submitted:
            if not new_name or not new_pattern:
                st.error("Rule name and pattern are required fields.")
            elif not token:
                st.error("Admin token is required to deploy rules.")
            else:
                try:
                    result = api.update_policy({
                        "rule_name": new_name,
                        "pattern": new_pattern,
                        "pattern_type": new_type,
                        "severity": new_severity,
                        "action": new_action,
                        "scope_type": new_scope_type,
                        "scope_target": new_scope_target,
                        "replacement_value": new_replacement or None,
                        "enabled": True,
                    })
                    rule_id = result.get("id", "?")
                    st.session_state["policy_flash_message"] = {
                        "type": "success",
                        "text": f"[SUCCESS] Policy rule '{new_name}' deployed successfully. (ID: {rule_id} | Severity: {new_severity} | Action: {new_action})",
                    }
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to create rule: {e}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Existing Rules
# ---------------------------------------------------------------------------

st.markdown("### Active Rule Catalog")

try:
    if token:
        rules = api.get_all_policies()
    else:
        rules = api.get_policies()

    if not rules:
        st.info("No policy rules configured in local storage.")
    else:
        for index, rule in enumerate(rules):
            rule_id = rule.get("id")
            rule_key = _rule_key(rule_id, index)
            enabled = rule.get("enabled", True)
            severity = rule.get("severity", "LOW")
            action = rule.get("action", "WARN")
            rule_name = rule.get("rule_name", "Unnamed Rule")

            status_text = "ACTIVE" if enabled else "DISABLED"
            expander_title = f"[{severity}]  {rule_name}  //  {action}  —  [{status_text}]"

            with st.expander(expander_title):
                st.markdown(
                    f"{severity_badge(severity)} &nbsp; {action_badge(action)} &nbsp; {status_badge(enabled)}",
                    unsafe_allow_html=True,
                )
                st.write("")

                with st.form(f"edit_rule_{rule_key}"):
                    edit_col1, edit_col2 = st.columns(2)

                    with edit_col1:
                        edit_name = st.text_input(
                            "Rule Name",
                            value=rule.get("rule_name", ""),
                            key=f"name_{rule_key}",
                        )
                        edit_pattern = st.text_area(
                            "Pattern",
                            value=rule.get("pattern", ""),
                            height=80,
                            key=f"pattern_{rule_key}",
                        )
                        edit_type = st.selectbox(
                            "Pattern Type",
                            options=["regex", "keyword"],
                            index=0 if rule.get("pattern_type") == "regex" else 1,
                            key=f"type_{rule_key}",
                        )

                    with edit_col2:
                        severity_options = ["LOW", "MEDIUM", "HIGH"]
                        edit_severity = st.selectbox(
                            "Severity",
                            options=severity_options,
                            index=severity_options.index(severity)
                            if severity in severity_options else 0,
                            key=f"severity_{rule_key}",
                        )
                        action_options = ["WARN", "OBFUSCATE", "REDACT", "BLOCK"]
                        current_action = rule.get("action", "WARN")
                        edit_action = st.selectbox(
                            "Action",
                            options=action_options,
                            index=action_options.index(current_action)
                            if current_action in action_options else 0,
                            key=f"action_{rule_key}",
                        )
                        edit_replacement = st.text_input(
                            "Replacement Value",
                            value=rule.get("replacement_value", "") or "",
                            key=f"replacement_{rule_key}",
                        )
                        edit_enabled = st.checkbox(
                            "Rule Enabled",
                            value=enabled,
                            key=f"enabled_{rule_key}",
                        )
                        scope_type_options = ["global", "device", "group"]
                        current_scope_type = rule.get("scope_type", "global")
                        edit_scope_type = st.selectbox(
                            "Policy Scope",
                            options=scope_type_options,
                            index=scope_type_options.index(current_scope_type)
                            if current_scope_type in scope_type_options else 0,
                            format_func=lambda value: "All Devices" if value == "global" else value.title(),
                            key=f"scope_type_{rule_key}",
                        )
                        if edit_scope_type == "device" and device_scope_options:
                            device_values = list(device_scope_options)
                            current_target = rule.get("scope_target")
                            target_index = device_values.index(current_target) if current_target in device_values else 0
                            edit_scope_target = st.selectbox(
                                "Target Device", device_values,
                                index=target_index,
                                format_func=lambda value: device_scope_options[value],
                                key=f"scope_target_{rule_key}",
                            )
                        elif edit_scope_type == "group" and group_scope_options:
                            target_index = group_scope_options.index(rule.get("scope_target")) if rule.get("scope_target") in group_scope_options else 0
                            edit_scope_target = st.selectbox(
                                "Target Group", group_scope_options,
                                index=target_index,
                                key=f"scope_target_{rule_key}",
                            )
                        else:
                            edit_scope_target = None

                    btn_col1, btn_col2, _ = st.columns([1.2, 1.2, 3.6])

                    with btn_col1:
                        update_btn = st.form_submit_button("Save Changes", type="primary")

                    with btn_col2:
                        delete_btn = st.form_submit_button("Delete Rule")

                    if update_btn:
                        if not token:
                            st.error("Admin authentication token required.")
                        else:
                            try:
                                api.update_policy({
                                    "id": rule_id,
                                    "rule_name": edit_name,
                                    "pattern": edit_pattern,
                                    "pattern_type": edit_type,
                                    "severity": edit_severity,
                                    "action": edit_action,
                                    "scope_type": edit_scope_type,
                                    "scope_target": edit_scope_target,
                                    "replacement_value": edit_replacement or None,
                                    "enabled": edit_enabled,
                                })
                                st.session_state["policy_flash_message"] = {
                                    "type": "success",
                                    "text": f"[SUCCESS] Policy rule '{edit_name}' updated successfully. (Action: {edit_action} | {'ACTIVE' if edit_enabled else 'DISABLED'})",
                                }
                                st.rerun()
                            except Exception as e:
                                st.error(f"Update failed: {e}")

                    if delete_btn:
                        if not token:
                            st.error("Admin authentication token required.")
                        else:
                            try:
                                api.delete_policy(rule_id)
                                rule_title = rule.get('rule_name', 'Rule')
                                st.session_state["policy_flash_message"] = {
                                    "type": "success",
                                    "text": f"[SUCCESS] Policy rule '{rule_title}' deleted successfully.",
                                }
                                st.rerun()
                            except Exception as e:
                                st.error(f"Delete failed: {e}")

except Exception as e:
    st.error(f"Could not fetch policies: {e}")
    st.info("Ensure the SentinelClip API daemon is running.")
