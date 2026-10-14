"""TryHackMe-inspired visual design system for the SentinelClip Streamlit dashboard."""

import streamlit as st


DASHBOARD_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    :root {
        --thm-bg: #0d1117;
        --thm-sidebar-bg: #11161d;
        --thm-surface: #161c24;
        --thm-surface-raised: #1c232e;
        --thm-border: #283548;
        --thm-border-light: #364459;
        --thm-text: #e6edf3;
        --thm-text-muted: #8b949e;
        --thm-green: #10b981;
        --thm-green-hover: #059669;
        --thm-green-dim: rgba(16, 185, 129, 0.12);
        --thm-red: #ef4444;
        --thm-red-dim: rgba(239, 68, 68, 0.12);
        --thm-amber: #f59e0b;
        --thm-amber-dim: rgba(245, 158, 11, 0.12);
        --thm-cyan: #0ea5e9;
        --thm-cyan-dim: rgba(14, 165, 233, 0.12);
    }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        color: var(--thm-text);
    }

    .stApp {
        background-color: var(--thm-bg) !important;
        background-image: radial-gradient(circle at 50% 0%, rgba(16, 185, 129, 0.03) 0%, transparent 70%);
        color: var(--thm-text);
    }

    /* Streamlit Main Container */
    .block-container {
        max-width: 1440px;
        padding-top: 1.75rem;
        padding-bottom: 3rem;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: var(--thm-sidebar-bg) !important;
        border-right: 1px solid var(--thm-border) !important;
    }

    section[data-testid="stSidebar"] hr {
        border-color: var(--thm-border) !important;
        margin: 0.85rem 0 !important;
    }

    /* Typography & Headers */
    h1, h2, h3, h4, h5, h6 {
        color: var(--thm-text) !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: -0.01em !important;
    }

    h1 { font-size: 1.65rem !important; margin-bottom: 0.25rem !important; }
    h2 { font-size: 1.25rem !important; margin-top: 1.25rem !important; }
    h3 { font-size: 1.05rem !important; margin-top: 1rem !important; }

    p, label, .stCaption {
        color: var(--thm-text-muted);
    }

    /* Technical Prefix Header */
    .thm-page-header {
        margin-bottom: 1.25rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid var(--thm-border);
    }

    .thm-page-category {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        color: var(--thm-green);
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 0.25rem;
    }

    .thm-page-title {
        font-size: 1.65rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0 0 0.25rem 0;
        letter-spacing: -0.02em;
    }

    .thm-page-subtitle {
        font-size: 0.88rem;
        color: var(--thm-text-muted);
        margin: 0;
    }

    /* Monospace elements */
    code, pre, .thm-mono, [data-testid="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.82rem;
    }

    /* Cyber Badges & Pills */
    .thm-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.70rem;
        font-weight: 700;
        padding: 0.15rem 0.55rem;
        border-radius: 3px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        line-height: 1.3;
        border: 1px solid transparent;
    }

    .thm-badge-high, .thm-badge-danger, .thm-badge-block {
        background: var(--thm-red-dim);
        color: var(--thm-red);
        border-color: rgba(239, 68, 68, 0.35);
    }

    .thm-badge-medium, .thm-badge-warn {
        background: var(--thm-amber-dim);
        color: var(--thm-amber);
        border-color: rgba(245, 158, 11, 0.35);
    }

    .thm-badge-low, .thm-badge-info, .thm-badge-redact {
        background: var(--thm-cyan-dim);
        color: var(--thm-cyan);
        border-color: rgba(14, 165, 233, 0.35);
    }

    .thm-badge-online, .thm-badge-active, .thm-badge-success {
        background: var(--thm-green-dim);
        color: var(--thm-green);
        border-color: rgba(16, 185, 129, 0.35);
    }

    .thm-badge-offline, .thm-badge-disabled, .thm-badge-neutral {
        background: rgba(139, 148, 158, 0.10);
        color: var(--thm-text-muted);
        border-color: rgba(139, 148, 158, 0.25);
    }

    /* TryHackMe Metric Cards */
    div[data-testid="stMetric"] {
        background: var(--thm-surface) !important;
        border: 1px solid var(--thm-border) !important;
        border-radius: 6px !important;
        padding: 0.9rem 1.1rem !important;
        transition: border-color 0.2s ease, transform 0.2s ease;
    }

    div[data-testid="stMetric"]:hover {
        border-color: var(--thm-border-light) !important;
    }

    div[data-testid="stMetric"] [data-testid="stMetricLabel"] {
        color: var(--thm-text-muted) !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.72rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }

    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.65rem !important;
        font-weight: 700 !important;
    }

    /* Forms, Expanders, and Cards */
    div[data-testid="stForm"],
    div[data-testid="stExpander"] {
        background: var(--thm-surface) !important;
        border: 1px solid var(--thm-border) !important;
        border-radius: 6px !important;
    }

    div[data-testid="stExpander"] summary {
        color: var(--thm-text) !important;
        font-weight: 600 !important;
        font-size: 0.92rem !important;
        padding: 0.65rem 0.85rem !important;
    }

    div[data-testid="stExpander"] summary:hover {
        color: var(--thm-green) !important;
    }

    /* Inputs, Selects, Textareas */
    div[data-baseweb="input"],
    div[data-baseweb="textarea"],
    div[data-baseweb="select"] > div {
        background-color: var(--thm-bg) !important;
        border: 1px solid var(--thm-border) !important;
        border-radius: 4px !important;
        color: var(--thm-text) !important;
    }

    input, textarea {
        color: var(--thm-text) !important;
        font-family: 'Inter', sans-serif !important;
    }

    div[data-baseweb="input"]:focus-within,
    div[data-baseweb="textarea"]:focus-within,
    div[data-baseweb="select"]:focus-within > div {
        border-color: var(--thm-green) !important;
        box-shadow: 0 0 0 1px var(--thm-green) !important;
    }

    /* Buttons: TryHackMe Terminal Style */
    .stButton > button,
    div[data-testid="stFormSubmitButton"] > button {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        border-radius: 4px !important;
        letter-spacing: 0.3px !important;
        transition: all 0.15s ease-in-out !important;
        padding: 0.45rem 1rem !important;
    }

    /* Primary Action Buttons (Green Terminal Accent) */
    .stButton > button[kind="primary"],
    div[data-testid="stFormSubmitButton"] > button[kind="primary"] {
        background-color: var(--thm-green) !important;
        border: 1px solid var(--thm-green) !important;
        color: #0a0e14 !important;
        font-weight: 700 !important;
    }

    .stButton > button[kind="primary"]:hover,
    div[data-testid="stFormSubmitButton"] > button[kind="primary"]:hover {
        background-color: var(--thm-green-hover) !important;
        border-color: var(--thm-green-hover) !important;
        color: #ffffff !important;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.35) !important;
    }

    /* Secondary / Outline Buttons */
    .stButton > button[kind="secondary"],
    div[data-testid="stFormSubmitButton"] > button[kind="secondary"] {
        background-color: var(--thm-surface-raised) !important;
        border: 1px solid var(--thm-border) !important;
        color: var(--thm-text) !important;
    }

    .stButton > button[kind="secondary"]:hover,
    div[data-testid="stFormSubmitButton"] > button[kind="secondary"]:hover {
        border-color: var(--thm-green) !important;
        color: var(--thm-green) !important;
    }

    /* Dataframe & Tables */
    [data-testid="stDataFrame"] {
        border: 1px solid var(--thm-border) !important;
        border-radius: 6px !important;
        overflow: hidden !important;
    }

    [data-testid="stDataFrame"] [role="columnheader"] {
        background: var(--thm-surface-raised) !important;
        color: var(--thm-text-muted) !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.72rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
        border-bottom: 1px solid var(--thm-border) !important;
    }

    [data-testid="stDataFrame"] [role="gridcell"] {
        font-size: 0.82rem !important;
        color: var(--thm-text) !important;
    }

    /* Alert / Flash Boxes */
    div[data-testid="stAlert"] {
        background-color: var(--thm-surface) !important;
        border-radius: 4px !important;
        border-left-width: 4px !important;
        color: var(--thm-text) !important;
    }

    div[data-testid="stAlert"] p {
        color: var(--thm-text) !important;
        font-size: 0.86rem !important;
    }

    /* Clean Dividers */
    hr {
        border-color: var(--thm-border) !important;
        margin: 1.25rem 0 !important;
    }
</style>
"""


def inject_css() -> None:
    """Inject TryHackMe-inspired CSS into the current Streamlit page."""
    st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)


def render_page_header(title: str, subtitle: str = "", category: str = "CONSOLE") -> None:
    """Render a clean, professional header without emojis."""
    st.markdown(
        f"""
        <div class="thm-page-header">
            <div class="thm-page-category">// {category}</div>
            <h1 class="thm-page-title">{title}</h1>
            {f'<p class="thm-page-subtitle">{subtitle}</p>' if subtitle else ''}
        </div>
        """,
        unsafe_allow_html=True,
    )


def badge(text: str, variant: str = "neutral") -> str:
    """Generate HTML for a TryHackMe-style cyber pill badge."""
    return f'<span class="thm-badge thm-badge-{variant}">[{text.upper()}]</span>'


def severity_badge(severity: str) -> str:
    """Return an uppercase badge for severity level."""
    s = (severity or "LOW").upper()
    variant = "high" if s == "HIGH" else "medium" if s == "MEDIUM" else "low"
    return badge(s, variant)


def status_badge(is_active: bool) -> str:
    """Return an uppercase badge for active/disabled status."""
    return badge("ACTIVE", "active") if is_active else badge("DISABLED", "disabled")


def online_badge(is_online: bool) -> str:
    """Return an uppercase badge for online/offline connectivity."""
    return badge("ONLINE", "online") if is_online else badge("OFFLINE", "offline")


def action_badge(action: str) -> str:
    """Return an uppercase badge for action types."""
    act = (action or "WARN").upper()
    variant = "block" if act == "BLOCK" else "warn" if act == "WARN" else "info"
    return badge(act, variant)
