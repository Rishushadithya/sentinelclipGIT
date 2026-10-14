"""Shared visual system for the SentinelClip Streamlit dashboard."""

import streamlit as st


# Keep visual rules in one place so dashboard pages share the same console UI.
DASHBOARD_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
        --sc-bg: #0D1117;
        --sc-surface: #161B22;
        --sc-surface-raised: #1C2128;
        --sc-border: #30363D;
        --sc-text: #E6EDF3;
        --sc-muted: #8B949E;
        --sc-accent: #22D3EE;
        --sc-high: #F87171;
        --sc-medium: #FBBF24;
        --sc-low: #60A5FA;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        letter-spacing: 0;
    }

    .stApp {
        background: var(--sc-bg);
        color: var(--sc-text);
    }

    .block-container {
        max-width: 1440px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    h1, h2, h3, h4 {
        color: var(--sc-text) !important;
        font-weight: 600 !important;
        letter-spacing: 0 !important;
    }

    h1 { font-size: 1.75rem !important; line-height: 1.25 !important; }
    h2 { font-size: 1.3rem !important; line-height: 1.35 !important; }
    h3 { font-size: 1.05rem !important; line-height: 1.4 !important; }
    p, label, .stCaption { color: var(--sc-muted); }

    [data-testid="stMetric"] {
        background: var(--sc-surface);
        border: 1px solid var(--sc-border);
        border-radius: 6px;
        padding: 0.85rem 1rem;
    }

    [data-testid="stMetricLabel"] {
        color: var(--sc-muted);
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    [data-testid="stMetricValue"] {
        color: var(--sc-text);
        font-size: 1.65rem;
        font-weight: 600;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--sc-border);
        border-radius: 6px;
        overflow: hidden;
    }

    [data-testid="stDataFrame"] [role="columnheader"] {
        background: var(--sc-surface-raised);
        color: var(--sc-muted);
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    [data-testid="stDataFrame"] [role="gridcell"] {
        font-size: 0.82rem;
    }

    .sc-mono,
    .sc-mono code,
    code,
    pre,
    [data-testid="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.78rem;
    }

    .sc-status-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        border: 1px solid currentColor;
        border-radius: 999px;
        padding: 0.18rem 0.55rem;
        font-size: 0.72rem;
        font-weight: 600;
        line-height: 1.2;
    }

    .sc-status-pill--online { color: #34D399; }
    .sc-status-pill--offline { color: var(--sc-muted); }
    .sc-status-pill--high { color: var(--sc-high); }
    .sc-status-pill--medium { color: var(--sc-medium); }
    .sc-status-pill--low { color: var(--sc-low); }

    .stButton > button[kind="primary"] {
        background: var(--sc-accent);
        border-color: var(--sc-accent);
        color: #0D1117;
    }

    .stButton > button[kind="primary"]:hover {
        background: #67E8F9;
        border-color: #67E8F9;
        color: #0D1117;
    }

    [data-testid="stExpander"] {
        background: var(--sc-surface);
        border: 1px solid var(--sc-border);
        border-radius: 6px;
    }
</style>
"""


def inject_css() -> None:
    """Inject the shared SentinelClip dashboard styles into the current page."""
    st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)
