"""
app.py
------
Entry point for NetSight — AI-Based Network Attack Forecaster (SIH26153).

Uses Streamlit multi-page navigation:
  1. Home       — hero, value proposition, project overview
  2. Dashboard  — the 5-tab SOC analysis dashboard

Everything runs offline on the committed models; no data leaves the machine.
"""

import streamlit as st

st.set_page_config(
    page_title="NetSight — Attack Forecaster",
    page_icon="🛰",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stApp { background-color: #0b0f19; color: #e2e8f0; }
    .block-container { padding-top: 1.4rem; }
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155; border-radius: 10px; padding: 14px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5);
    }
    .critical-badge { background: rgba(239,68,68,.2); color:#f87171;
        border:1px solid #ef4444; padding:4px 10px; border-radius:6px;
        font-weight:bold; }
    .safe-badge { background: rgba(34,197,94,.2); color:#4ade80;
        border:1px solid #22c55e; padding:4px 10px; border-radius:6px;
        font-weight:bold; }
    .hero {
        background: linear-gradient(135deg, #0b1220 0%, #111c33 100%);
        border: 1px solid #1e293b; border-radius: 16px; padding: 40px 36px;
        box-shadow: 0 12px 30px -8px rgba(0,0,0,0.6);
        margin-bottom: 8px;
    }
    .hero .kicker { color:#60a5fa; letter-spacing:.18em; font-weight:bold;
        font-size:.8rem; text-transform:uppercase; }
    .hero h1 { font-size:2.4rem; margin:.3rem 0 0; line-height:1.15; }
    .hero .sub { color:#94a3b8; font-size:1.05rem; margin-top: .5rem;
        max-width: 880px; }
    .stTabs [data-baseweb="tab"] { border-radius: 8px 8px 0 0; }
    .stTabs [aria-selected="true"] { background:#3b82f6 !important;
        color:#fff !important; font-weight:bold; }
</style>
""", unsafe_allow_html=True)


pg = st.navigation([
    st.Page("home.py", title="Home", icon="🏠", default=True),
    st.Page("dashboard.py", title="SOC Dashboard", icon="🛡"),
])
pg.run()
