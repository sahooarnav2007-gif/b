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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

:root {
    --bg:        #0b0f19;
    --border:    #1e293b;
    --surface-1: #0f172a;
    --surface-2: #1e293b;
    --accent:    #3b82f6;
    --accent-2:  #6366f1;
    --text:      #e2e8f0;
    --muted:     #94a3b8;
    --dim:       #64748b;
    --green:     #22c55e;
    --yellow:    #eab308;
    --orange:    #f97316;
    --red:       #ef4444;
    --radius:    12px;
    --mono:      'JetBrains Mono', ui-monospace, monospace;
}

html, body, [class*="css"] { font-family: 'Inter', -apple-system, sans-serif; }

.stApp { background: radial-gradient(1200px 600px at 80% -10%, #101a33 0%, #0b0f19 55%); }

/* ---------- scrollbars ---------- */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #283548; border-radius: 6px; }
::-webkit-scrollbar-thumb:hover { background: #35507a; }

/* ---------- layout ---------- */
.block-container { padding-top: 1.1rem; padding-bottom: 3rem; max-width: 1320px; }

/* ---------- hero ---------- */
.hero {
    position: relative; overflow: hidden;
    background: linear-gradient(135deg, #0c1430 0%, #101a33 55%, #0e1526 100%);
    border: 1px solid #233356; border-radius: 18px;
    padding: 42px 40px; margin-bottom: 26px;
    box-shadow: 0 18px 40px -14px rgba(0,0,0,.65), inset 0 1px 0 rgba(148,163,184,.08);
}
.hero::before {
    content: ""; position: absolute; inset: 0; pointer-events: none;
    background:
        radial-gradient(600px 220px at 85% -30%, rgba(59,130,246,.28), transparent 60%),
        radial-gradient(400px 200px at 8% 110%, rgba(99,102,241,.18), transparent 60%);
}
.hero .kicker { color:#60a5fa; letter-spacing:.22em; font-weight:700;
    font-size:.72rem; text-transform:uppercase; position:relative; }
.hero h1 { font-size:2.7rem; margin:.25rem 0 .35rem; line-height:1.12; position:relative;
    background: linear-gradient(90deg,#fff,#93c5fd 60%,#818cf8);
    -webkit-background-clip:text; background-clip:text; color:transparent; }
.hero .sub { color:#9fb0c9; font-size:1.02rem; max-width: 860px; line-height:1.6; position:relative; }
.stat-row { display:flex; gap:14px; flex-wrap:wrap; margin-top:24px; position:relative; }
.stat {
    flex:1; min-width:140px; background:rgba(15,23,42,.6); border:1px solid #24324d;
    border-radius:12px; padding:12px 16px; backdrop-filter: blur(4px);
}
.stat .n { font-size:1.7rem; font-weight:800; font-family:var(--mono); letter-spacing:-.01em; }
.stat .l { font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; color:var(--dim); margin-top:2px; }
.stat .n.g { color:#4ade80; } .stat .n.b { color:#60a5fa; }
.stat .n.v { color:#a78bfa; } .stat .n.o { color:#fbbf24; }

/* radar sweep (pure CSS) */
.radar {
    position:absolute; top:30px; right:44px; width:190px; height:190px; opacity:.85;
    border-radius:50%; pointer-events:none;
    background: conic-gradient(from 0deg, rgba(59,130,246,.0) 0deg, rgba(59,130,246,.55) 40deg, rgba(59,130,246,0) 90deg);
    animation: sweep 3.2s linear infinite;
    border: 1px solid rgba(59,130,246,.35);
}
.radar::before, .radar::after { content:""; position:absolute; inset:0; border-radius:50%;
    border:1px solid rgba(59,130,246,.14); }
.radar::after { inset:26%; border-color: rgba(59,130,246,.2); }
@keyframes sweep { to { transform: rotate(360deg); } }

/* ---------- cards ---------- */
.metric-card, .feat-card {
    background: linear-gradient(160deg, #141d33 0%, #0f172a 100%);
    border: 1px solid #22304b; border-radius: 12px; padding: 14px 16px;
    box-shadow: 0 6px 14px -8px rgba(0,0,0,.6); height: 100%;
}
.feat-card { padding: 18px 20px; border-left: 3px solid var(--accent); }
.feat-card.build { border-left-color:#f97316; }
.feat-card.audit { border-left-color:#a78bfa; }
.feat-card h3 { margin:0 0 8px; font-size:1.02rem; }

/* ---------- badges & status ---------- */
.badge { display:inline-block; padding:3px 11px; border-radius:999px; font-size:.72rem;
    font-weight:700; letter-spacing:.03em; }
.badge.crit { background:rgba(239,68,68,.16); color:#f87171; border:1px solid rgba(239,68,68,.5); }
.badge.high { background:rgba(249,115,22,.15); color:#fb923c; border:1px solid rgba(249,115,22,.5); }
.badge.med  { background:rgba(234,179,8,.15);  color:#facc15; border:1px solid rgba(234,179,8,.5); }
.badge.low  { background:rgba(34,197,94,.15);  color:#4ade80; border:1px solid rgba(34,197,94,.5); }
.badge.safe { background:rgba(34,197,94,.12);  color:#4ade80; border:1px solid rgba(34,197,94,.4); }
.badge.info { background:rgba(59,130,246,.15); color:#60a5fa; border:1px solid rgba(59,130,246,.5); }
.badge.warn { background:rgba(250,204,21,.12); color:#fde047; border:1px solid rgba(250,204,21,.45); }

.chip { display:inline-block; background:#172033; border:1px solid #27364f; color:#cfe1f7;
    font-family:var(--mono); font-size:.74rem; padding:3px 9px; border-radius:7px; margin:2px 3px 2px 0; }
.chip.r { color:#fca5a5; border-color:rgba(239,68,68,.4); }
.chip.o { color:#fdba74; border-color:rgba(249,115,22,.4); }

.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:7px; }
.dot.pulse { animation: pulseDot 1.6s ease-in-out infinite; }
.dot.g { background:#22c55e; } .dot.r { background:#ef4444; }
.dot.y { background:#eab308; } .dot.b { background:#3b82f6; }
@keyframes pulseDot { 0%,100%{ box-shadow:0 0 0 0 rgba(239,68,68,.5);} 50%{ box-shadow:0 0 0 6px rgba(239,68,68,0);} }

/* ---------- alert cards ---------- */
.alert-card {
    background: linear-gradient(160deg,#171328 0%, #101320 100%);
    border:1px solid #2a2b4d; border-left:4px solid var(--red);
    border-radius:10px; padding:12px 16px; margin:8px 0;
    box-shadow: 0 4px 12px -6px rgba(0,0,0,.6);
}
.alert-card .row { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
.alert-card .who { font-weight:700; }

/* ---------- pipeline ---------- */
.pipe { display:flex; gap:0; align-items:stretch; margin:18px 0 6px; position:relative; }
.pipe .step {
    flex:1; background:linear-gradient(170deg,#141d33,#0e1526); border:1px solid #22304b;
    border-radius:12px; padding:14px 16px; text-align:center; position:relative;
}
.pipe .step:not(:last-child)::after {
    content:"→"; position:absolute; right:-13px; top:50%; transform:translateY(-50%);
    color:#3b82f6; font-weight:800; font-size:1.15rem; z-index:2;
}
.pipe .step .emoji { font-size:1.4rem; }
.pipe .step .name { font-weight:700; margin-top:4px; }
.pipe .step .det { color:var(--dim); font-size:.76rem; margin-top:3px; line-height:1.35; }

/* ---------- context bar ---------- */
.ctxbar {
    display:flex; gap:10px; flex-wrap:wrap; align-items:center;
    background:#0f172a; border:1px solid #22304b; border-radius:10px;
    padding:8px 14px; margin:10px 0 18px; font-size:.8rem; color:var(--muted);
}
.ctxbar .k { color:var(--dim); }
.ctxbar .v { color:var(--text); font-family:var(--mono); }
.ctxbar .sep { color:#2c3c5a; }

/* ---------- section headers ---------- */
.sec-title { display:flex; align-items:center; gap:10px; margin:26px 0 12px; }
.sec-title::before { content:""; width:4px; height:18px; border-radius:3px;
    background:linear-gradient(180deg,#3b82f6,#6366f1); }
.sec-title h3 { margin:0; font-size:1.08rem; }

/* ---------- metric overrides (st.metric) ---------- */
[data-testid="stMetric"] {
    background: linear-gradient(160deg,#141d33 0%, #0f172a 100%);
    border:1px solid #22304b; border-radius:12px; padding:12px 14px;
}
[data-testid="stMetricLabel"] { color: var(--dim); font-size:.78rem; }
[data-testid="stMetricValue"] { color: var(--text); font-family:var(--mono); font-weight:700; }
[data-testid="stMetricDelta"] .st-emotion-cache-kg0p0z { color:#4ade80; }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] { background:#0d1220; border-right:1px solid #1c2740; }
[data-testid="stSidebar"] .block-container { padding-top: 1.4rem; }
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2 { font-size:1rem; }

/* ---------- tabs ---------- */
.stTabs [data-baseweb="tab-list"] { gap:6px; border-bottom:1px solid #1e293b; }
.stTabs [data-baseweb="tab"] {
    background:transparent; border-radius:9px 9px 0 0; padding:.55rem 1.1rem;
    color:var(--muted); font-weight:600; transition: .15s ease;
}
.stTabs [aria-selected="true"] {
    background:linear-gradient(180deg,#1e3a8a,#142858); color:#fff !important;
    box-shadow: inset 0 2px 0 #3b82f6, 0 -4px 14px -6px rgba(59,130,246,.35);
}

/* ---------- buttons ---------- */
.stButton > button, .stDownloadButton > button {
    border-radius:10px; font-weight:600; border:1px solid #2c3d5c;
    background:#151e33; color:var(--text); transition:.15s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color:#3b82f6; background:#1b2740; color:#fff;
}
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {
    background:linear-gradient(90deg,#2563eb,#4f46e5); border:none; color:#fff;
    box-shadow: 0 6px 18px -6px rgba(59,130,246,.55);
}
.stButton > button[kind="primary"]:hover { filter:brightness(1.1); }

/* ---------- inputs ---------- */
[data-testid="stSlider"] [data-baseweb="slider"] > div > div > div {
    color:#3b82f6; background:#3b82f6;
}
[data-testid="stRadio"] label, [data-testid="stSelectbox"] label,
[data-testid="stNumberInput"] label { color:var(--muted); }
.stRadio [data-testid="stMarkdownContainer"] p { color: var(--text); }

/* ---------- expander ---------- */
[data-testid="stExpander"] { border:1px solid #1e293b; background:#0f172a; border-radius:10px; }

/* ---------- dataframes / code ---------- */
[data-testid="stDataFrame"] { border:1px solid #1c2740; border-radius:10px; overflow:hidden; }
pre, code, [class*="codeCell"] { font-family:var(--mono); }

/* ---------- animations ---------- */
@keyframes fadeUp { from { opacity:0; transform: translateY(8px);} to { opacity:1; transform:none;} }
.fadeup { animation: fadeUp .45s ease both; }

footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


pg = st.navigation([
    st.Page("home.py", title="Home", icon="🏠", default=True),
    st.Page("dashboard.py", title="SOC Dashboard", icon="🛡"),
])
pg.run()