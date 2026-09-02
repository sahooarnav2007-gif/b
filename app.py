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

.stApp {
    isolation: isolate;
    background:
        radial-gradient(1100px 600px at 85% -10%, rgba(37,99,235,.16), transparent 60%),
        radial-gradient(900px 600px at -5% 40%, rgba(99,102,241,.10), transparent 55%),
        radial-gradient(700px 500px at 60% 110%, rgba(34,211,238,.10), transparent 55%),
        #090d16;
}
/* cyber grid */
.stApp::before {
    content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
    background-image:
        linear-gradient(rgba(59,130,246,.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(59,130,246,.05) 1px, transparent 1px);
    background-size: 44px 44px;
    mask-image: radial-gradient(ellipse 90% 70% at 50% 0%, black 40%, transparent 100%);
    -webkit-mask-image: radial-gradient(ellipse 90% 70% at 50% 0%, black 40%, transparent 100%);
    animation: gridDrift 80s linear infinite;
}
@keyframes gridDrift { to { background-position: 88px 88px, 88px 88px; } }
/* animated scanline sweep */
.stApp::after {
    content:""; position:fixed; left:0; right:0; height:160px; pointer-events:none;
    z-index:1; top:-160px;
    background: linear-gradient(180deg, transparent, rgba(59,130,246,.05), transparent);
    animation: scan 7s linear infinite;
}
@keyframes scan { to { transform: translateY(120vh); } }

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
@keyframes pulse { 0%,100%{ box-shadow:0 0 0 0 rgba(52,211,153,.6);} 50%{ box-shadow:0 0 0 6px rgba(52,211,153,0);} }

/* ---------- alert cards ---------- */
.alert-card {
    background: linear-gradient(160deg,#171328 0%, #101320 100%);
    border:1px solid #2a2b4d; border-left:4px solid var(--red);
    border-radius:10px; padding:12px 16px; margin:8px 0;
    box-shadow: 0 4px 12px -6px rgba(0,0,0,.6);
}
.alert-card .row { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
.alert-card .who { font-weight:700; }

/* ---------- context bar ---------- */
.ctxbar {
    display:flex; gap:10px; flex-wrap:wrap; align-items:center;
    background: linear-gradient(160deg, rgba(59,130,246,.07), rgba(15,23,42,.5));
    border:1px solid rgba(148,163,184,.16); border-radius:12px;
    padding:9px 14px; margin:10px 0 18px; font-size:.8rem; color:var(--muted);
    backdrop-filter: blur(10px); box-shadow: inset 0 1px 0 rgba(255,255,255,.06);
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
    background: linear-gradient(160deg, rgba(59,130,246,.10), rgba(15,23,42,.6));
    border:1px solid rgba(148,163,184,.16); border-radius:14px; padding:14px 16px;
    backdrop-filter: blur(12px) saturate(130%);
    -webkit-backdrop-filter: blur(12px) saturate(130%);
    box-shadow: 0 10px 26px -12px rgba(0,0,0,.6), inset 0 1px 0 rgba(255,255,255,.08);
}
[data-testid="stMetric"]:hover { border-color: rgba(59,130,246,.45); }
[data-testid="stMetricLabel"] { color: var(--dim); font-size:.78rem; letter-spacing:.04em; }
[data-testid="stMetricValue"] { color: var(--text); font-family:var(--mono); font-weight:700; }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, rgba(15,23,42,.82), rgba(9,13,22,.9));
    border-right:1px solid #1c2740;
    backdrop-filter: blur(14px) saturate(130%);
    -webkit-backdrop-filter: blur(14px) saturate(130%);
    box-shadow: inset -1px 0 0 rgba(59,130,246,.12);
}
[data-testid="stSidebar"] .block-container { padding-top: 1.4rem; }
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2 { font-size:1rem; }
/* page nav items */
[data-testid="stSidebarNav"] li a { border-radius:9px; transition:.15s ease; }
[data-testid="stSidebarNav"] li a:hover { background:rgba(59,130,246,.10); }

/* sidebar brand + live status (home) */
.sb-brand { display:flex; align-items:center; gap:10px; padding:2px 2px 6px; }
.sb-mark { position:relative; width:36px; height:36px; border-radius:10px; flex:none;
    display:grid; place-items:center; background:linear-gradient(135deg,#1e3a8a,#0f172a);
    border:1px solid rgba(59,130,246,.5); box-shadow:0 0 16px rgba(59,130,246,.35); }
.sb-mark::after { content:""; position:absolute; inset:4px; border-radius:6px;
    border:1px dashed rgba(103,232,249,.55); animation: spin 9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.sb-mark span { color:#60a5fa; font-size:1.2rem; font-weight:800; }
.sb-t { line-height:1.15; }
.sb-t b { color:#e2e8f0; font-size:.95rem; letter-spacing:.06em; display:block; }
.sb-t i { font-style:normal; color:#64748b; font-size:.66rem; letter-spacing:.18em; }
.sb-status { padding:10px 12px; border:1px solid #1c2740; border-radius:12px;
    background:linear-gradient(180deg, rgba(15,23,42,.6), rgba(9,13,22,.5)); }
.sb-status .sb-row { display:flex; justify-content:space-between; padding:5px 0;
    font-size:.78rem; }
.sb-status .sb-row:not(:last-child) { border-bottom:1px solid rgba(30,41,59,.6); }
.sb-status .k { color:#64748b; letter-spacing:.1em; font-size:.64rem; text-transform:uppercase; }
.sb-status .v { color:#cbd5e1; font-family:var(--mono); font-weight:600; }
.sb-status .v.g { color:#34d399; }
.sb-status .v.c { color:#22d3ee; }

/* ---------- tabs ---------- */
.stTabs [data-baseweb="tab-list"] { gap:6px; border-bottom:1px solid #1e293b; }
.stTabs [data-baseweb="tab"] {
    background:transparent; border-radius:9px 9px 0 0; padding:.55rem 1.1rem;
    color:var(--muted); font-weight:600; transition: .15s ease;
}
.stTabs [aria-selected="true"] {
    background:linear-gradient(180deg,#1e3a8a,#142858); color:#fff !important;
    box-shadow: inset 0 2px 0 #3b82f6, 0 -4px 14px -6px rgba(59,130,246,.35);
    animation: tabGlow 2.4s ease-in-out infinite;
}
@keyframes tabGlow {
    0%,100% { box-shadow: inset 0 2px 0 #3b82f6, 0 -4px 14px -6px rgba(59,130,246,.35); }
    50%     { box-shadow: inset 0 2px 0 #22d3ee, 0 -4px 20px -4px rgba(34,211,238,.5); }
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
[data-testid="stExpander"] {
    border:1px solid rgba(148,163,184,.16); border-radius:12px;
    background: linear-gradient(160deg, rgba(59,130,246,.06), rgba(15,23,42,.5));
    backdrop-filter: blur(10px); box-shadow: inset 0 1px 0 rgba(255,255,255,.06);
}
[data-testid="stExpander"]:hover { border-color: rgba(59,130,246,.4); }
[data-testid="stExpander"] [data-testid="stExpanderDetails"] { border-top:1px solid rgba(148,163,184,.12); }

/* ---------- iframe (home globe) ---------- */
[data-testid="stIFrame"] {
    margin-top: 4px;
    animation: fadeUp .6s cubic-bezier(.16,.84,.44,1) .2s both, levitate 9s ease-in-out 1.4s infinite;
}

/* ---------- dataframes / code ---------- */
[data-testid="stDataFrame"] { border:1px solid #1c2740; border-radius:10px; overflow:hidden; }
pre, code, [class*="codeCell"] { font-family:var(--mono); }

/* ---------- animations ---------- */
@keyframes fadeUp { from { opacity:0; transform: translateY(8px);} to { opacity:1; transform:none;} }
.fadeup { animation: fadeUp .45s ease backwards; }

/* ============================================================
   GLASS DESIGN SYSTEM
   ============================================================ */
.glass {
    position:relative; overflow:hidden;
    background: linear-gradient(150deg, rgba(255,255,255,.06), rgba(255,255,255,.015));
    border: 1px solid rgba(148,163,184,.16);
    border-radius: 16px;
    backdrop-filter: blur(14px) saturate(140%);
    -webkit-backdrop-filter: blur(14px) saturate(140%);
    box-shadow: 0 18px 40px -18px rgba(0,0,0,.7),
                inset 0 1px 0 rgba(255,255,255,.08);
}
.glass:not(.hero)::before {
    content:""; position:absolute; inset:0; pointer-events:none;
    background: linear-gradient(120deg,
        rgba(59,130,246,.10), transparent 30%,
        transparent 70%, rgba(34,211,238,.07));
    opacity:.5;
}
.glass.hover:hover {
    border-color: rgba(59,130,246,.45);
    transform: perspective(700px) translateY(-4px) rotateX(3deg) rotateY(-2deg) scale(1.01);
    box-shadow: 0 22px 50px -18px rgba(37,99,235,.55),
                inset 0 1px 0 rgba(255,255,255,.1);
}
.glass .glass-inner { position:relative; z-index:1; }

/* sheen sweep on hover */
.glass.hover::after {
    content:""; position:absolute; top:0; bottom:0; left:-80%; width:60%;
    background: linear-gradient(105deg, transparent, rgba(255,255,255,.12), transparent);
    transform: skewX(-18deg); transition: left .6s ease; pointer-events:none;
}
.glass.hover:hover::after { left: 120%; }

/* hero is itself glass but taller */
.hero.glass { padding: 42px 40px; margin-bottom: 10px; }

/* dashboard .metric-card as glass */
.metric-card {
    background: linear-gradient(160deg, rgba(59,130,246,.08), rgba(10,16,32,.5));
    border:1px solid rgba(148,163,184,.16); border-radius:12px; padding:14px 16px;
    backdrop-filter: blur(10px); box-shadow: inset 0 1px 0 rgba(255,255,255,.07);
}

/* neutral severity badge */
.badge.none { background:rgba(148,163,184,.14); color:#94a3b8; border:1px solid rgba(148,163,184,.4); }

/* cyber-style section heading */
.csec { display:flex; align-items:center; gap:12px; margin:34px 0 18px; position:relative; }
.csec::before { content:""; width:4px; height:20px; border-radius:3px;
    background:linear-gradient(180deg,#22d3ee,#3b82f6); box-shadow:0 0 12px rgba(34,211,238,.7); }
.csec h3 { margin:0; font-size:1.1rem; letter-spacing:.02em; }
.csec .csec-line { flex:1; height:2px; border-radius:1px;
    background:linear-gradient(90deg, rgba(59,130,246,.4), transparent); }

/* ============================================================
   ANIMATED DATA-FLOW PIPELINE
   ============================================================ */
.pipeline { position:relative; display:grid;
    grid-template-columns: repeat(5, 1fr); gap: 26px; margin: 8px 0 6px; }
.pipe-node { position:relative; text-align:center; padding: 22px 14px 18px; }
.pipe-node .ico { width:58px; height:58px; margin:0 auto 12px; border-radius:14px;
    display:flex; align-items:center; justify-content:center; font-size:1.6rem;
    background: linear-gradient(145deg, rgba(59,130,246,.18), rgba(30,41,59,.35));
    border: 1px solid rgba(59,130,246,.35); position:relative; overflow:visible;
    box-shadow: 0 0 20px -4px rgba(59,130,246,.5), inset 0 1px 0 rgba(255,255,255,.12); }
.pipe-node .ico::before {
    content:""; position:absolute; inset:-5px; border-radius:18px; pointer-events:none;
    border:1px solid rgba(34,211,238,.25); animation: nodeRing 2.6s ease-in-out infinite; }
@keyframes nodeRing { 0%,100%{ transform:scale(.94); opacity:.4;}
    50%{ transform:scale(1.05); opacity:.9;} }
.pipe-node .name { font-weight:800; font-size:.95rem; letter-spacing:.02em;
    color:var(--text); }
.pipe-node .det { color:var(--dim); font-size:.74rem; margin-top:5px; line-height:1.4;
    font-family:var(--mono); }
.pipe-node .tag { display:inline-flex; align-items:center; gap:6px; margin-top:10px;
    font-family:var(--mono); font-size:.66rem; letter-spacing:.12em; color:#7dd3fc;
    background:rgba(7,15,30,.55); border:1px solid rgba(59,130,246,.3);
    padding:3px 8px; border-radius:6px; }
.pipe-node .tag i { width:6px; height:6px; border-radius:50%; background:#34d399;
    animation: blink 1.4s steps(2,start) infinite; }
@keyframes blink { to { visibility:hidden; } }

/* animated data pulse traveling between nodes */
.pipe-link { position:absolute; top:45px; height:2px;
    background: linear-gradient(90deg, rgba(59,130,246,.25), rgba(34,211,238,.55)); z-index:0; }
.pipe-link::after {
    content:""; position:absolute; top:50%; left:0; width:8px; height:8px; margin-top:-4px;
    border-radius:50%; background:#7dd3fc; box-shadow:0 0 10px 2px #22d3ee;
    animation: dataFlow 1.5s linear infinite; }
@keyframes dataFlow { from { left:0; opacity:1;} to { left:100%; opacity:0;} }

/* ============================================================
   GLASS STAT CARDS
   ============================================================ */
.stat-row.glass { gap:14px; display:grid;
    grid-template-columns: repeat(6, 1fr); margin-top:20px; }
.stat.glass { flex:none; background:linear-gradient(150deg,
        rgba(59,130,246,.10), rgba(10,16,32,.55));
    border:1px solid rgba(148,163,184,.16); border-radius:14px; padding:14px 16px;
    backdrop-filter: blur(10px); box-shadow: inset 0 1px 0 rgba(255,255,255,.07); }
.stat.glass .n { font-size:1.75rem; font-weight:800; font-family:var(--mono); }
.stat.glass .l { font-size:.7rem; text-transform:uppercase; letter-spacing:.08em;
    color:var(--dim); margin-top:3px; }
.stat.glass .n.g { color:#4ade80; text-shadow:0 0 14px rgba(74,222,128,.5); }
.stat.glass .n.b { color:#60a5fa; text-shadow:0 0 14px rgba(96,165,250,.5); }
.stat.glass .n.v { color:#a78bfa; text-shadow:0 0 14px rgba(167,139,250,.5); }
.stat.glass .n.o { color:#fbbf24; text-shadow:0 0 14px rgba(251,191,36,.5); }

/* ============================================================
   CINEMATIC LAYER
   ============================================================ */
html { scroll-behavior: smooth; }
::selection { background: rgba(59,130,246,.45); color:#fff; }

/* smooth entrance */
.anim-in { animation: fadeUp .55s cubic-bezier(.16,.84,.44,1) backwards; }

/* ---------- ambient particle field ---------- */
#bgfx { position:fixed; inset:0; z-index:-1; pointer-events:none; overflow:hidden; }
#bgfx .fdot {
    position:absolute; bottom:-14px; border-radius:50%;
    background: radial-gradient(circle, #6fb1ff 0%, rgba(59,130,246,.0) 70%);
    animation: rise linear infinite;
    opacity:0;
}
@keyframes rise {
    0%   { transform: translateY(0) translateX(0); opacity:0; }
    8%   { opacity:1; }
    92%  { opacity:1; }
    100% { transform: translateY(-108vh) translateX(var(--drift, 30px)); opacity:0; }
}

/* ---------- ambient SOC ticker ---------- */
#soc-ticker {
    position:fixed; left:0; right:0; bottom:0; z-index:5; height:30px;
    display:flex; align-items:center; overflow:hidden; pointer-events:none;
    background: linear-gradient(90deg, rgba(10,15,30,.92), rgba(13,18,34,.85));
    border-top:1px solid rgba(59,130,246,.22);
    backdrop-filter: blur(6px);
    font-family:var(--mono); font-size:.68rem; letter-spacing:.06em;
}
#soc-ticker .tk-label {
    flex:none; padding:0 14px; color:#7dd3fc; font-weight:700; letter-spacing:.18em;
    display:flex; align-items:center; gap:8px;
    background: linear-gradient(90deg, rgba(59,130,246,.16), transparent);
    border-right:1px solid rgba(59,130,246,.22);
    height:100%;
}
#soc-ticker .tk-label i { width:6px; height:6px; border-radius:50%;
    background:#34d399; animation: pulse 1.6s ease-in-out infinite; }
#soc-ticker .tk-track { flex:1; overflow:hidden; white-space:nowrap; position:relative; }
#soc-ticker .tk-inner { display:inline-block; white-space:nowrap;
    animation: marquee 42s linear infinite; }
#soc-ticker .tk-inner span { color:#7d8db0; margin-right:34px; }
#soc-ticker .tk-inner b { color:#e2e8f0; font-weight:600; }
#soc-ticker .tk-inner em { font-style:normal; color:#34d399; }
@keyframes marquee { to { transform: translateX(-50%); } }

/* ---------- typewriter kicker ---------- */
.kicker.tt { display:inline-block; overflow:hidden; white-space:nowrap;
    width:0; animation: tt 1.5s steps(46, end) .2s forwards; }
.kicker.tt::after { content:""; display:inline-block; width:.55em; height:1em;
    background:#60a5fa; vertical-align:-.12em; margin-left:3px;
    animation: caret 1s steps(2,start) infinite; }
@keyframes tt { to { width: 62ch; } }
@keyframes caret { 50% { opacity:0; } }

/* ---------- floating hero / globe ---------- */
.levitate { animation: levitate 7s ease-in-out infinite; }
@keyframes levitate { 0%,100% { transform: translateY(0);} 50% { transform: translateY(-7px);} }

/* ---------- stat progress rings ---------- */
.stat.glass.ring { position:relative; display:flex; flex-direction:column;
    align-items:center; justify-content:center; text-align:center;
    min-height:96px; padding:14px 10px; }
.stat.glass.ring .rwrap { position:relative; width:74px; height:74px; margin-bottom:6px; }
.stat.glass.ring svg.ring { position:absolute; inset:0; width:74px; height:74px;
    transform: rotate(-90deg); }
.stat.glass.ring svg.ring .rt { fill:none; stroke:rgba(148,163,184,.12); stroke-width:4; }
.stat.glass.ring svg.ring .rf { fill:none; stroke-width:4; stroke-linecap:round;
    stroke-dasharray:188.5; stroke-dashoffset:188.5;
    animation: ringFill 1.2s .35s cubic-bezier(.3,.7,.3,1) forwards; }
@keyframes ringFill { to { stroke-dashoffset: var(--off, 188.5); } }
.stat.glass.ring .n { font-size:1.5rem; font-weight:800; font-family:var(--mono);
    position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
    animation: numIn .9s cubic-bezier(.16,.84,.44,1) .45s backwards; }
@keyframes numIn { from { opacity:0; transform: scale(.7); filter: blur(4px); }
    to { opacity:1; transform: scale(1); filter: blur(0); } }
.stat.glass.ring .l { font-size:.62rem; text-transform:uppercase; letter-spacing:.07em;
    color:var(--dim); margin-top:0; line-height:1.25; }
.stat.glass.ring .rf.g { stroke:#4ade80; filter:drop-shadow(0 0 5px rgba(74,222,128,.6)); }
.stat.glass.ring .rf.b { stroke:#60a5fa; filter:drop-shadow(0 0 5px rgba(96,165,250,.6)); }
.stat.glass.ring .rf.v { stroke:#a78bfa; filter:drop-shadow(0 0 5px rgba(167,139,250,.6)); }
.stat.glass.ring .rf.o { stroke:#fbbf24; filter:drop-shadow(0 0 5px rgba(251,191,36,.6)); }

/* ---------- animated section dividers ---------- */
.csec-line { position:relative; overflow:hidden; }
.csec-line::after {
    content:""; position:absolute; top:-2px; height:6px; width:110px; border-radius:3px;
    background: linear-gradient(90deg, transparent, rgba(103,232,249,.95), transparent);
    box-shadow: 0 0 12px rgba(103,232,249,.5);
    animation: travel 3.2s ease-in-out infinite;
}
@keyframes travel { 0% { left:-20%; opacity:0;} 12% { opacity:1;} 88% { opacity:1;}
    100% { left:105%; opacity:0;} }

/* ---------- feature grid with connectors ---------- */
.feat-grid { display:grid; grid-template-columns: repeat(3, 1fr); gap:26px; position:relative; }
.feat-grid .conn {
    position:absolute; top:40%; left:31%; width:38%; height:2px; pointer-events:none;
    background: linear-gradient(90deg, transparent, rgba(34,211,238,.5), transparent);
}
.feat-grid .conn::after { content:""; position:absolute; top:-4px; width:10px; height:10px;
    border-radius:50%; background:#7dd3fc; box-shadow:0 0 10px 2px #22d3ee;
    animation: flowX 2.4s ease-in-out infinite; }
.feat-grid .conn::before { content:""; position:absolute; top:-4px; left:100%; width:10px; height:10px;
    border-radius:50%; background:#fda4af; box-shadow:0 0 10px 2px #f87171;
    animation: flowX 2.4s ease-in-out 1.2s infinite; }
@keyframes flowX { 0% { left:-2%; opacity:0;} 15% { opacity:1;} 85% { opacity:1;}
    100% { left:100%; opacity:0;} }
.ficon { width:62px; height:62px; margin:0 0 14px; border-radius:16px;
    position:relative; display:flex; align-items:center; justify-content:center; font-size:1.7rem;
    background: linear-gradient(145deg, rgba(59,130,246,.22), rgba(30,41,59,.4));
    border:1px solid rgba(59,130,246,.4);
    box-shadow: 0 0 22px -6px rgba(59,130,246,.6), inset 0 1px 0 rgba(255,255,255,.14); }
.ficon::before { content:""; position:absolute; inset:-6px; border-radius:20px; border:1px dashed rgba(34,211,238,.35);
    animation: spinSlow 14s linear infinite; }
@keyframes spinSlow { to { transform: rotate(360deg); } }
.ficon.green { border-color:rgba(74,222,128,.4); box-shadow:0 0 22px -6px rgba(74,222,128,.6), inset 0 1px 0 rgba(255,255,255,.14); }
.ficon.green::before { border-color:rgba(74,222,128,.3); }
.ficon.violet { border-color:rgba(167,139,250,.4); box-shadow:0 0 22px -6px rgba(167,139,250,.6), inset 0 1px 0 rgba(255,255,255,.14); }
.ficon.violet::before { border-color:rgba(167,139,250,.3); }

/* ---------- journey steps ---------- */
.journey { display:grid; grid-template-columns: repeat(3, 1fr); gap:18px; position:relative; }
.jcard { text-align:center; padding:26px 18px 22px; }
.jnum { width:64px; height:64px; margin:0 auto 14px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    font-family:var(--mono); font-weight:800; font-size:1.5rem; color:#fff;
    background: linear-gradient(145deg, #2563eb, #4f46e5);
    border:1px solid rgba(129,140,248,.5);
    box-shadow: 0 0 24px -4px rgba(99,102,241,.8), inset 0 1px 0 rgba(255,255,255,.25);
    position:relative; }
.jnum::after { content:""; position:absolute; inset:-7px; border-radius:50%;
    border:1px solid rgba(34,211,238,.4); animation: nodeRing 2.6s ease-in-out infinite; }
.jarrow { position:absolute; top:44px; left:24%; width:52%; pointer-events:none;
    height:2px; background: linear-gradient(90deg, transparent, rgba(34,211,238,.6), transparent); }
.jarrow::after { content:""; position:absolute; top:-4px; width:10px; height:10px;
    border-radius:50%; background:#7dd3fc; box-shadow:0 0 10px 2px #22d3ee;
    animation: flowX 2.2s ease-in-out infinite; }

/* ---------- terminal ---------- */
.terminal { border-radius:14px; overflow:hidden; border:1px solid rgba(148,163,184,.16);
    background: linear-gradient(180deg, rgba(8,12,22,.95), rgba(5,8,15,.96));
    backdrop-filter: blur(10px);
    box-shadow: 0 18px 40px -18px rgba(0,0,0,.8), inset 0 1px 0 rgba(255,255,255,.05); }
.term-bar { display:flex; align-items:center; gap:8px; padding:10px 14px;
    background: rgba(30,41,59,.4); border-bottom:1px solid rgba(148,163,184,.12);
    font-family:var(--mono); font-size:.7rem; color:#7d8db0; letter-spacing:.1em; }
.term-bar .tb { width:11px; height:11px; border-radius:50%; }
.term-bar .tb.r { background:#f87171; } .term-bar .tb.y { background:#fbbf24; }
.term-bar .tb.g { background:#34d399; }
.term-title { margin-left:8px; font-weight:700; color:#93c5fd; }
.term-body { padding:14px 18px 18px; font-family:var(--mono); font-size:.76rem;
    line-height:1.75; }
.tline { white-space:pre-wrap; word-break:break-word; }
.tline .t { color:#52627e; margin-right:10px; }
.tline .tok { color:#4ade80; } .tline .tokw { color:#fbbf24; }
.tline .tokr { color:#f87171; } .tline .tokb { color:#7dd3fc; }
.tline .toki { color:#a78bfa; }
.cursor { display:inline-block; width:8px; height:14px; background:#7dd3fc;
    vertical-align:-2px; animation: caret 1s steps(2,start) infinite; }

/* ---------- stagger helpers ---------- */
.d1 { animation-delay: .08s; } .d2 { animation-delay: .16s; } .d3 { animation-delay: .24s; }
.d4 { animation-delay: .32s; } .d5 { animation-delay: .40s; } .d6 { animation-delay: .48s; }

/* colored hover glow on glass feature/journey cards */
.glow-blue:hover { border-color: rgba(59,130,246,.55); box-shadow: 0 20px 46px -18px rgba(37,99,235,.6), inset 0 1px 0 rgba(255,255,255,.1); }
.glow-green:hover { border-color: rgba(74,222,128,.5); box-shadow: 0 20px 46px -18px rgba(74,222,128,.5), inset 0 1px 0 rgba(255,255,255,.1); }
.glow-violet:hover { border-color: rgba(167,139,250,.5); box-shadow: 0 20px 46px -18px rgba(139,92,246,.55), inset 0 1px 0 rgba(255,255,255,.1); }

/* ============ sidebar brand + HUD panel ============ */
.ns-brand { display:flex; align-items:center; gap:10px; padding:14px 14px 12px; }
.ns-brand .ns-mark { position:relative; width:38px; height:38px; border-radius:10px;
    background:linear-gradient(135deg,#1e3a8a,#0f172a); border:1px solid rgba(59,130,246,.5);
    display:grid; place-items:center; box-shadow:0 0 18px rgba(59,130,246,.35); flex:none; }
.ns-brand .ns-mark::after { content:""; position:absolute; inset:4px; border-radius:6px;
    border:1px dashed rgba(103,232,249,.55); animation: spin 9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.ns-brand .ns-mark span { color:#60a5fa; font-size:1.25rem; font-weight:800; }
.ns-brand .ns-title { line-height:1.15; }
.ns-brand .ns-title b { color:#e2e8f0; font-size:.95rem; letter-spacing:.06em; display:block; }
.ns-brand .ns-title i { font-style:normal; color:#64748b; font-size:.68rem;
    letter-spacing:.18em; text-transform:uppercase; }
.ns-hud { margin:0 12px 14px; padding:12px 14px; border:1px solid #1c2740;
    border-radius:12px; background:linear-gradient(180deg, rgba(15,23,42,.6), rgba(9,13,22,.5));
    backdrop-filter:blur(8px); }
.ns-hud .ns-stat { display:flex; justify-content:space-between; align-items:center;
    padding:5px 0; font-size:.78rem; }
.ns-hud .ns-stat:not(:last-child) { border-bottom:1px solid rgba(30,41,59,.6); }
.ns-hud .ns-stat .k { color:#64748b; letter-spacing:.1em; font-size:.66rem; text-transform:uppercase; }
.ns-hud .ns-stat .v { color:#cbd5e1; font-family:var(--mono); font-weight:600; }
.ns-hud .ns-stat .v.g { color:#34d399; }
.ns-hud .ns-stat .v.c { color:#22d3ee; }
.ns-hud .ns-bar { height:4px; border-radius:2px; background:#1e293b; margin:8px 0 2px; overflow:hidden; }
.ns-hud .ns-bar i { display:block; height:100%; width:0; border-radius:2px;
    background:linear-gradient(90deg,#22d3ee,#3b82f6); animation: nsFill 1.6s ease .3s forwards;
    box-shadow:0 0 8px rgba(34,211,238,.6); }
@keyframes nsFill { to { width: var(--w, 100%); } }
.ns-tag { display:inline-flex; align-items:center; gap:6px; margin:2px 4px 2px 0;
    padding:3px 9px; border-radius:20px; font-size:.62rem; letter-spacing:.08em;
    border:1px solid #24324d; color:#8ea0bb; text-transform:uppercase; }
.ns-tag::before { content:""; width:5px; height:5px; border-radius:50%; background:#22c55e;
    box-shadow:0 0 6px #22c55e; }
.ns-ver { margin:0 12px 8px; text-align:center; color:#475569; font-size:.62rem;
    letter-spacing:.14em; font-family:var(--mono); }
[data-testid="stSidebar"] .ns-wrap { position:relative; }
[data-testid="stSidebar"] .ns-wrap::after { content:""; position:absolute; left:14px; right:14px;
    bottom:-6px; height:1px;
    background:linear-gradient(90deg, transparent, rgba(59,130,246,.4), transparent); }

/* ============================================================
   CURSOR-REACTIVE + MOTION LAYER (Layer 1,4,5,6)
   ============================================================ */
/* Layer 1 — ambient breathing light (pure CSS; no JS needed) */
body::after {
    content:""; position:fixed; top:-140px; right:-140px; width:560px; height:560px;
    border-radius:50%; pointer-events:none; z-index:0;
    background: radial-gradient(circle, rgba(59,130,246,.10), transparent 65%);
    animation: respire 9s ease-in-out infinite alternate;
}
@keyframes respire { from { opacity:.35; transform: scale(1);} to { opacity:.75; transform: scale(1.15);} }

/* Layer 5 — hero title breathing glow */
.hero h1 {
    background-size: 200% 100%;
    animation: heroGlow 5s ease-in-out infinite alternate;
}
@keyframes heroGlow {
    from { filter: drop-shadow(0 0 8px rgba(99,102,241,.25)); background-position: 0% 50%; }
    to   { filter: drop-shadow(0 0 22px rgba(59,130,246,.55)); background-position: 100% 50%; }
}

/* Layer 6 — ambient floating orb behind hero */
.hero::after {
    content:""; position:absolute; width:520px; height:520px; border-radius:50%;
    top:-140px; right:-120px; pointer-events:none;
    background: radial-gradient(circle, rgba(59,130,246,.10), rgba(34,211,238,.04) 45%, transparent 62%);
    animation: orbDrift 14s ease-in-out infinite alternate;
}
@keyframes orbDrift {
    from { transform: translate(0,0) scale(1); }
    to   { transform: translate(-50px,34px) scale(1.12); }
}

/* Layer 2 — 3D perspective lift on glass hover (pure CSS) */
.glass.hover { will-change: transform;
    transition: transform .18s ease-out, box-shadow .25s ease, border-color .25s ease; }

footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# LIVING BACKGROUND — particle field + ambient SOC ticker
# ============================================================
_particles = "".join(
    f"<i class='fdot' style='left:{pct:.1f}%;width:{2+3*(i%5)*.35:.1f}px;"
    f"height:{2+3*(i%5)*.35:.1f}px;animation-duration:{10+(i%7)*2.2:.1f}s;"
    f"animation-delay:{-i*0.9:.1f}s;--drift:{(i%9-4)*14}px'></i>"
    for i, pct in enumerate([(i * 37.7 + 13.3) % 100 for i in range(30)])
)

_ticker_entries = [
    ("SCAN", "window #187 · risk 0.847", "tokr"),
    ("FORECAST", "updated · 358 alert windows", "tok"),
    ("LEDGER", "sealed block #42 · SHA256 9f3a...", "tokb"),
    ("AUTO-PLAYBOOK", "iptables draft for DDoS", "tokw"),
    ("NOVELTY", "callout · window #203 · 96th pct", "toki"),
    ("ENGINE", "RandomForest @ 76-dim rolling", "tokb"),
    ("HONEYPOT", "decoy :8080 armed", "tok"),
    ("TELEMETRY", "CICIDS2017 · Friday · offline", "tokw"),
]

st.markdown(
    f"""
<div id="bgfx" aria-hidden="true">{_particles}</div>
<div id="soc-ticker" aria-hidden="true">
  <div class="tk-label"><i></i>NETSIGHT&nbsp;LIVE</div>
  <div class="tk-track">
    <div class="tk-inner">
      {''.join(f'<span><em>[{k.lower()}]</em> {d} <b>·</b> </span>' for k, d, _ in _ticker_entries)}
      {''.join(f'<span><em>[{k.lower()}]</em> {d} <b>·</b> </span>' for k, d, _ in _ticker_entries)}
    </div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

pg = st.navigation([
    st.Page("home.py", title="Home", icon="🏠", default=True),
    st.Page("dashboard.py", title="SOC Dashboard", icon="🛡"),
])
pg.run()