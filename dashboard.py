"""
dashboard.py
------------
NetSight SOC dashboard — the five analysis tabs on the real pipeline.

  1. Forecaster      — interactive risk timeline, alert feed, MITRE/CAPEC/CVE
  2. Explainability  — per-window feature attribution (ablation / LSTM saliency)
  3. What-If Lab     — counterfactual: perturb real window features, re-run model
  4. Active Defense  — MITRE intel + multi-OS firewall rules + honeypot sim
  5. Forensic Audit  — tamper-proof SHA-256 Merkle ledger + SOC PDF report
"""

import html
import json
import os
import tempfile
import time
from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

from infer import (
    WINDOW_SIZE,
    RandomForestEngine,
    LSTMEngine,
    run_inference,
)
from active_defense import ActiveDefenseEngine
from forensics_report import ForensicLedger, generate_pdf_report
from knowledge_base import family_meta, capec_chain

FAM_COLORS = {
    "botnet": "#f43f5e", "dos": "#f97316", "web_attack": "#eab308",
    "brute_force": "#34d399", "port_scan": "#60a5fa", "infiltration": "#a78bfa",
    "none": "#64748b",
}


@st.cache_resource(show_spinner=False)
def get_engine(model_name, threshold):
    if model_name == "RandomForest":
        return RandomForestEngine(threshold=threshold)
    return LSTMEngine(threshold=threshold)


@st.cache_resource(show_spinner=False)
def load_ledger():
    return ForensicLedger()


DEMO_CSVS = {
    "Friday DDoS (recommended)": "dataset/demo_friday_ddos_windows.csv",
    "Thursday web attacks": "dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday brute-force": "dataset/Tuesday-WorkingHours.pcap_ISCX.csv",
}


def risk_badge(risk):
    if risk >= 0.75:
        return "crit", "CRITICAL"
    if risk >= 0.5:
        return "high", "HIGH"
    return "med", "ELEVATED"


def sev_badge(sev):
    s = str(sev or "").upper()
    if s == "CRITICAL":
        return "crit", "CRITICAL"
    if s == "HIGH":
        return "high", "HIGH"
    if s == "MEDIUM":
        return "med", "MEDIUM"
    if s in ("NONE", "LOW"):
        return "none", s
    return "low", s or "—"


def fam_color(f):
    return FAM_COLORS.get(str(f), "#94a3b8")


def timeline_chart(tl, flagged, threshold):
    base = alt.Chart(tl).encode(
        x=alt.X("window_id:Q", title="Window"),
        y=alt.Y("risk_score:Q", title="Risk score", scale=alt.Scale(domain=[0, 1])),
        tooltip=[alt.Tooltip("window_id:O", title="window"),
                 alt.Tooltip("risk_score:Q", title="risk", format=".3f"),
                 alt.Tooltip("attack_family:N", title="family"),
                 alt.Tooltip("mitre_stage:N", title="MITRE")],
    )
    area = base.mark_area(opacity=0.12, color="#3b82f6", line=False)
    line = base.mark_line(color="#3b82f6", strokeWidth=2)
    layers = [area, line]
    if len(flagged):
        d = alt.Chart(flagged).mark_circle(color="#ef4444", size=78).encode(
            x=alt.X("window_id:Q"),
            y=alt.Y("risk_score:Q"),
            tooltip=[alt.Tooltip("window_id:O", title="alert window"),
                     alt.Tooltip("risk_score:Q", title="risk", format=".3f"),
                     alt.Tooltip("attack_family:N", title="family")],
        )
        layers.append(d)
    th = alt.Chart(pd.DataFrame({"y": [threshold]})).mark_rule(
        color="#fbbf24", strokeDash=[5, 4]).encode(y="y:Q")
    layers.append(th)
    return alt.layer(*layers).properties(height=330).interactive()


ledger = load_ledger()
defense = ActiveDefenseEngine()

def _load_json(name, default=None):
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), name)) as fh:
            return json.load(fh)
    except Exception:
        return default

full = _load_json("full_model_summary.json", {})
evalf = _load_json("eval_forecasting.json", {})
world = _load_json("world_model_dynamics.json", {})
wf = _load_json("walk_forward_cv.json", {})
lt = evalf.get("lead_time_windows") or {}

# ============================ SIDEBAR ======================================
with st.sidebar:
    st.header("⚙️ Controls")
    model_name = st.radio("Model", ["RandomForest", "LSTM"], horizontal=True)
    threshold = st.slider("Alert threshold (risk)", 0.0, 1.0, 0.5, 0.05)
    max_windows = st.number_input("Max windows (0 = whole file)",
                                  min_value=0, value=0, step=50)
    st.markdown("---")
    ingest = st.radio("Data source", ["Upload file", "Demo artifact"],
                      key="src_ingest", horizontal=False)
    uploaded = None
    demo_file = None
    if ingest == "Demo artifact":
        chosen = st.selectbox("Pick a CICIDS2017 day-file", list(DEMO_CSVS),
                              key="src_demo")
        demo_file = DEMO_CSVS[chosen]
    else:
        uploaded = st.file_uploader(
            "Upload a CICIDS2017 flow CSV, a pre-featurized window CSV, "
            "or a PCAP", type=["csv", "pcap"])
    with st.expander("ℹ️ System info"):
        import sys
        st.markdown(f"- **Python** {sys.version.split()[0]}\n"
                    f"- **Streamlit** {st.__version__}\n"
                    f"- **scikit-learn** {__import__('sklearn').__version__}\n"
                    f"- **Window** = {WINDOW_SIZE} flows\n"
                    f"- **Features** = 76-dim rolling")

# ============================ TITLE ========================================
st.title("🛡 SOC Dashboard")
st.caption(
    "Forecasts **known attack progressions** up to 6 windows ahead · maps "
    "alerts to MITRE ATT&CK · explains every prediction · novelty callout for "
    "activity unlike anything in training.")

# ============================ RESOLVE INPUT ================================
is_pcap = False
input_path = None
if demo_file:
    if os.path.exists(demo_file):
        input_path = demo_file
    else:
        st.warning("Demo dataset not found locally. Upload a CSV/PCAP instead "
                   "or clone the raw captures (git-ignored).")
        input_path = None
elif uploaded is not None:
    is_pcap = uploaded.name.lower().endswith(".pcap")
    strip = tempfile.NamedTemporaryFile(
        suffix=".pcap" if is_pcap else ".csv", delete=False)
    strip.write(uploaded.getbuffer())
    strip_path = strip.name
    strip.close()
    input_path = strip_path

# ============================ EMPTY STATE ==================================
def _launch_demo():
    st.session_state["src_ingest"] = "Demo artifact"
    st.session_state["src_demo"] = "Friday DDoS (recommended)"


if input_path is None:
    ec1, ec2, ec3 = st.columns([1.2, 2.2, 1.2])
    with ec2:
        st.markdown("""
        <div class="hero" style="text-align:center; padding:34px 28px">
          <div class="kicker">Awaiting data</div>
          <h1 style="font-size:1.9rem">Ready when you are</h1>
          <div class="sub" style="margin:0 auto">Pick a data source in the
          sidebar, or hit <b>Run Demo</b> to analyze the committed Friday DDoS
          sample (452 windows · 358 alerts — the recommended showcase).</div>
        </div>""", unsafe_allow_html=True)
        st.button("🚀 Run Friday DDoS Demo", type="primary",
                  use_container_width=True, on_click=_launch_demo)
        st.caption("Or upload your own CSV / PCAP from the sidebar controls.")
    st.stop()

# ============================ INFERENCE ====================================
engine = get_engine(model_name, threshold)
tmp_path = input_path
pcap_extras = None
t0 = time.time()
try:
    if is_pcap:
        from packet_features import pcap_to_windows_csv
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as t:
            tmp_path = t.name
        with st.spinner("Parsing PCAP → flow windows…"):
            pcap_to_windows_csv(input_path, tmp_path)
        pcap_extras = pd.read_csv(tmp_path)
    with st.spinner("Streaming inference… this runs offline; big files take a moment."):
        timeline, summary = run_inference(tmp_path, engine,
                                           max_windows=int(max_windows))
finally:
    if uploaded is not None:
        os.unlink(input_path)
        if tmp_path != input_path:
            os.unlink(tmp_path)
elapsed = time.time() - t0

if not timeline:
    st.warning("No windows produced. Check the CSV schema.")
    st.stop()

tl = pd.DataFrame(timeline)
if "zero_day" in tl.columns:
    tl["zero_day_likely"] = tl["zero_day"].apply(
        lambda z: bool(z and z.get("zero_day_likely")))
    tl["novelty_pctl"] = tl["zero_day"].apply(
        lambda z: z.get("novelty_pctl") if z else None)
flagged = tl[tl["predicted_alert"]]
src_label = f"Demo:{chosen}" if demo_file else (f"Upload:{uploaded.name}" if uploaded else "—")

# lead-time: windows from earliest real attack onset to the model's first alert
first_alert_win = int(flagged["window_id"].min()) if len(flagged) else None
lead_str = "—"
if len(flagged):
    if "gt_family" in tl.columns:
        g_att = tl[tl["gt_family"].map(lambda g: str(g).strip().lower() != "none")]
        if len(g_att):
            onset = int(g_att["window_id"].min())
            lead_wins = max(0, first_alert_win - onset)
            lead_str = f"{lead_wins}w{' on-time' if lead_wins == 0 else ''}"
        else:
            lead_str = f"w{first_alert_win}"
    else:
        lead_str = f"w{first_alert_win}"

# ============================ CONTEXT BAR ==================================
st.markdown(
    f"<div class='ctxbar'>"
    f"<span class='k'>Model</span> <span class='v'>{model_name}</span>"
    f"<span class='sep'>·</span>"
    f"<span class='k'>Threshold</span> <span class='v'>{threshold:.2f}</span>"
    f"<span class='sep'>·</span>"
    f"<span class='k'>Source</span> <span class='v'>{src_label}</span>"
    f"<span class='sep'>·</span>"
    f"<span class='k'>Windows</span> <span class='v'>{summary['windows_processed']}</span>"
    f"<span class='sep'>·</span>"
    f"<span class='k'>Alerts</span> <span class='v'>{summary['flagged_windows']}</span>"
    f"<span class='sep'>·</span>"
    f"<span class='k'>First</span> <span class='v'>w{first_alert_win}</span>"
    f"<span class='sep'>·</span>"
    f"<span class='k'>Lead</span> <span class='v'>{lead_str}</span>"
    f"<span class='sep'>·</span>"
    f"<span class='k'>⏱</span> <span class='v'>{elapsed:.1f}s</span>"
    f"</div>", unsafe_allow_html=True)

# ============================ OVERVIEW STRIP ===============================
alert_stat = "ALERT" if len(flagged) else "CLEAR"
o1, o2, o3, o4, o5 = st.columns(5)
dstate = "r" if len(flagged) else "g"
with o1:
    st.markdown(
        f"<div class='metric-card' style='height:100%'>"
        f"<span class='dot {dstate} {'pulse' if len(flagged) else ''}'></span>"
        f"<span style='color:var(--dim);font-size:.72rem;text-transform:uppercase;"
        f"letter-spacing:.06em'>Status</span><br>"
        f"<span style='font-family:var(--mono);font-weight:800;font-size:1.5rem'>"
        f"{alert_stat}</span></div>", unsafe_allow_html=True)
o2.metric("Windows", summary["windows_processed"])
o3.metric("Flags", summary["flagged_windows"])
o4.metric("Flag rate", f"{summary['flag_rate']:.1%}")
o5.metric("Peak risk", f"{summary['peak_risk']:.3f}")

spark = alt.Chart(tl).mark_line(color="#3b82f6", strokeWidth=2).encode(
    x=alt.X("window_id:Q", axis=None),
    y=alt.Y("risk_score:Q", axis=None, scale=alt.Scale(domain=[0, 1])),
    tooltip=[alt.Tooltip("window_id:O", title="window"),
             alt.Tooltip("risk_score:Q", title="risk", format=".3f")])
if len(flagged):
    spark = alt.layer(
        spark,
        alt.Chart(flagged).mark_circle(color="#ef4444", opacity=0.7).encode(
            x="window_id:Q", y="risk_score:Q")).resolve_scale(y="shared")
st.altair_chart(spark.properties(height=64), width="stretch")
st.caption("Risk signal across the timeline — red dots mark alert windows. "
           "Full interactive view in the 🔭 Forecaster tab.")

# ================= DETECTION QUALITY (vs ground truth) ====================
# Exclude engine warm-up rows (no prediction was made) from the confusion
# count, and skip entirely when ground-truth labels are unavailable.
has_truth = "gt_family" in tl.columns and tl["gt_family"].notna().any()
try:
    if "warming_up" in tl.columns:
        scored = tl[~tl["warming_up"].astype(bool)].copy()
    else:
        scored = tl.copy()
    if has_truth and len(scored):
        gt_attack = scored["gt_family"].map(lambda g: str(g).strip().lower() != "none")
        pred_alert = scored["predicted_alert"].astype(bool)
        tp = int((gt_attack & pred_alert).sum())
        fp = int((~gt_attack & pred_alert).sum())
        fn = int((gt_attack & ~pred_alert).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        true_neg = int(len(scored) - tp - fp - fn)
        scored_n = len(scored)
    else:
        tp = fp = fn = 0; precision = recall = f1 = 0.0; true_neg = 0; scored_n = 0
except Exception:
    tp = fp = fn = 0; precision = recall = f1 = 0.0; true_neg = 0; scored_n = 0

if has_truth:
    st.markdown(f"""
    <div style="font-size:.78rem;letter-spacing:.06em;color:var(--dim);margin:6px 0 4px;
        text-transform:uppercase">Detection quality · vs ground-truth labels</div>
    <div class="metric-grid glass">
      <div class="mq"><span class="mile">Precision</span><span class="miv g">{precision:.2%}</span></div>
      <div class="mq"><span class="mile">Recall</span><span class="miv c">{recall:.2%}</span></div>
      <div class="mq"><span class="mile">F1</span><span class="miv v">{f1:.2%}</span></div>
      <div class="mq"><span class="mile">TP</span><span class="miv g">{tp}</span></div>
      <div class="mq"><span class="mile">FP</span><span class="miv r">{fp}</span></div>
      <div class="mq"><span class="mile">FN</span><span class="miv o">{fn}</span></div>
    </div>""", unsafe_allow_html=True)

    if len(flagged):
        st.markdown(f"""
        <div style="font-size:.78rem;letter-spacing:.06em;color:var(--dim);margin:10px 0 4px;
            text-transform:uppercase">Earliest warnings · model fired first</div>
        <div class="feed-window">
        """, unsafe_allow_html=True)
        for _, r in list(flagged.head(6).iterrows()):
            fcls, _ = risk_badge(r["risk_score"])
            right = "hit" if str(r.get("gt_family", "")).strip().lower() != "none" else "miss"
            rcolor = "#4ade80" if right == "hit" else "#f87171"
            st.markdown(
                f"<div class='feed-row'><span class='fw'>{int(r['window_id'])}</span>"
                f"<span class='fam'>{html.escape(str(r['attack_family']))}</span>"
                f"<span class='risk'>{r['risk_score']:.3f}</span>"
                f"<span class='truth' style='color:{rcolor}'>{right}</span></div>",
                unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

# ============================ TABS =========================================
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔭 Forecaster", "🔬 Explainability", "🧪 What-If Lab",
    "🛡 Active Defense", "📜 Forensic Audit"])

# ==========================================================================
# TAB 1 — FORECASTER
# ==========================================================================
with tab1:
    if is_pcap and pcap_extras is not None and not pcap_extras.empty:
        st.subheader("Packet-level features (per 500-packet window)")
        cols = ["window_id", "packet_rate", "byte_rate", "syn_only_rate",
                "retrans_ratio", "ttl_std", "tcp_win_mean", "frag_ratio",
                "icmp_ratio", "attack_family", "heuristic_stage"]
        cols = [c for c in cols if c in pcap_extras.columns]
        st.dataframe(pcap_extras[cols].set_index("window_id").head(80),
                     width="stretch", height=220)

    st.markdown('<div class="sec-title"><h3>Forecast timeline</h3></div>',
                unsafe_allow_html=True)
    st.altair_chart(timeline_chart(tl, flagged, threshold), width="stretch")

    # ---- ATTACK PROGRESSION SCRUBBER ----
    if len(tl):
        wmin, wmax = int(tl["window_id"].min()), int(tl["window_id"].max())
        scrub_w = st.slider("Scrub timeline", wmin, wmax, wmin,
                            key="scrub_timeline",
                            help="Pick a window to inspect its risk, family, and MITRE stage.")
        srow = tl[tl["window_id"].astype(int) == scrub_w]
        if len(srow):
            sr = srow.iloc[0]
            sr_cls, sr_lab = risk_badge(sr["risk_score"])
            gt_hit = str(sr.get("gt_family", "none")).strip().lower() != "none"
            gt_color = "#4ade80" if gt_hit else "#94a3b8"
            gt_label = "attack" if gt_hit else "benign"
            atc = int(sr.get("predicted_alert", False))
            atc_color = "#f87171" if atc else "#94a3b8"
            atc_label = "ALERT" if atc else "clear"
            st.markdown(
                f"<div class='glass' style='padding:18px 22px; margin:8px 0 12px; "
                f"border-left:3px solid {sr_cls.replace('badge ','').split()[0] if sr_cls else '#3b82f6'}'>"
                f"<div style='display:grid; grid-template-columns:auto 1fr 1fr 1fr 1fr auto; "
                f"gap:20px; align-items:center'>"
                f"<div><span style='font-family:var(--mono); font-weight:800; font-size:1.35rem; "
                f"color:#e2e8f0'>W{scrub_w}</span></div>"
                f"<div><span style='font-size:.64rem; text-transform:uppercase; color:#64748b; "
                f"letter-spacing:.08em'>Risk</span><br>"
                f"<span style='font-family:var(--mono); font-weight:700; font-size:1.1rem; "
                f"color:{sr_cls.replace('badge ','').split()[0] if sr_cls else '#3b82f6'}'>"
                f"{sr['risk_score']:.3f}</span></div>"
                f"<div><span style='font-size:.64rem; text-transform:uppercase; color:#64748b; "
                f"letter-spacing:.08em'>Family</span><br>"
                f"<span style='font-family:var(--mono); font-weight:600; font-size:.95rem; "
                f"color:#e2e8f0'>{html.escape(str(sr['attack_family']))}</span></div>"
                f"<div><span style='font-size:.64rem; text-transform:uppercase; color:#64748b; "
                f"letter-spacing:.08em'>MITRE</span><br>"
                f"<span style='font-family:var(--mono); font-weight:600; font-size:.95rem; "
                f"color:#93c5fd'>{html.escape(str(sr['mitre_stage']))}</span></div>"
                f"<div><span style='font-size:.64rem; text-transform:uppercase; color:#64748b; "
                f"letter-spacing:.08em'>GT / Model</span><br>"
                f"<span style='font-family:var(--mono); font-size:.82rem'>"
                f"<span style='color:{gt_color}'>{gt_label}</span> → "
                f"<span style='color:{atc_color}'>{atc_label}</span></span></div>"
                f"</div></div>", unsafe_allow_html=True)

    # ---- threat-matrix heatmap: attack family x risk across windows ----
    if "attack_family" in tl.columns and len(tl):
        fam = tl["attack_family"].fillna("none").astype(str)
        fam = fam.map(lambda x: "benign" if x == "none" else x)
        try:
            hdf = tl.assign(_fam=fam)
            heat = alt.Chart(hdf).mark_rect().encode(
                x=alt.X("window_id:O", title="Window"),
                y=alt.Y("_fam:N", title="attack family"),
                color=alt.Color("risk_score:Q",
                                scale=alt.Scale(scheme="blues", domain=[0.2, 1.0]),
                                title="risk"),
                tooltip=[alt.Tooltip("window_id:O", title="window"),
                         alt.Tooltip("_fam:N", title="family"),
                         alt.Tooltip("risk_score:Q", title="risk", format=".3f"),
                         alt.Tooltip("mitre_stage:N", title="MITRE")],
            ).properties(height=200)
            st.markdown('<div class="sec-title"><h3>Threat matrix</h3></div>',
                        unsafe_allow_html=True)
            st.altair_chart(heat, width="stretch")
            st.caption("Per-window risk as a heatmap by predicted attack family — "
                       "visualizes which families are active and when.")
        except Exception:
            pass

    if len(flagged) == 0:
        st.success("No alerts at the current threshold.")
    else:
        n_zd = int(flagged["zero_day_likely"].sum()) if "zero_day_likely" in flagged else 0
        if n_zd:
            st.markdown(
                f"<span class='badge warn'>⚠ {n_zd} of {len(flagged)} alert "
                f"windows: possible novel activity (outside known-attack "
                f"manifold)</span>", unsafe_allow_html=True)

        st.markdown('<div class="sec-title"><h3>First alert</h3></div>',
                    unsafe_allow_html=True)
        first = flagged.iloc[0]
        rcls, rlab = risk_badge(first["risk_score"])
        zdflag = bool(first.get("zero_day", {}).get("zero_day_likely")) if first.get("zero_day") else False
        st.markdown(
            f"<div class='alert-card fadeup'>"
            f"<div class='row'><span class='who'>Window "
            f"<span style='font-family:var(--mono)'>#{int(first['window_id'])}</span>"
            f" · risk <span style='font-family:var(--mono)'>{first['risk_score']:.3f}</span></span>"
            f"<span><span class='badge {rcls}'>{rlab}</span> "
            f"<span class='badge info'>{html.escape(str(first['attack_family']))}</span>"
            f"{' <span class=\'badge warn\'>novelty</span>' if zdflag else ''}</span></div>"
            f"<div class='row' style='margin-top:8px'>"
            f"<span>MITRE stage <span style='font-family:var(--mono)'>{html.escape(str(first['mitre_stage']))}</span></span>"
            f"<span style='color:var(--dim)'>ground truth: {html.escape(str(first.get('gt_family','—'))) if first.get('gt_family') else '—'}</span>"
            f"</div></div>", unsafe_allow_html=True)

        zd = first.get("zero_day")
        if zd:
            st.markdown(
                f"**Zero-day callout:** {zd.get('family_confidence')} conf · "
                f"novelty distance `{zd.get('novelty_dist')}` "
                f"(pctl `{zd.get('novelty_pctl')}`)")

        meta = family_meta(first["attack_family"])
        with st.expander("ATT&CK / CAPEC / CVE enrichment"):
            st.markdown(f"**{meta['description']}**\n\n"
                        f"- **Stage:** `{first['mitre_stage']}`\n"
                        f"- **CAPEC:** {capec_chain(first['attack_family'])}\n"
                        f"- **Known CVEs (illustrative):** "
                        f"{', '.join(meta['cves']) if meta['cves'] else '-'}")

        cc1, cc2 = st.columns(2)
        with cc1:
            if "mitre_stage" in flagged:
                st.markdown('<div class="sec-title"><h3>MITRE stage breakdown</h3></div>',
                            unsafe_allow_html=True)
                stages = Counter(flagged["mitre_stage"])
                sdf = pd.DataFrame(stages.items(), columns=["stage", "count"])
                st.altair_chart(
                    alt.Chart(sdf).mark_bar(cornerRadiusEnd=4).encode(
                        x=alt.X("stage:N", sort="-y", title=None),
                        y=alt.Y("count:Q", title="alert windows"),
                        color=alt.Color("stage:N", legend=None,
                                        scale=alt.Scale(range=["#60a5fa", "#818cf8",
                                                              "#a78bfa", "#c084fc",
                                                              "#38bdf8"])),
                        tooltip=["stage:N", "count:Q"]).properties(height=240),
                    width="stretch")
        with cc2:
            if "attack_family" in flagged:
                st.markdown('<div class="sec-title"><h3>Attack families</h3></div>',
                            unsafe_allow_html=True)
                fcount = flagged["attack_family"].value_counts().reset_index()
                fcount.columns = ["family", "count"]
                st.altair_chart(
                    alt.Chart(fcount).mark_arc(innerRadius=46).encode(
                        theta=alt.Theta("count:Q"),
                        color=alt.Color("family:N", legend=alt.Legend(symbolType="circle"),
                                        scale=alt.Scale(domain=list(fcount["family"]),
                                                        range=[fam_color(f) for f in fcount["family"]])),
                        tooltip=["family:N", "count:Q"]).properties(height=240),
                    width="stretch")

        st.markdown('<div class="sec-title"><h3>Alert feed</h3></div>',
                    unsafe_allow_html=True)
        n_show = st.selectbox(
            "Show", [10, 25, 50, len(flagged)],
            index=1,
            format_func=lambda n: ("All" if n >= len(flagged)
                                   else f"First {n}"),
            key="feed_limit")
        shown_cnt = n_show if n_show < len(flagged) else len(flagged)
        st.caption(f"Showing **{shown_cnt} of {len(flagged)}** alert windows.")
        for _, row in flagged.head(shown_cnt).iterrows():
            rcls, rlab = risk_badge(row["risk_score"])
            zd_b = bool(row.get("zero_day", {}).get("zero_day_likely")) if row.get("zero_day") else False
            attr = row.get("attribution") or {}
            drivers = ", ".join(f"{k}" for k, _ in list(attr.items())[:4]) if attr else ""
            st.markdown(
                f"<div class='alert-card fadeup'><div class='row'>"
                f"<span class='who'>#{int(row['window_id'])}</span>"
                f"<span style='font-family:var(--mono);font-weight:700'>{row['risk_score']:.3f}</span>"
                f"<span class='badge {rcls}'>{rlab}</span>"
                f"<span class='badge info'>{html.escape(str(row['attack_family']))}</span>"
                f"<span style='font-family:var(--mono);font-size:.78rem;color:var(--dim)'>{html.escape(str(row['mitre_stage']))}</span>"
                f"{'<span class=\'badge warn\'>novelty</span>' if zd_b else ''}"
                f"</div>"
                f"{'<div style=\'margin-top:6px;color:var(--muted);font-size:.78rem\'>drivers: ' + ' · '.join(html.escape(k) for k in drivers.split(', ')) if drivers else ''}</div></div>",
                unsafe_allow_html=True)
        if len(flagged) > shown_cnt:
            st.caption(f"…and {len(flagged) - shown_cnt} more alerts — switch to "
                       "What-If / Explainability for per-window depth, or raise "
                       "the limit above for the full set.")
        with st.expander("Full alerts table"):
            shown = flagged.copy()
            if "attribution" in shown:
                shown["drivers"] = shown["attribution"].apply(
                    lambda a: ", ".join(f"{k}: {v:.3g}" for k, v in (a or {}).items()))
            show_cols = [c for c in ["window_id", "risk_score", "attack_family",
                                     "mitre_stage", "gt_family", "drivers"]
                         if c in shown.columns]
            st.dataframe(shown[show_cols].set_index("window_id"),
                         width="stretch", height=300)
            if "zero_day_likely" in shown.columns:
                st.caption("Zero-day callout marks alert windows whose feature "
                           "vector sits outside the known-attack manifold "
                           "(>95th-percentile NN distance). Analyst review, not "
                           "an automated verdict.")

# ==========================================================================
# TAB 2 — EXPLAINABILITY
# ==========================================================================
with tab2:
    # ---- MODEL COMPARISON (RF vs LSTM) ----
    rf_data = {
        "Cross-day AUC": (full.get("roc_auc"), "g"),
        "Precision": (full.get("precision"), "g"),
        "Recall": (full.get("recall"), "r"),
        "F1": (full.get("f1"), "o"),
        "Lead (median)": (lt.get("median"), "b"),
    }
    lstm_data = {
        "Next-state AUC": (world.get("lstm_next_attack_window_auc"), "v"),
        "Walk-forward AUC": (wf.get("pooled_auc"), "o"),
        "Forecast AUPRC": (evalf.get("auprc_forecast"), "b"),
    }
    try:
        comp_cols = st.columns([1, 1], gap="large")
        with comp_cols[0]:
            st.markdown('<div class="sec-title"><h3>Model comparison</h3></div>',
                        unsafe_allow_html=True)
            comp_html = "<div style='display:grid; grid-template-columns:1fr 1fr; gap:10px'>"
            for label, (val, cls) in rf_data.items():
                v = f"{val:.3f}" if val is not None else "—"
                comp_html += (
                    f"<div class='metric-card' style='padding:10px 12px'>"
                    f"<div style='font-size:.6rem; text-transform:uppercase; color:var(--dim); "
                    f"letter-spacing:.08em'>{label}</div>"
                    f"<div style='font-family:var(--mono); font-weight:800; font-size:1.05rem; "
                    f"color:var(--{cls})'>{v}</div></div>")
            comp_html += "</div>"
            st.markdown(comp_html, unsafe_allow_html=True)
            st.caption("RandomForest · 76-dim rolling · trained Mon–Thu, tested Fri")
        with comp_cols[1]:
            st.markdown('<div class="sec-title"><h3>LSTM world model</h3></div>',
                        unsafe_allow_html=True)
            lstm_html = "<div style='display:grid; grid-template-columns:1fr 1fr; gap:10px'>"
            for label, (val, cls) in lstm_data.items():
                v = f"{val:.3f}" if val is not None else "—"
                lstm_html += (
                    f"<div class='metric-card' style='padding:10px 12px'>"
                    f"<div style='font-size:.6rem; text-transform:uppercase; color:var(--dim); "
                    f"letter-spacing:.08em'>{label}</div>"
                    f"<div style='font-family:var(--mono); font-weight:800; font-size:1.05rem; "
                    f"color:var(--{cls})'>{v}</div></div>")
            lstm_html += "</div>"
            st.markdown(lstm_html, unsafe_allow_html=True)
            st.caption("LSTM · learns state-transition P(S_t+1 | S_t) · never auto-blocks")
    except Exception:
        pass

    st.markdown("---")

    # ---- FAMILY-LEVEL BREAKDOWN ----
    pf = evalf.get("per_family", {})
    if pf:
        try:
            st.markdown('<div class="sec-title"><h3>Per-family detection rate</h3></div>',
                        unsafe_allow_html=True)
            rows = []
            for fam, d in pf.items():
                rows.append({
                    "family": fam,
                    "total": d.get("windows", 0),
                    "warned": d.get("warned_within_horizon", 0),
                    "lead": d.get("median_lead_windows", 0),
                    "rate": (d.get("warned_within_horizon", 0) / d.get("windows", 1)
                             if d.get("windows") else 0),
                })
            fam_df = pd.DataFrame(rows)
            fam_chart = alt.Chart(fam_df).mark_bar(cornerRadiusEnd=4).encode(
                x=alt.X("family:N", title=None),
                y=alt.Y("rate:Q", title="detection rate", scale=alt.Scale(domain=[0, 1])),
                color=alt.Color("family:N", legend=None,
                                scale=alt.Scale(domain=fam_df["family"].tolist(),
                                                range=["#f87171", "#60a5fa", "#4ade80"])),
                tooltip=["family:N",
                         alt.Tooltip("warned:Q", title="warned"),
                         alt.Tooltip("total:Q", title="total"),
                         alt.Tooltip("lead:Q", title="lead (median w)")],
            ).properties(height=220)
            st.altair_chart(fam_chart, width="stretch")
            st.caption("DDoS warned 269/278 · Botnet 16/92 · PortScan 0/351 (cross-day blind spot)")
        except Exception:
            pass

    st.markdown("---")

    # ---- PER-WINDOW ATTRIBUTION ----
    st.markdown('<div class="sec-title"><h3>Real per-window feature attribution</h3></div>',
                unsafe_allow_html=True)
    st.markdown("For the **RandomForest**, risk is re-run with each top feature "
                "set to its batch mean (mean-imputation ablation) — the drop in "
                "risk is that feature's contribution. For the **LSTM**, gradient "
                "saliency over the input sequence is used. This is the model's "
                "*own* reasoning, not a separate explainer.")
    if len(flagged) == 0:
        st.info("No alert windows to explain at the current threshold.")
    else:
        opts = flagged["window_id"].astype(int).tolist()
        sel = st.selectbox("Alert window to explain", opts, index=0)
        row = flagged[flagged["window_id"].astype(int) == sel].iloc[0]
        rcls, rlab = risk_badge(row["risk_score"])
        st.markdown(
            f"<div class='alert-card'><div class='row'>"
            f"<span>Window <span style='font-family:var(--mono)'>#{int(sel)}</span></span>"
            f"<span class='badge {rcls}'>{rlab}</span>"
            f"<span class='badge info'>{html.escape(str(row['attack_family']))}</span>"
            f"<span style='font-family:var(--mono);font-size:.78rem;color:var(--dim)'>{html.escape(str(row['mitre_stage']))}</span>"
            f"</div></div>", unsafe_allow_html=True)
        attr = row.get("attribution") or {}
        if attr:
            contrib = pd.DataFrame(
                [{"feature": k, "contribution": v} for k, v in attr.items()])
            contrib = contrib.reindex(
                contrib["contribution"].abs().sort_values(
                    ascending=False).index)
            top10 = contrib.head(10)
            st.markdown("**Top drivers**")
            chips = "".join(
                f"<span class='chip {'r' if c > 0 else 'o'}'>{html.escape(f)} "
                f"{c:+.3f}</span>" for f, c in zip(top10["feature"], top10["contribution"]))
            st.markdown(f"<div>{chips}</div>", unsafe_allow_html=True)
            bar = alt.Chart(top10).mark_bar(cornerRadiusEnd=3).encode(
                x=alt.X("contribution:Q", title="contribution "
                        "(risk drop on mean-imputation)"),
                y=alt.Y("feature:N", sort="-x"),
                color=alt.condition(alt.datum.contribution < 0,
                                    alt.value("#22c55e"),
                                    alt.value("#ef4444")),
                tooltip=["feature:N", alt.Tooltip("contribution:Q", format=".4f")],
            ).properties(height=300)
            st.altair_chart(bar, width="stretch")
            st.caption("Red = pushes risk up · green = pulls it down")
        else:
            st.info("No attribution produced for this window (LSTM saliency is "
                    "emitted only for forecast-positive windows).")
        meta = family_meta(row["attack_family"])
        st.markdown(
            f"<div class='metric-card'><b>Human-readable diagnosis</b><br>"
            f"<span style='color:var(--muted)'>{html.escape(meta['description'])}</span></div>",
            unsafe_allow_html=True)
        if row.get("zero_day", {}).get("zero_day_likely"):
            st.warning("This window is flagged **possible novel / zero-day** — "
                       "it sits outside the known-attack feature manifold.")

# ==========================================================================
# TAB 3 — WHAT-IF LAB
# ==========================================================================
with tab3:
    st.markdown('<div class="sec-title"><h3>Counterfactual what-if on real features</h3></div>',
                unsafe_allow_html=True)
    st.markdown("Pick an alert window, perturb its **real raw traffic features**, "
                "and re-run the model to see whether the change would suppress "
                "the alert. Demonstrates how the forecaster responds to "
                "mitigation (rate-limiting, blocking a scanner, changing flow mix).")
    if len(flagged) == 0:
        st.info("No alert windows available to perturb at the current threshold.")
    else:
        sel3 = st.selectbox("Alert window to perturb",
                            flagged["window_id"].astype(int).tolist(), index=0,
                            key="whatif_window")
        prow = flagged[flagged["window_id"].astype(int) == sel3].iloc[0]
        baseline_row = prow.get("row76")
        feat = dict(prow.get("features") or {})
        if not feat:
            st.info("This window has no raw feature record for what-if tuning.")
        else:
            colL, colR = st.columns(2)
            cur_risk = float(prow["risk_score"])
            with colL:
                st.markdown(
                    f"<div class='metric-card'><span style='color:var(--dim);"
                    f"font-size:.72rem;text-transform:uppercase;letter-spacing:.06em'>Baseline</span><br>"
                    f"<span style='font-family:var(--mono);font-weight:800;font-size:2rem'>{cur_risk:.3f}</span><br>"
                    f"<span class='badge {'crit' if cur_risk>=0.75 else 'high'}'>ALERT</span> "
                    f"<span class='badge info'>{html.escape(str(prow['attack_family']))}</span>",
                    unsafe_allow_html=True)
                st.caption("Starting from the window's **real** 76-feature "
                           "vector (`row76`).")
            edited = {}
            with st.expander("Adjust raw traffic features"):
                cc = st.columns(2)
                cols = list(feat.keys())
                for i, c in enumerate(cols):
                    base = float(feat[c])
                    lo = float(min(base * 0.5, base))
                    hi = float(max(base * 2.0, base + 1.0))
                    with cc[i % 2]:
                        edited[c] = st.slider(c.replace("_", " ").title(),
                                              lo, hi, base, key=f"wi_{c}")
                        st.caption(f"baseline `{base:.4g}`")
            with colR:
                st.markdown(
                    f"<div class='metric-card'><span style='color:var(--dim);"
                    f"font-size:.72rem;text-transform:uppercase;letter-spacing:.06em'>Result"
                    f"</span></div>",
                    unsafe_allow_html=True)
                if st.button("▶ Run What-If", type="primary", use_container_width=True):
                    new_row = dict(baseline_row or {})
                    for c in cols:
                        if c in new_row:
                            new_row[c] = float(edited[c])
                    risk, alert, fam, stage, attr, zd = \
                        engine.predict_batch([new_row], [edited])[0]
                    delta = risk - cur_risk
                    rcls, rlab = risk_badge(risk)
                    if not alert:
                        rcls, rlab = "safe", "SUPPRESSED"
                    st.markdown(
                        f"<div class='metric-card'><span style='font-family:var(--mono);"
                        f"font-weight:800;font-size:2rem'>{risk:.3f}</span>&nbsp;"
                        f"<span class='badge {rcls}'>{rlab}</span><br>"
                        f"<span style='font-family:var(--mono);color:{'#f87171' if delta>0 else '#4ade80'}"
                        f";font-weight:700'>{delta:+.3f}</span> Δ<br><br>"
                        f"<span class='chip'>{html.escape(str(fam))}</span> "
                        f"<span class='chip'>{html.escape(str(stage))}</span></div>",
                        unsafe_allow_html=True)
                    if not alert:
                        st.success("The proposed mitigation would suppress "
                                   "this alert below threshold.")
                    else:
                        st.warning("Risk changed but still above threshold — "
                                   "combine with rate-limiting / blocking.")
                else:
                    st.markdown("Hit **Run What-If** to evaluate the edited "
                                "features against the live model.")

# ==========================================================================
# TAB 4 — ACTIVE DEFENSE
# ==========================================================================
with tab4:
    st.markdown('<div class="sec-title"><h3>SOAR active-defense playbooks</h3></div>',
                unsafe_allow_html=True)
    st.markdown("Given the current alert we surface MITRE ATT&CK intel and "
                "generate **ready-to-review** firewall rules. These are "
                "suggestions for a human to approve — the tool never applies them "
                "automatically.")
    if len(flagged) == 0:
        st.info("No active alert to build a playbook around.")
    else:
        sel4_opts = flagged.sort_values(
            "risk_score", ascending=False)["window_id"].astype(int).tolist()
        sel4 = st.selectbox("Alert to defend", sel4_opts,
                            format_func=lambda w: f"Window #{int(w)}",
                            index=0, key="defense_window")
        row = flagged[flagged["window_id"].astype(int) == sel4].iloc[0]
        fam = row["attack_family"]
        src = "attacker.example"
        try:
            dport = int((row.get("features") or {}).get(
                "unique_dst_ports", 0)) or 80
        except Exception:
            dport = 80
        intel = defense.get_mitre_intel(fam)
        scls, slab = sev_badge(intel["severity"])
        cc1a, cc1b = st.columns(2)
        with cc1a:
            st.markdown(
                f"<div class='metric-card'><b>MITRE ATT&CK</b><br>"
                f"<span class='badge {scls}'>{slab}</span> "
                f"<span class='badge info'>{html.escape(str(intel['technique_id']))}</span>"
                f"<p style='margin:.6rem 0 0'><b>Tactic:</b> {html.escape(str(intel['tactic']))}<br>"
                f"<b>Technique:</b> {html.escape(str(intel['technique_name']))}<br>"
                f"<b>CVSS v3.1:</b> {intel['cvss_score']}<br>"
                f"<b>Illustrative CVE:</b> <span style='font-family:var(--mono)'>{html.escape(str(intel['cve_example']))}</span></p>"
                f"<p style='margin:.6rem 0 0'><span class='badge med'>ACTION</span><br>"
                f"<span style='color:var(--muted)'>{html.escape(str(intel['recommended_action']))}</span></p></div>",
                unsafe_allow_html=True)
        with cc1b:
            st.markdown(
                f"<div class='metric-card'><b>Playbook for window "
                f"<span style='font-family:var(--mono)'>#{int(row['window_id'])}</span></b><br>"
                f"<span class='chip'>{html.escape(str(fam))}</span> "
                f"<span class='chip'>{html.escape(str(row['mitre_stage']))}</span>"
                f"<p style='margin:.6rem 0 0;color:var(--muted)'>Rule source IPs "
                f"are shown generically — the model surfaces features, not "
                f"captured addresses.</p></div>", unsafe_allow_html=True)
        st.markdown('<div class="sec-title"><h3>Suggested firewall rules</h3></div>',
                    unsafe_allow_html=True)
        rules = defense.generate_firewall_rules(src, dport, fam)
        rc1, rc2, rc3 = st.columns(3)
        with rc1:
            st.code(rules["iptables"], language="bash")
        with rc2:
            st.code(rules["windows_netsh"], language="bat")
        with rc3:
            st.code(rules["cisco_acl"], language="text")
        st.markdown('<div class="sec-title"><h3>Dynamic decoy honeypot</h3></div>',
                    unsafe_allow_html=True)
        if st.button("🪤 Trigger honeypot redirection demo", type="primary"):
            trap = defense.simulate_honeypot_trap(src, dport)
            st.success(
                f"Simulated redirect of **{trap['attacker_ip']}** to sandbox "
                f"session **{trap['sandbox_session_id']}** (decoy "
                f":{trap['diverted_to_decoy_port']}).")
            for log in trap["honeypot_log"]:
                st.code(log, language="text")

# ==========================================================================
# TAB 5 — FORENSIC AUDIT
# ==========================================================================
with tab5:
    st.markdown('<div class="sec-title"><h3>Tamper-proof forensic audit ledger</h3></div>',
                unsafe_allow_html=True)
    st.markdown("Every incident is appended to an SHA-256 Merkle chain — each "
                "block's hash depends on the previous block, so any tampering "
                "breaks the chain. Verifiable chain of custody for compliance "
                "and legal admissibility.")
    f_p1, f_p2 = st.columns([1.25, 1])
    with f_p1:
        chain_html = "".join(
            (f"<span class='chip'><b>{b['block_id']}</b> "
             f"{b['event_type'][:12]} {b['block_hash'][:10]}</span>"
             f"<span style='color:#3b82f6;padding:0 2px'>→</span>")
            for b in ledger.chain)
        st.markdown(f"<div class='metric-card'><b>Block chain</b><br>"
                    f"<div style='margin-top:8px;overflow-x:auto;"
                    f"white-space:nowrap;padding-bottom:6px'>{chain_html}</div>"
                    f"</div>",
                    unsafe_allow_html=True)
        if ledger.verify_integrity():
            st.success("✅ Merkle chain integrity: **VALID** — no tampering detected")
        else:
            st.error("❌ INTEGRITY VIOLATION: ledger hash mismatch!")
        try:
            chain_df = pd.DataFrame(ledger.chain)[
                ["block_id", "timestamp", "event_type", "block_hash"]]
            st.dataframe(chain_df, width="stretch", height=200)
        except Exception:
            st.json(ledger.chain)
    with f_p2:
        st.subheader("Log the current alert + export report")
        if len(flagged) == 0:
            st.info("No active alert to record.")
        else:
            sel5_opts = flagged.sort_values(
                "risk_score", ascending=False)["window_id"].astype(int).tolist()
            sel5 = st.selectbox("Alert to record", sel5_opts,
                                format_func=lambda w: f"Window #{int(w)}",
                                index=0, key="forensic_window")
            row = flagged[flagged["window_id"].astype(int) == sel5].iloc[0]
            intel = defense.get_mitre_intel(row["attack_family"])
            meta = family_meta(row["attack_family"])
            scls, slab = sev_badge(intel["severity"])
            attr = row.get("attribution") or {}
            reasoning = meta["description"] + (". " + ", ".join(
                f"{k} {v:+.3f}" for k, v in list(attr.items())[:5]) if attr else "")
            incident = {
                "attack_family": row["attack_family"],
                "severity": intel["severity"],
                "cvss_score": intel["cvss_score"],
                "src_ip": "attacker.example",
                "dst_ip": "target.example",
                "dst_port": 80,
                "window_id": int(row["window_id"]),
                "risk_score": float(row["risk_score"]),
                "mitre_tactic": intel["tactic"],
                "mitre_id": intel["technique_id"],
                "mitre_name": intel["technique_name"],
                "cve_example": intel["cve_example"],
                "forensic_reasoning": reasoning,
                "recommended_action": intel["recommended_action"],
                "iptables_cmd": defense.generate_firewall_rules(
                    "attacker.example", 80, row["attack_family"])["iptables"],
            }
            st.markdown(
                f"<div class='metric-card'>"
                f"<span class='badge {scls}'>{slab}</span> "
                f"<span class='chip'>{html.escape(str(row['attack_family']))}</span>"
                f"<p style='margin:.6rem 0 0'>Window "
                f"<span style='font-family:var(--mono)'>#{int(row['window_id'])}</span>"
                f" · risk <span style='font-family:var(--mono)'>{row['risk_score']:.3f}</span>"
                f" · MITRE <span style='font-family:var(--mono)'>{intel['technique_id']}</span></p></div>",
                unsafe_allow_html=True)
            if st.button("📄 Record incident + generate report", type="primary",
                         use_container_width=True):
                block = ledger.record_incident(incident)
                incident["block_hash"] = block["block_hash"]
                pdf_path = generate_pdf_report(
                    incident, "SOC_Incident_Report.pdf")
                st.session_state["last_report"] = pdf_path
                st.success(f"Recorded as block #{block['block_id']} "
                           f"(SHA-256 {block['block_hash'][:16]}…)")
            pdf_path = st.session_state.get("last_report")
            if pdf_path and os.path.exists(pdf_path):
                ext = pdf_path.rsplit(".", 1)[-1]
                mime = "application/pdf" if ext == "pdf" else "text/plain"
                with open(pdf_path, "rb") as fh:
                    st.download_button(
                        label="⬇ Download forensic report",
                        data=fh.read(),
                        file_name=os.path.basename(pdf_path),
                        mime=mime,
                        use_container_width=True)