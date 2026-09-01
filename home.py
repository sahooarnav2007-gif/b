"""
home.py
-------
NetSight home page: hero, value proposition, and quick-start for SIH26153.
"""

import streamlit as st

st.markdown("""
<div class="hero">
  <div class="kicker">AI-Based Network Attack Forecasting · SIH26153</div>
  <h1>🛰 NetSight</h1>
  <div class="sub">
    A fully offline SOC forecaster that forecasts <b>known attack
    progressions</b> up to 6 windows ahead, maps every alert to
    <b>MITRE ATT&CK</b>, explains each prediction with the model's own
    reasoning, and raises a <b>novelty callout</b> for activity unlike
    anything seen in training. Ingests raw CICIDS2017 flow CSV, pre-featurized
    windows, or a PCAP — everything runs on committed models with nothing
    leaving your machine.
  </div>
</div>
""", unsafe_allow_html=True)

# --- What it does -----------------------------------------------------------
st.markdown("#### What NetSight does")
c1, c2, c3 = st.columns(3)
with c1:
    st.markdown("""
    **Forecast**
    : Predicts the risk window-by-window and which **known attack family** is
    unfolding, along with its MITRE stage.
    """)
with c2:
    st.markdown("""
    **Explain**
    : Attribute every prediction to the traffic features that drove it — the
    model's own ablation / saliency, not a black box.
    """)
with c3:
    st.markdown("""
    **Respond + audit**
    : Generate MITRE-grounded firewall playbooks, simulate a honeypot, and log
    incidents to a tamper-proof SHA-256 ledger with a SOC PDF report.
    """)

# --- How to use -------------------------------------------------------------
st.markdown("#### Get started")
st.markdown("""
1. Open the **🛡 SOC Dashboard** from the left navigation.
2. Pick an ingestion source — upload a CSV/PCAP or load a demo day-file
   (Friday DDoS is the recommended showcase).
3. Choose a model (RandomForest or LSTM), then explore the five tabs:
   🔭 **Forecaster** · 🔬 **Explainability** · 🧪 **What-If Lab** ·
   🛡 **Active Defense** · 📜 **Forensic Audit**.
""")

# --- Pipeline ---------------------------------------------------------------
st.markdown("#### Pipeline at a glance")
p = st.columns(5)
for i, (stage, detail) in enumerate([
    ("Ingest", "Flow CSV / PCAP / pre-featurized windows"),
    ("Feature", "76-dim rolling window (10 raw + rolling stats)"),
    ("Predict", "RF forecaster or LSTM sequence model"),
    ("Enrich", "MITRE ATT&CK · CAPEC · CVE · novelty callout"),
    ("Act", "Playbooks · honeypot · forensic ledger"),
]):
    with p[i]:
        st.markdown(
            f"<div class='metric-card'><b>{stage}</b><br>"
            f"<span style='color:#94a3b8'>{detail}</span></div>",
            unsafe_allow_html=True)
