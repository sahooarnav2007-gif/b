"""
app.py
------
Offline Streamlit demo UI for SIH26153 — AI based Network Attack Forecasting.

Upload a CICIDS2017 flow CSV (raw, any size — streamed chunk-by-chunk) or a
pre-featurized window CSV, pick a model (RandomForest / NumPy LSTM), and get:
  - a rolling risk timeline with per-window alerts
  - the predicted attack family + MITRE ATT&CK stage per alert
  - per-window attribution (which features drove the risk score)
  - summary metrics and a stage breakdown

Run:  streamlit run app.py
All inference logic is imported from infer.py / lstm_world_model.py — nothing is
re-implemented here and nothing leaves the machine (fully offline demo).
"""

import os
import tempfile
from collections import Counter

import altair as alt
import pandas as pd
import streamlit as st

from infer import (
    WINDOW_SIZE,
    RandomForestEngine,
    LSTMEngine,
    run_inference,
    summarize,
)

st.set_page_config(page_title="Attack Forecaster", layout="wide")

DESC = (
    "**SIH26153 — AI based Network Attack Forecasting.** Stream a raw CICIDS2017 "
    "flow CSV through the saved RandomForest / NumPy-LSTM forecasters, one "
    "500-flow window at a time, with MITRE ATT&CK stage mapping and "
    "per-window explainability. The whole demo runs offline."
)
st.markdown(DESC)


@st.cache_resource(show_spinner=False)
def get_engine(model_name, threshold):
    if model_name == "RandomForest":
        return RandomForestEngine(threshold=threshold)
    return LSTMEngine(threshold=threshold)


with st.sidebar:
    st.header("Controls")
    model_name = st.radio("Model", ["RandomForest", "LSTM"], horizontal=True)
    threshold = st.slider("Alert threshold (risk)", 0.0, 1.0, 0.5, 0.05)
    max_windows = st.number_input(
        "Max windows (0 = whole file)", min_value=0, value=0, step=50)
    st.caption("")

uploaded = st.file_uploader(
    "Upload a CICIDS2017 flow CSV or a pre-featurized window CSV",
    type=["csv"],
)

st.caption(
    f"Raw schema expected: CICIDS2017 columns (Destination Port, Flow Duration, "
    f"Flow Packets/s, …) — {WINDOW_SIZE}-flow windows, horizon 6. Pre-featurized "
    f"CSVs (with `window_id` + `y_forecast`) are detected automatically."
)

if uploaded is not None:
    engine = get_engine(model_name, threshold)

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp.write(uploaded.getbuffer())
        tmp_path = tmp.name
    try:
        with st.spinner("Streaming inference… this runs offline, big files take a moment."):
            timeline, summary = run_inference(
                tmp_path, engine, max_windows=int(max_windows))
    finally:
        os.unlink(tmp_path)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Windows processed", summary["windows_processed"])
    c2.metric("Flags", summary["flagged_windows"])
    c3.metric("Flag rate", f"{summary['flag_rate']:.1%}")
    c4.metric("Peak risk", f"{summary['peak_risk']:.3f}")

    if not timeline:
        st.warning("No windows produced. Check the CSV schema.")
        st.stop()

    tl = pd.DataFrame(timeline)
    flagged = tl[tl["predicted_alert"]]

    if flagged.empty:
        st.success("No alerts at the current threshold.")
    else:
        stages = Counter(tl.loc[tl.index.isin(flagged.index), "mitre_stage"])
        first = flagged.iloc[0]
        af = flagged["attack_family"].value_counts()
        st.subheader("First alert")
        ic = st.columns(3)
        ic[0].info(f"window **{int(first['window_id'])}** · risk "
                   f"**{first['risk_score']:.3f}**")
        ic[1].info(f"family **{first['attack_family']}**")
        ic[2].info(f"MITRE stage **{first['mitre_stage']}**")
        if first.get("attribution"):
            st.markdown("Driving features (mean-imputation ablation / saliency):")
            st.json(first["attribution"])

        st.subheader("MITRE ATT&CK stage breakdown")
        st.bar_chart(pd.Series(stages, name="windows"))

        st.subheader("Forecast timeline")
        chart = alt.Chart(tl).mark_line().encode(
            x=alt.X("window_id:Q", title="window id"),
            y=alt.Y("risk_score:Q", title="risk score", scale=alt.Scale(domain=[0, 1])),
        )
        alert_pts = alt.Chart(tl.query("predicted_alert")).mark_point(
            color="#ff4b4b", size=70).encode(
            x="window_id:Q", y="risk_score:Q")
        rule = alt.Chart(pd.DataFrame({"y": [threshold]})).mark_rule(
            color="gray", strokeDash=[4, 4]).encode(y="y:Q")
        st.altair_chart(chart + alert_pts + rule, width="stretch")

        st.subheader("Alerts detail")
        shown = flagged.copy()
        shown["drivers"] = shown["attribution"].apply(
            lambda a: ", ".join(f"{k}: {v:.3g}" for k, v in (a or {}).items()))
        st.dataframe(
            shown[["window_id", "risk_score", "attack_family", "mitre_stage",
                   "gt_family", "drivers"]].set_index("window_id"),
            width="stretch", height=330)
else:
    st.info(
        "No file uploaded yet. Use the **demo artifacts** in the repo: "
        "`dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` "
        "(web attacks) or `dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` "
        "(DDoS) for a quick run.")