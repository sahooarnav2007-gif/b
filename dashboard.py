"""
dashboard.py
------------
NetSight SOC dashboard — the five analysis tabs on the real pipeline.

  1. Forecaster      — risk timeline, alerts, MITRE stage, CAPEC/CVE, novelty callout
  2. Explainability  — real per-window feature attribution (ablation / LSTM saliency)
  3. What-If Lab     — counterfactual: perturb real window features, re-run the model
  4. Active Defense  — MITRE intel + multi-OS firewall rules + honeypot simulation
  5. Forensic Audit  — tamper-proof SHA-256 Merkle ledger + SOC PDF report
"""

import os
import tempfile
from collections import Counter

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


@st.cache_resource(show_spinner=False)
def get_engine(model_name, threshold):
    if model_name == "RandomForest":
        return RandomForestEngine(threshold=threshold)
    return LSTMEngine(threshold=threshold)


DEMO_CSVS = {
    "Friday DDoS (recommended)": "dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Thursday web attacks": "dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday brute-force": "dataset/Tuesday-WorkingHours.pcap_ISCX.csv",
}


@st.cache_resource(show_spinner=False)
def load_ledger():
    return ForensicLedger()


ledger = load_ledger()
defense = ActiveDefenseEngine()

with st.sidebar:
    st.header("Controls")
    model_name = st.radio("Model", ["RandomForest", "LSTM"], horizontal=True)
    threshold = st.slider("Alert threshold (risk)", 0.0, 1.0, 0.5, 0.05)
    max_windows = st.number_input("Max windows (0 = whole file)",
                                  min_value=0, value=0, step=50)
    st.markdown("---")
    ingest = st.radio("Data source", ["Upload file", "Demo artifact"],
                      horizontal=False)
    uploaded = None
    demo_file = None
    if ingest == "Demo artifact":
        chosen = st.selectbox("Pick a CICIDS2017 day-file", list(DEMO_CSVS))
        demo_file = DEMO_CSVS[chosen]
    else:
        uploaded = st.file_uploader(
            "Upload a CICIDS2017 flow CSV, a pre-featurized window CSV, "
            "or a PCAP", type=["csv", "pcap"])
    st.markdown("---")
    st.caption("NetSight · SIH26153 · runs 100% offline on your machine")

st.title("🛡 SOC Dashboard")
st.caption(
    "Forecasts **known attack progressions** up to 6 windows ahead · maps "
    "alerts to MITRE ATT&CK · explains every prediction · novelty callout for "
    "activity unlike anything in training. Ingests flow CSV or PCAP.")

# ----- resolve input file ---------------------------------------------------
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

if input_path is None:
    st.info("Select an ingestion source on the left (upload a CICIDS2017 flow "
            "CSV, a pre-featurized window CSV, a PCAP, or pick a demo day-file).")
    st.stop()

# ----- run inference --------------------------------------------------------
engine = get_engine(model_name, threshold)
tmp_path = input_path
pcap_extras = None
try:
    if is_pcap:
        from packet_features import pcap_to_windows_csv
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as t:
            tmp_path = t.name
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

# ----- header metrics -------------------------------------------------------
alert_stat = "ALERT" if len(flagged) else "CLEAR"
c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    badge = "critical-badge" if len(flagged) else "safe-badge"
    st.markdown(f"<div class='metric-card'>Status<br><span class='{badge}'>"
                f"{alert_stat}</span></div>", unsafe_allow_html=True)
c2.metric("Windows", summary["windows_processed"])
c3.metric("Flags", summary["flagged_windows"])
c4.metric("Flag rate", f"{summary['flag_rate']:.1%}")
c5.metric("Peak risk", f"{summary['peak_risk']:.3f}")

# ============================================================================
# TAB 1 — FORECASTER
# ============================================================================
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔭 Forecaster", "🔬 Explainability", "🧪 What-If Lab",
    "🛡 Active Defense", "📜 Forensic Audit"])

with tab1:
    if is_pcap and pcap_extras is not None and not pcap_extras.empty:
        st.subheader("Packet-level features (per 500-packet window)")
        cols = ["window_id", "packet_rate", "byte_rate", "syn_only_rate",
                "retrans_ratio", "ttl_std", "tcp_win_mean", "frag_ratio",
                "icmp_ratio", "attack_family", "heuristic_stage"]
        cols = [c for c in cols if c in pcap_extras.columns]
        st.dataframe(pcap_extras[cols].set_index("window_id").head(80),
                     width="stretch", height=220)

    st.subheader("Forecast timeline (risk score by window)")
    chart_cols = [c for c in ["window_id", "risk_score", "predicted_alert"]
                  if c in tl.columns]
    cdata = tl[chart_cols]
    st.line_chart(cdata.set_index("window_id").rename(
        columns={"risk_score": "risk"})["risk"])

    if len(flagged) == 0:
        st.success("No alerts at the current threshold.")
    else:
        n_zd = int(flagged["zero_day_likely"].sum()) if "zero_day_likely" in flagged else 0
        if n_zd:
            st.markdown(
                f"**{n_zd} of {len(flagged)} alert windows : possible novel / "
                f"zero-day activity (outside known-attack feature manifold)**")

        st.subheader("First alert")
        first = flagged.iloc[0]
        ic = st.columns(4)
        ic[0].info(f"window **{int(first['window_id'])}** · risk "
                   f"**{first['risk_score']:.3f}**")
        ic[1].info(f"family **{first['attack_family']}**")
        ic[2].info(f"MITRE stage **{first['mitre_stage']}**")
        ic[3].info(f"GT **{first['gt_family']}**" if "gt_family" in first else "")

        zd = first.get("zero_day")
        if zd:
            badge = "POSSIBLE NOVEL / ZERO-DAY" if zd.get("zero_day_likely") else "matches known families"
            st.markdown(f"**Zero-day callout:** `{badge}` — family confidence "
                        f"`{zd.get('family_confidence')}` · novelty distance "
                        f"`{zd.get('novelty_dist')}` (pct `{zd.get('novelty_pctl')}`)")

        meta = family_meta(first["attack_family"])
        with st.expander("ATT&CK / CAPEC / CVE enrichment"):
            st.markdown(f"**{meta['description']}**\n\n"
                        f"- **Stage:** `{first['mitre_stage']}`\n"
                        f"- **CAPEC:** {capec_chain(first['attack_family'])}\n"
                        f"- **Known CVEs (illustrative):** "
                        f"{', '.join(meta['cves']) if meta['cves'] else '-'}")

        if "mitre_stage" in tl:
            st.subheader("MITRE ATT&CK stage breakdown")
            stages = Counter(tl.loc[tl.index.isin(flagged.index), "mitre_stage"])
            st.bar_chart(pd.Series(stages, name="windows"))

        st.subheader("Alerts detail")
        shown = flagged.copy()
        if "attribution" in shown:
            shown["drivers"] = shown["attribution"].apply(
                lambda a: ", ".join(f"{k}: {v:.3g}" for k, v in (a or {}).items()))
        show_cols = [c for c in ["window_id", "risk_score", "attack_family",
                                 "mitre_stage", "gt_family", "drivers"]
                     if c in shown.columns]
        st.dataframe(shown[show_cols].set_index("window_id"),
                     width="stretch", height=320)
        if "zero_day_likely" in shown.columns:
            st.caption("Zero-day callout marks alert windows whose feature "
                       "vector sits outside the known-attack manifold "
                       "(>95th-percentile NN distance). Analyst review, not an "
                       "automated verdict.")

# ============================================================================
# TAB 2 — EXPLAINABILITY
# ============================================================================
with tab2:
    st.subheader("Real per-window feature attribution")
    st.markdown("For the **RandomForest**, risk is re-run with each top feature "
                "set to its batch mean (mean-imputation ablation) — the drop in "
                "risk is that feature's contribution. For the **LSTM**, "
                "gradient saliency over the input sequence is used. This is the "
                "model's *own* reasoning, not a separate explainer — exactly the "
                "PS's explainability requirement.")
    if len(flagged) == 0:
        st.info("No alert windows to explain at the current threshold.")
    else:
        opts = flagged["window_id"].astype(int).tolist()
        sel = st.selectbox("Alert window to explain", opts, index=0)
        row = flagged[flagged["window_id"].astype(int) == sel].iloc[0]
        attr = row.get("attribution") or {}
        st.markdown(f"**Window {sel}** · risk **{row['risk_score']:.3f}** · "
                    f"family **{row['attack_family']}** · "
                    f"MITRE **{row['mitre_stage']}**")
        if attr:
            contrib = pd.DataFrame(
                [{"feature": k, "contribution": v} for k, v in attr.items()])
            if not contrib.empty:
                contrib = contrib.reindex(
                    contrib["contribution"].abs().sort_values(
                        ascending=False).index).head(10)
                import altair as alt
                bar = alt.Chart(contrib).mark_bar().encode(
                    x=alt.X("contribution:Q", title="contribution "
                            "(risk drop on mean-imputation)"),
                    y=alt.Y("feature:N", sort="-x"),
                    color=alt.condition(alt.datum.contribution < 0,
                                        alt.value("#22c55e"),
                                        alt.value("#ef4444")),
                ).properties(height=320)
                st.altair_chart(bar, width="stretch")
        else:
            st.info("No attribution produced for this window (LSTM saliency "
                    "is emitted only for forecast-positive windows).")
        meta = family_meta(row["attack_family"])
        st.markdown(f"**Human-readable diagnosis:** {meta['description']}")
        if row.get("zero_day", {}).get("zero_day_likely"):
            st.warning("This window is flagged **possible novel / zero-day** — "
                       "it sits outside the known-attack feature manifold.")

# ============================================================================
# TAB 3 — WHAT-IF LAB (counterfactual on real features)
# ============================================================================
with tab3:
    st.subheader("Counterfactual 'What-If' simulation on real window features")
    st.markdown("Pick an alert window, perturb its **real raw traffic features**, "
                "and the model is re-run to show whether the change would suppress "
                "the alert. This demonstrates how the forecaster responds to "
                "mitigation (e.g. rate-limiting, blocking a scanner, changing "
                "flow mix). Reconstructed rolling features assume steady-state "
                "history, so treat values as indicative, not exact.")
    if len(flagged) == 0:
        st.info("No alert windows available to perturb at the current threshold.")
    else:
        opts3 = flagged["window_id"].astype(int).tolist()
        sel3 = st.selectbox("Alert window to perturb", opts3,
                            index=0, key="whatif_window")
        prow = flagged[flagged["window_id"].astype(int) == sel3].iloc[0]
        baseline_row = prow.get("row76")
        feat = dict(prow.get("features") or {})
        if not feat:
            st.info("This window has no raw feature record for what-if tuning.")
        else:
            st.caption("Starting from the window's **real** 76-feature vector "
                       "(`row76`); perturb the 10 raw traffic features below and "
                       "re-run the model to see whether the alert would survive "
                       "the corresponding mitigation.")
            col_c, col_v = st.columns([1.2, 1])
            cols = list(feat.keys())
            colmap = {c: c.replace("_", " ").title() for c in cols}
            edited = {}
            with col_c:
                for c in cols:
                    base = float(feat[c])
                    lo = float(min(base * 0.5, base))
                    hi = float(max(base * 2.0, base + 1.0))
                    edited[c] = st.slider(colmap[c], lo, hi, base,
                                          key=f"wi_{c}")
            with col_v:
                cur_risk = float(prow["risk_score"])
                st.metric("Baseline risk", f"{cur_risk:.3f}")
                if st.button("▶ Run What-If", type="primary"):
                    new_row = dict(baseline_row or {})
                    for c in cols:
                        if c in new_row:
                            new_row[c] = float(edited[c])
                    risk, alert, fam, stage, attr, zd = \
                        engine.predict_batch([new_row], [edited])[0]
                    delta = risk - cur_risk
                    st.metric("New risk", f"{risk:.3f}", delta=f"{delta:+.3f}")
                    if not alert:
                        st.success("✅ The proposed mitigation would suppress "
                                   "this alert below threshold.")
                    else:
                        st.warning("⚠ Risk changed but still above threshold — "
                                   "combine with rate-limiting / blocking.")
                    st.markdown(f"Reclassified family: **{fam}** · "
                                f"MITRE: **{stage}**")

# ============================================================================
# TAB 4 — ACTIVE DEFENSE
# ============================================================================
with tab4:
    st.subheader("SOAR active-defense playbooks (generated, never executed)")
    st.markdown("Given the current alert, we surface the MITRE ATT&CK intel and "
                "generate **ready-to-review** firewall rules for the operator. "
                "These are suggestions for a human to approve — the tool does "
                "not apply them.")
    if len(flagged) == 0:
        st.info("No active alert to build a playbook around.")
    else:
        first = flagged.iloc[0]
        fam = first["attack_family"]
        src = "attacker.example"  # surfaced generically; no IP is harvested by the model
        try:
            dport = int(tl[tl["predicted_alert"]].iloc[0].get(
                "features", {}).get("unique_dst_ports", 0)) or 80
        except Exception:
            dport = 80
        intel = defense.get_mitre_intel(fam)
        c_d1, c_d2 = st.columns(2)
        with c_d1:
            st.markdown(f"**Tactic:** `{intel['tactic']}`")
            st.markdown(f"**Technique:** `{intel['technique_id']}` "
                        f"({intel['technique_name']})")
            st.markdown(f"**Severity:** `{intel['severity']}` "
                        f"(CVSS v3.1: {intel['cvss_score']})")
            st.markdown(f"**Illustrative CVE:** `{intel['cve_example']}`")
            st.info(f"**Recommended action:**\n{intel['recommended_action']}")
        with c_d2:
            st.subheader("Suggested firewall rules")
            rules = defense.generate_firewall_rules(src, dport, fam)
            st.code(rules["iptables"], language="bash")
            st.code(rules["windows_netsh"], language="bat")
            st.code(rules["cisco_acl"], language="text")
        st.markdown("---")
        st.subheader("Dynamic decoy honeypot (simulation)")
        if st.button("🪤 Trigger honeypot redirection demo"):
            trap = defense.simulate_honeypot_trap(src, dport)
            st.success(f"Simulated redirect of **{trap['attacker_ip']}** to "
                       f"sandbox session **{trap['sandbox_session_id']}** "
                       f"(decoy :{trap['diverted_to_decoy_port']}).")
            for log in trap["honeypot_log"]:
                st.code(log, language="text")

# ============================================================================
# TAB 5 — FORENSIC AUDIT
# ============================================================================
with tab5:
    st.subheader("Tamper-proof forensic audit ledger")
    st.markdown("Every incident you record is appended to an SHA-256 Merkle "
                "chain — each block's hash depends on the previous block, so "
                "any tampering breaks the chain. Verifiable chain of custody "
                "for compliance / legal admissibility.")
    c_p1, c_p2 = st.columns([1.2, 1])
    with c_p1:
        try:
            chain_df = pd.DataFrame(ledger.chain)[
                ["block_id", "timestamp", "event_type", "block_hash"]]
            st.dataframe(chain_df, width="stretch", height=220)
        except Exception as e:
            st.json(ledger.chain)
        if ledger.verify_integrity():
            st.success("✅ Merkle chain integrity: VALID (no tampering detected)")
        else:
            st.error("❌ INTEGRITY VIOLATION: ledger hash mismatch!")
    with c_p2:
        st.subheader("Log the current alert + export report")
        if len(flagged) == 0:
            st.info("No active alert to record.")
        else:
            first = flagged.iloc[0]
            intel = defense.get_mitre_intel(first["attack_family"])
            meta = family_meta(first["attack_family"])
            attr = first.get("attribution") or {}
            reasoning = meta["description"] + (". " + ", ".join(
                f"{k} {v:+.3f}" for k, v in list(attr.items())[:5]) if attr else "")
            incident = {
                "attack_family": first["attack_family"],
                "severity": intel["severity"],
                "cvss_score": intel["cvss_score"],
                "src_ip": "attacker.example",
                "dst_ip": "target.example",
                "dst_port": 80,
                "window_id": int(first["window_id"]),
                "risk_score": float(first["risk_score"]),
                "mitre_tactic": intel["tactic"],
                "mitre_id": intel["technique_id"],
                "mitre_name": intel["technique_name"],
                "cve_example": intel["cve_example"],
                "forensic_reasoning": reasoning,
                "recommended_action": intel["recommended_action"],
                "iptables_cmd": defense.generate_firewall_rules(
                    "attacker.example", 80, first["attack_family"])["iptables"],
            }
            if st.button("📄 Record incident + generate report", type="primary"):
                block = ledger.record_incident(incident)
                incident["block_hash"] = block["block_hash"]
                pdf_path = generate_pdf_report(
                    incident, "SOC_Incident_Report.pdf")
                st.session_state["last_report"] = pdf_path
                st.success(f"Incident recorded as block #{block['block_id']} "
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
                        mime=mime)
