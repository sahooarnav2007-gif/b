# SIH26153 — System Architecture (2 pages)

## 1. Problem & goal

The PS asks for an **AI-based Network Attack Forecasting system**: given raw
network traffic, (a) *forecast* an attack before it lands, (b) map it to the
MITRE ATT&CK kill-chain, (c) explain every prediction, and (d) beat a logistic
regression baseline. The PS wants the core to be a **"World Model"** that learns
state-transition dynamics P(S_t+1 | S_t) over network state windows — not just a
static classifier. Both **flow-level and packet-level** features are required,
plus an offline demo tool accepting **PCAP/CSV**.

This build trains on all 8 real CICIDS2017 capture files (~2.83M flows) and must
run fully offline (no torch/tensorflow in the sandbox) — hence a hand-rolled
NumPy LSTM and, at inference time, batched predictions to dodge a per-call
scikit-learn overhead.

## 2. High-level data flow

```
                  TRAIN TIME (offline)
 flow CSVs ──► full_pipeline.py ──► full_features.csv
      (8 day files)   │ windows of 500 flows, per-window raw feats
                      ▼ rolling 3/6/12 (66 more cols) + forecast labels (horizon 6)
                 full_train.py ──► rf_forecaster.pkl, rf_family_classifier.pkl
                 lstm_world_model.py ──► lstm_weights.json   (the World Model)
                 logreg_baseline.py ──► logreg_summary.json  (required benchmark)

                  RUN TIME (offline, any machine)
 flow CSV ──► infer.py ─────────────────────────╮
 PCAP ─────► packet_features.py ─► windows.csv ──┤► same rolling features ─► models
                                                 ▼       ──► risk timeline, family,
                                          app.py (Streamlit)   MITRE stage, attribution
```

## 3. Data & preprocessing

- **8 captures** (Mon → Fri, `dataset/*.pcap_ISCX.csv`): Monday (benign only),
  Tuesday (FTP/SSH brute-force), Wednesday (DoS: Hulk/GoldenEye/slowloris/
  Slowhttptest/Heartbleed), Thursday (web attacks + infiltration), Friday
  (botnet, port-scan, DDoS). Labels are the CICIDS attack names.
- Columns are stripped of the CICIDS trailing-space mangling, infinities are
  NaN'd, rows missing core fields dropped. `Label → family` mapping is exact
  match first, then substring (web-attack rows ship with a corrupted em-dash).
- **Windowing** (`full_pipeline.py`): flow rows are sliced into **500-flow
  windows** (~5,650 windows across the week). A window is an *attack window*
  when its attack-flow fraction **> 1%** (the majority-50% threshold misses
  sparse-but-real attack bursts inside heavy background traffic).

## 4. Feature engineering

- **10 raw per-window features**: `packet_rate, byte_rate, unique_dst_ips,
  unique_dst_ports, syn_ack_ratio, avg_pkt_size, dst_port_entropy,
  failed_conn_rate, fwd_psh_rate, avg_flow_duration`.
- **Rolling features**: for each window-size in {3,6,12} and each raw column a
  moving-average and moving-std (2×10×3 = 60 cols), plus `portcount_slope` and
  `entropy_slope` (2×3 = 6 cols). Rolling stats are computed **per-day** so no
  information leaks across day boundaries — total **76 features**.
- **Forecast label** (`y_forecast`): a window is 1 if an attack window starts
  within the next **6 windows** (FORECAST_HORIZON) *on the same day*. This makes
  the task truly a *forecast* (attack imminent) rather than instant detection.

## 5. Models

| Model | Cross-day AUC (test on unseen Friday) | Within-day AUC (70/30) | Within-day recall |
|---|---|---|---|
| Logistic Regression (baseline) | 0.539 | 0.763 | 0.501 |
| RandomForest (400 trees, depth 10, balanced) | 0.763 | 0.838 | 0.486 |
| **LSTM World Model** (seq 12 → hidden 24, NumPy BPTT + Adam, 40 ep., saliency) | 0.471 | 0.700 | **0.878** |

- **Cross-day**: train Mon–Thu (incl. Thursday web/infil), test entirely unseen
  Friday. **Within-day**: 70/30 shuffle (leak-prone by construction; reported as
  an upper-bound reference).
- **Forecasting metric beyond AUC**: on the cross-day test Friday (721 attack
  windows) the RF fired an alert ≥1 window *before* the attack in **285/721
  (39.5%)** cases with **avg lead time 6.13 windows** — and Friday DDoS alone:
  **269/278 with 6.14-window lead**.
- **Attack-family classifier** (RF, 300 trees) labels *which* attack is coming;
  accuracy 0.241 — honest and low, dominated by confusable families.

### Honest interpretation
- Within a day, LSTM and RF are close on AUC, but **LSTM recall 0.878 vs RF
  0.486** — the sequence model catches far more real attacks at the cost of
  precision. For early-warning, missing an attack is worse than a false alarm,
  so this justifies the world-model over the baseline.
- Cross-day, the LSTM (0.471) generalizes worse than RF (0.763) and logreg
  (0.539) — a classic small-data deep-learning problem (~3.3k training
  sequences), fixed by more training days or augmentation, not a flawed
  architecture. We report this explicitly rather than hiding it.

## 6. MITRE ATT&CK mapping

`port_scan → Reconnaissance` · `brute_force / web_attack / infiltration /
exploit → Initial Access` · `botnet → Command & Control`. `dos/ddos` is MITRE
TA0040 **Impact**, which is not one of the PS's 5 stages — surfaced as its own
explicitly-labeled bucket (see `kill_chain_mapping.json`: botnet 92, brute_force
505, dos 1209, port_scan 351, web_attack 91 attack windows).

## 7. Explainability

- **LSTM**: gradient-output saliency per input feature (from-scratch, SHAP not
  installable offline). Saved demo (`saliency_demo.json`): a real DDoS forecast
  at risk 0.744 driven by `packet_rate` (34%) and `dst_port_entropy` +
  `unique_dst_ports` (~31%) — exactly the domain intuition for flooding.
- **RandomForest (run-time)**: mean-imputation ablation over the top-6 global
  importances —*"risk dropped X when we set byte_rate to its mean"* — emitted
  per window in `infer.py`.

## 8. Inference runtime (offline demo)

- `infer.py` — streams CSVs in 20k-row chunks into a 500-flow window buffer,
  rebuilds the 76 rolling features incrementally, predicts in **batches of 128**
  (this env's sklearn carries ~250 ms fixed per-call overhead), and emits a JSON
  timeline: risk, alert, family, MITRE stage, attribution. Handles raw CICIDS
  CSVs or pre-featurized window CSVs.
- `packet_features.py` — the **packet-level** path: Scapy `PcapReader` streams a
  PCAP into 500-packet windows, derives the same 10 raw features (via a
  lightweight 5-tuple flow table for durations/retrans) plus PS-required
  packet extras — TTL mean/std, TCP window sizes, IP fragment/DF ratios,
  SYN-only flood rate, retransmission rate, protocol mix — and a heuristic
  stage label for label-less pcaps. Output feeds `infer.py` unchanged.
- `app.py` — Streamlit: upload CSV (or the packet windows CSV), pick RF/LSTM,
  threshold slider; renders risk timeline, MITRE stage breakdown, alert table.
  Runs fully offline (`server.headless`, 1 GB upload cap).

## 9. Reproducibility

```
python3 full_pipeline.py → full_train.py → lstm_world_model.py → logreg_baseline.py
        → mitre_stages_and_explainability.py
python3 infer.py dataset/<file>.csv ; python3 packet_features.py capture.pcap -o w.csv --infer
streamlit run app.py
```

Artifacts: `full_features*.csv`, `*_summary.json`, `rf_forecaster.pkl`,
`rf_family_classifier.pkl`, `lstm_weights.json`, `kill_chain_mapping.json`,
`saliency_demo.json`. Raw captures are git-ignored (>100 MB per file); download
the official UNB CICIDS2017 release to reproduce.

## 10. Known limitations

1. Cross-day LSTM generalization (see §5). 2. Packet path not yet validated on a
real CICIDS2017 PCAP (only synthetic). 3. Family-classifier accuracy 0.241.
4. No CAPEC/CVE-NVD enrichment yet. 5. sklearn-version drift on pickle reload is
a warning; predictions remain valid (verified on 1.9.0).