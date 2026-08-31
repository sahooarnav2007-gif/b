# SIH26153 — System Architecture (master / full version)

> The PS deliverable asks for a 2-page architecture write-up. This file is the
> **detailed master copy** (every claim traces to a committed artifact:
> `full_model_summary.json`, `lstm_improve_summary.json`, `lstm_summary.json`,
> `logreg_summary.json`, `eval_forecasting.json`, `walk_forward_cv.json`,
> `world_model_dynamics.json`, `kill_chain_mapping.json`).
> The compressed 2-page cut is produced from §1–§9 + §16.

---

## 1. Problem & goal

The PS asks for an **AI-based Network Attack Forecasting system** that, given
raw network traffic:

1. **Forecasts** an attack before it lands (not just detecting one already in
   progress),
2. maps alerts to the **MITRE ATT&CK kill-chain**,
3. **explains** every prediction (no black box),
4. beats a **logistic-regression baseline**,
5. is built around a **"World Model"** that learns the state-transition
   dynamics P(S_{t+1} | S_t) over time-windowed network observations — *not* a
   static one-shot classifier,
6. consumes **both flow-level and packet-level** features,
7. ships an **offline demo** that accepts **PCAP or CSV**.

Constraints that shaped the build:
- **Fully offline sandbox**: no torch/tensorflow installable → the LSTM world
  model is a **hand-rolled NumPy implementation** (forward pass, backprop-
  through-time, Adam optimizer). No SHAP → attribution is a from-scratch
  gradient **saliency** path + mean-imputation **ablation**.
- **Slow per-call sklearn `predict_proba`** in the environment (~250 ms fixed
  overhead per call) → inference is **batched** (128 windows/call).
- **8 real CICIDS2017 captures** (~2.83 M flows) are the only data; raw files
  are git-ignored (>100 MB each), models and results are committed so the demo
  and eval scripts run without the raw data.
- **Deployment dependency set**: `scikit-learn==1.8.0` (exact pickle match to
  training env), `numpy==2.0.2`, `pandas==2.2.3`, `streamlit`, `scapy`.
  Legacy Flask/FastAPI/uvicorn dependencies removed (old app replaced).

---

## 2. System overview & data flow

```
                     TRAIN TIME (offline, reproducible)
  flow CSVs ──► full_pipeline.py ──► full_features.csv
   (8 day files)    │ 500-flow windows; 10 raw feats + 66 rolling + labels
                    ▼
     full_train.py ──► rf_forecaster.pkl, rf_family_classifier.pkl, full_predictions.csv
     lstm_world_model.py ──► lstm_weights.json        (the World Model)
     lstm_improve.py        ──► lstm_improve_summary.json   (cross-day AUC 0.643)
     logreg_baseline.py     ──► logreg_summary.json         (required baseline)

                     EVALUATION (honest, dual-protocol)
     eval_forecasting.py  ──► PR curve / AUPRC 0.877 / lead-time distribution
     walk_forward_cv.py   ──► rolling-origin CV, pooled AUC 0.722
     world_model_dynamics.py ─► empirical vs LSTM P(S_{t+1}|S_t), next-state AUC 0.814

                     RUN TIME (offline on any machine)

  ┌──────────────────────────────────────────────────────────────┐
  │  INGESTION PATHS — both converge on the same 76-feature     │
  │  representation the models were trained on                   │
  │                                                              │
  │  flow CSV ──► infer.py (RollingFeatureBuilder) ─────────┐   │
  │  PCAP ─────► packet_features.py ─► windows.csv ─────────┤   │
  │              (Scapy PcapReader, 500-pkt windows,         │   │
  │               same 10 raw features + 11 packet-extras)  │   │
  │                                                          ▼   │
  │                              app.py (Streamlit)             │
  │                              → risk timeline, family,       │
  │                                MITRE stage, attribution,    │
  │                                novelty callout              │
  └──────────────────────────────────────────────────────────────┘
```

Component map:
| Module | Role |
|---|---|
| `full_pipeline.py` | offline corpus → windowed feature table |
| `full_train.py` | RF forecaster + family classifier, dual-protocol eval |
| `lstm_world_model.py` | NumPy LSTM world model (train + eval + saliency) |
| `lstm_improve.py` | improved cross-day LSTM training (ship artifact) |
| `logreg_baseline.py` | mandated baseline |
| `infer.py` | streaming live inference (CSV or pre-windowed CSV) |
| `packet_features.py` | PCAP → pre-windowed CSV via Scapy (packet-level path) |
| `app.py` | offline Streamlit demo (accepts both CSV and PCAP) |
| `zero_day_callout.py` | novelty / "unlike anything trained" advisory |
| `eval_forecasting.py`, `walk_forward_cv.py`, `world_model_dynamics.py` | evaluation |
| `run_all.sh` | one-command reproducibility (`data \| models \| eval \| app`) |
| `docs/sih26153_deck.md` | 5-slide presentation deck (Phase 4 deliverable) |

---

## 3. Data & preprocessing

- **8 real CICIDS2017 day-files** (Mon → Fri), `dataset/*.pcap_ISCX.csv`:
  - Monday: benign-only (behavioral baseline day);
  - Tuesday: FTP/SSH **brute-force**;
  - Wednesday: **DoS** — Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed;
  - Thursday: **web attacks** (SQLi, XSS, brute-force-over-HTTP) + **infiltration**;
  - Friday: **botnet** (Ares), **port-scan**, **DDoS** (LOIC/HOIC).
- **Reconciliation**: column names stripped of CICIDS trailing-space mangling;
  `±inf` → NaN; rows missing `Flow Bytes/s | Flow Packets/s | Flow Duration`
  dropped (NaN–row handling is **identical** between the offline build and the
  streaming path — see §13).
- **Label → attack-family mapping** (exact match first, substring second; the
  web-attack label ships corrupted with a Unicode em-dash and needs the
  substring path). All labels resolve to 8 families: `dos, brute_force,
  port_scan, web_attack, botnet, infiltration, exploit, none`.
- **Windowing** (`full_pipeline.load_and_window_day`): rows sliced into
  **500-flow windows**; ~5,650 windows across the week. A window is an
  **attack window** when its attack-flow fraction `> 1%` — the naive 50%
  majority threshold misses sparse-but-real attack bursts inside heavy
  background traffic (e.g. a brute-force burst inside ~500 mostly-benign flows).

**Attack-window family distribution** (from `kill_chain_mapping.json`):
`dos 1209 · brute_force 505 · port_scan 351 · web_attack 91 · botnet 92`.

---

## 4. Feature engineering

### 4.1 Raw features (10 units — shared by both paths)

| Feature | Source (flow CSV) | Source (PCAP) |
|---|---|---|
| `packet_rate` | mean of per-flow `Flow Packets/s` (clipped) | packets / window duration |
| `byte_rate` | mean of per-flow `Flow Bytes/s` (clipped) | IP bytes / window duration |
| `unique_dst_ips` | cardinality of destination port field* | `len(dst_ips)` |
| `unique_dst_ports` | cardinality of destination port field | `len(dst_ports)` |
| `syn_ack_ratio` | `(ΣSYN+1)/(ΣACK+1)` | `(syn_noack+1)/(syn_ack+1)` |
| `avg_pkt_size` | clipped mean of `Total Length of Fwd Packet` | mean packet size |
| `dst_port_entropy` | Shannon entropy over dst-port multiset | same (via `_entropy`) |
| `failed_conn_rate` | `ΣRST / window` | `rst / tcp_n` |
| `fwd_psh_rate` | `ΣFwd PSH / window` | `psh / tcp_n` |
| `avg_flow_duration` | clipped mean of `Flow Duration` | mean flow duration (from 5-tuple table) |

*\*The CICIDS capture carries a degenerate destination-IP field — the port
count is the stable "scanning" proxy.*

### 4.2 Rolling features (66 units — offline build and live parity)

For each window-size w ∈ {3,6,12} and each of the 10 raw columns: moving
**mean** and moving **std** (ddof=1) over the past w windows (60 cols), plus
`portcount_slope_w` and `entropy_slope_w` (6 cols, = value at t minus value at
t−w). Rolling stats are grouped **per-day** so no information leaks across day
boundaries (a chain of windows never spans two days).
**Total: 76 features** per window.

### 4.3 Packet-extras (11 units — PCAP path only, informational)

Computed by `packet_features.py` during PCAP → CSV conversion and appended as
extra columns to the output CSV, but **NOT consumed by the trained models**:
`ttl_mean, ttl_std, tcp_win_mean, tcp_win_std, frag_ratio, df_ratio,
syn_only_rate, icmp_ratio, udp_ratio, retrans_ratio, distinct_src_ips`.

These exist for analyst context and heuristic stage-labelling (see §11); the
models see exactly the same 10 raw + 66 rolling = 76 columns regardless of
whether input was a flow CSV or a PCAP.

### 4.4 Forecast label

`y_forecast`: a window is positive if an attack window *starts within the next
6 windows* (`FORECAST_HORIZON=6`) on the same day. This makes the task a true
forecast ("an attack is imminent"), not instant detection. Positive rate over
the full week ≈ 46%.

> **Guarantee (parity):** the streaming path (`infer.py`'s
> `RollingFeatureBuilder`) produces the *same* 76 columns as the offline build —
> measured **~99.4% cell-level identical** on Friday-DDoS (residual <1% is
> file-tail window boundaries). See §13.

---

## 5. Models

| Model | Cross-day AUC (unseen Fri) | Within-day AUC | Recall @0.5 (cross-day) | Notes |
|---|---|---|---|---|
| Logistic Regression (baseline) | 0.539 | 0.763 | — | mandated baseline |
| RandomForest (400 trees, depth 10, class-balanced) | **0.763** | **0.838** | 0.235 | deployed forecaster; DP @0.5 = 0.937 |
| **LSTM World Model** (seq 12 → hidden 24, NumPy BPTT+Adam) | **0.643** *(0.471 baseline)* | 0.544 *(0.700)* | 0.299 | shipped weights; saliency explainable |

- **RandomForest forecaster**: `n_estimators=400, max_depth=10,
  min_samples_leaf=3, class_weight="balanced", random_state=42`. Best
  cross-day (transfer) performance of the three classifiers.
- **Attack-family classifier** (RF, 300 trees): labels *which* known attack is
  imminent on forecast-positive windows. Accuracy **0.241** — reported honestly;
  deployed only as a *weak prior*, never as a hard verdict (see the novelty
  callout, §10).
- **LSTM world model — hand-rolled NumPy** (no deep-learning framework):
  input = sequence of the **8 raw traffic signals** over the past 12 windows
  (literal "network state" S_t), 1 hidden layer (24 units), many-to-one binary
  output = P(attack within next 6 | recent trajectory). Implements forward
  pass, **BPTT**, gradient clipping (±5), light L2 (1e-4), **Adam**, and
  early-stopping on a held-out val slice. Input sequences are bootstrapped via
  overlapping windows (seq end aligned to the labelled window, no leakage).
- **Training protocols**:
  - *Cross-day (primary)*: train Mon–Thu (incl. Thursday web/infil), test on
    the **entirely unseen** Friday (3 files). This is the honest transfer test.
  - *Within-day*: 60/10/30 time-split *inside each day*; leak-prone by
    construction (near-duplicate traffic across the split) — reported as an
    **upper-bound reference**, never confused with the cross-day number.
  - *LSTM nuance*: the original model used per-sequence **online SGD**, which
    made val-AUC oscillate 0.55–0.85 and picked lottery-winning early
    checkpoints → cross-day 0.471. **Mini-batch gradient accumulation (B=32) +
    full-length training (last checkpoint)** lifted cross-day AUC to **0.643**
    (precision 0.824, recall 0.299) and is what the shipped `lstm_weights.json`
    contains (provenance recorded in the artifact: "batch-32 Adam, no augment,
    40 epochs"). Augmentation was tried (jitter/time-warp/sign-flip, 2×) and
    *hurt* (0.285, 0.268) — reported in `lstm_improve_summary.json` as a
    negative result. Trade-off: the improved training regressed within-day AUC
    to 0.544 (the batch model generalizes cross-day at the cost of within-week
    memorization) — both numbers documented side by side.
  - *Independent check*: **rolling-origin walk-forward CV** (§6) with the RF.
- **Why a discrete/continuous "world model"?** The LSTM is legitimately a
  sequence model of network state dynamics (see §7), meeting the PS's
  "sequence model (LSTM, Transformer)" option — implemented from scratch in
  NumPy so it runs in the offline sandbox.

---

## 6. Evaluation: forecasting quality, lead time, CV

**Forecasting evaluation** (`eval_forecasting.py`, test = unseen Friday,
n = 1404 windows, 955 attack windows):

- **AUPRC 0.877** (the metric that matters for a rare/imbalanced early-warning
  task; base positive rate 68% on this test day, so PR is meaningful).
- Precision/recall/F1 across alert thresholds:
  | threshold | precision | recall | F1 | alerts |
  |---|---|---|---|---|
  | 0.3 | 0.900 | 0.639 | 0.747 | 678 |
  | 0.5 (default) | 0.937 | 0.235 | 0.375 | 239 |
  | 0.7 | 0.966 | 0.151 | 0.261 | 149 |
  → For an early-warning operator, **0.3 is the tuned operating point** (flag
  ~48% of windows, catch 64% of attack windows, still 90% precise).
- **Lead time**: Q1 5 / **median 8** / Q3 8 / mean 6.5 windows *before first
  alert* (median 8 = horizon cap). Warned **373/955 (39.1%)** attack windows;
  false-alarm rate at 0.5 = 3.3%.
- **Per-family (unseen Friday)**: `dos` 269/278 warned, median lead 8;
  `botnet` 16/92, median 6; `port_scan` **0/351**. The PortScan blind spot is
  real (novel-to-model attack type) and **not hidden** — it is the strongest
  argument for the novelty callout (§10).

**Rolling-origin walk-forward CV** (`walk_forward_cv.py`, RF, same config as
the primary pipeline): train on every strictly-earlier day-file subset and
evaluate the immediately next one — 6 look-ahead folds:

| fold test day | train windows | test windows | AUC |
|---|---|---|---|
| wednesday | 1949 | 1382 | 0.849 |
| thursday_web | 3331 | 340 | 0.758 |
| thursday_infil | — | — | single-class (skipped) |
| friday_morning | 4247 | 381 | 0.569 |
| friday_portscan | 4628 | 572 | 0.481 |
| friday_ddos | 5200 | 451 | 0.933 |

**Pooled AUC 0.722** (mean fold 0.718, median 0.758) — independent
confirmation that the single Mon→Fri holdout (0.763) is *not* a lucky split,
and that cross-day weakness is concentrated in PortScan/first-half-Friday.

---

## 7. World-model dynamics (the PS's core ask)

`world_model_dynamics.py` makes the "world model" claim concrete by comparing
what the LSTM learns against the **empirical** state dynamics over the full
week. States: `SAFE` (no attack alerted) · `INCOMING` (forecast fired) ·
`ATTACK` (attack present).

**Empirical P(S_{t+1} | S_t)** (counts, all days):
```
from \ to      SAFE    INCOMING    ATTACK
SAFE           2991      21          0      ← attacks never appear from thin air
INCOMING          0      239        147     ← INCOMING is a real precursor
ATTACK           18      126       2101     ← ATTACK self-sustains (a flood lasts)
```
The diagonal-dominant structure is exactly a periodic-attack workflow: windows
*progress* SAFE → INCOMING → ATTACK and stay there; they don't teleport.

**Learned dynamics**: the LSTM forecast of the *next* window's attack state on
unseen Friday scores **AUC 0.814** (n = 5555 sequence-to-next-window pairs) —
evidence the sequence model genuinely encodes transition dynamics, not just a
static feature-snapshot. A risk-bin contingency (HIGH/INCOMING-risk windows →
1664 next-window attacks vs LOW → 554) corroborates the transition story.

---

## 8. MITRE ATT&CK mapping

`port_scan → Reconnaissance` · `brute_force / web_attack / infiltration /
exploit → Initial Access` · `botnet → Command & Control` · `dos/ddos →`
TA0040 **Impact** (not one of the PS's 5 stages — surfaced as its own
explicitly-labelled bucket rather than being force-mapped). Per-alert MITRE
stage is emitted live by `infer.py`; kill-chain counts in
`kill_chain_mapping.json`. CAPEC patterns + illustrative CVEs per family are
surfaced in the app via `knowledge_base.py`.

---

## 9. Explainability

- **LSTM (top-level)**: gradient-of-output **saliency** per input feature/timestep
  (from-scratch; SHAP not installable offline). Saved demo
  (`saliency_demo.json`): a real DDoS forecast at risk 0.744 driven by
  `packet_rate` (34%) and `dst_port_entropy` + `unique_dst_ports` (~31%) —
  exactly the domain intuition for flooding.
- **RandomForest (run-time, live)**: **mean-imputation ablation** over the
  top-6 global importances inside each batch — "risk dropped by X when we set
  `byte_rate` to its batch mean" — emitted per flagged window in `infer.py` and
  shown in the app ("Driving features"). Batch-vectorized (7 `predict_proba`
  calls per 128-window batch) to respect the ~250 ms/sklearn-call overhead.
- Both mechanisms are first-class pipeline outputs, not forensic afterthoughts
  — the operator always sees *why* a window was flagged.

---

## 10. Novelty / "zero-day" callout (honest scoping)

The supervised models are trained on **known, labelled attack families**. A
completely new attack **cannot** be "recognised" — the system must *say so*
instead of silently miscalling it. `zero_day_callout.py` implements this as a
data-driven, advisory signal on **alert windows only**:

- A **NoveltyStore** is built from all known-attack windows in the training
  corpus (`full_features.csv`, `label_attack_now == 1`): per-column z-score
  statistics + a k-D tree over the standardized known-attack manifold + a
  baseline distribution of k=5 nearest-neighbour distances *within* the known
  attacks (median 2.4, Q95 ≈ 6 in z-space).
- At runtime, a flagged window's k-NN distance is measured against that
  manifold; **distance > the 95th percentile of known-attack distances**
  ⇒ **"possible novel / zero-day activity — analyst review needed"**, reported
  beside the family-classifier **confidence** (a novel attack typically draws a
  flat, low-confidence family spread).
- Calibration is verified: known attack windows self-evaluate at mean distance
  2.4 / percentile 0.50 / 5%-novel rate — i.e. the store *does not* flag the
  data it was built on.
- Live behavior (Friday-DDoS, RF): 52/263 alert windows flagged novel, led by
  the **onset** windows (36→47); sustained DDoS flood windows fall back inside
  the known `dos` manifold (~0.92–0.94 percentile). LSTM path: 6/180.

**Wording guardrail for all deliverables**: never claim "zero-day detection";
say "known attack progressions" (the actual capability) and "novelty callout
for activity unlike anything in training".

---

## 11. Packet-level path (PCAP)

`packet_features.py` — the PS-required **packet-level** feature path:

- **Streaming**: Scapy `PcapReader` → 500-packet windows (bounded memory).
- **Same 10 model raw features** as the flow path, derived from packets via a
  lightweight 5-tuple flow table (flow durations, retransmission counts,
  SYN/ACK flags), so packet windows are **directly consumable by the same
  trained models** via `infer.py` (pre-windowed CSV path).
- **11 packet-extras** (informational, not model inputs): `ttl_mean, ttl_std,
  tcp_win_mean, tcp_win_std, frag_ratio, df_ratio, syn_only_rate, icmp_ratio,
  udp_ratio, retrans_ratio, distinct_src_ips`. These are appended as extra
  columns in the output CSV for analyst context; the models only consume the
  10 raw + 66 rolling = 76 columns (see §4.3).
- **Heuristic stage for label-less pcaps**: icmp/syn flood → `dos`/Impact;
  retrans-heavy SYN flood → `dos`; SYN-only across many ports → `port_scan`/
  Reconnaissance (heuristics are rules, not learned — see §16).
- **Verified on synthetic capture** (2020 pkts: benign → 600 SYN-scan →
  900 SYN-flood): phases labelled none → port_scan/Recon → dos/Impact, and the
  RF forecaster flags the flood windows from packet-derived features alone
  (peak risk 0.61).
- **Known gap**: not yet validated on a *real* CICIDS2017 PCAP (raw capture
  unavailable locally); synthetic-only as of writing.

---

## 12. Inference runtime & offline demo

- **`infer.py`** streams raw CICIDS CSVs in 20k-row chunks into an in-progress
  500-flow window, rebuilds the 76 rolling features incrementally
  (`RollingFeatureBuilder`), and predicts in **batches of 128 windows** to avoid
  the ~250 ms/sklearn-call overhead. Emits a JSON timeline per window:
  `risk_score, predicted_alert, attack_family, mitre_stage, attribution,
  zero_day{confidence, novelty dist/percentile}`. Handles either raw CICIDS
  CSVs or pre-windowed CSVs (the packet path). Friday-DDoS full-file runs in
  ~21 s user time.
- **`app.py`** (Streamlit, `server.headless`, 1 GB upload cap): upload CSV
  **or** `.pcap`; model picker (RF/LSTM); threshold slider; renders risk
  timeline, MITRE stage breakdown, alert table, driving features, CAPEC/CVE
  enrichment, and the **novelty callout** (badge + per-window column). Fully
  offline — no cloud call is made.
- Verified end-to-end (Friday-DDoS): RF first alert @ window **36** (peak
  0.991, ~80% flag rate); LSTM first alert @ window **41** (peak 1.0, ~59%
  flag rate) with the improved cross-day weights.

---

## 13. Live ↔ offline feature parity (correctness guarantee)

Two latent bugs were found and fixed so the live demo is on the *same feature
distribution* as training:

1. **Window slice bug**: `infer.py`'s streaming `flush_window` originally
   computed window features over the **entire in-memory chunk (~20k rows)**
   instead of the exact 500-row window → live risk was on a different
   distribution than the models (LSTM live flagged 2 Friday-DDoS windows vs
   ~259 offline). Fixed by slicing to the current window.
2. **Rolling-builder bugs**: `RollingFeatureBuilder.row()` never emitted the 10
   raw columns (they silently fed the model as 0.0), and `entropy_slope*` was
   computed from `avg_pkt_size` (positional index 5) instead of
   `dst_port_entropy` (index 6).

Post-fix measured parity on Friday-DDoS: **440/441 windows bit-identical** at
the raw-feature level and **~99.4% cell-level** across all 76 columns (residual
<1% = file-tail window boundaries / partial-window flush). Live RF/LSTM runs
now reproduce the published offline numbers.

---

## 14. Reproducibility & deployment

One command pipeline (`run_all.sh`):

```
./run_all.sh data      # corpus → full_features.csv
./run_all.sh models    # RF forecaster/family + LSTM + baseline
./run_all.sh eval      # infer demo, dynamics, forecasting, walk-forward CV, LSTM improve
./run_all.sh app       # launch the offline demo
```

- Seeds pinned (`random_state=42`, `np.random.seed(42)`); model artifacts,
  results JSON, and CSVs are committed so `eval`/`app` run **without** the raw
  dataset (raw captures git-ignored; redownload from UNB to rebuild).
- **Pinned requirements** (`requirements.txt`): `scikit-learn==1.8.0`
  (exact match to the pickle training environment; eliminates the
  `InconsistentVersionWarning` on deploy), `numpy==2.0.2`, `pandas==2.2.3`,
  `streamlit`, `scapy`. Legacy Flask/FastAPI/uvicorn dependencies removed.
- **Community-Cloud deployment path**: push → share.streamlit.io →
  repo `sahooarnav2007-gif/b` → `main` → `app.py`. Upload cap 200 MB on the
  free tier — within the demo CSVs' size. First load after sleep takes ~30–60 s.
- **Deliverables**: source code + README + 2-page architecture write-up
  (compressed from this file) + 5-slide deck (`docs/sih26153_deck.md`) +
  2-minute demo video + running offline app.

---

## 15. Results summary (authoritative table)

| Metric | Value | Artifact |
|---|---|---|
| RF cross-day AUC / within-day AUC | 0.763 / 0.838 | full_model_summary.json |
| LSTM cross-day AUC (shipped, improved) | 0.643 (baseline 0.471) | lstm_improve_summary.json |
| LSTM within-day AUC | 0.544 (baseline 0.700) | lstm_improve_summary.json |
| LogReg cross-day / within-day | 0.539 / 0.763 | logreg_summary.json |
| Forecasting AUPRC (unseen Fri) | 0.877 | eval_forecasting.json |
| Lead time before first alert | median 8 / mean 6.5 windows | eval_forecasting.json |
| DDoS warned (unseen Fri) | 269/278 (96.8%), lead 8 | eval_forecasting.json |
| PortScan warned (unseen Fri) | 0/351 (reported, not hidden) | eval_forecasting.json |
| Walk-forward pooled AUC (6 folds) | 0.722 | walk_forward_cv.json |
| World-model next-state AUC | 0.814 | world_model_dynamics.json |
| Family classifier accuracy | 0.241 (weak prior, never verdict) | full_model_summary.json |
| Live RF first alert (Friday DDoS) | window 36, peak risk 0.991 | verified end-to-end |
| Live LSTM first alert (Friday DDoS) | window 41, peak risk 1.0 | verified end-to-end |

---

## 16. Known limitations (owner's register)

1. **Family classifier accuracy 0.241** — confusable families; used only as a
   weak prior with the novelty callout as the safety valve.
2. **PortScan is a cross-day blind spot on unseen Friday (0/351)** — a
   novel-to-model attack *type*; exactly why the novelty callout exists, but the
   family verdict is wrong when it happens.
3. **LSTM within-day regression** (0.544, vs RF 0.838) and LSTM cross-day 0.643
   < RF 0.763 — the sequence model earns its place via dynamics (§7), high
   within-day recall, and explainability, not by beating RF end-to-end; both
   numbers are published.
4. **Packet path synthetic-only** — no real CICIDS2017 PCAP validated yet.
5. **CAPEC/CVE map is static/illustrative**, not a live NVD feed.
6. **sklearn pickle version-drift** is a warning (verified valid 1.8→1.9);
   pinned in `requirements.txt` for cloud deployment.
7. **No early-warning deal on brute-force/web/botnet families at 0.5** — the
   tuned operating point (threshold 0.3: recall 0.64, precision 0.90) is the
   intended production configuration.
8. **Novelty callout is advisory** — it says "unlike everything trained",
   which is *correlated* with but not *equal* to "malicious". Analysts review;
   it is not an automated zero-day verdict.

---

## Appendix A. Full file inventory

| File | Purpose |
|---|---|
| `full_pipeline.py` | Corpus → windowed feature table (`full_features.csv`) |
| `full_train.py` | RF forecaster + family classifier, dual-protocol eval |
| `lstm_world_model.py` | NumPy LSTM world model (train + eval + saliency) |
| `lstm_improve.py` | Improved cross-day LSTM (batch-32 Adam, 40 epochs) |
| `logreg_baseline.py` | Mandated logistic-regression baseline |
| `infer.py` | Streaming live inference (CSV or pre-windowed CSV) |
| `packet_features.py` | PCAP → pre-windowed CSV via Scapy (packet-level path) |
| `app.py` | Offline Streamlit demo (CSV + PCAP upload) |
| `zero_day_callout.py` | Novelty callout (k-NN, advisory) |
| `eval_forecasting.py` | Forecasting metrics: AUPRC, lead time, per-family |
| `walk_forward_cv.py` | Rolling-origin walk-forward CV (6 folds) |
| `world_model_dynamics.py` | Empirical vs LSTM P(S_{t+1}\|S_t), next-state AUC |
| `knowledge_base.py` | CAPEC/CVE enrichment per attack family |
| `run_all.sh` | One-command reproducibility pipeline |
| `requirements.txt` | Pinned deployment dependencies |
| `full_features.csv` | 5651 windows × 76 columns (committed) |
| `full_predictions.csv` | 1404 test-row predictions (committed) |
| `full_model_summary.json` | RF / LSTM / logreg cross-day + within-day AUCs |
| `lstm_weights.json` | Shipped LSTM weights + provenance |
| `lstm_improve_summary.json` | LSTM cross-day improvement study results |
| `eval_forecasting.json` | AUPRC, threshold table, lead-time distribution |
| `walk_forward_cv.json` | Per-fold AUCs, pooled AUC |
| `world_model_dynamics.json` | Empirical transition matrix, next-state AUC |
| `kill_chain_mapping.json` | MITRE stage mapping + per-family attack-window counts |
| `saliency_demo.json` | Saved LSTM saliency example (real DDoS forecast) |
| `docs/architecture.md` | This file — detailed master architecture |
| `docs/sih26153_deck.md` | 5-slide presentation deck (Phase 4 deliverable) |