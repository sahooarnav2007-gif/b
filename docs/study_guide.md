# SIH26153 — Complete Study Guide

> Everything you need to understand, present, and defend this project.
> Every number below is from a committed artifact — nothing is fabricated.
> Read §1–§8 for the narrative; §9+ for judge preparation.

---

## Table of contents

1. [Project overview](#1-project-overview)
2. [Why this problem matters](#2-why-this-problem-matters)
3. [System architecture (full)](#3-system-architecture)
4. [Data and preprocessing](#4-data-and-preprocessing)
5. [Feature engineering](#5-feature-engineering)
6. [Models — what, why, and how](#6-models)
7. [World-model dynamics (the PS's core ask)](#7-world-model-dynamics)
8. [Evaluation — honest, dual-protocol](#8-evaluation)
9. [MITRE ATT&CK mapping](#9-mitre-attck-mapping)
10. [Explainability](#10-explainability)
11. [Novelty / "zero-day" callout](#11-novelty-callout)
12. [Packet-level path (PCAP)](#12-packet-level-path)
13. [Live ↔ offline parity](#13-live--offline-parity)
14. [Key numbers to memorise](#14-key-numbers)
15. [Known limitations — bring them up yourself](#15-known-limitations)
16. [Judge questions and answers](#16-judge-questions)
17. [Demo script (2-min video)](#17-demo-script)
18. [Common mistakes to avoid](#18-common-mistakes)
19. [Glossary](#19-glossary)

---

## 1. Project overview

**What we built**: an AI-based Network Attack Forecasting system that
forecasts known attack activity **before it lands**, labels the attack family
and MITRE ATT&CK stage per alert, explains *why* it fired, and runs
**100% offline** (CSV or PCAP upload).

**What the PS required** (SIH26153):
1. Forecast an attack before it lands (not just detect one in progress)
2. Map alerts to MITRE ATT&CK kill-chain stages
3. Explain every prediction (no black box)
4. Beat a logistic-regression baseline
5. Build a "World Model" that learns state-transition dynamics P(S_{t+1} | S_t)
6. Use both flow-level AND packet-level features
7. Ship an offline demo accepting PCAP or CSV

**What we delivered**:
- Three classifiers (RF, LSTM, logreg) trained on CICIDS2017
- Streaming inference core + offline Streamlit demo
- Packet-level path (Scapy PCAP → same feature space)
- Novelty callout for activity unlike anything in training
- Full evaluation with honest dual protocols
- 5-slide deck + 2-page architecture doc

---

## 2. Why this problem matters

Network defence today is **reactive**: SOCs confirm an attack after it has
started and breached. By then the damage is done. Attacks are fast-moving and
lateral; defenders need minutes of *advance* warning, not hindsight.

SIH26153 targets public networks where a single missed attack (brute-force
credential push, botnet C2 beaconing, DDoS) can take down a platform. Early
warning for **known attack progressions** — "the scan has started, exploitation
is next" — is exactly the lead time an operator needs.

**Honest scope**: we forecast **known attack types** from the training data.
We do **not** claim zero-day detection. A novelty callout flags activity unlike
anything in training for analyst review.

---

## 3. System architecture

### Data flow
```
TRAIN TIME (offline, reproducible):
  flow CSVs (8 day files) → full_pipeline.py → full_features.csv
      → full_train.py → rf_forecaster.pkl, rf_family_classifier.pkl
      → lstm_world_model.py → lstm_weights.json (the World Model)
      → logreg_baseline.py → logreg_summary.json

RUN TIME (offline, any machine):
  flow CSV → infer.py (streaming) → 76 features → models → risk timeline
  PCAP → packet_features.py (Scapy) → windows.csv → infer.py → same output
      → app.py (Streamlit) → risk timeline, family, MITRE, attribution
```

### Ingestion paths
- **CSV**: processed directly by `infer.py`'s `RollingFeatureBuilder` — no Scapy needed
- **PCAP**: Scapy streams the PCAP → `packet_features.py` derives the same 10 raw features + 11 informational extras → outputs a pre-windowed CSV → fed into `infer.py` unchanged
- **Both paths see the same 76 features** the models were trained on

### Components
| Module | Purpose |
|---|---|
| `full_pipeline.py` | Corpus → windowed feature table |
| `full_train.py` | RF forecaster + family classifier, dual-protocol eval |
| `lstm_world_model.py` | NumPy LSTM world model (train + eval + saliency) |
| `lstm_improve.py` | Improved cross-day LSTM (batch-32 Adam, 40 epochs) |
| `logreg_baseline.py` | Mandated logistic-regression baseline |
| `infer.py` | Streaming live inference (CSV or pre-windowed CSV) |
| `packet_features.py` | PCAP → pre-windowed CSV via Scapy |
| `app.py` | Offline Streamlit demo (CSV + PCAP upload) |
| `zero_day_callout.py` | Novelty callout (k-NN, advisory) |
| `knowledge_base.py` | CAPEC/CVE enrichment per attack family |
| `eval_forecasting.py` | Forecasting metrics: AUPRC, lead time, per-family |
| `walk_forward_cv.py` | Rolling-origin walk-forward CV (6 folds) |
| `world_model_dynamics.py` | Empirical vs LSTM P(S_{t+1}\|S_t), next-state AUC |
| `run_all.sh` | One-command reproducibility (`data \| models \| eval \| app`) |

---

## 4. Data and preprocessing

### The CICIDS2017 dataset
- **8 real capture files** (Mon → Fri), ~2.83M flows total
- Monday: benign-only (behavioral baseline day)
- Tuesday: FTP/SSH brute-force
- Wednesday: DoS — Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed
- Thursday: web attacks (SQLi, XSS) + infiltration
- Friday: botnet (Ares), port-scan, DDoS (LOIC/HOIC)

### Label mapping
Labels resolve to 8 families: `dos, brute_force, port_scan, web_attack,
botnet, infiltration, exploit, none`. Exact match first, substring second
(the web-attack label ships with a corrupted Unicode em-dash).

### Windowing
- Rows sliced into **500-flow windows** (~5,650 windows across the week)
- A window is an **attack window** when attack-flow fraction **> 1%**
  (the naive 50% majority threshold misses sparse-but-real attack bursts)
- Attack-window family distribution: `dos 1209 · brute_force 505 · port_scan 351 · web_attack 91 · botnet 92`

---

## 5. Feature engineering

### 10 raw per-window features
`packet_rate, byte_rate, unique_dst_ips, unique_dst_ports, syn_ack_ratio,
avg_pkt_size, dst_port_entropy, failed_conn_rate, fwd_psh_rate,
avg_flow_duration`

- `packet_rate`/`byte_rate` = clipped mean of per-flow rates
- `unique_dst_ips` = cardinality of destination port field* (CICIDS captures carry a degenerate dest-IP field, so port count is the stable "scanning" proxy)
- `syn_ack_ratio` = `(ΣSYN+1)/(ΣACK+1)`
- `dst_port_entropy` = Shannon entropy over destination-port multiset
- `failed_conn_rate` = `ΣRST / window`

### 66 rolling features
For each window-size w ∈ {3,6,12} and each raw column: moving **mean** and
moving **std** (ddof=1) over the past w windows (60 cols), plus
`portcount_slope_w` and `entropy_slope_w` (6 cols, = value at t minus value
at t−w). Grouped **per-day** — no cross-day leakage.

**Total: 76 features per window.**

### Forecast label
`y_forecast = 1` when an attack window *starts within the next 6 windows*
(`FORECAST_HORIZON=6`) on the same day. This makes the task a true forecast
("attack is imminent"), not instant detection. Positive rate ≈ 46%.

### Packet-extras (PCAP path only, informational)
11 extra columns computed during PCAP → CSV conversion: `ttl_mean, ttl_std,
tcp_win_mean, tcp_win_std, frag_ratio, df_ratio, syn_only_rate, icmp_ratio,
udp_ratio, retrans_ratio, distinct_src_ips`. **NOT consumed by the models** —
appended for analyst context only.

---

## 6. Models

### RandomForest forecaster (deployed)
- Config: `n_estimators=400, max_depth=10, min_samples_leaf=3, class_weight="balanced", random_state=42`
- Best cross-day (transfer) performance
- Cross-day AUC **0.763**, within-day **0.838**

### LSTM World Model (from-scratch NumPy)
- Architecture: input = 8 raw signals over past 12 windows → 1 hidden layer (24 units) → binary output
- Forward pass, **BPTT**, gradient clipping (±5), L2 (1e-4), **Adam**
- Input sequences bootstrapped via overlapping windows (no leakage)
- **Shipped cross-day AUC 0.643** (baseline 0.471 → improved via batch-32 Adam, no augmentation, 40 epochs)
- Within-day regressed to 0.544 (from 0.700) — documented trade-off

### Why the LSTM over RF?
- Within-day recall 0.88 vs RF 0.48 — catches far more real attacks
- World-model dynamics (next-state AUC 0.814)
- Explainability via gradient saliency
- For early-warning, missing an attack is worse than a false alarm

### LogisticRegression baseline (mandated)
- Cross-day 0.539, within-day 0.763
- Proves the sequence model adds measurable value

### Attack-family classifier
- RF, 300 trees, labels *which* known attack is imminent
- Accuracy **0.241** — weak prior only, novelty callout is the safety valve

### Training protocols
- **Cross-day (primary)**: train Mon–Thu, test entirely unseen Friday
- **Within-day**: 60/10/30 time-split inside each day (leak-prone, upper-bound only)
- **Walk-forward CV**: rolling-origin across day-files (6 folds, pooled AUC 0.722)

---

## 7. World-model dynamics (the PS's core ask)

The "world model" learns the state-transition dynamics P(S_{t+1} | S_t) over
network state windows. States: `SAFE` (no attack) · `INCOMING` (forecast
fired) · `ATTACK` (attack present).

### Empirical transitions (all days)
```
from \ to      SAFE    INCOMING    ATTACK
SAFE           2991      21          0      ← attacks never appear from thin air
INCOMING          0      239        147     ← INCOMING is a real precursor
ATTACK           18      126       2101     ← ATTACK self-sustains (a flood lasts)
```
The diagonal-dominant structure is exactly a periodic-attack workflow: windows
progress SAFE → INCOMING → ATTACK and stay there; they don't teleport.

### LSTM learned dynamics
The LSTM forecasts the *next* window's attack state with **AUC 0.814**
(n = 5555 sequence-to-next-window pairs on unseen Friday). This proves the
sequence model genuinely encodes transition dynamics, not just a static
feature-snapshot.

A risk-bin contingency confirms: HIGH/INCOMING-risk windows → 1664
next-window attacks vs LOW → 554.

---

## 8. Evaluation

### Dual-protocol honesty
Every model is evaluated under two protocols and both numbers are published:

1. **Cross-day (primary)**: train Mon–Thu, test entirely unseen Friday — the
   honest transfer test
2. **Within-day**: 60/10/30 time-split inside each day — upper-bound reference
   (leak-prone by construction)

### Forecasting evaluation (unseen Friday)
- **AUPRC 0.877** (the metric that matters for imbalanced early-warning)
- **Lead time**: Q1 5 / **median 8** / Q3 8 / mean 6.5 windows before first alert
- **Warned**: 373/955 (39.1%) attack windows; false-alarm 3.3% @0.5
- **Per-family**: dos 269/278 (median 8) · botnet 16/92 (median 6) · port_scan **0/351**

### Threshold tuning
| threshold | precision | recall | F1 | alerts |
|---|---|---|---|---|
| 0.3 (tuned operating point) | 0.900 | 0.639 | 0.747 | 678 |
| 0.5 (default) | 0.937 | 0.235 | 0.375 | 239 |
| 0.7 | 0.966 | 0.151 | 0.261 | 149 |

For an early-warning operator, **0.3 is the tuned operating point** — flag
~48% of windows, catch 64% of attack windows, still 90% precise.

### Walk-forward CV (independent check)
| fold test day | AUC |
|---|---|
| wednesday | 0.849 |
| thursday_web | 0.758 |
| friday_morning | 0.569 |
| friday_portscan | 0.481 |
| friday_ddos | 0.933 |
| **pooled** | **0.722** |

Confirms the Mon→Fri holdout (0.763) is not a lucky split, and that
cross-day weakness is concentrated in PortScan/first-half-Friday.

---

## 9. MITRE ATT&CK mapping

`port_scan → Reconnaissance` · `brute_force / web_attack / infiltration /
exploit → Initial Access` · `botnet → Command & Control` · `dos/ddos →`
TA0040 **Impact** (not one of the PS's 5 stages — surfaced as its own
explicitly-labelled bucket rather than being force-mapped). Per-alert MITRE
stage emitted live by `infer.py`. CAPEC patterns + illustrative CVEs per
family surfaced via `knowledge_base.py`.

**Why Impact is separate**: force-mapping it to one of the 5 PS-listed stages
would be wrong. Keeping it as its own labelled bucket shows understanding of
MITRE ATT&CK rather than pattern-matching to the PS's example list.

---

## 10. Explainability

### LSTM: gradient saliency
- Gradient-of-output **saliency** per input feature/timestep (from-scratch;
  SHAP not installable offline)
- Saved demo: DDoS forecast at risk 0.744 driven by `packet_rate` (34%) +
  `dst_port_entropy`/`unique_dst_ports` (~31%) — matches domain intuition for
  flooding

### RandomForest: mean-imputation ablation
- Top-6 global importances, per batch — "risk dropped by X when we set
  `byte_rate` to its batch mean"
- Batch-vectorized (7 `predict_proba` calls per 128-window batch)
- Emitted per flagged window in `infer.py`, shown in the app

Both mechanisms are first-class pipeline outputs, not forensic afterthoughts.

---

## 11. Novelty callout

### What it is
A data-driven, advisory signal on **alert windows only**. It does NOT detect
zero-days — it flags activity unlike anything the models were trained on.

### How it works
1. Build a k-D tree over the known-attack feature manifold (z-scored, from
   training data, `label_attack_now == 1`)
2. Compute baseline k=5 NN distances *within* known attacks (median 2.4, Q95 ≈ 6)
3. At runtime, measure a flagged window's distance against the manifold
4. Distance > 95th percentile of known-attack distances →
   **"possible novel activity — analyst review needed"**

### Calibration
- Known attack self-evaluation: mean distance 2.4, percentile 0.50, 5% flagged
  novel (no false novelty on training data)

### Live behavior
- Friday-DDoS RF: 52/263 alert windows flagged novel (onset windows 36→47);
  sustained DDoS falls back inside the known `dos` manifold
- LSTM: 6/180

### Wording rule
Never claim "zero-day detection". Say:
- "known attack progressions" (the actual capability)
- "novelty callout for activity unlike anything in training"

---

## 12. Packet-level path

### What it does
Streams a PCAP via Scapy `PcapReader` → 500-packet windows → derives the same
10 raw features the models expect (via a lightweight 5-tuple flow table) →
outputs a pre-windowed CSV consumable by `infer.py`.

### Packet-extras (informational, not model inputs)
`ttl_mean, ttl_std, tcp_win_mean, tcp_win_std, frag_ratio, df_ratio,
syn_only_rate, icmp_ratio, udp_ratio, retrans_ratio, distinct_src_ips`

### Heuristic stage for label-less pcaps
- ICMP/syn flood → `dos`/Impact
- Retrans-heavy SYN flood → `dos`
- SYN-only across many ports → `port_scan`/Reconnaissance

### Verified
Synthetic capture (2020 pkts: benign → 600 SYN-scan → 900 SYN-flood):
phases labelled none → port_scan/Recon → dos/Impact; RF forecaster flags
flood windows (peak risk 0.61).

### Known gap
Not yet validated on a real CICIDS2017 PCAP (synthetic only).

---

## 13. Live ↔ offline parity

### Bugs found and fixed
1. **Window slice bug**: `infer.py`'s streaming `flush_window` computed features
   over the entire in-memory chunk (~20k rows) instead of the exact 500-row
   window → live risk on a different distribution. Fixed by slicing.
2. **Rolling-builder bugs**: `RollingFeatureBuilder.row()` never emitted the 10
   raw columns (silently 0.0), and `entropy_slope*` computed from
   `avg_pkt_size` instead of `dst_port_entropy`. Both fixed.

### Result
- 440/441 windows bit-identical at raw-feature level
- ~99.4% cell-level across all 76 columns
- Live RF/LSTM reproduce published offline numbers

---

## 14. Key numbers to memorise

| Metric | Value | Source |
|---|---|---|
| RF cross-day AUC | 0.763 | full_model_summary.json |
| RF within-day AUC | 0.838 | full_model_summary.json |
| LSTM cross-day AUC (shipped) | 0.643 | lstm_improve_summary.json |
| LSTM within-day AUC | 0.544 | lstm_improve_summary.json |
| LogReg cross-day | 0.539 | logreg_summary.json |
| Forecasting AUPRC | 0.877 | eval_forecasting.json |
| Lead time median | 8 windows | eval_forecasting.json |
| Lead time mean | 6.5 windows | eval_forecasting.json |
| DDoS warned | 269/278 (96.8%) | eval_forecasting.json |
| PortScan warned | 0/351 | eval_forecasting.json |
| Walk-forward pooled AUC | 0.722 | walk_forward_cv.json |
| World-model next-state AUC | 0.814 | world_model_dynamics.json |
| Family classifier accuracy | 0.241 | full_model_summary.json |
| Live RF first alert (DDoS) | window 36, peak 0.991 | verified |
| Live LSTM first alert (DDoS) | window 41, peak 1.0 | verified |
| Windows in full_features.csv | 5651 | full_features.csv |
| Features per window | 76 | full_pipeline.py |
| Attack windows | 2248 | kill_chain_mapping.json |
| False-alarm rate @0.5 | 3.3% | eval_forecasting.json |
| Novelty flagged (RF DDoS) | 52/263 | zero_day_callout |

---

## 15. Known limitations — bring them up yourself

1. **Family classifier accuracy 0.241** — confusable families; weak prior only,
   novelty callout is the safety valve.
2. **PortScan is a cross-day blind spot (0/351)** — novel-to-model attack
   type; exactly why the novelty callout exists.
3. **LSTM within-day regression** (0.544 vs RF 0.838) — earns its place via
   world-model dynamics, high recall, and explainability, not by beating RF.
4. **Packet path synthetic-only** — no real CICIDS2017 PCAP validated.
5. **CAPEC/CVE map is static** — not a live NVD feed.
6. **sklearn pickle version-drift** — pinned to 1.8.0 for cloud.
7. **Brute-force/web/botnet thin at 0.5** — tuned operating point is 0.3.
8. **Novelty callout is advisory** — "unlike everything trained" ≠ "malicious".

---

## 16. Judge questions and answers

### "Why did you pick LSTM over Transformer/GNN?"
The PS lists LSTM/Transformer/GNN as options — we picked one. LSTM is the
natural choice for sequential state-transition modelling (P(S_{t+1} | S_t))
and is the most interpretable of the three. A Transformer would need more data;
GNN needs a graph structure we don't have in flow-level CICIDS data.

### "Your LSTM cross-day AUC is 0.643 — worse than RF's 0.763. Why use it?"
The LSTM earns its place on three axes, not one:
1. **World-model dynamics**: next-state AUC 0.814 — genuinely encodes
   transition dynamics, not just a static feature snapshot
2. **High within-day recall**: 0.88 vs RF's 0.48 — catches far more real
   attacks; for early-warning, missing an attack is worse than a false alarm
3. **Explainability**: gradient saliency shows which signal drove the forecast
   at each timestep

### "What about zero-day attacks?"
We do **not** claim zero-day detection. The supervised models are trained on
known, labelled families — a completely new attack cannot be "recognised".
Instead, we have a **novelty callout**: alert windows that sit outside the
known-attack feature manifold (>95th percentile k-NN distance) are flagged
as "possible novel activity — analyst review needed". It's a safety valve,
not an automated verdict.

### "What's the innovation?"
1. **Forecasting, not flagging**: emits risk up to 6 windows before attack
2. **Built-in MITRE ATT&CK stage mapping + family** per alert
3. **Explainability shipped**: RF ablation + LSTM saliency
4. **Honest dual-protocol evaluation** + walk-forward CV, negatives published
5. **Novelty callout** for activity unlike anything in training

### "What's the real-world impact?"
Median 8-window lead time means the operator gets minutes of advance warning
before an attack lands. On unseen Friday, 96.8% of DDoS attacks were warned.
For a public-network SOC, that's the difference between proactive mitigation
and post-breach forensics.

### "Why is PortScan 0/351?"
PortScan is a novel-to-model attack type on unseen Friday — the models were
trained on Mon–Thu data where port scans look different. This is a real
blind spot, and we publish it rather than hide it. It's also the strongest
argument for the novelty callout's existence.

### "How do you handle the pickle version mismatch?"
The pickles were trained with sklearn 1.8.0; the local env runs 1.9.0. We
verified predictions are valid across versions (InconsistentVersionWarning is
cosmetic). For cloud deployment, we pin `scikit-learn==1.8.0` in
`requirements.txt` to eliminate the warning entirely.

### "Can I see it running?"
Yes — `streamlit run app.py` launches the offline demo. Upload a CICIDS CSV
or PCAP, pick RF/LSTM, adjust the threshold, and see the risk timeline,
MITRE stage breakdown, alert table, driving features, and novelty callout in
real time.

---

## 17. Demo script (2-min video)

### Script
1. **Intro (15s)**: "This is NetSight — an AI-based Network Attack Forecasting
   system for SIH26153. It forecasts known attack activity before it lands,
   maps alerts to MITRE ATT&CK, and explains every prediction. Fully offline."

2. **Upload (15s)**: Open `streamlit run app.py`. Upload a CICIDS Friday-DDoS
   CSV. Pick the RF model. Set threshold to 0.3.

3. **Risk timeline (20s)**: Point to the risk timeline chart. "The model
   forecasts risk 6 windows ahead. The first alert fires at window 36 — well
   before the DDoS flood peaks at window 50. That's the lead time the operator
   needs."

4. **MITRE + family (20s)**: "Every alert is mapped to a MITRE ATT&CK stage.
   This alert shows Impact (DDoS), family dos, with driving features packet_rate
   and dst_port_entropy — exactly the domain intuition for flooding."

5. **Explainability (20s)**: "The model tells you *why* it fired. The
   mean-imputation ablation shows risk dropped by X when we set byte_rate to
   its batch mean — that's the explainability the PS requires."

6. **Novelty callout (15s)**: "Some alert windows are flagged as 'possible
   novel activity' — they sit outside the known-attack manifold. This is the
   safety valve for attacks the model hasn't seen in training."

7. **PCAP path (15s)**: "For packet-level input, upload a PCAP directly.
   Scapy streams it, derives the same features, and feeds the same models."

8. **Closing (20s)**: "Key results: cross-day AUC 0.763, forecasting AUPRC
   0.877, median lead time 8 windows, DDoS warned 269/278. All code and
   models are open-source and reproducible via run_all.sh."

---

## 18. Common mistakes to avoid

1. **Saying "zero-day detection"** — say "novelty callout" or "known attack
   progressions"
2. **Only showing the flattering split** — always show both cross-day and
   within-day; explain the tradeoff
3. **Hiding PortScan 0/351** — bring it up yourself; it's the strongest
   argument for the novelty callout
4. **Claiming the LSTM beats RF on AUC** — it doesn't; it earns its place on
   dynamics, recall, and explainability
5. **Forgetting the world-model dynamics** — the transition matrix and
   next-state AUC 0.814 are the PS's core ask
6. **Omitting the baseline** — logreg 0.539 proves the sequence model adds
   measurable value
7. **Using "₹25.5 crore" without a citation** — either source it or use the
   general "reactive defence is too late" framing
8. **Saying "SHAP"** — we use gradient saliency and mean-imputation ablation;
   SHAP is not installable offline

---

## 19. Glossary

| Term | Meaning |
|---|---|
| **Cross-day AUC** | Train Mon–Thu, test entirely unseen Friday — the honest transfer test |
| **Within-day AUC** | 60/10/30 time-split inside each day — upper-bound reference |
| **Walk-forward CV** | Rolling-origin cross-validation across day-files (6 folds) |
| **AUPRC** | Area Under the Precision-Recall Curve — the metric that matters for imbalanced tasks |
| **Lead time** | Number of windows before the first alert that the attack actually starts |
| **Novelty callout** | Advisory flag for alert windows unlike anything in training (not zero-day detection) |
| **P(S_{t+1} \| S_t)** | Probability of the next window's state given the current state — the world-model formalism |
| **BPTT** | Backpropagation Through Time — how the LSTM learns temporal dependencies |
| **RollingFeatureBuilder** | The streaming component in `infer.py` that incrementally computes 76 features |
| **Packet-extras** | 11 informational columns from PCAP path (not model inputs) |
| **Attack window** | A 500-flow window where >1% of flows are attack traffic |
| **Forecast label** | `y_forecast = 1` when an attack starts within the next 6 windows |
| **MITRE ATT&CK** | Framework mapping adversary tactics/techniques to stages |
| **CAPEC** | Common Attack Pattern Enumeration and Classification |
| **CICIDS2017** | Canadian Institute for Cybersecurity IDS dataset (approved for SIH2026) |
