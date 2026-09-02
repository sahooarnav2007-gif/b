# SIH26153 — AI-Based Network Attack Forecasting

> **PS**: build an AI-based Network Attack Forecasting system with a "World
> Model" that learns state-transition dynamics P(S_{t+1} | S_t), maps alerts
> to MITRE ATT&CK, explains every prediction, beats a logistic-regression
> baseline, uses both flow-level and packet-level features, and ships an
> offline demo accepting **PCAP or CSV**.

> **Approved dataset**: CICIDS2017 (confirmed from sih2026.vuce.in/en/ps/SIH26153
> and the NCIIPC contact list).

---

## Quick start

```bash
# one-command pipeline (installs deps if needed, runs everything)
./run_all.sh data       # corpus → full_features.csv
./run_all.sh models     # RF forecaster/family + LSTM + logreg baseline
./run_all.sh eval       # forecasting metrics, walk-forward CV, world-model dynamics, LSTM improve
./run_all.sh app        # launch the offline Streamlit demo (http://localhost:8501)

# or run the full pipeline manually:
python3 full_pipeline.py          # loads 8 real CICIDS2017 day-files, windows, labels
python3 full_train.py             # RF forecaster + family classifier, dual-protocol eval
python3 lstm_world_model.py       # LSTM world model (from-scratch NumPy, BPTT + Adam)
python3 logreg_baseline.py        # required baseline
python3 mitre_stages_and_explainability.py   # kill-chain mapping + saliency demo

# inference from a raw flow CSV
python3 infer.py dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

# packet-level path: PCAP → windows → forecast
python3 packet_features.py capture.pcap -o windows.csv --infer

# upload-and-forecast demo (accepts CSV or PCAP)
streamlit run app.py
```

---

## Ingestion paths — how PCAP and CSV are handled

Both paths converge on the **same 76-feature representation** the models were
trained on. The models never know which path the data came from.

### CSV path (direct)
```
flow CSV → infer.py → RollingFeatureBuilder (500-flow windows, 76 rolling features)
                     → saved RF / LSTM / logreg → risk timeline + family + MITRE + attribution
```
No Scapy required. Accepts raw CICIDS CSVs or pre-windowed CSVs (the packet
path's output).

### PCAP path (Scapy required)
```
.pcap → packet_features.py (Scapy PcapReader, 500-packet windows)
      → 10 raw model features + 11 packet-extras (informational, not model inputs)
      → pre-windowed CSV → infer.py (same pipeline as CSV path above)
```
Scapy is the hard dependency for PCAP ingestion. The 11 packet-extras
(`ttl_mean, ttl_std, tcp_win_mean, tcp_win_std, frag_ratio, df_ratio,
syn_only_rate, icmp_ratio, udp_ratio, retrans_ratio, distinct_src_ips`) are
appended as extra columns in the output CSV for analyst context; the models
only consume the 10 raw + 66 rolling = 76 columns.

---

## Feature engineering

### 10 raw per-window features (shared by both paths)

| Feature | Flow CSV source | PCAP source |
|---|---|---|
| `packet_rate` | mean of per-flow `Flow Packets/s` (clipped) | packets / window duration |
| `byte_rate` | mean of per-flow `Flow Bytes/s` (clipped) | IP bytes / window duration |
| `unique_dst_ips` | cardinality of destination port field* | `len(dst_ips)` |
| `unique_dst_ports` | cardinality of destination port field | `len(dst_ports)` |
| `syn_ack_ratio` | `(ΣSYN+1)/(ΣACK+1)` | `(syn_noack+1)/(syn_ack+1)` |
| `avg_pkt_size` | clipped mean of `Total Length of Fwd Packet` | mean packet size |
| `dst_port_entropy` | Shannon entropy over dst-port multiset | same (`_entropy`) |
| `failed_conn_rate` | `ΣRST / window` | `rst / tcp_n` |
| `fwd_psh_rate` | `ΣFwd PSH / window` | `psh / tcp_n` |
| `avg_flow_duration` | clipped mean of `Flow Duration` | mean flow duration (5-tuple table) |

*\*The CICIDS capture carries a degenerate destination-IP field — the port
count is the stable "scanning" proxy.*

### 66 rolling features (offline build and live parity)

For each window-size w ∈ {3,6,12} and each raw column: moving **mean** and
moving **std** (ddof=1) over the past w windows (60 cols), plus
`portcount_slope_w` and `entropy_slope_w` (6 cols, value at t minus value at
t−w). Grouped **per-day** — no cross-day leakage.
**Total: 76 features per window.**

### Forecast label

`y_forecast = 1` when an attack window *starts within the next 6 windows*
(`FORECAST_HORIZON=6`) on the same day. True forecast ("attack is imminent"),
not instant detection. Positive rate ≈ 46%.

### Parity guarantee

The streaming path (`infer.py`'s `RollingFeatureBuilder`) produces the *same*
76 columns as the offline build — measured **~99.4% cell-level identical** on
Friday-DDoS (residual <1% = file-tail window boundaries). See the parity bug
fix history below.

---

## Models

| Model | Cross-day AUC (unseen Fri) | Within-day AUC | Recall @0.5 | Notes |
|---|---|---|---|---|
| Logistic Regression (baseline) | 0.539 | 0.763 | — | mandated baseline |
| RandomForest (400 trees, depth 10, balanced) | **0.763** | **0.838** | 0.235 | deployed forecaster; DP @0.5 = 0.937 |
| **LSTM World Model** (NumPy, no framework) | **0.643** *(0.471)* | 0.544 *(0.700)* | 0.299 | shipped weights; saliency explainable |

- **RF forecaster**: `n_estimators=400, max_depth=10, min_samples_leaf=3,
  class_weight="balanced", random_state=42`. Best cross-day transfer
  performance.
- **LSTM world model**: from-scratch NumPy — forward pass, BPTT, gradient
  clipping (±5), L2 (1e-4), Adam. Input = sequence of 8 raw signals over past
  12 windows → 1 hidden layer (24 units) → binary output. Mini-batch training
  (B=32, no augmentation, 40 epochs) shipped as the improved cross-day model.
  Augmentation tried and rejected (hurt performance — negative result in
  `lstm_improve_summary.json`). Trade-off: improved cross-day AUC (0.471→0.643)
  regressed within-day AUC (0.700→0.544); both numbers documented.
- **Family classifier** (RF, 300 trees): labels *which* known attack. Accuracy
  **0.241** — used only as a weak prior, never a hard verdict.

### Training protocols

- **Cross-day (primary)**: train Mon–Thu, test entirely unseen Friday. The
  honest transfer test.
- **Within-day**: 60/10/30 time-split inside each day. Leak-prone by
  construction (near-duplicate traffic) — upper-bound reference only.
- **Walk-forward CV**: rolling-origin across day-files (6 folds, pooled AUC
  0.722, median fold 0.758). Confirms the Mon→Fri holdout isn't a lucky split.

---

## Evaluation: forecasting quality and lead time

**Forecasting** (`eval_forecasting.py`, unseen Friday, n=1404, 955 attack windows):

- **AUPRC 0.877**
- **Lead time**: Q1 5 / **median 8** / Q3 8 / mean 6.5 windows before first alert
- **Warned**: 373/955 (39.1%) attack windows; false-alarm 3.3% @0.5
- **Per-family**: dos 269/278 (median 8) · botnet 16/92 (median 6) · port_scan **0/351**

| threshold | precision | recall | F1 | alerts |
|---|---|---|---|---|
| 0.3 (tuned operating point) | 0.900 | 0.639 | 0.747 | 678 |
| 0.5 (default) | 0.937 | 0.235 | 0.375 | 239 |
| 0.7 | 0.966 | 0.151 | 0.261 | 149 |

**World-model dynamics** (`world_model_dynamics.py`):
```
from \ to      SAFE    INCOMING    ATTACK
SAFE           2991      21          0      ← attacks never appear from thin air
INCOMING          0      239        147     ← INCOMING is a real precursor
ATTACK           18      126       2101     ← ATTACK self-sustains
```
LSTM next-window attack forecast AUC = **0.814** (n=5555).

**Walk-forward CV** (`walk_forward_cv.py`):

| fold test day | AUC |
|---|---|
| wednesday | 0.849 |
| thursday_web | 0.758 |
| friday_morning | 0.569 |
| friday_portscan | 0.481 |
| friday_ddos | 0.933 |
| **pooled** | **0.722** |

---

## MITRE ATT&CK mapping

`port_scan → Reconnaissance` · `brute_force / web_attack / infiltration /
exploit → Initial Access` · `botnet → Command & Control` · `dos/ddos →`
TA0040 **Impact** (not one of the PS's 5 stages — surfaced as its own
explicitly-labelled bucket rather than being force-mapped). Per-alert MITRE
stage is emitted live by `infer.py`. Kill-chain counts in
`kill_chain_mapping.json`. CAPEC patterns + illustrative CVEs per family
surfaced in the app via `knowledge_base.py`.

---

## Explainability

- **LSTM**: gradient-of-output **saliency** per input feature/timestep
  (from-scratch; SHAP not installable offline). Saved demo: DDoS forecast at
  risk 0.744 driven by `packet_rate` (34%) + `dst_port_entropy`/`unique_dst_ports`
  (~31%) — matches domain intuition for flooding.
- **RandomForest (live)**: **mean-imputation ablation** over the top-6 global
  importances inside each batch (7 `predict_proba` calls per 128-window batch).
  Shows "risk dropped by X when we set `byte_rate` to its batch mean" per
  flagged window.

---

## Novelty / "zero-day" callout (honest scoping)

The supervised models are trained on known, labelled attack families. A
completely new attack **cannot** be "recognised" — the system must say so
instead of silently miscalling it.

`zero_day_callout.py` implements a **novelty callout** on alert windows only:
k-NN (k=5) distance of the alert window's features against the known-attack
manifold (z-scored, baseline from training data). Distance > 95th percentile
of known-attack distances ⇒ **"possible novel activity — analyst review needed"**,
reported beside family-classifier confidence.

- Verified: known attack self-evaluation mean distance 2.4, percentile 0.50,
  5% flagged novel (no false novelty on training data).
- Friday-DDoS live: 52/263 RF alert windows flagged novel (onset windows
  36→47); LSTM: 6/180.

**Wording rule**: never claim "zero-day detection"; say "known attack
progressions" (the actual capability) and "novelty callout for activity unlike
anything in training".

---

## Live ↔ offline feature parity

Two latent bugs were found and fixed:

1. **Window slice bug**: `infer.py`'s streaming `flush_window` computed
   features over the entire in-memory chunk (~20k rows) instead of the exact
   500-row window. Fixed by slicing to the current window.
2. **Rolling-builder bugs**: `RollingFeatureBuilder.row()` never emitted the 10
   raw columns (silently 0.0), and `entropy_slope*` was computed from
   `avg_pkt_size` instead of `dst_port_entropy`. Both fixed.

Post-fix: **440/441 windows bit-identical** at the raw-feature level,
**~99.4% cell-level** across all 76 columns. Live RF/LSTM reproduce the
published offline numbers.

---

## Deployment

### Requirements (`requirements.txt`)
```
numpy
pandas
scikit-learn
streamlit
scapy
fpdf2
```
Left **unpinned** on purpose: pinning `numpy==2.0.2` shipped no py3.14 wheel and
broke the Cloud build (`ModuleNotFoundError` at `pickle.load`). sklearn now loads
1.8 pickles with a harmless `InconsistentVersionWarning`. `fpdf2` powers the SOC
incident PDF report (falls back to `.txt` when absent).

### Community Cloud
1. Push `main` via GitHub Desktop
2. share.streamlit.io → New app → repo `sahooarnav2007-gif/b` → branch `main`
   → file `app.py` → Deploy
3. Verify: Home page + SOC Dashboard (5 tabs — 🔭 Forecaster + 🔬
   Explainability + 🧪 What-If Lab + 🛡 Active Defense + 📜 Forensic Audit) —
   across CSV upload, PCAP upload, RF/LSTM toggle, and the demo artifact
   (Friday DDoS recommended)
4. Free tier sleeps after inactivity (~30–60 s cold start). Upload cap 200 MB.

---

## Known limitations — be upfront with judges before they find them

1. **Family classifier accuracy 0.241** — confusable families; weak prior only,
   novelty callout is the safety valve.
2. **PortScan is a cross-day blind spot (0/351 warned)** — novel-to-model
   attack type; exactly why the novelty callout exists.
3. **LSTM within-day regression** (0.544 vs RF 0.838) — the sequence model
   earns its place via world-model dynamics (§7), high within-day recall, and
   explainability, not by beating RF end-to-end.
4. **Packet path synthetic-only** — no real CICIDS2017 PCAP validated yet.
5. **CAPEC/CVE map is static/illustrative**, not a live NVD feed.
6. **sklearn pickle version-drift** — pinned to 1.8.0 in requirements.txt
   (verified valid across 1.8→1.9, but pinning eliminates the warning).
7. **Brute-force/web/botnet families thin at threshold 0.5** — tuned operating
   point is 0.3 (recall 0.64, precision 0.90).
8. **Novelty callout is advisory** — "unlike everything trained" ≠ "malicious".
   Analysts review; it's not an automated verdict.
9. **Transformer/GNN not attempted** — PS lists them as options; LSTM satisfies
   the requirement; this is a choice, not a gap.

---

## Files

| File | Purpose |
|---|---|
| `full_pipeline.py` | Corpus → windowed feature table (`full_features.csv`) |
| `full_train.py` | RF forecaster + family classifier, dual-protocol eval |
| `lstm_world_model.py` | NumPy LSTM world model (train + eval + saliency) |
| `lstm_improve.py` | Improved cross-day LSTM (batch-32 Adam, 40 epochs) |
| `logreg_baseline.py` | Mandated logistic-regression baseline |
| `mitre_stages_and_explainability.py` | MITRE stage remapping + saliency demo |
| `infer.py` | Streaming live inference (CSV or pre-windowed CSV); snapshots the real `row76` vector on alert windows for What-If |
| `packet_features.py` | PCAP → pre-windowed CSV via Scapy (packet-level path) |
| `active_defense.py` | SOAR tab: MITRE ATT&CK intel, generated firewall rules (iptables/netsh/Cisco ACL), honeypot DNAT simulation |
| `forensics_report.py` | SHA-256 Merkle-chain ledger (tamper-detecting) + SOC incident PDF report (fpdf2) |
| `app.py` | Multi-page entry point (`st.navigation`) → Home + SOC Dashboard |
| `home.py` | Home page: animated threat-arc globe, live eval stats, pipeline diagram, "for judges" metrics panel |
| `dashboard.py` | SOC Dashboard: empty-state CTA + Run Demo, overview strip + risk sparkline, detection quality, incident intelligence, threat-matrix heatmap, timeline scrubber, 5 tabs (Forecaster / Explainability + model comparison / What-If / Active Defense / Forensic Audit) |
| `dataset/demo_friday_ddos_windows.csv` | Committed pre-featurized demo (Friday DDoS, 452 windows) — Run Demo works on a fresh clone |
| `zero_day_callout.py` | Novelty callout (k-NN, advisory) |
| `knowledge_base.py` | CAPEC/CVE enrichment per attack family |
| `eval_forecasting.py` | Forecasting metrics: AUPRC, lead time, per-family |
| `walk_forward_cv.py` | Rolling-origin walk-forward CV (6 folds) |
| `world_model_dynamics.py` | Empirical vs LSTM P(S_{t+1}\|S_t), next-state AUC |
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
| `live_predictor.html` | Interactive browser tool (single-window classifier) |
| `docs/architecture.md` | Detailed master architecture (520 lines) |
| `docs/sih26153_deck.md` | 5-slide presentation deck (Phase 4 deliverable) |

---

## Implementation checklist

### Phase 1 — Streaming inference core ✅
- [x] Chunked CSV streaming → 500-flow windows, rolling 3/6/12 features
- [x] Saves models: RandomForest forecaster + family classifier, NumPy LSTM
- [x] MITRE ATT&CK stage mapping per alert + mean-imputation ablation attribution
- [x] Pre-featurized CSV path (`window_id` + `y_forecast`)
- [x] Verified: full Friday-DDoS file in ~20s

### Phase 2 — Offline demo app ✅
- [x] Upload raw CICIDS flow CSV or pre-featurized window CSV
- [x] RF / LSTM model picker, alert-threshold slider, max-windows option
- [x] Risk timeline chart + alert markers, MITRE stage breakdown, alert table
- [x] AppTest-verified upload flow (no exceptions)

### Phase 3 — Packet-level features ✅
- [x] Scapy `PcapReader` streaming → 500-packet windows, same 10 raw features
- [x] Packet-extras (PS list): TTL, TCP window, fragment/DF, SYN-flood, retrans, protocol mix
- [x] Lightweight 5-tuple flow table (durations, seq/retrans estimate)
- [x] Pre-featurized window CSV consumable by `infer.py` / `app.py`
- [x] Heuristic family/stage for label-less pcaps
- [x] Direct PCAP upload in `app.py`
- [x] Verified on synthetic capture (2020 pkts)

### World-model dynamics & forecasting evidence ✅
- [x] `world_model_dynamics.py` — empirical P(S_{t+1}|S_t) + LSTM next-state AUC 0.814
- [x] `eval_forecasting.py` — AUPRC 0.877, lead-time distribution, per-family
- [x] `walk_forward_cv.py` — rolling-origin CV, pooled AUC 0.722
- [x] `lstm_improve.py` — cross-day LSTM: 0.471 → 0.643
- [x] `knowledge_base.py` — CAPEC/CVE enrichment
- [x] `zero_day_callout.py` — novelty callout (k-NN, advisory)

### Phase 4 — Docs + deck ✅
- [x] `docs/architecture.md` — detailed master architecture (520 lines)
- [x] `docs/sih26153_deck.md` — 5 slides (zero-day wording corrected, innovation callout added)

### Phase 5 — Video + shipping
- [ ] 2-minute demo video: file upload → risk timeline → MITRE stage → attribution
- [x] Multi-page UI: Home hero + overview/dashboard with interactive charts
- [x] README updated, committed, pushed
- [ ] Community Cloud re-verify of tabbed app (needs browser login) + live URL
  → `https://<app>.streamlit.app`
- [ ] Sidebar stack trace verification of `row76` features on pre-featurized path

### Stretch (optional)
- [ ] Real CICIDS2017 PCAP validation of packet path
- [ ] Family-classifier accuracy uplift (0.241)
- [ ] LSTM within-day re-tune (0.544)
- [ ] Live NVD feed for CAPEC/CVE
- [ ] Restore FastAPI as `api.py` (pending decision)

---

## Honest interpretation for judges

**Don't hide the weaknesses — bring them up yourself:**

- On the **within-day split**, LSTM and RF are close on AUC, but **LSTM recall
  0.88 vs RF 0.48** — the sequence model catches far more real attacks at some
  cost to precision. For early-warning, missing an attack is worse than a false
  alarm.
- On the **cross-day holdout**, the LSTM (0.643) generalizes worse than RF
  (0.763). This is a real small-data deep-learning problem (~3,300 training
  sequences); the fix is more training days, not a flawed architecture.
- The LSTM earns its place via **world-model dynamics** (next-state AUC 0.814),
  **explainability** (gradient saliency), and **high within-day recall** — not
  by beating RF on AUC alone.
- The **novelty callout** honestly says "this is unlike anything in training —
  analyst review needed" instead of guessing. It's not zero-day detection;
  it's a safety valve for the unknown.
- The **PortScan blind spot (0/351)** is published, not hidden. It's the
  strongest argument for the novelty callout's existence.

Present both protocols. A team that only shows the flattering split looks like
it's hiding something; a team that shows both and explains the tradeoff looks
like it did real science.

---

## Git & deployment

- **Repo**: `https://github.com/sahooarnav2007-gif/b`
- **Commits on `main`**: all code + models + docs + deck pushed
- **Shipped demo dataset**: `dataset/demo_friday_ddos_windows.csv` (39 KB) is the
  pre-featurized version of the full Friday-DDoS capture — **bit-identical
  pipeline output** (452 windows · 358 alerts · peak risk 1.000 · first alert at
  window 36) so anyone can run the recommended demo from a fresh clone with no
  large downloads. Click **Run Friday DDoS Demo** in the SOC Dashboard.
- **Raw CICIDS2017 CSVs**: git-ignored (too large, ~700 MB total); download from
  UNB to rebuild the full corpus — `demo_friday_ddos_windows.csv` is generated
  from Friday-WorkingHours-Afternoon-DDos via `infer.py`.
- **Community Cloud**: share.streamlit.io → `app.py` on `main`; unpinned deps
  (see Requirements) — sklearn 1.9 loads 1.8 pickles with a harmless
  `InconsistentVersionWarning`
