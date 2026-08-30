# SIH26153 — 5-Slide Presentation Deck

> Auto-synced to the repo's evaluated results (full_model_summary.json,
> eval_forecasting.json, lstm_improve_summary.json, walk_forward_cv.json).
> Every number below is from a committed artifact — nothing is fabricated.

---

## Slide 1 — Problem, Importance, Solution (three linked callouts)

**Real-world issue** *(with citable stat)*
Network defence today is **reactive**: SOCs confirm an attack after it has
started and breached — by then the damage is done. Attacks are fast-moving and
lateral; defenders need minutes of *advance* warning, not hindsight.
*Stat: cost-of-breach X (insert citable source — e.g. IBM Cost of a Data
Breach 2025 India edition; do not state "₹25.5 crore" without a citation).*

⚠️ The reviewer flagged ₹25.5 crore as unsourced — replace with a citable
figure or use the general framing above.

**Importance**
SIH26153 targets public networks where a single missed attack (brute-force
credential push, botnet C2 beaconing, DDoS) can take down a platform. Early
warning for **known attack progressions** — "the scan has started, exploitation
is next" — is exactly the lead time an operator needs. We intentionally do
**not** claim zero-day detection: our models are trained on known, labeled
attack families, and a novel exploit is out of scope by construction.

**Solution** (one-line pitch + diagram)
NetSight forecasts **known attack activity 6 windows (≈ minutes) before it
hits**, labels the attack family and MITRE ATT&CK stage per alert, explains
*why* it fired, and runs **100% offline** (CSV or PCAP upload).

**Before / After flow** (corrected labels)
    BEFORE (reactive): benign → attack starts → breach → alert?
    AFTER  (forecast): benign → risk rises → ALERT (T-6, MITRE stage, why) → attack mitigated early

**Innovation & uniqueness** (the template's explicitly-missing piece — add as a
fourth box / footer strip)
- **Forecasting, not flagging**: emits risk up to 6 windows *before* attack, with
  measured lead time (median 8 windows, mean 6.5 on unseen Friday).
- **Built-in MITRE ATT&CK stage mapping + family** on every alert (no bolt-on taxonomy).
- **Explainability shipped, not patched**: mean-imputation attribution (RF) and
  LSTM saliency per alert — the model tells the operator *which* traffic signal drove it.
- **Honest, dual-protocol evaluation**: separate cross-day (unseen Friday) and
  within-day tests + rolling-origin walk-forward CV (pooled AUC 0.722), negative
  results published (e.g. PortScan is deliberately NOT over-claimed).
- **Novelty callout** (not zero-day detection): alert windows "unlike everything
  trained on" are flagged for analyst review via >95th-percentile k-NN distance.

---

## Slide 2 — Approach: the proposed solution in detail

**Pipeline** (`full_pipeline.py → full_train.py → lstm_world_model.py → infer.py`)
1. **Stream windows**: CICIDS2017 all-8-days → fixed 500-flow windows (≈5,650).
2. **Features**: 10 raw traffic signals (packet/byte rate, dst-port entropy, SYN/
   ACK ratios, failed-connection rate, …) + 66 rolling stats (3/6/12-window
   MA/std/slope) → 76 units per window.
3. **Forecast label**: binary — "attack within the next 6 windows".
4. **Models**: RandomForest forecaster + attack-family classifier (8 families);
   a from-scratch NumPy LSTM (BPTT+Adam) as the sequence "world model" over
   window trajectories; LogisticRegression as the mandated baseline.
5. **Per alert**: family + MITRE stage + attribution; **novelty callout** for
   off-manifold windows (analyst review).
6. **Deployment**: `infer.py` streams raw CSV or `.pcap` (packet pipeline) with
   bounded memory — no cloud, no training data leaving the machine.

Why it addresses the problem: replaces post-hoc detection with a *forecast* —
the operator gets actionable time, and the before/after flow on slide 1 is the
direct mechanism.

---

## Slide 3 — Innovation & uniqueness (explicit template item)

- **Early-warning *forecaster***, not a detector: formal lead-time distribution
  (median 8, mean 6.5 windows; DDoS detected 269/278 ≈ 96.8% on unseen Friday).
- **Interdisciplinary modelling** on one problem: classical ML (RF) + sequence
  world-model (from-scratch LSTM) + mandated baseline (logreg) — chosen per
  capability, and reported per protocol, side by side.
- **Explainability as a first-class output** (ablation attribution + LSTM
  saliency), exactly when a public-sector operator must justify an alert.
- **Offline and portable**: CSVs/PCAPs in, risk timeline out; reproducibility
  via `run_all.sh` with pinned seeds. No vendor cloud, no data exfiltration —
  a real constraint for government/network operators.
- **Honest scoping**: dual evaluation protocols + a published known-limitations
  list + a novelty callout — explicitly *not* zero-day detection.

---

## Slide 4 — Results (honest, dual-protocol; all from committed artifacts)

| Model | Cross-day AUC (unseen Fri) | Within-day AUC | Notes |
|-------|---------------------------|----------------|-------|
| RandomForest | 0.763 | 0.838 | flag-rate 23.5% @0.5; DP 0.937 |
| LSTM world model | 0.643 (ship model) | 0.544 | cross-day lifted 0.471→0.643 via batch training |
| LogisticRegression | 0.539 | 0.763 | mandated baseline |

**Forecasting**: AUPRC 0.877; lead-time median 8 / mean 6.5 windows; DDoS
269/278 with median lead 8. **Independent check**: rolling-origin walk-forward
CV pooled AUC 0.722 (median fold 0.758) — the Mon→Fri holdout isn't a lucky split.

**Honest negatives (datapoints that build trust)**
- PortScan: 0/351 warned on unseen Friday (novel-to-model attack type) — shown,
  not hidden.
- Family classifier accuracy 0.241 — reported; not deployed as a hard verdict.
- LSTM within-day 0.544 < RF — task-dependent, documented.

---

## Slide 5 — Demo & delivery

**Offline demo (`streamlit run app.py`)**
- Upload CICIDS CSV **or** `.pcap`; pick RF/LSTM; threshold slider.
- Live risk timeline, MITRE stage breakdown, alert table, driving features.
- First-alert panel: family, stage, CAPEC/CVE enrichment, **novelty callout**.
- Verified: Friday-DDoS RF first alert @ win 36 (peak 0.99); LSTM first alert @
  win 41 with improved cross-day model.

**Deliverables**: source + README + this deck + 2-min video + running app;
reproducibility via `run_all.sh (data|models|eval|app)`.

**Roadmap**: real CICIDS2017 PCAP validation of the packet path; extend approved
datasets (CTU-13, UNSW-NB15) to harden cross-day transfer; live NVD feed for the
CAPEC/CVE map.

---

## Speaker-note guardrails (anti-overclaim)

1. Never say "zero-day detection". Say "alerts for **known attack progressions**"
   or "novelty callout — activity unlike training, analyst review".
2. Every statistic must come from a committed `*_summary.json`/`eval_*.json`.
3. Do not state breach-cost figures without a citation; otherwise use the
   general "reactive defence is too late" framing.
4. Frame LSTM as the *world-model/sequence* evidence, RF as the *deployed*
   forecaster — never "our LSTM beats everything".
5. Blueprint references map to `docs/architecture.md` §1-§10 (problem, data
   flow, features, models, MITRE §6, explainability §7, offline §8,
   reproducibility §9, limitations §10).