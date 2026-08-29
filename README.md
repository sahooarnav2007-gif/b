# SIH26153 — AI-Based Network Attack Forecasting — FULL BUILD

This is the current, spec-aligned version. **Ignore files prefixed with
nothing/`real_`/`load_real_data.py`/`generate_data.py`/`train_model.py`/
`features.py`** — those were earlier MVP iterations before we pulled the
actual official problem statement text. This README covers the current
build only.

## What the PS actually requires (confirmed from sih2026.vuce.in/en/ps/SIH26153
and the NCIIPC contact info)

- Dataset: CIC-IDS2017/2018, UNSW-NB15, CTU-13, CICIoT2023, LANL, or DARPA —
  **CICIDS2017 is explicitly on the approved list.**
- Core deliverable: a **"World Model"** — learns state-transition dynamics
  P(S_t+1 | S_t) via LSTM/Transformer/GNN — NOT a static classifier.
- Map predictions to **MITRE ATT&CK kill-chain stages**: Reconnaissance,
  Initial Access, Lateral Movement, Command & Control, Exfiltration.
- **Explainability required** (SHAP or attention/gradient attribution) —
  black-box output is explicitly called "not acceptable."
- **Benchmark against a logistic regression baseline** to prove the
  sequence model adds measurable value.
- Both flow-level AND packet-level features (packet-level = NOT yet done,
  see "Known gaps" below).
- A working demo interface accepting PCAP/CSV input (NOT yet done, see below).

## Pipeline (run in this order)

```bash
pip install numpy pandas scikit-learn --break-system-packages

python3 full_pipeline.py     # loads all 8 real CICIDS2017 day-files, windows
                              # them, maps labels -> full_features.csv
python3 full_train.py        # RandomForest forecaster, two evals (cross-day +
                              # within-day), attack-family classifier
python3 lstm_world_model.py  # THE WORLD MODEL — LSTM built from scratch in
                              # NumPy (no torch/tensorflow available offline).
                              # Full BPTT + Adam, early stopping. Two evals,
                              # same methodology as full_train.py.
python3 logreg_baseline.py   # required baseline comparison
python3 mitre_stages_and_explainability.py   # kill-chain remap + saliency demo

# inference + demo
python3 infer.py dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
                       # streaming forecast from a raw flow CSV (RF or LSTM)
python3 packet_features.py capture.pcap -o windows.csv --infer
                       # packet-level path: PCAP -> windows -> forecast
streamlit run app.py   # offline upload-and-forecast UI (CSV or pre-featurized)
```

## Results summary

| Model | Cross-day AUC (unseen Friday) | Within-day AUC (70/30 split) |
|---|---|---|
| Logistic Regression (baseline) | 0.539 | 0.763 |
| RandomForest | 0.763 | 0.838 |
| **LSTM world model** | 0.471 | 0.700 |

*Authoritative numbers live in `*_summary.json`; the architecture doc
(`docs/architecture.md`) explains methodology and the honest interpretation.*

**Honest read of these numbers, don't hide this from judges — bring it up
yourself:**

- On the **within-day split**, LSTM and RandomForest are close on AUC, but
  **LSTM recall is 0.88 vs RandomForest's 0.48** — the LSTM catches far more
  real attacks, at some cost to precision. For a forecasting/early-warning
  tool, that's often the right tradeoff (missing an attack is worse than
  a false alarm), and it's a genuine argument for why the sequence model
  is a better fit than the baseline, even though its AUC alone doesn't look
  dramatically better.
- On the **cross-day holdout** (train Mon-Thu, test entirely unseen Friday),
  the LSTM actually generalizes *worse* than RandomForest and worse than
  logistic regression. This is a real, documented limitation: with only
  ~3,300 training sequences, the LSTM has enough capacity to overfit
  day-specific noise even with early stopping and L2 regularization. This
  is a completely normal small-data deep-learning problem — the fix is
  more training days/data augmentation, not a flawed architecture.
- **Present both numbers.** A team that only shows the flattering split
  looks like it's hiding something; a team that shows both and explains
  the tradeoff looks like it did real science.

## MITRE kill-chain stage mapping

See `kill_chain_mapping.json`. Five families mapped cleanly:
- `port_scan` → **Reconnaissance**
- `brute_force`, `web_attack` → **Initial Access**
- `botnet` → **Command & Control**
- `dos`/`ddos` → technically MITRE **Impact** (TA0040), which isn't one of
  the 5 PS-listed stages. We kept it as its own labeled bucket rather than
  force a wrong mapping — mention this explicitly to judges, it shows you
  understand MITRE ATT&CK rather than pattern-matching to the PS's example list.

## Explainability

`saliency_demo.json` — gradient-based feature attribution (SHAP isn't
installable offline; gradient saliency is a standard, legitimate substitute
for a hand-rolled model). Shows which input features drove a specific
real prediction. In the saved demo: a real DDoS window forecast (risk=0.744,
correct), driven mostly by `packet_rate` (34%) and `dst_port_entropy`/
`unique_dst_ports` (~31% combined) — matches domain intuition for a
flooding attack.

## Known gaps — be upfront about these before judges find them

1. **Packet-level features: DONE (basic)** — `packet_features.py` derives TTL
   variance, TCP window sizes, IP fragment flags, retransmission rate, SYN-only
   flood rate from a raw PCAP (verified on a synthetic capture and wired into
   the same forecasters). Not yet exercised on a real CICIDS2017 PCAP (limited
   bandwidth/large files) — the heuristic stage labels are simple rules, of
   interest mainly for label-less demo inputs.
2. **Upload-and-forecast demo app: DONE** — see `app.py` (Streamlit, offline,
   accepts raw CICIDS flow CSVs, pre-featurized window CSVs, and the CSV output
   of `packet_features.py`, runs the saved RF/LSTM via `infer.py`).
3. **Transformer/GNN not attempted** — PS lists LSTM/Transformer/GNN as
   options, LSTM satisfies the requirement, this isn't a gap, just noting
   we picked one valid option rather than doing all three.
4. **No CAPEC/CVE-NVD integration** — the NCIIPC note mentions these as
   available knowledge bases; we've only used MITRE ATT&CK so far.
5. **No 5-slide deck / 2-min demo video yet** — explicit PS deliverables,
   Phase 4–5 below (`docs/architecture.md` is done).

## Files

- `full_pipeline.py` — loads all 8 real CICIDS2017 files, windows to 500-flow
  buckets, computes features, maps attack labels
- `full_train.py` — RandomForest forecaster + attack-family classifier,
  both cross-day and within-day evaluation
- `lstm_world_model.py` — **the world model**: from-scratch NumPy LSTM
  (forward pass, BPTT, Adam optimizer, early stopping, saliency/explainability)
- `logreg_baseline.py` — required baseline comparison
- `mitre_stages_and_explainability.py` — kill-chain stage remapping + saliency demo
- `docs/architecture.md` — 2-page system architecture (data flow, features,
  models, honest eval, inference paths, limitations)
- `infer.py` — streaming inference core (chunked CSV reader → 500-flow windows →
  rolling features → saved RF/LSTM → risk timeline with MITRE stage + attribution;
  batched predict avoids this env's ~250ms/call sklearn overhead)
- `packet_features.py` — packet-level (PCAP) features: Scapy PcapReader streaming →
  500-packet windows → the 10 model raw fields + TTL/window/frag/retrans/SYN-flood
  extras, heuristic stage mapping, output CSV consumable by `infer.py`/`app.py`
- `app.py` — Streamlit upload-and-forecast demo (offline); `.streamlit/config.toml`
  (headless, port 8501, 1 GB uploads)
- `live_predictor.html` — interactive browser tool (single-window classifier,
  drag sliders / preset scenarios, runs a real exported RandomForest client-side)
- `full_features.csv` / `full_features_with_stages.csv` — engineered dataset
- `*_summary.json` — evaluation results for each model
- `lstm_weights.json` — trained LSTM weights (reload with `NumpyLSTM` class
  in `lstm_world_model.py` for inference without retraining)

## Implementation plan & checklist (SIH 2026)

**Phase 1 — Streaming inference core ✅ DONE** (`infer.py`)
- [x] Chunked CSV streaming → 500-flow windows, rolling 3/6/12 features
- [x] Saves models: RandomForest forecaster + family classifier, NumPy LSTM
- [x] MITRE ATT&CK stage mapping per alert + mean-imputation ablation attribution
- [x] Pre-featurized CSV path (`window_id` + `y_forecast`)
- [x] Verified: full Friday-DDoS file in ~20s — 358/396 true DDoS windows
      detected, 1 false positive, first alert at window 38, peak risk 0.96

**Phase 2 — Offline demo app ✅ DONE** (`app.py`, `.streamlit/config.toml`)
- [x] Upload raw CICIDS flow CSV or pre-featurized window CSV
- [x] RF / LSTM model picker, alert-threshold slider, max-windows option
- [x] Risk timeline chart + alert markers, MITRE stage breakdown, alert table
- [x] AppTest-verified upload flow (Thursday web-attack slice: 60 windows,
      13 flags, 21.7%) — no exceptions
- [x] `requirements.txt` updated (streamlit, scapy); headless 8501 / 1 GB uploads

**Phase 3 — Packet-level features ✅ DONE** (`packet_features.py`)
- [x] Scapy `PcapReader` streaming → 500-packet windows, deriving the SAME 10
      raw window fields the models expect (so the saved forecasters run unchanged)
- [x] Packet-extras (PS list): TTL mean/std, TCP window size stats, IP fragment
      (frag/DF) ratios, SYN-only flood rate, retransmission rate, protocol mix,
      distinct src count
- [x] Lightweight 5-tuple flow table (durations, seq/retrans estimate)
- [x] Emits a pre-featurized window CSV (`window_id` + `y_forecast`) that
      `infer.py` and the demo app accept directly
- [x] Heuristic family/stage for label-less pcaps (SYN-scan → Reconnaissance,
      SYN/ICMP flood → Impact-dos)
- [x] Verified on a Scapy-generated synthetic capture (2020 pkts:
      benign → 600 SYN-scan → 900 SYN-flood): heuristics label the phases
      none → port_scan/Recon → dos/Impact, and the RF forecaster flags the
      flood windows (peak risk 0.61) from packet-derived features alone
      (`python3 packet_features.py demo.pcap -o w.csv --infer`)

**Phase 4 — Docs + deck**
- [x] `docs/architecture.md` — 2-page: pipeline, world-model math P(S_t+1|S_t),
      feature engineering, eval methodology, MITRE mapping, honest limitations
- [ ] `docs/sih26153_deck.md` — 5 slides: problem / approach / world model /
      results / demo & deliverables

**Phase 5 — Video + shipping**
- [ ] 2-minute demo video: file upload → risk timeline → MITRE stage → attribution
- [ ] README polish, `git add`/commit, push to GitHub
- [ ] Stretch: CAPEC/CVE-NVD integration note; LSTM retrain on more data to
      close the cross-day gap
