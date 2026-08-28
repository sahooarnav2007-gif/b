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
```

## Results summary

| Model | Cross-day AUC (unseen Friday) | Within-day AUC (70/30 split) |
|---|---|---|
| Logistic Regression (baseline) | 0.539 | 0.763 |
| RandomForest | 0.765 | 0.832 |
| **LSTM world model** | 0.412 | 0.729 |

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

1. **Packet-level features not implemented.** The PS explicitly wants TTL
   variance, TCP window size, IP fragment flags, retransmission counts —
   these require raw PCAP parsing (Scapy/PyShark), and the CICIDS CSV
   export we have is flow-level only. Fix: download PCAP files from the
   same CICIDS2017 release and extract these with Scapy.
2. **No upload-and-infer demo app.** Everything here runs from the command
   line against pre-loaded CSVs. The PS wants a Streamlit/Flask/CLI tool
   that accepts a new PCAP/CSV and runs live inference. This is a
   half-day build on top of what exists (the LSTM/RF are already trained
   and saved — `lstm_weights.json` — so inference code just needs wiring
   to a file-upload interface).
3. **Transformer/GNN not attempted** — PS lists LSTM/Transformer/GNN as
   options, LSTM satisfies the requirement, this isn't a gap, just noting
   we picked one valid option rather than doing all three.
4. **No CAPEC/CVE-NVD integration** — the NCIIPC note mentions these as
   available knowledge bases; we've only used MITRE ATT&CK so far.

## Files

- `full_pipeline.py` — loads all 8 real CICIDS2017 files, windows to 500-flow
  buckets, computes features, maps attack labels
- `full_train.py` — RandomForest forecaster + attack-family classifier,
  both cross-day and within-day evaluation
- `lstm_world_model.py` — **the world model**: from-scratch NumPy LSTM
  (forward pass, BPTT, Adam optimizer, early stopping, saliency/explainability)
- `logreg_baseline.py` — required baseline comparison
- `mitre_stages_and_explainability.py` — kill-chain stage remapping + saliency demo
- `live_predictor.html` — interactive browser tool (single-window classifier,
  drag sliders / preset scenarios, runs a real exported RandomForest client-side)
- `full_features.csv` / `full_features_with_stages.csv` — engineered dataset
- `*_summary.json` — evaluation results for each model
- `lstm_weights.json` — trained LSTM weights (reload with `NumpyLSTM` class
  in `lstm_world_model.py` for inference without retraining)

## Recommended next steps, in priority order

1. Build the upload-and-infer demo app (Streamlit is fastest) — this is
   an explicit, named deliverable, don't skip it.
2. Add packet-level features via Scapy on a PCAP subset — even a partial
   implementation (TTL variance alone) is worth having.
3. Write the 2-page architecture document and 5-slide deck the PS asks for.
4. Record the 2-minute demo video showing: file upload → risk timeline →
   MITRE stage prediction → saliency explanation.
