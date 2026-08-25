# SIH26153 — AI-Based Network Attack Forecasting — MVP

## What this is
A working forecasting pipeline (not detection): predicts whether an attack
will occur in the NEXT 6 traffic windows, using precursor/recon patterns +
a mock threat-intel feed, and mapping predicted attacks to MITRE ATT&CK
techniques.

## Run order
```bash
pip install numpy pandas scikit-learn matplotlib
python3 generate_data.py     # synthetic traffic + threat intel + attack episodes
python3 features.py          # rolling-window features + forward-looking labels
python3 train_model.py       # trains RandomForest, evaluates, computes lead-time metric
```
Then open `dashboard.html` in a browser — it's self-contained (data is embedded inline).

## Files
- `generate_data.py` — synthetic traffic generator with realistic attack buildup
  (recon/scan precursor -> actual attack), plus mock threat-intel feed (known-bad
  IPs tagged with MITRE techniques)
- `features.py` — rolling-window feature engineering (3/6/12-window stats,
  slopes) + threat-intel correlation + FORWARD-LOOKING forecast labels
  (y[t] = attack within next 6 windows, not "is t itself an attack")
- `train_model.py` — RandomForest classifier, time-based train/test split,
  computes the key forecasting metric: average lead time (windows of advance
  warning before real attacks)
- `dashboard.html` — SOC-style console: risk timeline showing the model's
  score climbing before a real attack, full test-set overview, feature
  importance, MITRE breakdown, threat intel sample
- `traffic.csv`, `threat_intel.csv`, `episodes.csv` — generated data
- `features.csv` — engineered feature set
- `predictions.csv` — model outputs on the test set
- `model_summary.json`, `feature_importance.csv` — evaluation results

## Current result (synthetic data, offline dev environment)
- ROC-AUC: 1.0 | Precision: 1.0 | Recall: 0.98
- 33/33 test-set attacks caught with advance warning
- Average lead time: ~6.8 windows (~3.4 min at 30s/window) before attack onset

Note: this near-perfect score reflects clean synthetic signal. Swap in a real
dataset (CICIDS2017/2018, UNSW-NB15) for the actual SIH submission — expect
noisier, more realistic numbers, which is fine and expected.

## Next steps for the full submission
1. Replace synthetic generator with real CICIDS2017/UNSW-NB15 flow data
2. Add an LSTM/Transformer sequence model to compare against the RandomForest baseline
3. Wire in a real threat-intel API (AbuseIPDB / AlienVault OTX free tier)
4. Add live-stream simulation (replay traffic at real time speed) for the demo

---

## UPDATE: Real CICIDS2017 data run

Ran the same forecasting approach on the real **CICIDS2017 Friday-Afternoon-DDoS**
capture (225,711 real network flows, 56.7% attack traffic).

### Run order (after generate_data.py's synthetic files already exist)
```bash
# 1. Put the CICIDS CSV at: cicids_raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
#    (update RAW_FILE path in load_real_data.py if yours is elsewhere)
python3 load_real_data.py     # buckets 500 real flows per "window", builds traffic_real.csv
python3 real_features.py      # rolling-window features + forecast labels -> features_real.csv
python3 real_train_model.py   # trains + evaluates -> predictions_real.csv, model_summary_real.json
```
Then open `real_dashboard.html` (self-contained, real data embedded).

### Real-data results (honest, not overfit to clean synthetic signal)
- ROC-AUC: **0.936** | Precision: 0.74 | Recall: 0.99 | F1: 0.85
- 55/55 test-set attack windows caught with advance warning (100% detection)
- Average lead time: **7.5 windows** (each window = 500 flows) before attack onset

### Important differences from the synthetic run
- **No timestamp column** in this CICIDS export — flows are in capture order,
  so windows are bucketed by flow-count (500 flows/window), not wall-clock time.
  If you get a version with timestamps, switch to time-based windowing for a
  more realistic "X minutes of lead time" claim.
- **No source-IP column** in this export — threat-intel IP correlation is
  stubbed to 0 for this run. If your SIH submission needs that feature working,
  use a CICIDS2017 distribution that retains IP addresses (check the PCAP-derived
  GeneratedLabelledFlows version on the official UNB site), or add a synthetic
  IP-tagging layer back in.
- **Single attack type** (DDoS) in this capture — precision is lower (0.74)
  than the synthetic run because real traffic has natural noise the model
  sometimes misreads as pre-attack buildup. This is realistic and defensible —
  call it out to judges as an accuracy/coverage tradeoff, and mention that
  training on more CICIDS days (Tuesday brute-force, Wednesday DoS, Thursday
  web attacks/infiltration) would let the model learn multiple attack signatures.

### To go further before submission
1. Download the other 7 CICIDS2017 day-files (Monday–Thursday, other Friday
   captures) and concatenate them through `load_real_data.py` for multi-attack-type
   training — this also lets you rebuild the MITRE ATT&CK breakdown table.
2. Add an LSTM/GRU sequence model and compare against this RandomForest baseline.
3. If you find a CICIDS variant with timestamp + source IP columns, switch
   windowing to real time-based buckets and re-enable threat-intel correlation.
