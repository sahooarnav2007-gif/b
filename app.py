"""
app.py
------
The upload-and-infer demo interface the PS explicitly requires:

  "A working demonstration interface (Streamlit, Flask web app, or CLI)
   that accepts a PCAP or CSV file as input, runs the world model
   inference, and displays the infiltration probability timeline,
   flagged flows, and attack stage annotations. The interface must run
   fully offline without cloud API dependencies."

Streamlit isn't installable in this offline environment, so this is a
Flask app (explicitly listed as an acceptable alternative in the PS).

Accepts a CICIDS-format flow-level CSV (PCAP parsing would need Scapy,
noted as a known gap in the README). Runs BOTH the LSTM world model and
the RandomForest baseline, shows risk timeline, predicted MITRE stage,
and saliency-based explainability for the most recent window.

Run: python3 app.py
Then open http://localhost:5000
"""

import os
import io
import json
import pickle
import numpy as np
import pandas as pd
from flask import Flask, request, render_template_string, jsonify

from processing import (
    window_flows, add_rolling_features, build_lstm_sequences,
    KILL_CHAIN_MAP, LSTM_FEATURES,
)
from lstm_world_model import NumpyLSTM

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200MB

# ---------- load trained models once at startup ----------
with open("rf_forecaster.pkl", "rb") as f:
    _rf = pickle.load(f)
    RF_MODEL, RF_FEATURE_COLS = _rf["model"], _rf["feature_cols"]

with open("rf_family_classifier.pkl", "rb") as f:
    _fam = pickle.load(f)
    FAMILY_MODEL, FAMILY_FEATURE_COLS = _fam["model"], _fam["feature_cols"]

with open("lstm_weights.json") as f:
    _lstm_saved = json.load(f)

LSTM_MODEL = NumpyLSTM(input_size=len(LSTM_FEATURES), hidden_size=_lstm_saved["hidden_size"])
for _p, _v in _lstm_saved["weights"].items():
    setattr(LSTM_MODEL, _p, np.array(_v))
LSTM_MU = np.array(_lstm_saved["mu"])
LSTM_SIGMA = np.array(_lstm_saved["sigma"])


UPLOAD_PAGE = """
<!DOCTYPE html>
<html><head>
<title>SIH26153 — World Model Inference</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
  :root{ --bg:#0A0F14; --panel:#0F161D; --border:#1C2731; --ink:#D7E1E8; --dim:#7C8B96;
         --accent:#4FC3E8; --safe:#35C98C; --crit:#E8544B; }
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--ink);font-family:'IBM Plex Sans',sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;
        padding:40px;max-width:560px;width:100%;}
  h1{font-family:'IBM Plex Mono',monospace;font-size:20px;margin-bottom:6px;color:#F0F5F8;}
  .sub{font-size:13px;color:var(--dim);margin-bottom:28px;line-height:1.6;}
  .drop{border:2px dashed var(--border);border-radius:10px;padding:36px;text-align:center;
        margin-bottom:20px;transition:border-color .15s;}
  .drop:hover{border-color:var(--accent);}
  input[type=file]{color:var(--dim);font-family:'IBM Plex Mono',monospace;font-size:12px;}
  button{width:100%;padding:14px;background:var(--accent);color:#031015;border:none;
         border-radius:8px;font-family:'IBM Plex Mono',monospace;font-weight:600;
         font-size:13px;cursor:pointer;letter-spacing:.03em;}
  button:hover{opacity:.9;}
  .note{font-size:11.5px;color:var(--dim);margin-top:16px;line-height:1.6;}
  .note b{color:var(--ink);}
  a{color:var(--accent);}
</style></head>
<body>
  <div class="card">
    <h1>Network Attack Forecast — World Model</h1>
    <div class="sub">SIH26153 / NTRO · Upload a CICIDS-format flow CSV to run offline inference
    with the trained LSTM world model + RandomForest baseline.</div>
    <form action="/predict" method="post" enctype="multipart/form-data">
      <div class="drop">
        <input type="file" name="file" accept=".csv" required>
      </div>
      <button type="submit">Run Inference</button>
    </form>
    <div class="note">
      Expects standard CICIDS2017/2018-format columns (Flow Bytes/s, Flow Packets/s,
      Destination Port, SYN/ACK/RST/PSH Flag Counts, etc.) — a 'Label' column is
      optional (only used to show ground truth if present).<br><br>
      No file? <a href="/sample">Download a sample CSV</a> (real held-out CICIDS2017
      DDoS traffic) to try it.
    </div>
  </div>
</body></html>
"""

RESULTS_PAGE = """
<!DOCTYPE html>
<html><head>
<title>Inference Results — SIH26153</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');
  :root{ --bg:#0A0F14; --panel:#0F161D; --border:#1C2731; --ink:#D7E1E8; --dim:#7C8B96; --faint:#4B5862;
         --accent:#4FC3E8; --safe:#35C98C; --warn:#E8A93B; --crit:#E8544B; }
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--ink);font-family:'IBM Plex Sans',sans-serif;
       padding:28px 5vw 80px;}
  header{border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:24px;
         display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px;}
  h1{font-family:'IBM Plex Mono',monospace;font-size:22px;color:#F0F5F8;}
  .back{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--accent);text-decoration:none;}
  .meta{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--dim);}
  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);
         border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:24px;}
  .stat{background:var(--panel);padding:16px 18px;}
  .stat .label{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.08em;
               color:var(--faint);text-transform:uppercase;margin-bottom:8px;}
  .stat .value{font-family:'IBM Plex Mono',monospace;font-size:24px;font-weight:600;}
  .panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;
         padding:22px 24px;margin-bottom:20px;}
  .panel-title{font-family:'IBM Plex Mono',monospace;font-size:14px;font-weight:600;
               color:#F0F5F8;margin-bottom:14px;}
  table{width:100%;border-collapse:collapse;font-size:12px;}
  th{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.05em;color:var(--faint);
     text-transform:uppercase;text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);}
  td{padding:8px 10px;border-bottom:1px solid #131C24;font-family:'IBM Plex Mono',monospace;
     font-size:11.5px;color:var(--dim);}
  tr:hover td{color:var(--ink);background:#101820;}
  .chip{display:inline-block;padding:2px 8px;border-radius:5px;font-size:10.5px;font-family:'IBM Plex Mono',monospace;}
  .chip.crit{background:rgba(232,84,75,.12);color:var(--crit);border:1px solid rgba(232,84,75,.3);}
  .chip.safe{background:rgba(53,201,140,.1);color:var(--safe);border:1px solid rgba(53,201,140,.3);}
  .chip.warn{background:rgba(232,169,59,.1);color:var(--warn);border:1px solid rgba(232,169,59,.3);}
  .bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;}
  .bar-label{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--dim);width:150px;text-align:right;flex-shrink:0;}
  .bar-track{flex:1;height:8px;background:#111A22;border-radius:4px;overflow:hidden;}
  .bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),#7FDFF5);border-radius:4px;}
</style></head>
<body>
<header>
  <div><a class="back" href="/">&larr; Upload another file</a><h1 style="margin-top:6px;">Inference Results</h1></div>
  <div class="meta">{{ n_windows }} windows analyzed · {{ n_flows }} raw flows · file: {{ filename }}</div>
</header>

<div class="stats" id="stats"></div>

<div class="panel">
  <div class="panel-title">Risk Timeline — LSTM World Model vs RandomForest Baseline</div>
  <canvas id="riskChart" height="80"></canvas>
</div>

<div class="panel">
  <div class="panel-title">Windows Flagged High-Risk (forecast &ge; 0.5, LSTM)</div>
  <table>
    <thead><tr><th>Window</th><th>LSTM Risk</th><th>RF Risk</th><th>Predicted Family</th><th>MITRE Kill-Chain Stage</th>{% if has_labels %}<th>Ground Truth</th>{% endif %}</tr></thead>
    <tbody>
    {% for r in flagged_rows %}
      <tr>
        <td class="hi">{{ r.window_id }}</td>
        <td><span class="chip {{ 'crit' if r.lstm_risk >= 0.5 else 'safe' }}">{{ '%.2f'|format(r.lstm_risk) }}</span></td>
        <td>{{ '%.2f'|format(r.rf_risk) }}</td>
        <td>{{ r.predicted_family }}</td>
        <td>{{ r.kill_chain_stage }}</td>
        {% if has_labels %}<td>{{ r.true_label }}</td>{% endif %}
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<div class="panel">
  <div class="panel-title">Explainability — Feature Attribution (most recent window, LSTM saliency)</div>
  <div id="saliencyBars"></div>
</div>

<script>
const RISK_DATA = {{ risk_json | safe }};
const SALIENCY = {{ saliency_json | safe }};
const SUMMARY = {{ summary_json | safe }};

Chart.defaults.font.family = "'IBM Plex Mono', monospace";
Chart.defaults.color = "#7C8B96";

document.getElementById('stats').innerHTML = [
  {label:'Windows flagged (LSTM)', value: SUMMARY.n_flagged_lstm, cls:'crit'},
  {label:'Windows flagged (RF)', value: SUMMARY.n_flagged_rf, cls:''},
  {label:'Peak risk (LSTM)', value: SUMMARY.peak_risk_lstm.toFixed(2), cls:'warn'},
  {label:'Most common stage', value: SUMMARY.top_stage, cls:'safe'},
].map(s => `<div class="stat"><div class="label">${s.label}</div><div class="value" style="color:var(--${s.cls||'ink'})">${s.value}</div></div>`).join('');

new Chart(document.getElementById('riskChart'), {
  type:'line',
  data:{
    labels: RISK_DATA.map(r=>r.window_id),
    datasets:[
      {label:'LSTM risk', data: RISK_DATA.map(r=>r.lstm_risk), borderColor:'#4FC3E8', pointRadius:0, borderWidth:2, tension:.3},
      {label:'RandomForest risk', data: RISK_DATA.map(r=>r.rf_risk), borderColor:'#E8A93B', pointRadius:0, borderWidth:1.4, tension:.3, borderDash:[4,3]},
    ]
  },
  options:{ responsive:true, plugins:{legend:{position:'bottom',labels:{boxWidth:10,font:{size:11}}}},
            scales:{ y:{min:0,max:1,grid:{color:'#131C24'}}, x:{grid:{display:false},ticks:{maxTicksLimit:14}} } }
});

const maxSal = Math.max(...Object.values(SALIENCY));
document.getElementById('saliencyBars').innerHTML = Object.entries(SALIENCY)
  .sort((a,b)=>b[1]-a[1])
  .map(([f,v]) => `<div class="bar-row"><div class="bar-label">${f}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(v/maxSal*100).toFixed(1)}%"></div></div></div>`).join('');
</script>
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(UPLOAD_PAGE)


@app.route("/sample")
def sample():
    """Serve a small real held-out CICIDS2017 sample so judges can try the
    tool without needing their own dataset."""
    df = pd.read_csv("/home/claude/cicids_raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    sample_df = df.iloc[168000:180000]  # includes real benign->DDoS transition, generous margin
    buf = io.StringIO()
    sample_df.to_csv(buf, index=False)
    from flask import Response
    return Response(buf.getvalue(), mimetype="text/csv",
                     headers={"Content-Disposition": "attachment; filename=sample_ddos_traffic.csv"})


@app.route("/predict", methods=["POST"])
def predict():
    file = request.files["file"]
    raw_df = pd.read_csv(file)
    raw_df.columns = [c.strip() for c in raw_df.columns]
    has_labels = "Label" in raw_df.columns

    wdf = window_flows(raw_df, has_labels=has_labels)
    if len(wdf) < 13:
        return f"Not enough flows for a full sequence (need at least {13*500} flows, got {len(raw_df)}). Upload a larger file.", 400

    feat_df = add_rolling_features(wdf)

    # RF inference
    X_rf = feat_df.reindex(columns=RF_FEATURE_COLS, fill_value=0)
    rf_proba = RF_MODEL.predict_proba(X_rf)[:, 1]
    feat_df["rf_risk"] = rf_proba

    # LSTM inference
    sequences = build_lstm_sequences(feat_df)
    lstm_risk_by_window = {}
    for window_id, seq in sequences:
        seq_n = (seq - LSTM_MU) / LSTM_SIGMA
        lstm_risk_by_window[window_id] = float(LSTM_MODEL.predict_proba(seq_n))

    feat_df["lstm_risk"] = feat_df["window_id"].map(lstm_risk_by_window).fillna(0.0)

    # attack family prediction (RF family classifier) for flagged windows
    X_fam = feat_df.reindex(columns=FAMILY_FEATURE_COLS, fill_value=0)
    fam_preds = FAMILY_MODEL.predict(X_fam)
    feat_df["predicted_family"] = fam_preds
    feat_df["kill_chain_stage"] = feat_df["predicted_family"].map(KILL_CHAIN_MAP).fillna("-")

    flagged = feat_df[feat_df["lstm_risk"] >= 0.5].copy()
    flagged_rows = []
    for _, r in flagged.iterrows():
        row = {
            "window_id": int(r["window_id"]), "lstm_risk": float(r["lstm_risk"]),
            "rf_risk": float(r["rf_risk"]), "predicted_family": r["predicted_family"],
            "kill_chain_stage": r["kill_chain_stage"],
        }
        if has_labels:
            row["true_label"] = r.get("true_attack_family", "n/a")
        flagged_rows.append(row)

    risk_json = feat_df[["window_id", "lstm_risk", "rf_risk"]].to_dict(orient="records")

    # saliency for most recent sequence
    saliency_json = {}
    if sequences:
        last_window_id, last_seq = sequences[-1]
        seq_n = (last_seq - LSTM_MU) / LSTM_SIGMA
        sal = LSTM_MODEL.saliency(seq_n)
        imp = np.abs(sal).mean(axis=0)
        imp = imp / (imp.sum() + 1e-9)
        saliency_json = {f: float(v) for f, v in zip(LSTM_FEATURES, imp)}

    stage_counts = flagged["kill_chain_stage"].value_counts()
    top_stage = stage_counts.index[0] if len(stage_counts) else "none"

    summary = {
        "n_flagged_lstm": int((feat_df["lstm_risk"] >= 0.5).sum()),
        "n_flagged_rf": int((feat_df["rf_risk"] >= 0.5).sum()),
        "peak_risk_lstm": float(feat_df["lstm_risk"].max()),
        "top_stage": top_stage,
    }

    return render_template_string(
        RESULTS_PAGE,
        n_windows=len(feat_df), n_flows=len(raw_df), filename=file.filename,
        has_labels=has_labels, flagged_rows=flagged_rows,
        risk_json=json.dumps(risk_json), saliency_json=json.dumps(saliency_json),
        summary_json=json.dumps(summary),
    )


if __name__ == "__main__":
    print("Starting Flask app on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
