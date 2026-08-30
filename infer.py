"""
infer.py
--------
Streaming inference engine for SIH26153. Accepts an arbitrarily-large
CICIDS2017 flow CSV (or a pre-featurized window CSV) and produces a rolling
risk timeline WITHOUT loading the whole file into memory — the PS's demo
requirement (large uploads, offline, no cloud).

Design:
  - raw CSV rows are streamed through a window buffer (WINDOW_SIZE flows / window)
  - per-window aggregate features are computed EXACTLY as in full_pipeline.py
  - rolling 3/6/12-window MA/std/slope features are rebuilt on the fly
  - the saved RandomForest forecaster + attack-family classifier (or the
    saved NumPy LSTM) produce one prediction per window
  - output: JSON timeline [{window_id, risk_score, predicted_alert,
    attack_family, mitre_stage, attribution, ...}, ...] + console summary

Usage:
  python3 infer.py dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
      [--out timeline.json] [--max-windows 0] [--model rf|lstm] [--threshold 0.5]

App code imports stream_windows / RollingFeatureBuilder / run_inference rather
than re-implementing feature logic.
"""

import argparse
import json
import os
import pickle
from collections import Counter

import numpy as np
import pandas as pd

from zero_day_callout import NoveltyStore

WINDOW_SIZE = 500
FORECAST_HORIZON = 6
ROLL_WINDOWS = [3, 6, 12]
RAW_FEATURE_COLS = [
    "packet_rate", "byte_rate", "unique_dst_ips", "unique_dst_ports",
    "syn_ack_ratio", "avg_pkt_size", "dst_port_entropy", "failed_conn_rate",
    "fwd_psh_rate", "avg_flow_duration",
]

MITRE_FAMILY_MAP = {
    "port_scan":    "Reconnaissance",
    "brute_force":  "Initial Access",
    "web_attack":   "Initial Access",
    "infiltration": "Initial Access",
    "botnet":       "Command & Control",
    "exploit":      "Initial Access",
    "dos":          "Impact (DDoS is MITRE TA0040 — noted explicitly)",
}

LABEL_FAMILY_MAP = {
    "BENIGN": "none",
    "FTP-Patator": "brute_force", "SSH-Patator": "brute_force",
    "DoS Hulk": "dos", "DoS GoldenEye": "dos",
    "DoS slowloris": "dos", "DoS Slowhttptest": "dos",
    "Heartbleed": "exploit", "Infiltration": "infiltration", "Bot": "botnet",
    "PortScan": "port_scan", "DDoS": "dos",
}


def map_label_to_family(label):
    s = str(label).strip()
    if s in LABEL_FAMILY_MAP:
        return LABEL_FAMILY_MAP[s]
    if "Web Attack" in s:
        return "web_attack"
    return "none"


def _entropy(values):
    counts = Counter(values)
    n = sum(counts.values())
    return float(-sum(c / n * np.log2(c / n + 1e-12) for c in counts.values()))


def stream_windows(path, window_size=WINDOW_SIZE, max_windows=0):
    """Yield (window_id, feature_dict, gt_family) one window at a time.

    Streams the CSV in chunks, holds at most one in-progress window in memory.
    Returns generator; also yields final partial window (< window_size flows).
    """
    header = None
    cols = None
    buffer = {c: [] for c in [
        "Flow Packets/s", "Flow Bytes/s", "Destination Port",
        "SYN Flag Count", "ACK Flag Count", "Average Packet Size",
        "RST Flag Count", "Fwd PSH Flags", "Flow Duration", "Label",
    ]}

    def flush_window(wid):
        n = min(window_size, len(buffer["Flow Packets/s"]))
        if n == 0:
            return None
        fpk = np.asarray(buffer["Flow Packets/s"][:n], dtype=float)
        fby = np.asarray(buffer["Flow Bytes/s"][:n], dtype=float)
        ports = buffer["Destination Port"][:n]
        syn = np.asarray(buffer["SYN Flag Count"][:n], dtype=float)
        ack = np.asarray(buffer["ACK Flag Count"][:n], dtype=float)
        rst = np.asarray(buffer["RST Flag Count"][:n], dtype=float)
        psh = np.asarray(buffer["Fwd PSH Flags"][:n], dtype=float)
        pkt_size = np.asarray(buffer["Average Packet Size"][:n], dtype=float)
        dur = np.asarray(buffer["Flow Duration"][:n], dtype=float)
        labels = buffer["Label"][:n]

        non_benign = [l for l in labels if str(l).strip() != "BENIGN"]
        dominant = Counter(non_benign).most_common(1)
        gt_family = map_label_to_family(dominant[0][0]) if dominant else "none"

        uniq = len(np.unique(ports))
        feature = {
            "packet_rate": float(np.clip(fpk, 0, 1e6).mean()),
            "byte_rate": float(np.clip(fby, 0, 1e8).mean()),
            "unique_dst_ips": uniq,
            "unique_dst_ports": uniq,
            "syn_ack_ratio": float((syn.sum() + 1) / (ack.sum() + 1)),
            "avg_pkt_size": float(pkt_size.mean()),
            "dst_port_entropy": _entropy(ports),
            "failed_conn_rate": float(rst.sum() / n),
            "fwd_psh_rate": float(psh.sum() / n),
            "avg_flow_duration": float(dur.mean()),
        }
        return wid, feature, gt_family

    wid = 0
    reader = pd.read_csv(
        path, chunksize=20000, iterator=True, low_memory=False, on_bad_lines="skip"
    )
    for chunk in reader:
        chunk.columns = [c.strip() for c in chunk.columns]
        if header is None:
            header = True
            cols = [c.strip() for c in chunk.columns]
            chunk.columns = cols
            missing = set(buffer) - set(cols)
            if missing:
                # not a raw CICIDS schema — let caller fall back to pre-featurized
                stream_windows.schema = {"raw": False}
                return
            stream_windows.schema = {"raw": True}
        chunk = chunk.replace([np.inf, -np.inf], np.nan)
        chunk = chunk.dropna(subset=["Flow Bytes/s", "Flow Packets/s", "Flow Duration"])
        for col in buffer:
            buffer[col].extend(chunk[col].tolist())

        while len(buffer["Flow Packets/s"]) >= window_size:
            if max_windows and wid >= max_windows:
                return
            yield flush_window(wid)
            wid += 1
            for col in buffer:
                buffer[col] = buffer[col][window_size:]

    if max_windows and wid >= max_windows:
        return
    final = flush_window(wid)
    if final is not None:
        stream_windows.schema["final_partial"] = True
        yield final


class RollingFeatureBuilder:
    """Incrementally rebuilds the 3/6/12-window MA/std/slope features on the
    streamed window series — identical to full_pipeline.add_rolling_features."""

    def __init__(self, raw_cols=RAW_FEATURE_COLS, roll=ROLL_WINDOWS):
        self.raw_cols = raw_cols
        self.roll = roll
        self.history = []  # each entry: dict of raw per-window features

    def add(self, feature_dict):
        self.history.append(feature_dict)

    def row(self):
        if not self.history:
            return None
        out = {c: self.history[-1][c] for c in self.raw_cols}
        for w in self.roll:
            for col in self.raw_cols:
                vals = [h[col] for h in self.history[-w:]]
                out[f"{col}_ma{w}"] = float(np.mean(vals))
                out[f"{col}_std{w}"] = float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0
            live = self.history[-1]["unique_dst_ports"]
            ent = self.history[-1]["dst_port_entropy"]
            out[f"portcount_slope{w}"] = float(
                live - self.history[-(w + 1)]["unique_dst_ports"]
            ) if len(self.history) > w else 0.0
            out[f"entropy_slope{w}"] = float(
                ent - self.history[-(w + 1)]["dst_port_entropy"]
            ) if len(self.history) > w else 0.0
        return out


class RandomForestEngine:
    """RandomForest forecaster + family classifier.

    NOTE: this environment's sklearn carries ~250ms of fixed per-call overhead
    for predict_proba, so we always predict in BATCHes (one call per column-
    ablation across the whole batch) instead of once per window. Result per row
    is the same as calling predict() per window.
    """

    def __init__(self, forecaster_path="rf_forecaster.pkl",
                 family_path="rf_family_classifier.pkl", threshold=0.5):
        with open(forecaster_path, "rb") as f:
            saved = pickle.load(f)
        self.model = saved["model"]
        self.feature_cols = list(saved["feature_cols"])
        self.family_model = None
        self.family_classes = None
        if os.path.exists(family_path):
            with open(family_path, "rb") as f:
                saved_f = pickle.load(f)
            self.family_model = saved_f["model"]
            self.family_classes = list(self.family_model.classes_)
        self.threshold = threshold
        imp = np.array(self.model.feature_importances_)
        self.top_features = [self.feature_cols[i] for i in np.argsort(imp)[::-1][:6]]
        self.novelty = NoveltyStore()
        self.novelty.build(self.feature_cols)

    def predict(self, rolling_row, raw_feat=None):
        return self.predict_batch([rolling_row])[0]

    def predict_batch(self, rolling_rows, raw_feats=None):
        n = len(rolling_rows)
        X = pd.concat([self._frame(r) for r in rolling_rows], ignore_index=True)
        X = X[self.feature_cols]
        risk = self.model.predict_proba(X)[:, 1]
        alert = risk >= self.threshold
        if n == 0:
            return []

        families = np.array(["none"] * n, dtype=object)
        stages = np.array(["-"] * n, dtype=object)
        fam_conf = np.zeros(n)
        fam_idx = np.where(alert)[0]
        if len(fam_idx) and self.family_model is not None and self.family_classes:
            fam_proba = self.family_model.predict_proba(X.iloc[fam_idx])
            best = fam_proba.argmax(axis=1)
            names = np.array(self.family_classes)[best]
            fam_conf[fam_idx] = fam_proba.max(axis=1)
            for j, name in zip(fam_idx, names):
                families[j] = name
                stages[j] = MITRE_FAMILY_MAP.get(str(name), "unmapped")

        nov_dist, nov_pct, nov_flag = self.novelty.evaluate(X.values)

        top5 = self._attribution_batch(X, risk)

        out = []
        for i in range(n):
            zero_day = None
            if alert[i]:
                zero_day = {
                    "family_confidence": round(float(fam_conf[i]), 3),
                    "low_family_confidence": bool(fam_conf[i] < 0.5),
                    "novelty_dist": round(float(nov_dist[i]), 3),
                    "novelty_pctl": round(float(nov_pct[i]), 3),
                    "zero_day_likely": bool(nov_flag[i]),
                }
            out.append((
                float(risk[i]),
                bool(alert[i]),
                str(families[i]),
                str(stages[i]),
                top5[i],
                zero_day,
            ))
        return out

    def _frame(self, feature_row):
        row = pd.Series(feature_row).reindex(self.feature_cols).fillna(0.0)
        return row.to_frame().T

    def _attribution_batch(self, X, risk):
        """Mean-imputation ablation: for each of the top-importance features,
        set that column to its batch mean and measure the risk delta. One
        vectorized predict_proba call per feature (7 calls total per batch)."""
        col_mean = X.mean(axis=0)
        deltas = np.zeros((len(X), len(self.top_features)))
        for j, feat in enumerate(self.top_features):
            Xb = X.copy()
            Xb[feat] = col_mean[feat]
            after = self.model.predict_proba(Xb)[:, 1]
            deltas[:, j] = risk - after
        top5 = []
        for i in range(len(X)):
            order = np.argsort(-np.abs(deltas[i]))
            top5.append({self.top_features[j]: round(float(deltas[i, j]), 4)
                         for j in order[:5] if abs(deltas[i, j]) > 1e-9})
        return top5


class LSTMEngine:
    def __init__(self, weights_path="lstm_weights.json", threshold=0.5):
        with open(weights_path) as f:
            saved = json.load(f)
        self.mu = np.array(saved["mu"])
        self.sigma = np.array(saved["sigma"])
        self.seq_len = saved["seq_len"]
        self.features = saved["features"]
        self.threshold = threshold

        from lstm_world_model import NumpyLSTM, HIDDEN_SIZE
        self.model = NumpyLSTM(input_size=len(self.features), hidden_size=HIDDEN_SIZE)
        for p, val in saved["weights"].items():
            setattr(self.model, p, np.array(val))
        self.history = []
        try:
            raw_cols = self.features
            self.novelty = NoveltyStore()
            self.novelty.build(list(raw_cols))
        except Exception:
            self.novelty = NoveltyStore()

    def _novelty(self, x):
        if not self.novelty.available:
            return None
        dist, pct, fl = self.novelty.evaluate(x.reshape(1, -1))
        return {"family_confidence": None, "low_family_confidence": False,
                "novelty_dist": round(float(dist[0]), 3),
                "novelty_pctl": round(float(pct[0]), 3),
                "zero_day_likely": bool(fl[0])}

    def predict(self, rolling_row, raw_feat=None):
        x = np.array([raw_feat[f] for f in self.features])
        self._raw_last = x
        self.history.append((x - self.mu) / self.sigma)
        if len(self.history) < self.seq_len:
            return None
        seq = np.stack(self.history[-self.seq_len:])
        risk = float(self.model.predict_proba(seq))
        alert = risk >= self.threshold
        family, stage = "none", "-"
        if alert:
            sal = np.abs(self.model.saliency(seq)).mean(axis=0)
            norm = sal / (sal.sum() + 1e-9)
            attribution = dict(sorted(
                zip(self.features, [round(float(v), 4) for v in norm]),
                key=lambda kv: -kv[1])[:5])
        else:
            attribution = None
        zero_day = self._novelty(self._raw_last) if alert else None
        return risk, alert, family, stage, attribution, zero_day

    def predict_batch(self, rolling_rows, raw_feats):
        out = []
        for row, raw in zip(rolling_rows, raw_feats):
            out.append(self.predict(row, raw))
        return out


BATCH_ROWS = 128


def run_inference(path, engine, max_windows=0, window_size=WINDOW_SIZE,
                  progress=True):
    """Process a raw CICIDS CSV OR a pre-featurized window CSV and return
    (timeline, summary)."""
    with open(path, "rb") as fh:
        first = pd.read_csv(fh, nrows=1)
    stripped = [c.strip() for c in first.columns]
    if "y_forecast" in stripped and "window_id" in stripped:
        return _run_prefeatured(path, engine, max_windows)

    timeline, rows_seen = [], 0
    builder = RollingFeatureBuilder()
    pending = []  # (window_id, raw_feat, gt_family, rolling_row)

    def flush(batch):
        nonlocal timeline, rows_seen
        preds = engine.predict_batch(
            [b[3] for b in batch], [b[1] for b in batch])
        for (wid, raw_feat, gt_family, _), pred in zip(batch, preds):
            if pred is None:
                continue
            risk, alert, family, stage, attr, zero_day = pred
            rows_seen += 1
            timeline.append({
                "window_id": wid,
                "flows_in_window": window_size,
                "gt_family": gt_family,
                "risk_score": round(risk, 4),
                "predicted_alert": alert,
                "attack_family": family,
                "mitre_stage": stage,
                "attribution": attr,
                "zero_day": zero_day,
                "features": {k: round(float(v), 3) for k, v in raw_feat.items()},
            })
            if progress and (wid % 50 == 0):
                print(f"  window {wid}: risk={risk:.3f} {'ALERT' if alert else ''}")

    gen = stream_windows(path, window_size=window_size, max_windows=max_windows)
    try:
        for wid, raw_feat, gt_family in gen:
            builder.add(raw_feat)
            pending.append((wid, raw_feat, gt_family, builder.row()))
            if len(pending) >= BATCH_ROWS:
                flush(pending)
                pending.clear()
    finally:
        gen.close()
    if pending:
        flush(pending)

    summary = summarize(timeline)
    return timeline, summary


def _run_prefeatured(path, engine, max_windows=0):
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    if max_windows:
        df = df.head(max_windows)
    timeline = []
    builder = RollingFeatureBuilder()
    pending = []

    def flush(batch):
        nonlocal timeline
        preds = engine.predict_batch(
            [b[3] for b in batch], [b[1] for b in batch])
        for (ridx, raw_feat, gtfam, row), pred in zip(batch, preds):
            if pred is None:
                continue
            r = df.iloc[ridx]
            risk, alert, family, stage, attr, zero_day = pred
            timeline.append({
                "window_id": int(r["window_id"]),
                "flows_in_window": WINDOW_SIZE,
                "gt_family": str(r.get("attack_family", "none")),
                "risk_score": round(float(risk), 4),
                "predicted_alert": bool(alert),
                "attack_family": family,
                "mitre_stage": stage,
                "attribution": attr,
                "zero_day": zero_day,
                "features": {k: round(float(r[k]), 3) for k in RAW_FEATURE_COLS},
            })

    for idx, r in df.iterrows():
        raw_feat = {c: r[c] for c in RAW_FEATURE_COLS}
        builder.add(raw_feat)
        pending.append((idx, raw_feat, str(r.get("attack_family", "none")),
                        builder.row()))
        if len(pending) >= BATCH_ROWS:
            flush(pending)
            pending.clear()
    if pending:
        flush(pending)
    return timeline, summarize(timeline)


def summarize(timeline):
    flagged = [t for t in timeline if t["predicted_alert"]]
    return {
        "windows_processed": len(timeline),
        "flagged_windows": len(flagged),
        "flag_rate": round(len(flagged) / len(timeline), 3) if timeline else 0.0,
        "peak_risk": max([t["risk_score"] for t in timeline], default=0.0),
        "flagged_window_ids": [t["window_id"] for t in flagged][:50],
    }


def main():
    parser = argparse.ArgumentParser(description="Streaming attack-forecast inference")
    parser.add_argument("input", help="CICIDS2017 flow CSV or pre-featurized window CSV")
    parser.add_argument("--out", default=None, help="write timeline JSON here")
    parser.add_argument("--max-windows", type=int, default=0, help="stop after N windows (0=all)")
    parser.add_argument("--model", choices=["rf", "lstm"], default="rf")
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    engine = (RandomForestEngine(threshold=args.threshold) if args.model == "rf"
              else LSTMEngine(threshold=args.threshold))

    print(f"Running {args.model.upper()} inference on {args.input} "
          f"(windows of {WINDOW_SIZE} flows, horizon {FORECAST_HORIZON})...")
    timeline, summary = run_inference(args.input, engine, args.max_windows)
    print(f"\n=== Summary ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    if timeline:
        first_alert = next((t for t in timeline if t["predicted_alert"]), None)
        if first_alert:
            print(f"\nFirst alert at window {first_alert['window_id']} "
                  f"(risk {first_alert['risk_score']}) — stage: {first_alert['mitre_stage']}")
            if first_alert["attribution"]:
                print("  driving:", first_alert["attribution"])

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"summary": summary, "timeline": timeline}, f, indent=2)
        print(f"\nSaved {args.out}")


if __name__ == "__main__":
    main()