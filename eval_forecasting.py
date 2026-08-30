"""
eval_forecasting.py
-------------------
Forecasting-oriented evaluation of the saved cross-day test predictions
(`full_predictions.csv`, produced by full_train.py on unseen Friday).

AUC alone hides the property the PS actually cares about: *how far ahead does
the system warn?* This script reports:

  - precision/recall/F1 curve over the alert threshold (the forecasting target
    y_forecast = "attack starts within the next 6 windows")
  - AUPRC + the operating point at the default threshold 0.5
  - lead-time distribution: for each attack window, how many windows before it
    did the FIRST alert fire (mirrors full_train's methodology)
  - per-family forecast performance on unseen Friday
  - false-alarm fraction at the default threshold

Usage:  python3 eval_forecasting.py
"""

import json
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve, auc as pr_auc

HORIZON = 6
THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7]


def main():
    df = pd.read_csv("full_predictions.csv")
    df["risk_score"] = df["risk_score"].fillna(0.5)
    y = df["y_forecast"].to_numpy()
    r = df["risk_score"].to_numpy()

    prec, rec, th = precision_recall_curve(y, r)
    auprc = pr_auc(rec, prec)

    curve = []
    for t in THRESHOLDS:
        p = r >= t
        tp = int((p & (y == 1)).sum())
        fp = int((p & (y == 0)).sum())
        fn = int((~p & (y == 1)).sum())
        curve.append({
            "threshold": t,
            "precision": round(tp / max(tp + fp, 1), 3),
            "recall": round(tp / max(tp + fn, 1), 3),
            "f1": round(2 * tp / max(2 * tp + fp + fn, 1), 3),
            "alerts": int(p.sum()),
        })
    op = next((c for c in curve if abs(c["threshold"] - 0.5) < 0.01), curve[-1])

    # lead-time: for each attack window (y true), look back up to horizon+2 for
    # the first alert and measure how many windows ahead it fired
    leads = []
    warned_attack = 0
    n_attack = int(y.sum())
    for t in range(len(df)):
        if y[t] != 1:
            continue
        lo = max(0, t - HORIZON - 2)
        alerted = df["predicted_alert"].astype(bool).to_numpy()[lo:t]
        if alerted.any():
            warned_attack += 1
            first = lo + int(np.argmax(alerted))
            leads.append(t - first)
    if leads:
        lead_summary = {
            "min": int(np.min(leads)), "q25": int(np.quantile(leads, 0.25)),
            "median": int(np.median(leads)), "q75": int(np.quantile(leads, 0.75)),
            "max": int(np.max(leads)), "mean": round(float(np.mean(leads)), 2),
        }
    else:
        lead_summary = {}
    fpr_ops = {}
    p50 = r >= 0.5
    fpr_ops["alerts_without_attack_in_horizon"] = int(((p50) & (y == 0)).sum())
    fpr_ops["clean_windows"] = int((y == 0).sum())
    fpr_ops["false_alarm_rate_windows"] = round(
        int(((p50) & (y == 0)).sum()) / max(int((y == 0).sum()), 1), 3)

    per_family = {}
    for fam in df["attack_family"].unique():
        if fam == "none":
            continue
        m = df[df["attack_family"] == fam]
        fam_leads = []
        for t in m.index:
            lo = max(0, t - HORIZON - 2)
            alerted = df["predicted_alert"].astype(bool).to_numpy()[lo:t]
            if alerted.any():
                fam_leads.append(int(t - (lo + int(np.argmax(alerted)))))
        per_family[fam] = {
            "windows": int(len(m)),
            "warned_within_horizon": len(fam_leads),
            "median_lead_windows": (int(np.median(fam_leads)) if fam_leads else 0),
        }

    summary = {
        "n_test_windows": int(len(df)),
        "attack_windows": n_attack,
        "auprc_forecast": round(float(auprc), 3),
        "operating_point_0.5": op,
        "curve": curve,
        "lead_time_windows": lead_summary,
        "warned_attack_windows": warned_attack,
        "detection_rate": round(warned_attack / max(n_attack, 1), 3),
        "false_alarms": fpr_ops,
        "per_family": per_family,
    }
    with open("eval_forecasting.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"n_test({len(df)}) attack_windows({n_attack}) AUPRC={auprc:.3f}")
    print("threshold  precision  recall   f1   alerts")
    for c in curve:
        print(f"  {c['threshold']:<9.1f} {c['precision']:<10.3f} {c['recall']:<8.3f} "
              f"{c['f1']:<6.3f} {c['alerts']}")
    print(f"\nLead time (windows before first alert): {lead_summary}")
    print(f"warned {warned_attack}/{n_attack} attack windows "
          f"({warned_attack / max(n_attack, 1):.1%})")
    print(f"false-alarm rate at 0.5: {fpr_ops['false_alarm_rate_windows']}")
    print("\nPer-family (unseen Friday):")
    for fam, v in per_family.items():
        print(f"  {fam:12s} warned {v['warned_within_horizon']:>3}/{v['windows']:<4}"
              f" median_lead {v['median_lead_windows']}")
    print("\nSaved eval_forecasting.json")


if __name__ == "__main__":
    main()