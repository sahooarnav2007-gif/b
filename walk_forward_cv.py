"""
walk_forward_cv.py
------------------
Rolling-origin (walk-forward) Time-Series CV with the RandomForest forecaster.

The single Mon-Thu -> Fri holdout in full_train.py is a good stress test but is
ONE split. A rolling-origin evaluation trains on every strictly-earlier subset
of the 8 day-files and evaluates on the immediately-next one, producing:

  fold 1: train [mon, tue]                                   -> eval wednesday
  fold 2: train [mon, tue, wed]                              -> eval thursday_web
  fold 3: train [mon, tue, wed, thursday_web]                -> eval thursday_infil
  fold 4: train [mon .. thursday_infil]                      -> eval friday_morning
  fold 5: train [mon .. friday_morning]                      -> eval friday_portscan
  fold 6: train [mon .. friday_portscan]                     -> eval friday_ddos

This gives 6 independent look-ahead evaluations, an honest pooled AUC, and a
per-day picture -- eliminating any luck-of-the-split criticism. Same model
(400-tree RF, max_depth 10, class_weight balanced) and same feature set as
full_train.py. Fast: RF on 76 features over ~1k-5k rows.
"""

import json
import warnings
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score, confusion_matrix

FORECAST_HORIZON = 6
DAYS_ORDER = ["monday", "tuesday", "wednesday", "thursday_web", "thursday_infil",
              "friday_morning", "friday_portscan", "friday_ddos"]

EXCLUDE_COLS = {
    "day", "window_id", "attack_family", "mitre", "label_attack_now",
    "attack_fraction", "y_forecast", "upcoming_attack_family", "windows_to_attack",
}


def main():
    df = pd.read_csv("full_features.csv")
    feat_cols = [c for c in df.columns if c not in EXCLUDE_COLS]
    print(f"Days in order: {DAYS_ORDER}")
    print(f"{len(df.columns)-len(EXCLUDE_COLS)} features | "
          f"{len(df)} windows | {df.y_forecast.mean()*100:.1f}% positive\n")

    folds, pooled_probs, pooled_labels, per_day = [], [], [], {}
    for i in range(2, len(DAYS_ORDER)):
        train_days = DAYS_ORDER[:i]
        test_day = DAYS_ORDER[i]
        tr = df[df.day.isin(train_days)]
        te = df[df.day == test_day]
        if te.y_forecast.nunique() < 2:
            print(f"fold {i-1}: {test_day:18s} single class -> skipped")
            continue

        m = RandomForestClassifier(n_estimators=400, max_depth=10,
                                   min_samples_leaf=3, class_weight="balanced",
                                   random_state=42, n_jobs=-1)
        m.fit(tr[feat_cols], tr["y_forecast"])
        proba = m.predict_proba(te[feat_cols])[:, 1]
        auc = roc_auc_score(te["y_forecast"], proba)
        tn, fp, fn, tp = confusion_matrix(te["y_forecast"], (proba >= 0.5).astype(int)).ravel()
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        folds.append({"test_day": test_day, "train_windows": len(tr),
                      "test_windows": len(te), "auc": round(auc, 3),
                      "precision@0.5": round(prec, 3), "recall@0.5": round(rec, 3),
                      "f1@0.5": round(2 * prec * rec / (prec + rec), 3) if (prec + rec) else 0.0})
        pooled_probs.extend(proba.tolist())
        pooled_labels.extend(te["y_forecast"].tolist())
        per_day[test_day] = round(auc, 3)
        print(f"  {test_day:18s} train={len(tr):5d} test={len(te):4d}  "
              f"AUC={auc:.3f}  P@0.5={prec:.3f}  R@0.5={rec:.3f}")

    pooled_auc = roc_auc_score(pooled_labels, pooled_probs)
    print(f"\nPOOLED walk-forward AUC (all 6 folds): {pooled_auc:.3f}")
    print(f"Mean fold AUC: {np.mean([f['auc'] for f in folds]):.3f}")
    print(f"Median fold AUC: {np.median([f['auc'] for f in folds]):.3f}")

    summary = {
        "method": "rolling-origin walk-forward CV (RandomForest, full_train.py config)",
        "folds": folds,
        "per_day_auc": per_day,
        "pooled_auc": round(pooled_auc, 3),
        "mean_fold_auc": round(float(np.mean([f["auc"] for f in folds])), 3),
        "median_fold_auc": round(float(np.median([f["auc"] for f in folds])), 3),
    }
    with open("walk_forward_cv.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved walk_forward_cv.json")


if __name__ == "__main__":
    main()