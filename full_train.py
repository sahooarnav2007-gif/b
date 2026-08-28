"""
full_train.py
--------------
Trains on Monday-Thursday (5 real capture files), tests on Friday
(3 real capture files the model never saw) — a genuine day-level holdout,
not a random shuffle split. This is the honest way to evaluate a forecaster:
can it generalize to a day it never trained on.

Trains two models:
  1. forecaster: binary — attack in next 6 windows?
  2. family_classifier: multi-class — on windows where an attack IS
     forecasted, which family is it most likely to be? (trained only on
     positive-forecast windows, evaluated the same way)
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import json
import warnings
warnings.filterwarnings("ignore")

FORECAST_HORIZON = 6
TRAIN_DAYS = ["monday", "tuesday", "wednesday", "thursday_web", "thursday_infil"]
TEST_DAYS  = ["friday_morning", "friday_portscan", "friday_ddos"]

EXCLUDE_COLS = {
    "day", "window_id", "attack_family", "mitre", "label_attack_now",
    "attack_fraction", "y_forecast", "upcoming_attack_family", "windows_to_attack",
}


def get_feature_cols(df):
    return [c for c in df.columns if c not in EXCLUDE_COLS]


def train_and_evaluate():
    df = pd.read_csv("full_features.csv")
    feat_cols = get_feature_cols(df)

    train_df = df[df.day.isin(TRAIN_DAYS)].reset_index(drop=True)
    test_df = df[df.day.isin(TEST_DAYS)].reset_index(drop=True)

    print(f"TRAIN days: {TRAIN_DAYS} -> {len(train_df)} windows "
          f"({train_df.y_forecast.mean()*100:.1f}% positive)")
    print(f"TEST days:  {TEST_DAYS} -> {len(test_df)} windows "
          f"({test_df.y_forecast.mean()*100:.1f}% positive)")

    X_train, y_train = train_df[feat_cols], train_df["y_forecast"]
    X_test, y_test = test_df[feat_cols], test_df["y_forecast"]

    # ---------- Model 1: binary forecaster ----------
    forecaster = RandomForestClassifier(
        n_estimators=400, max_depth=10, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    forecaster.fit(X_train, y_train)
    proba = forecaster.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)

    print("\n=== FORECASTER: Classification Report (test = unseen Friday) ===")
    report = classification_report(y_test, preds, output_dict=True, zero_division=0)
    print(classification_report(y_test, preds, zero_division=0))
    auc = roc_auc_score(y_test, proba) if y_test.nunique() > 1 else float("nan")
    print(f"ROC-AUC: {auc:.3f}")

    importances = pd.Series(forecaster.feature_importances_, index=feat_cols).sort_values(ascending=False)
    top_features = importances.head(15)
    print("\n=== Top 15 Features ===")
    print(top_features)

    # ---------- Lead-time metric, computed PER DAY (don't bleed across days) ----------
    test_df = test_df.copy()
    test_df["risk_score"] = proba
    test_df["predicted_alert"] = preds

    all_lead_times = []
    all_attack_windows = 0
    per_day_summary = {}
    for day, g in test_df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        attack_windows = g.index[g["label_attack_now"] == 1].tolist()
        lead_times = []
        for aw in attack_windows:
            lookback_start = max(0, aw - FORECAST_HORIZON - 2)
            window_slice = g.iloc[lookback_start:aw]
            alerted = window_slice.index[window_slice["predicted_alert"] == 1]
            if len(alerted) > 0:
                lead_times.append(aw - alerted.min())
        per_day_summary[day] = {
            "attack_windows": len(attack_windows),
            "caught_with_warning": len(lead_times),
            "avg_lead_time": round(float(np.mean(lead_times)), 2) if lead_times else 0.0,
        }
        all_lead_times.extend(lead_times)
        all_attack_windows += len(attack_windows)

    avg_lead_time = float(np.mean(all_lead_times)) if all_lead_times else 0.0
    detection_rate = len(all_lead_times) / all_attack_windows if all_attack_windows else 0.0

    print(f"\n=== Forecasting Performance (per unseen Friday day) ===")
    for day, s in per_day_summary.items():
        print(f"  {day}: {s['caught_with_warning']}/{s['attack_windows']} caught, "
              f"avg lead {s['avg_lead_time']} windows")
    print(f"\nOVERALL: {len(all_lead_times)}/{all_attack_windows} attacks caught with warning "
          f"({100*detection_rate:.1f}%), avg lead time {avg_lead_time:.2f} windows")

    # ---------- Model 2: attack-family classifier (on positive-forecast windows) ----------
    fam_train = train_df[train_df.y_forecast == 1]
    fam_test = test_df[test_df.y_forecast == 1]
    family_model = None
    fam_report = {}
    if fam_train["upcoming_attack_family"].nunique() > 1 and len(fam_test) > 0:
        Xf_train, yf_train = fam_train[feat_cols], fam_train["upcoming_attack_family"]
        Xf_test, yf_test = fam_test[feat_cols], fam_test["upcoming_attack_family"]
        family_model = RandomForestClassifier(
            n_estimators=300, max_depth=10, min_samples_leaf=2,
            class_weight="balanced", random_state=42, n_jobs=-1
        )
        family_model.fit(Xf_train, yf_train)
        fam_preds = family_model.predict(Xf_test)
        print("\n=== ATTACK-FAMILY CLASSIFIER (on forecasted-positive windows) ===")
        fam_report = classification_report(yf_test, fam_preds, output_dict=True, zero_division=0)
        print(classification_report(yf_test, fam_preds, zero_division=0))

    # ---------- Save everything ----------
    test_df.to_csv("full_predictions.csv", index=False)
    top_features.to_csv("full_feature_importance.csv", header=["importance"])

    summary = {
        "roc_auc": None if np.isnan(auc) else round(auc, 3),
        "precision": round(report.get("1", {}).get("precision", 0), 3),
        "recall": round(report.get("1", {}).get("recall", 0), 3),
        "f1": round(report.get("1", {}).get("f1-score", 0), 3),
        "attack_windows_test": all_attack_windows,
        "attacks_with_warning": len(all_lead_times),
        "detection_rate": round(detection_rate, 3),
        "avg_lead_time_windows": round(avg_lead_time, 2),
        "forecast_horizon": FORECAST_HORIZON,
        "train_days": TRAIN_DAYS,
        "test_days": TEST_DAYS,
        "per_day": per_day_summary,
        "family_classifier_accuracy": round(fam_report.get("accuracy", 0), 3) if fam_report else None,
        "data_source": "CICIDS2017 — all 8 real capture files (Mon-Fri)",
    }
    with open("full_model_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\nSaved: full_predictions.csv, full_feature_importance.csv, full_model_summary.json")

    # ---------- Second evaluation: within-day time-split (practical deployment scenario) ----------
    # Cross-day holdout above is a hard generalization stress-test (can the model
    # handle attack families it has NEVER seen a single example of). That's honest
    # but pessimistic — a real deployment would calibrate on some traffic from its
    # own network first. This second split (70/30 time-split WITHIN each day, then
    # combined) reflects that more typical scenario and is directly comparable to
    # the single-day CICIDS runs.
    print("\n\n========== SECONDARY EVAL: within-day time-split (all 8 days) ==========")
    train_parts, test_parts = [], []
    for day, g in df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        split = int(len(g) * 0.7)
        train_parts.append(g.iloc[:split])
        test_parts.append(g.iloc[split:])
    wd_train = pd.concat(train_parts, ignore_index=True)
    wd_test = pd.concat(test_parts, ignore_index=True)

    Xw_train, yw_train = wd_train[feat_cols], wd_train["y_forecast"]
    Xw_test, yw_test = wd_test[feat_cols], wd_test["y_forecast"]

    wd_model = RandomForestClassifier(
        n_estimators=400, max_depth=10, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    wd_model.fit(Xw_train, yw_train)
    wd_proba = wd_model.predict_proba(Xw_test)[:, 1]
    wd_preds = (wd_proba >= 0.5).astype(int)

    wd_report = classification_report(yw_test, wd_preds, output_dict=True, zero_division=0)
    print(classification_report(yw_test, wd_preds, zero_division=0))
    wd_auc = roc_auc_score(yw_test, wd_proba) if yw_test.nunique() > 1 else float("nan")
    print(f"ROC-AUC: {wd_auc:.3f}")

    wd_test = wd_test.copy()
    wd_test["risk_score"] = wd_proba
    wd_test["predicted_alert"] = wd_preds
    wd_lead_times, wd_attack_windows = [], 0
    for day, g in wd_test.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        attack_windows = g.index[g["label_attack_now"] == 1].tolist()
        for aw in attack_windows:
            lookback_start = max(0, aw - FORECAST_HORIZON - 2)
            window_slice = g.iloc[lookback_start:aw]
            alerted = window_slice.index[window_slice["predicted_alert"] == 1]
            if len(alerted) > 0:
                wd_lead_times.append(aw - alerted.min())
        wd_attack_windows += len(attack_windows)
    wd_avg_lead = float(np.mean(wd_lead_times)) if wd_lead_times else 0.0
    wd_detection_rate = len(wd_lead_times) / wd_attack_windows if wd_attack_windows else 0.0
    print(f"OVERALL: {len(wd_lead_times)}/{wd_attack_windows} attacks caught with warning "
          f"({100*wd_detection_rate:.1f}%), avg lead time {wd_avg_lead:.2f} windows")

    wd_summary = {
        "roc_auc": None if np.isnan(wd_auc) else round(wd_auc, 3),
        "precision": round(wd_report.get("1", {}).get("precision", 0), 3),
        "recall": round(wd_report.get("1", {}).get("recall", 0), 3),
        "f1": round(wd_report.get("1", {}).get("f1-score", 0), 3),
        "attack_windows_test": wd_attack_windows,
        "attacks_with_warning": len(wd_lead_times),
        "detection_rate": round(wd_detection_rate, 3),
        "avg_lead_time_windows": round(wd_avg_lead, 2),
    }
    summary["within_day_eval"] = wd_summary
    with open("full_model_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    wd_test.to_csv("within_day_predictions.csv", index=False)
    print("\nUpdated full_model_summary.json with within_day_eval block")

    return forecaster, family_model, test_df, summary


if __name__ == "__main__":
    train_and_evaluate()
