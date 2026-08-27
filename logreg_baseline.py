"""
logreg_baseline.py
-------------------
The PS explicitly requires: "Benchmark results comparing model performance
against a logistic regression baseline trained on the same features,
demonstrating that the world model's temporal dynamics learning provides
measurable improvement."

Runs LogReg on the SAME two splits used for the LSTM and RandomForest:
  1. Cross-day holdout (train Mon-Thu, test unseen Friday)
  2. Within-day time-split (70/30 per day, all 8 days)

Uses the flattened rolling-window features (full_features.csv) — same
feature set as the RandomForest, giving LogReg every advantage a linear
model can take from engineered features (fair baseline).
"""

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
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


def eval_split(X_train, y_train, X_test, y_test):
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    model = LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)
    model.fit(X_train_s, y_train)
    proba = model.predict_proba(X_test_s)[:, 1]
    preds = (proba >= 0.5).astype(int)

    report = classification_report(y_test, preds, output_dict=True, zero_division=0)
    auc = roc_auc_score(y_test, proba) if len(set(y_test)) > 1 else float("nan")
    return {
        "roc_auc": None if np.isnan(auc) else round(auc, 3),
        "precision": round(report.get("1", {}).get("precision", 0), 3),
        "recall": round(report.get("1", {}).get("recall", 0), 3),
        "f1": round(report.get("1", {}).get("f1-score", 0), 3),
    }, model, scaler


def main():
    df = pd.read_csv("full_features.csv")
    feat_cols = get_feature_cols(df)

    # ---------- Split 1: cross-day holdout ----------
    train_df = df[df.day.isin(TRAIN_DAYS)]
    test_df = df[df.day.isin(TEST_DAYS)]
    r1, model1, scaler1 = eval_split(
        train_df[feat_cols], train_df["y_forecast"],
        test_df[feat_cols], test_df["y_forecast"]
    )
    print("=== Cross-day holdout (train Mon-Thu, test unseen Friday) ===")
    print(json.dumps(r1, indent=2))

    # ---------- Split 2: within-day time-split ----------
    train_parts, test_parts = [], []
    for day, g in df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        split = int(len(g) * 0.7)
        train_parts.append(g.iloc[:split])
        test_parts.append(g.iloc[split:])
    wd_train = pd.concat(train_parts, ignore_index=True)
    wd_test = pd.concat(test_parts, ignore_index=True)
    r2, model2, scaler2 = eval_split(
        wd_train[feat_cols], wd_train["y_forecast"],
        wd_test[feat_cols], wd_test["y_forecast"]
    )
    print("\n=== Within-day time-split (70/30, all 8 days) ===")
    print(json.dumps(r2, indent=2))

    # top coefficients (interpretability — inherent to logistic regression)
    coefs = pd.Series(model2.coef_[0], index=feat_cols).sort_values(key=abs, ascending=False)
    print("\n=== Top 10 |coefficients| (within-day model) ===")
    print(coefs.head(10))

    summary = {
        "cross_day_holdout": r1,
        "within_day_split": r2,
        "top_coefficients": coefs.head(10).round(4).to_dict(),
    }
    with open("logreg_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved logreg_summary.json")


if __name__ == "__main__":
    main()
