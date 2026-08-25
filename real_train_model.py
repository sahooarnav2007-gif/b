"""
real_train_model.py
--------------------
Same approach as train_model.py, run on real CICIDS2017-derived features.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import json

FORECAST_HORIZON = 6
TEST_FRACTION = 0.3


def get_feature_columns(df):
    exclude = {
        "window_id", "attack_type", "label_attack_now", "attack_fraction",
        "y_forecast", "windows_to_attack",
    }
    return [c for c in df.columns if c not in exclude]


def time_split(df, test_frac=TEST_FRACTION):
    n = len(df)
    split_idx = int(n * (1 - test_frac))
    return df.iloc[:split_idx].copy(), df.iloc[split_idx:].copy()


def train_and_evaluate():
    df = pd.read_csv("features_real.csv")
    feat_cols = get_feature_columns(df)

    train_df, test_df = time_split(df)
    X_train, y_train = train_df[feat_cols], train_df["y_forecast"]
    X_test, y_test = test_df[feat_cols], test_df["y_forecast"]

    print(f"Train: {len(X_train)} windows | Test: {len(X_test)} windows")
    print(f"Train positive rate: {y_train.mean():.3f} | Test positive rate: {y_test.mean():.3f}")

    model = RandomForestClassifier(
        n_estimators=300, max_depth=8, min_samples_leaf=2,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)

    print("\n=== Classification Report (threshold=0.5) ===")
    report = classification_report(y_test, preds, output_dict=True, zero_division=0)
    print(classification_report(y_test, preds, zero_division=0))

    if y_test.nunique() > 1:
        auc = roc_auc_score(y_test, proba)
    else:
        auc = float("nan")
    print(f"ROC-AUC: {auc}")

    importances = pd.Series(model.feature_importances_, index=feat_cols).sort_values(ascending=False)
    top_features = importances.head(15)
    print("\n=== Top 15 Features ===")
    print(top_features)

    test_df = test_df.reset_index(drop=True)
    test_df["risk_score"] = proba
    test_df["predicted_alert"] = preds

    attack_windows = test_df.index[test_df["label_attack_now"] == 1].tolist()
    lead_times = []
    for aw in attack_windows:
        lookback_start = max(0, aw - FORECAST_HORIZON - 2)
        window_slice = test_df.iloc[lookback_start:aw]
        alerted = window_slice.index[window_slice["predicted_alert"] == 1]
        if len(alerted) > 0:
            lead_times.append(aw - alerted.min())

    avg_lead_time = float(np.mean(lead_times)) if lead_times else 0.0
    detection_rate = len(lead_times) / len(attack_windows) if attack_windows else 0.0

    print(f"\n=== Forecasting Performance ===")
    print(f"Attack windows in test set: {len(attack_windows)}")
    print(f"Attacks with advance warning: {len(lead_times)} ({100*detection_rate:.1f}%)")
    print(f"Average lead time: {avg_lead_time:.1f} windows before attack")

    test_df.to_csv("predictions_real.csv", index=False)
    top_features.to_csv("feature_importance_real.csv", header=["importance"])

    summary = {
        "roc_auc": None if np.isnan(auc) else round(auc, 3),
        "precision": round(report.get("1", {}).get("precision", 0), 3),
        "recall": round(report.get("1", {}).get("recall", 0), 3),
        "f1": round(report.get("1", {}).get("f1-score", 0), 3),
        "attack_windows_test": len(attack_windows),
        "attacks_with_warning": len(lead_times),
        "detection_rate": round(detection_rate, 3),
        "avg_lead_time_windows": round(avg_lead_time, 2),
        "forecast_horizon": FORECAST_HORIZON,
        "data_source": "CICIDS2017 Friday Afternoon DDoS capture (real)",
        "n_flows_used": 225711,
        "window_size_flows": 500,
    }
    with open("model_summary_real.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\nSaved: predictions_real.csv, feature_importance_real.csv, model_summary_real.json")
    return model, test_df, summary


if __name__ == "__main__":
    train_and_evaluate()
