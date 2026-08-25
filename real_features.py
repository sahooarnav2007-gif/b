"""
real_features.py
-----------------
Same rolling-window + forward-looking-label logic as features.py,
adapted for the real CICIDS2017-derived traffic_real.csv (no source-IP
column in this export, so threat-intel correlation is stubbed to 0).
"""

import numpy as np
import pandas as pd

FORECAST_HORIZON = 6
ROLL_WINDOWS = [3, 6, 12]

RAW_FEATURES = [
    "packet_rate", "byte_rate", "unique_dst_ips", "unique_dst_ports",
    "syn_ack_ratio", "avg_pkt_size", "dst_port_entropy", "failed_conn_rate",
]


def add_rolling_features(df):
    out = df.copy()
    for w in ROLL_WINDOWS:
        for col in RAW_FEATURES:
            out[f"{col}_ma{w}"] = df[col].rolling(w, min_periods=1).mean()
            out[f"{col}_std{w}"] = df[col].rolling(w, min_periods=1).std().fillna(0)
        out[f"portcount_slope{w}"] = df["unique_dst_ports"].diff(w).fillna(0)
        out[f"entropy_slope{w}"] = df["dst_port_entropy"].diff(w).fillna(0)
    return out


def add_forecast_labels(df, horizon=FORECAST_HORIZON):
    n = len(df)
    y = np.zeros(n, dtype=int)
    windows_to_attack = np.full(n, -1)
    attack_idx = df.index[df["label_attack_now"] == 1].to_numpy()

    for t in range(n):
        future_slice = attack_idx[(attack_idx > t) & (attack_idx <= t + horizon)]
        if len(future_slice) > 0:
            y[t] = 1
            windows_to_attack[t] = int(future_slice.min() - t)

    out = df.copy()
    out["y_forecast"] = y
    out["windows_to_attack"] = windows_to_attack
    # stub threat-intel columns so downstream code (same feature schema) still works
    out["intel_match"] = 0
    out["intel_confidence"] = 0.0
    return out


def build_dataset():
    traffic = pd.read_csv("traffic_real.csv")
    df = add_rolling_features(traffic)
    df = add_forecast_labels(df)
    df.to_csv("features_real.csv", index=False)
    print(f"Feature set built: {df.shape[0]} rows, {df.shape[1]} columns")
    print(f"Positive forecast windows (attack within next {FORECAST_HORIZON}): "
          f"{df['y_forecast'].sum()} / {len(df)} ({100*df['y_forecast'].mean():.1f}%)")
    return df


if __name__ == "__main__":
    build_dataset()
