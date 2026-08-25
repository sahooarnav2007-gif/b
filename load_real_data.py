"""
load_real_data.py
------------------
Replaces the synthetic generator with REAL CICIDS2017 flow data
(Friday Afternoon DDoS capture).

The raw file is per-FLOW (one row = one completed network flow), not
per-time-window, and has no timestamp column in this distribution.
Flows are stored in capture order, so we treat sequential row order as
a time proxy and bucket flows into fixed-size windows (like grouping
raw packets into 30s buckets in a live sensor).

Output: traffic.csv with the SAME column schema as the synthetic
generator produced, so features.py and train_model.py work unchanged.
"""

import numpy as np
import pandas as pd

RAW_FILE = "dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
WINDOW_SIZE = 500   # flows per window (~44 windows total from 225k flows)
FORECAST_HORIZON = 6


def load_raw():
    df = pd.read_csv(RAW_FILE)
    df.columns = [c.strip() for c in df.columns]
    # replace inf (Flow Bytes/s can divide by ~0 duration) and drop broken rows
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=["Flow Bytes/s", "Flow Packets/s", "Flow Duration"])
    df["is_attack"] = (df["Label"] != "BENIGN").astype(int)
    return df


def bucket_into_windows(df, window_size=WINDOW_SIZE):
    n_windows = len(df) // window_size
    rows = []
    for w in range(n_windows):
        chunk = df.iloc[w * window_size:(w + 1) * window_size]
        attack_frac = chunk["is_attack"].mean()

        # Map real CICIDS flow features onto the same feature names
        # the rest of the pipeline (features.py) already expects.
        row = {
            "window_id": w,
            "packet_rate": chunk["Flow Packets/s"].clip(upper=1e6).mean(),
            "byte_rate": chunk["Flow Bytes/s"].clip(upper=1e8).mean(),
            "unique_dst_ips": chunk["Destination Port"].nunique(),  # proxy: no dst IP col in this export
            "unique_dst_ports": chunk["Destination Port"].nunique(),
            "syn_ack_ratio": (chunk["SYN Flag Count"].sum() + 1) / (chunk["ACK Flag Count"].sum() + 1),
            "avg_pkt_size": chunk["Average Packet Size"].mean(),
            "dst_port_entropy": _entropy(chunk["Destination Port"]),
            "failed_conn_rate": chunk["RST Flag Count"].sum() / len(chunk),
            "src_ip_flag": "",           # no IP column in this export; intel matching disabled for real-data run
            "attack_type": "ddos" if attack_frac > 0.5 else "none",
            "label_attack_now": int(attack_frac > 0.5),
            "attack_fraction": round(float(attack_frac), 3),  # kept for reference/plots
        }
        rows.append(row)
    return pd.DataFrame(rows)


def _entropy(series):
    counts = series.value_counts(normalize=True)
    return float(-(counts * np.log2(counts + 1e-12)).sum())


def main():
    print("Loading raw CICIDS2017 DDoS capture...")
    raw = load_raw()
    print(f"Loaded {len(raw)} flows ({raw['is_attack'].mean()*100:.1f}% attack)")

    windows = bucket_into_windows(raw)
    print(f"Bucketed into {len(windows)} windows of {WINDOW_SIZE} flows each")
    print(f"Attack windows: {windows['label_attack_now'].sum()} / {len(windows)}")

    windows.to_csv("traffic_real.csv", index=False)
    print("Saved traffic_real.csv")

    # also drop a minimal threat_intel.csv (empty/placeholder — real export has no IPs)
    pd.DataFrame(columns=["ip", "attack_type", "mitre_technique", "confidence"]).to_csv(
        "threat_intel_real.csv", index=False
    )
    print("Saved placeholder threat_intel_real.csv (no IP column in this CICIDS export)")


if __name__ == "__main__":
    main()
