"""
processing.py
--------------
The exact same windowing + feature engineering logic used in full_pipeline.py,
extracted into importable functions so app.py can process a freshly uploaded
CSV with IDENTICAL logic to what the models were trained on. Keeping this in
one place (instead of copy-pasting into app.py) avoids train/inference skew,
a common and easy-to-miss bug in ML demo apps.
"""

import numpy as np
import pandas as pd

WINDOW_SIZE = 500
ROLL_WINDOWS = [3, 6, 12]
SEQ_LEN = 12

RAW_FEATURES = [
    "packet_rate", "byte_rate", "unique_dst_ips", "unique_dst_ports",
    "syn_ack_ratio", "avg_pkt_size", "dst_port_entropy", "failed_conn_rate",
    "fwd_psh_rate", "avg_flow_duration",
]
LSTM_FEATURES = [
    "packet_rate", "byte_rate", "unique_dst_ports", "syn_ack_ratio",
    "avg_pkt_size", "dst_port_entropy", "failed_conn_rate", "fwd_psh_rate",
]

REQUIRED_RAW_COLUMNS = [
    "Flow Bytes/s", "Flow Packets/s", "Flow Duration", "Destination Port",
    "SYN Flag Count", "ACK Flag Count", "Average Packet Size", "RST Flag Count",
    "Fwd PSH Flags",
]

MITRE_MAP = {
    "BENIGN": ("none", "-"),
    "FTP-Patator": ("brute_force", "TA0006 Credential Access / T1110.001 Password Guessing"),
    "SSH-Patator": ("brute_force", "TA0006 Credential Access / T1110.001 Password Guessing"),
    "DoS Hulk": ("dos", "TA0040 Impact / T1499 Endpoint DoS"),
    "DoS GoldenEye": ("dos", "TA0040 Impact / T1499 Endpoint DoS"),
    "DoS slowloris": ("dos", "TA0040 Impact / T1499 Endpoint DoS"),
    "DoS Slowhttptest": ("dos", "TA0040 Impact / T1499 Endpoint DoS"),
    "Heartbleed": ("exploit", "TA0006 Credential Access / T1212 Exploitation for Credential Access"),
    "Infiltration": ("infiltration", "TA0001 Initial Access / T1091 Replication Through Removable Media"),
    "Bot": ("botnet", "TA0011 Command and Control / T1071 Application Layer Protocol"),
    "PortScan": ("port_scan", "TA0043 Reconnaissance / T1595 Active Scanning"),
    "DDoS": ("dos", "TA0040 Impact / T1498 Network Denial of Service"),
}

KILL_CHAIN_MAP = {
    "port_scan": "Reconnaissance",
    "brute_force": "Initial Access",
    "web_attack": "Initial Access",
    "infiltration": "Initial Access",
    "botnet": "Command & Control",
    "dos": "Impact (not one of the 5 PS-listed stages)",
    "exploit": "Initial Access",
    "none": "-",
    "unknown": "-",
}


def map_label_to_family(label):
    if label in MITRE_MAP:
        return MITRE_MAP[label]
    if "Web Attack" in str(label):
        return ("web_attack", "TA0001 Initial Access / T1190 Exploit Public-Facing Application")
    return ("unknown", "unmapped")


def _entropy(series):
    counts = series.value_counts(normalize=True)
    return float(-(counts * np.log2(counts + 1e-12)).sum())


def window_flows(df, window_size=WINDOW_SIZE, has_labels=True):
    """Turns a raw CICIDS-format flow CSV into windowed feature rows.
    Works whether or not a 'Label' column is present (real deployment
    traffic won't have ground-truth labels)."""
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=["Flow Bytes/s", "Flow Packets/s", "Flow Duration"])

    if has_labels and "Label" in df.columns:
        df["Label"] = df["Label"].astype(str).str.strip()
        df["is_attack"] = (df["Label"] != "BENIGN").astype(int)
    else:
        has_labels = False

    n_windows = len(df) // window_size
    rows = []
    for w in range(n_windows):
        chunk = df.iloc[w * window_size:(w + 1) * window_size]
        row = {
            "window_id": w,
            "packet_rate": chunk["Flow Packets/s"].clip(upper=1e6).mean(),
            "byte_rate": chunk["Flow Bytes/s"].clip(upper=1e8).mean(),
            "unique_dst_ips": chunk["Destination Port"].nunique(),
            "unique_dst_ports": chunk["Destination Port"].nunique(),
            "syn_ack_ratio": (chunk["SYN Flag Count"].sum() + 1) / (chunk["ACK Flag Count"].sum() + 1),
            "avg_pkt_size": chunk["Average Packet Size"].mean(),
            "dst_port_entropy": _entropy(chunk["Destination Port"]),
            "failed_conn_rate": chunk["RST Flag Count"].sum() / len(chunk),
            "fwd_psh_rate": chunk["Fwd PSH Flags"].sum() / len(chunk),
            "avg_flow_duration": chunk["Flow Duration"].mean(),
        }
        if has_labels:
            attack_frac = chunk["is_attack"].mean()
            non_benign = chunk[chunk["Label"] != "BENIGN"]["Label"]
            dominant = non_benign.mode().iloc[0] if len(non_benign) > 0 else "BENIGN"
            family, mitre = map_label_to_family(dominant)
            is_attack_window = int(attack_frac > 0.01)
            row["label_attack_now"] = is_attack_window
            row["attack_fraction"] = round(float(attack_frac), 3)
            row["true_attack_family"] = family if is_attack_window else "none"
        rows.append(row)
    return pd.DataFrame(rows)


def add_rolling_features(wdf):
    """Same rolling-window logic used at training time (single 'day' — no
    day grouping needed here since this is one uploaded file)."""
    g = wdf.copy()
    for w in ROLL_WINDOWS:
        for col in RAW_FEATURES:
            g[f"{col}_ma{w}"] = g[col].rolling(w, min_periods=1).mean()
            g[f"{col}_std{w}"] = g[col].rolling(w, min_periods=1).std().fillna(0)
        g[f"portcount_slope{w}"] = g["unique_dst_ports"].diff(w).fillna(0)
        g[f"entropy_slope{w}"] = g["dst_port_entropy"].diff(w).fillna(0)
    return g


def build_lstm_sequences(feat_df, seq_len=SEQ_LEN):
    """Returns list of (window_id, sequence array) for every window that has
    enough history (>= seq_len prior windows including itself)."""
    vals = feat_df[LSTM_FEATURES].values
    out = []
    for t in range(seq_len - 1, len(feat_df)):
        out.append((int(feat_df.iloc[t]["window_id"]), vals[t - seq_len + 1: t + 1]))
    return out
