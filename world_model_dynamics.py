"""
world_model_dynamics.py
-----------------------
Concrete evidence for the "World Model" claim in SIH26153: the PS wants a model
that learns state-transition dynamics P(S_t+1 | S_t) over network state, not a
static classifier. This script:

  1. Builds the EMPIRICAL transition matrix of the observed network macro-states
     (SAFE -> INCOMING -> ATTACK, plus back-transitions) from the full CICIDS2017
     week, window to window.
  2. Runs the saved NumPy LSTM over the same sequence and measures how well its
     risk forecast at time t predicts the actual next-window state S_t+1:
     - next-ATTACK-window AUC
     - a LOW/MED/HIGH-risk (t) x  {safe, incoming, attack} (t+1) contingency
  3. Writes world_model_dynamics.json (matrices + metrics) and prints a summary.

Usage:  python3 world_model_dynamics.py
"""

import json

import pandas as pd
from sklearn.metrics import roc_auc_score

from infer import LSTMEngine

STATE_NAMES = {0: "SAFE", 1: "INCOMING", 2: "ATTACK"}
RISK_BINS = [(0.0, 0.4, "LOW"), (0.4, 0.6, "MED"), (0.6, 1.01, "HIGH")]


def macro_state(row):
    if row["label_attack_now"] == 1:
        return 2
    if row["y_forecast"] == 1:
        return 1
    return 0


def risk_bin(risk):
    for lo, hi, name in RISK_BINS:
        if lo <= risk < hi:
            return name
    return "HIGH"


def main():
    df = pd.read_csv("full_features.csv")
    df.columns = [c.strip() for c in df.columns]

    # empirical next-window transitions, per-day (no cross-day jumps)
    trans = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
    pairs = 0
    states = {}
    for day, g in df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        st = [macro_state(r) for _, r in g.iterrows()]
        for i in range(len(st) - 1):
            trans[st[i]][st[i + 1]] += 1
            pairs += 1
            states[(day, i)] = st[i]
        states[(day, len(g) - 1)] = st[-1]

    # LSTM next-window forecast
    risks = {}
    next_label = {}
    engine_template = dict(
        weights_path="lstm_weights.json", threshold=0.5)
    for day, g in df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        eng = LSTMEngine(**engine_template)
        for i, row in g.iterrows():
            raw = {c: float(row[c]) for c in eng.features}
            pred = eng.predict(raw, raw)
            if pred is None:
                risks[(day, i)] = None
                continue
            risks[(day, i)] = pred[0]
            if i + 1 < len(g):
                next_label[(day, i)] = int(g.iloc[i + 1]["label_attack_now"])

    pairs_lstm = [(day, i) for (day, i), r in risks.items()
                  if r is not None and (day, i) in next_label]
    y_true = [next_label[p] for p in pairs_lstm]
    y_score = [risks[p] for p in pairs_lstm]
    auc = roc_auc_score(y_true, y_score) if len(set(y_true)) > 1 else 0.0

    cont = {}
    for name in ["LOW", "MED", "HIGH"]:
        cont[name] = {"safe": 0, "incoming": 0, "attack": 0}
    for p, r in risks.items():
        if r is None:
            continue
        day, i = p
        if (day, i + 1) not in states:
            continue
        s_next = states[(day, i + 1)]
        key = {0: "safe", 1: "incoming", 2: "attack"}[s_next]
        cont[risk_bin(r)][key] += 1

    emp = [[trans[i][j] for j in range(3)] for i in range(3)]
    emp_prob = [
        [round(trans[i][j] / max(sum(trans[i]), 1), 3) for j in range(3)]
        for i in range(3)
    ]

    summary = {
        "empirical_next_window_state_transitions": {
            "rows": STATE_NAMES,
            "counts": emp,
            "row_normalized_probabilities": emp_prob,
        },
        "lstm_next_attack_window_auc": round(float(auc), 3),
        "n_forecast_pairs": len(pairs_lstm),
        "risk_t_vs_actual_state_t1_contingency": cont,
    }
    with open("world_model_dynamics.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("=== Empirical P(S_t+1 | S_t) — counts ===")
    print("            safe   incoming  attack")
    for i, name in enumerate(STATE_NAMES.values()):
        print(f"{name:9s} {emp[i]}")
    print(f"\nLSTM next-ATTACK-window AUC: {auc:.3f}  (n={len(pairs_lstm)})")
    print("Con: risk(t) -> actual state(t+1)")
    for k, v in cont.items():
        print(f"  {k:4s} {v}")
    print("\nSaved world_model_dynamics.json")


if __name__ == "__main__":
    main()