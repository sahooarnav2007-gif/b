"""
lstm_world_model.py
--------------------
A real LSTM implemented from scratch in NumPy (no torch/tensorflow available
in this offline environment — full forward pass, backprop-through-time (BPTT),
and Adam optimizer are hand-written below, not a wrapper around a library).

This directly targets the PS26153 requirement: "Learn state-transition
dynamics using sequence models (LSTM, Transformer)... operating over
time-windowed traffic observations" — NOT a static classifier.

Architecture:
  Input:  sequence of SEQ_LEN consecutive traffic windows, each a vector of
          RAW traffic features (packet rate, byte rate, port entropy, etc.)
          -- this is literally "network state S_t" at each timestep.
  LSTM:   single layer, learns P(relevant future state | S_t, S_t-1, ..., S_t-k)
  Output: binary probability -- will an attack occur in the next
          FORECAST_HORIZON windows, given the trajectory just observed.

Explainability: saliency maps (gradient of the output probability w.r.t.
each input timestep/feature) — a standard, legitimate attention-free
feature-attribution technique, satisfying the "explainability" requirement
without needing the (unavailable) SHAP library.
"""

import numpy as np
import pandas as pd
import json

np.random.seed(42)

SEQ_LEN = 12          # how many past windows the LSTM looks at
HIDDEN_SIZE = 24
FORECAST_HORIZON = 6
EPOCHS = 40
LR = 0.01
BATCH_SIZE = 32

RAW_FEATURES = [
    "packet_rate", "byte_rate", "unique_dst_ports", "syn_ack_ratio",
    "avg_pkt_size", "dst_port_entropy", "failed_conn_rate", "fwd_psh_rate",
]

TRAIN_DAYS = ["monday", "tuesday", "wednesday", "thursday_web", "thursday_infil"]
TEST_DAYS  = ["friday_morning", "friday_portscan", "friday_ddos"]


def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -30, 30)))


def tanh(x):
    return np.tanh(x)


class NumpyLSTM:
    """Single-layer LSTM, many-to-one, binary output. Pure NumPy."""

    def __init__(self, input_size, hidden_size):
        self.input_size = input_size
        self.hidden_size = hidden_size
        H, D = hidden_size, input_size
        scale = 1.0 / np.sqrt(H + D)
        # combined weight matrices for [forget, input, cand, output] gates
        self.Wf = np.random.randn(H, H + D) * scale
        self.Wi = np.random.randn(H, H + D) * scale
        self.Wc = np.random.randn(H, H + D) * scale
        self.Wo = np.random.randn(H, H + D) * scale
        self.bf = np.zeros(H)
        self.bi = np.zeros(H)
        self.bc = np.zeros(H)
        self.bo = np.zeros(H)
        # output head: hidden -> scalar logit
        self.Wy = np.random.randn(1, H) * scale
        self.by = np.zeros(1)

        self.params = ["Wf", "Wi", "Wc", "Wo", "bf", "bi", "bc", "bo", "Wy", "by"]
        # Adam optimizer state
        self.m = {p: np.zeros_like(getattr(self, p)) for p in self.params}
        self.v = {p: np.zeros_like(getattr(self, p)) for p in self.params}
        self.t = 0

    def forward(self, x_seq):
        """x_seq: (T, D). Returns prob, cache for backward pass."""
        T = len(x_seq)
        H = self.hidden_size
        h = np.zeros(H)
        c = np.zeros(H)
        cache = []
        for t in range(T):
            z = np.concatenate([h, x_seq[t]])
            f = sigmoid(self.Wf @ z + self.bf)
            i = sigmoid(self.Wi @ z + self.bi)
            g = tanh(self.Wc @ z + self.bc)
            o = sigmoid(self.Wo @ z + self.bo)
            c_new = f * c + i * g
            h_new = o * tanh(c_new)
            cache.append((z, f, i, g, o, c, c_new, h, h_new))
            h, c = h_new, c_new
        logit = self.Wy @ h + self.by
        prob = sigmoid(logit)[0]
        return prob, cache, h

    def backward(self, x_seq, y_true, prob, cache):
        """Full BPTT. Returns grads dict."""
        H = self.hidden_size
        T = len(x_seq)
        grads = {p: np.zeros_like(getattr(self, p)) for p in self.params}

        dlogit = (prob - y_true)  # d(BCE loss)/d(logit) for sigmoid output
        h_final = cache[-1][8]
        grads["Wy"] += np.outer([dlogit], h_final)
        grads["by"] += np.array([dlogit])

        dh_next = (self.Wy.T @ np.array([dlogit])).flatten()
        dc_next = np.zeros(H)

        for t in reversed(range(T)):
            z, f, i, g, o, c_prev, c_new, h_prev, h_new = cache[t]
            dh = dh_next
            do = dh * tanh(c_new)
            do_raw = do * o * (1 - o)

            dc = dh * o * (1 - tanh(c_new) ** 2) + dc_next
            df = dc * c_prev
            df_raw = df * f * (1 - f)
            di = dc * g
            di_raw = di * i * (1 - i)
            dg = dc * i
            dg_raw = dg * (1 - g ** 2)

            grads["Wf"] += np.outer(df_raw, z)
            grads["Wi"] += np.outer(di_raw, z)
            grads["Wc"] += np.outer(dg_raw, z)
            grads["Wo"] += np.outer(do_raw, z)
            grads["bf"] += df_raw
            grads["bi"] += di_raw
            grads["bc"] += dg_raw
            grads["bo"] += do_raw

            dz = (self.Wf.T @ df_raw + self.Wi.T @ di_raw +
                  self.Wc.T @ dg_raw + self.Wo.T @ do_raw)
            dh_next = dz[:H]
            dc_next = dc * f

        # clip gradients (standard LSTM stabilization)
        for p in grads:
            np.clip(grads[p], -5, 5, out=grads[p])
        return grads

    def adam_step(self, grads, lr=LR, beta1=0.9, beta2=0.999, eps=1e-8):
        self.t += 1
        for p in self.params:
            g = grads[p]
            self.m[p] = beta1 * self.m[p] + (1 - beta1) * g
            self.v[p] = beta2 * self.v[p] + (1 - beta2) * (g ** 2)
            m_hat = self.m[p] / (1 - beta1 ** self.t)
            v_hat = self.v[p] / (1 - beta2 ** self.t)
            update = lr * m_hat / (np.sqrt(v_hat) + eps)
            setattr(self, p, getattr(self, p) - update)

    def predict_proba(self, x_seq):
        prob, _, _ = self.forward(x_seq)
        return prob

    def saliency(self, x_seq):
        """Gradient of output probability w.r.t. each input timestep/feature.
        A standard, legitimate feature-attribution technique (no SHAP needed)."""
        prob, cache, h_final = self.forward(x_seq)
        grads = self.backward(x_seq, 0.0, prob, cache)  # dummy target, we only need dz path
        # Recompute input-gradients specifically (re-run backward tracking dz w.r.t x)
        H = self.hidden_size
        T = len(x_seq)
        dlogit = prob * (1 - prob)  # d(prob)/d(logit) at prob itself (not loss)
        dh_next = (self.Wy.T * dlogit).flatten()
        dc_next = np.zeros(H)
        input_grads = np.zeros((T, self.input_size))
        for t in reversed(range(T)):
            z, f, i, g, o, c_prev, c_new, h_prev, h_new = cache[t]
            dh = dh_next
            do = dh * tanh(c_new)
            do_raw = do * o * (1 - o)
            dc = dh * o * (1 - tanh(c_new) ** 2) + dc_next
            df = dc * c_prev
            df_raw = df * f * (1 - f)
            di = dc * g
            di_raw = di * i * (1 - i)
            dg = dc * i
            dg_raw = dg * (1 - g ** 2)
            dz = (self.Wf.T @ df_raw + self.Wi.T @ di_raw +
                  self.Wc.T @ dg_raw + self.Wo.T @ do_raw)
            input_grads[t] = dz[H:]
            dh_next = dz[:H]
            dc_next = dc * f
        return input_grads


def build_sequences(df, feat_cols, seq_len=SEQ_LEN):
    """For each day, build overlapping sequences of length seq_len ending at
    window t, with target y_forecast[t]."""
    X, y, meta = [], [], []
    for day, g in df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        vals = g[feat_cols].values
        targets = g["y_forecast"].values
        for t in range(seq_len - 1, len(g)):
            X.append(vals[t - seq_len + 1: t + 1])
            y.append(targets[t])
            meta.append((day, g.loc[t, "window_id"], g.loc[t, "label_attack_now"]))
    return X, np.array(y), meta


def normalize_features(train_seqs, *other_seqs):
    """Z-score normalize using train statistics only (no leakage)."""
    all_train = np.concatenate(train_seqs, axis=0)
    mu = all_train.mean(axis=0)
    sigma = all_train.std(axis=0) + 1e-6
    def norm(seqs):
        return [(s - mu) / sigma for s in seqs]
    train_norm = norm(train_seqs)
    others_norm = [norm(s) for s in other_seqs]
    return train_norm, others_norm, mu, sigma


def train():
    df = pd.read_csv("full_features.csv")
    train_df = df[df.day.isin(TRAIN_DAYS)]
    test_df = df[df.day.isin(TEST_DAYS)]

    # Carve a validation split OUT of the training days (last 20% of each
    # training day, by time) so we can early-stop before the model starts
    # memorizing train-day noise instead of learning transferable dynamics.
    tr_parts, val_parts = [], []
    for day, g in train_df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        split = int(len(g) * 0.8)
        tr_parts.append(g.iloc[:split])
        val_parts.append(g.iloc[split:])
    tr_df = pd.concat(tr_parts, ignore_index=True)
    val_df = pd.concat(val_parts, ignore_index=True)

    Xtr, ytr, meta_tr = build_sequences(tr_df, RAW_FEATURES)
    Xval, yval, meta_val = build_sequences(val_df, RAW_FEATURES)
    Xte, yte, meta_te = build_sequences(test_df, RAW_FEATURES)
    print(f"Train sequences: {len(Xtr)} | Val sequences: {len(Xval)} | Test sequences: {len(Xte)}")
    print(f"Train positive rate: {ytr.mean():.3f} | Val positive rate: {yval.mean():.3f} | "
          f"Test positive rate: {yte.mean():.3f}")

    Xtr_n, (Xval_n, Xte_n), mu, sigma = normalize_features(Xtr, Xval, Xte)

    model = NumpyLSTM(input_size=len(RAW_FEATURES), hidden_size=HIDDEN_SIZE)

    n = len(Xtr_n)
    idx_all = np.arange(n)
    from sklearn.metrics import roc_auc_score, classification_report

    print(f"\nTraining LSTM world model (up to {EPOCHS} epochs, hidden={HIDDEN_SIZE}, "
          f"seq_len={SEQ_LEN}, early stopping on val AUC)...")
    best_val_auc = -1
    best_weights = None
    patience, patience_left = 5, 5
    l2 = 1e-4

    for epoch in range(EPOCHS):
        np.random.shuffle(idx_all)
        total_loss = 0.0
        for idx in idx_all:
            x_seq, y_true = Xtr_n[idx], ytr[idx]
            prob, cache, h = model.forward(x_seq)
            prob_c = np.clip(prob, 1e-7, 1 - 1e-7)
            loss = -(y_true * np.log(prob_c) + (1 - y_true) * np.log(1 - prob_c))
            total_loss += loss
            grads = model.backward(x_seq, y_true, prob, cache)
            # light L2 weight decay to fight overfitting
            for p in ["Wf", "Wi", "Wc", "Wo", "Wy"]:
                grads[p] += l2 * getattr(model, p)
            model.adam_step(grads)
        avg_loss = total_loss / n

        val_probs = np.array([model.predict_proba(x) for x in Xval_n])
        val_auc = roc_auc_score(yval, val_probs) if len(set(yval)) > 1 else 0.5
        print(f"  epoch {epoch+1}/{EPOCHS}  loss={avg_loss:.4f}  val_auc={val_auc:.3f}")

        if val_auc > best_val_auc:
            best_val_auc = val_auc
            best_weights = {p: getattr(model, p).copy() for p in model.params}
            patience_left = patience
        else:
            patience_left -= 1
            if patience_left <= 0:
                print(f"  early stopping (no val improvement for {patience} epochs)")
                break

    # restore best checkpoint
    for p, val in best_weights.items():
        setattr(model, p, val)
    print(f"\nBest validation AUC: {best_val_auc:.3f} (restored that checkpoint)")

    print("\nEvaluating on held-out Friday (unseen day)...")
    test_probs = np.array([model.predict_proba(x) for x in Xte_n])
    test_preds = (test_probs >= 0.5).astype(int)

    print(classification_report(yte, test_preds, zero_division=0))
    auc = roc_auc_score(yte, test_probs) if len(set(yte)) > 1 else float("nan")
    print(f"ROC-AUC: {auc:.3f}")

    # Save model weights + results
    weights = {p: getattr(model, p).tolist() for p in model.params}
    with open("lstm_weights.json", "w") as f:
        json.dump({"weights": weights, "mu": mu.tolist(), "sigma": sigma.tolist(),
                    "features": RAW_FEATURES, "seq_len": SEQ_LEN, "hidden_size": HIDDEN_SIZE}, f)

    results_df = pd.DataFrame(meta_te, columns=["day", "window_id", "label_attack_now"])
    results_df["risk_score"] = test_probs
    results_df["predicted_alert"] = test_preds
    results_df["y_forecast"] = yte
    results_df.to_csv("lstm_predictions.csv", index=False)

    report = classification_report(yte, test_preds, output_dict=True, zero_division=0)
    summary = {
        "model": "NumPy LSTM (from scratch, BPTT + Adam)",
        "seq_len": SEQ_LEN, "hidden_size": HIDDEN_SIZE, "epochs": EPOCHS,
        "roc_auc": None if np.isnan(auc) else round(auc, 3),
        "precision": round(report.get("1", {}).get("precision", 0), 3),
        "recall": round(report.get("1", {}).get("recall", 0), 3),
        "f1": round(report.get("1", {}).get("f1-score", 0), 3),
        "n_train_sequences": len(Xtr), "n_test_sequences": len(Xte),
    }
    with open("lstm_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved lstm_weights.json, lstm_predictions.csv, lstm_summary.json")

    # ================================================================
    # SECOND EVAL: within-day time-split (matches full_train.py's RF
    # methodology exactly) — gives an apples-to-apples LSTM vs RandomForest
    # vs LogisticRegression comparison, not just the harder cross-day stress test.
    # ================================================================
    print("\n\n========== SECONDARY EVAL: within-day time-split (all 8 days) ==========")
    wtr_parts, wval_parts, wte_parts = [], [], []
    for day, g in df.groupby("day", sort=False):
        g = g.reset_index(drop=True)
        split1 = int(len(g) * 0.6)
        split2 = int(len(g) * 0.7)
        wtr_parts.append(g.iloc[:split1])
        wval_parts.append(g.iloc[split1:split2])
        wte_parts.append(g.iloc[split2:])
    wtr_df = pd.concat(wtr_parts, ignore_index=True)
    wval_df = pd.concat(wval_parts, ignore_index=True)
    wte_df = pd.concat(wte_parts, ignore_index=True)

    Xwtr, ywtr, _ = build_sequences(wtr_df, RAW_FEATURES)
    Xwval, ywval, _ = build_sequences(wval_df, RAW_FEATURES)
    Xwte, ywte, meta_wte = build_sequences(wte_df, RAW_FEATURES)
    print(f"Train: {len(Xwtr)} | Val: {len(Xwval)} | Test: {len(Xwte)}")

    Xwtr_n, (Xwval_n, Xwte_n), wmu, wsigma = normalize_features(Xwtr, Xwval, Xwte)

    wmodel = NumpyLSTM(input_size=len(RAW_FEATURES), hidden_size=HIDDEN_SIZE)
    n2 = len(Xwtr_n)
    idx2 = np.arange(n2)
    best_val_auc2, best_w2, patience_left2 = -1, None, patience
    for epoch in range(EPOCHS):
        np.random.shuffle(idx2)
        for idx in idx2:
            x_seq, y_true = Xwtr_n[idx], ywtr[idx]
            prob, cache, h = wmodel.forward(x_seq)
            grads = wmodel.backward(x_seq, y_true, prob, cache)
            for p in ["Wf", "Wi", "Wc", "Wo", "Wy"]:
                grads[p] += l2 * getattr(wmodel, p)
            wmodel.adam_step(grads)
        val_probs2 = np.array([wmodel.predict_proba(x) for x in Xwval_n])
        val_auc2 = roc_auc_score(ywval, val_probs2) if len(set(ywval)) > 1 else 0.5
        print(f"  epoch {epoch+1}/{EPOCHS}  val_auc={val_auc2:.3f}")
        if val_auc2 > best_val_auc2:
            best_val_auc2 = val_auc2
            best_w2 = {p: getattr(wmodel, p).copy() for p in wmodel.params}
            patience_left2 = patience
        else:
            patience_left2 -= 1
            if patience_left2 <= 0:
                print(f"  early stopping")
                break
    for p, val in best_w2.items():
        setattr(wmodel, p, val)

    wte_probs = np.array([wmodel.predict_proba(x) for x in Xwte_n])
    wte_preds = (wte_probs >= 0.5).astype(int)
    print(classification_report(ywte, wte_preds, zero_division=0))
    wauc = roc_auc_score(ywte, wte_probs) if len(set(ywte)) > 1 else float("nan")
    print(f"ROC-AUC: {wauc:.3f}")

    wreport = classification_report(ywte, wte_preds, output_dict=True, zero_division=0)
    within_day_summary = {
        "roc_auc": None if np.isnan(wauc) else round(wauc, 3),
        "precision": round(wreport.get("1", {}).get("precision", 0), 3),
        "recall": round(wreport.get("1", {}).get("recall", 0), 3),
        "f1": round(wreport.get("1", {}).get("f1-score", 0), 3),
    }
    summary["within_day_eval"] = within_day_summary
    with open("lstm_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    wte_results = pd.DataFrame(meta_wte, columns=["day", "window_id", "label_attack_now"])
    wte_results["risk_score"] = wte_probs
    wte_results["predicted_alert"] = wte_preds
    wte_results.to_csv("lstm_within_day_predictions.csv", index=False)
    print("\nUpdated lstm_summary.json with within_day_eval block")
    return model, summary


if __name__ == "__main__":
    train()
