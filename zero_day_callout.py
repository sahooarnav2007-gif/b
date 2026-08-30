"""
zero_day_callout.py
-------------------
Zero-day / novel-malicious-activity callout for the early-warning pipeline.

The forecasters are supervised -- they are excellent at KNOWN attacks but have
no built-in notion of "I have never seen anything like this before." This module
adds that notion in a data-driven, honest way:

  * During evaluation we keep the FEATURE MANIFOLD of all KNOWN attack windows
    from the training corpus (full_features.csv, label_attack_now == 1).
  * For an attack-FLAGGED window during live inference we measure:
      1. novelty distance d  = mean distance to its k nearest known attack
                              windows (k=5), in z-scored feature space.
      2. novelty percentile  = where d falls relative to the distribution of
                              d among the known attack windows themselves
                              (if d > 95% of known attacks, the flagged window
                              lives OUTSIDE the known-attack manifold).
      3. family confidence   = max the family-classifier assigns across known
                              families (a novel attack typically gets a
                              flat/uncertain spread rather than a confident hit)
  * flag = novelty_percentile >= threshold (default 0.95)

Semantics: a flag is NOT "this is a zero-day attack" -- it is "this is clearly
malicious/anomalous (forecaster fired) but is unlike anything in our training
data, so the predicted family is probably wrong; an analyst should review it."
This is exactly the callout the supervised pipeline was missing.

Usage (inside infer.py)::

    from zero_day_callout import NoveltyStore
    ns = NoveltyStore(feature_cols)          # built once, lazily
    dists, pcts, flags = ns.evaluate(X_rows) # X_rows: (n, n_features) numpy
"""

import numpy as np
import pandas as pd

K = 5
DEFAULT_QUANTILE = 0.95


class NoveltyStore:
    """Nearest-neighbour novelty detector over known-attack windows."""

    def __init__(self, csv_path="full_features.csv", k=K,
                 quantile=DEFAULT_QUANTILE):
        self.k = k
        self.quantile = quantile
        self.feature_cols = None
        self.available = False
        try:
            self._atk = _load_attack_windows(csv_path)
        except FileNotFoundError:
            self._atk = None

    def build(self, feature_cols):
        """Compute mu/sigma, KD-tree, and within-known-attack distance baseline
        from the supplied feature column list (must match model input cols)."""
        if self._atk is None or len(self._atk) < self.k + 1:
            return
        self.feature_cols = list(feature_cols)
        X = self._atk[self.feature_cols].astype(float).values
        self.mu = X.mean(axis=0)
        self.sigma = X.std(axis=0) + 1e-9
        Z = (X - self.mu) / self.sigma
        if len(Z) <= self.k:
            return
        from scipy.spatial import cKDTree
        self.tree = cKDTree(Z)
        d, _ = self.tree.query(Z, k=self.k + 1)  # +1: self is its own neighbor
        # distance to the k-th (farthest of the k real) known neighbors
        self.base = np.asarray(d[:, -1])
        self.q95 = float(np.quantile(self.base, self.quantile))
        self.available = True

    def evaluate(self, X_rows):
        """X_rows: (n, n_features) aligned to feature_cols.

        Returns (distances, percentiles, flags)."""
        n = len(X_rows)
        if not self.available or n == 0:
            return (np.zeros(n), np.zeros(n), np.zeros(n, dtype=bool))
        Z = (np.asarray(X_rows, dtype=float) - self.mu) / self.sigma
        d, _ = self.tree.query(Z, k=self.k + 1)
        dd = np.asarray(d[:, -1]) if d.ndim == 2 else np.asarray([d[-1]])
        dist = np.atleast_1d(dd)
        pct = np.array([(self.base < x).mean() for x in dist])
        flags = pct >= self.quantile
        return dist, pct, flags

    def percentile(self, _dist):
        """Percentile of one novelty distance vs the known-attack baseline."""
        return float((self.base < _dist).mean())


def _load_attack_windows(csv_path):
    df = pd.read_csv(csv_path)
    df.columns = [c.strip() for c in df.columns]
    atk = df[df.get("label_attack_now").astype(int) == 1]
    if len(atk) < 2:
        raise FileNotFoundError(csv_path)
    return atk