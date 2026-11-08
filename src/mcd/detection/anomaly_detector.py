"""Hybrid unsupervised anomaly detection, trained locally on benign history.

Components (each calibrated to [0,1] against its own training-score distribution):
* ``iforest`` — Isolation Forest (global isolation of rare feature combinations)
* ``lof``     — Local Outlier Factor, novelty mode (local density deviation)
* ``stat``    — max |z| of the window against a per-entity EWMA baseline
                initialised from global training statistics

Calibration: p = empirical CDF of the training scores; a = clip((p - q)/(1 - q), 0, 1).
Values in the top (1-q) of *benign* training scores get a > 0, so the
anomaly score is an interpretable "how far into the benign tail" measure, not
a probability of maliciousness.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor


@dataclass
class AnomalyResult:
    score: float
    components: dict[str, float] = field(default_factory=dict)
    top_features: list[tuple[str, float, float]] = field(default_factory=list)


class _Calibrator:
    def __init__(self, train_scores: np.ndarray, q: float) -> None:
        self.sorted = np.sort(np.asarray(train_scores, dtype=float))
        self.q = q

    def __call__(self, s: np.ndarray) -> np.ndarray:
        if self.sorted.size == 0:
            return np.zeros_like(s, dtype=float)
        p = np.searchsorted(self.sorted, s, side="right") / self.sorted.size
        return np.clip((p - self.q) / (1.0 - self.q), 0.0, 1.0)


class HybridAnomalyDetector:
    def __init__(
        self,
        feature_names: list[str],
        *,
        components: tuple[str, ...] = ("iforest", "lof", "stat"),
        n_estimators: int = 64,
        lof_neighbors: int = 20,
        calib_q: float = 0.9,
        combine: str = "mean",
        ewma_alpha: float = 0.05,
        min_train: int = 15,
        seed: int = 0,
    ) -> None:
        self.names = feature_names
        self.components = components
        self.n_estimators = n_estimators
        self.lof_neighbors = lof_neighbors
        self.q = calib_q
        self.combine = combine
        self.alpha = ewma_alpha
        self.min_train = min_train
        self.seed = seed
        self.fitted = False
        self.ml_enabled = False
        self._entity: dict[str, tuple[np.ndarray, np.ndarray]] = {}

    # ------------------------------------------------------------------ fit
    def _std_floor(self, mean: np.ndarray, var: np.ndarray) -> np.ndarray:
        return np.maximum(np.sqrt(var), 0.01 + 0.1 * np.abs(mean))

    def fit(self, X: np.ndarray) -> "HybridAnomalyDetector":
        X = np.asarray(X, dtype=float).reshape(-1, len(self.names))
        if X.shape[0] == 0:
            X = np.zeros((1, len(self.names)))
        self.mean = X.mean(axis=0)
        self.var = X.var(axis=0)
        self.std = self._std_floor(self.mean, self.var)
        Z = (X - self.mean) / self.std
        self.cal: dict[str, _Calibrator] = {}
        if "stat" in self.components:
            self.cal["stat"] = _Calibrator(np.abs(Z).max(axis=1), self.q)
        self.ml_enabled = X.shape[0] >= self.min_train
        if self.ml_enabled and "iforest" in self.components:
            self.iforest = IsolationForest(n_estimators=self.n_estimators, random_state=self.seed).fit(Z)
            self.cal["iforest"] = _Calibrator(-self.iforest.score_samples(Z), self.q)
        if self.ml_enabled and "lof" in self.components:
            k = max(2, min(self.lof_neighbors, X.shape[0] - 1))
            self.lof = LocalOutlierFactor(n_neighbors=k, novelty=True).fit(Z)
            self.cal["lof"] = _Calibrator(-self.lof.score_samples(Z), self.q)
        self.fitted = True
        return self

    # ---------------------------------------------------------------- score
    def score_batch(self, X: np.ndarray, entity_ids: list[str] | None = None) -> list[AnomalyResult]:
        if not self.fitted:
            raise RuntimeError("detector not fitted")
        X = np.asarray(X, dtype=float).reshape(-1, len(self.names))
        if X.shape[0] == 0:
            return []
        Z = (X - self.mean) / self.std
        comps: dict[str, np.ndarray] = {}
        if "iforest" in self.cal:
            comps["iforest"] = self.cal["iforest"](-self.iforest.score_samples(Z))
        if "lof" in self.cal:
            comps["lof"] = self.cal["lof"](-self.lof.score_samples(Z))
        if "stat" in self.cal:
            ez = np.vstack([self._entity_z(x, eid) for x, eid in zip(X, entity_ids or [None] * len(X))])
            comps["stat"] = self.cal["stat"](np.abs(ez).max(axis=1))
        if comps:
            M = np.vstack(list(comps.values()))
            agg = M.max(axis=0) if self.combine == "max" else M.mean(axis=0)
        else:
            agg = np.zeros(X.shape[0])
        out = []
        for i in range(X.shape[0]):
            order = np.argsort(-np.abs(Z[i]))[:3]
            top = [(self.names[j], float(X[i, j]), float(Z[i, j])) for j in order if abs(Z[i, j]) >= 1.0]
            out.append(AnomalyResult(float(agg[i]), {k: float(v[i]) for k, v in comps.items()}, top))
        return out

    def _entity_z(self, x: np.ndarray, eid: str | None) -> np.ndarray:
        if eid is None or eid not in self._entity:
            mu, var = self.mean, self.var
        else:
            mu, var = self._entity[eid]
        return (x - mu) / self._std_floor(mu, var)

    def update_entity(self, eid: str, x: np.ndarray) -> None:
        """EWMA update of the entity baseline (call only for non-flagged windows)."""
        mu, var = self._entity.get(eid, (self.mean.copy(), self.var.copy()))
        a = self.alpha
        d = np.asarray(x, dtype=float) - mu
        mu = mu + a * d
        var = (1 - a) * (var + a * d * d)
        self._entity[eid] = (mu, var)
