"""Statistics helpers: bootstrap CIs, paired Wilcoxon tests, Holm correction."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def bootstrap_ci(values, n_boot: int = 2000, alpha: float = 0.05, seed: int = 0) -> tuple[float, float, float]:
    """(mean, lo, hi) percentile bootstrap CI of the mean; NaNs ignored."""
    x = np.asarray([v for v in values if v == v], dtype=float)
    if x.size == 0:
        return float("nan"), float("nan"), float("nan")
    if x.size == 1:
        return float(x[0]), float(x[0]), float(x[0])
    rng = np.random.default_rng(seed)
    means = rng.choice(x, size=(n_boot, x.size), replace=True).mean(axis=1)
    return float(x.mean()), float(np.quantile(means, alpha / 2)), float(np.quantile(means, 1 - alpha / 2))


@dataclass
class PairedTest:
    metric: str
    a: str
    b: str
    n: int
    mean_a: float
    mean_b: float
    median_diff: float
    statistic: float
    p_value: float
    effect_r: float
    p_holm: float = float("nan")


def paired_wilcoxon(metric: str, a_name: str, b_name: str, a, b) -> PairedTest:
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    mask = ~(np.isnan(a) | np.isnan(b))
    a, b = a[mask], b[mask]
    d = a - b
    n = int(d.size)
    if n == 0:
        return PairedTest(metric, a_name, b_name, 0, float("nan"), float("nan"), float("nan"), float("nan"), float("nan"), float("nan"))
    nz = d[d != 0]
    if nz.size == 0:
        stat, p, r = 0.0, 1.0, 0.0
    else:
        from scipy.stats import rankdata, wilcoxon

        res = wilcoxon(nz, alternative="two-sided")
        stat, p = float(res.statistic), float(res.pvalue)
        ranks = rankdata(np.abs(nz))
        w_plus, w_minus = ranks[nz > 0].sum(), ranks[nz < 0].sum()
        r = float((w_plus - w_minus) / (nz.size * (nz.size + 1) / 2))
    return PairedTest(metric, a_name, b_name, n, float(a.mean()), float(b.mean()), float(np.median(d)), stat, p, r)


def holm(tests: list[PairedTest]) -> list[PairedTest]:
    valid = sorted([t for t in tests if t.p_value == t.p_value], key=lambda t: t.p_value)
    m = len(valid)
    running = 0.0
    for i, t in enumerate(valid):
        running = max(running, min(1.0, (m - i) * t.p_value))
        t.p_holm = running
    return tests
