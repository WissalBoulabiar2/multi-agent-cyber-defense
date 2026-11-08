import math

import numpy as np
import pytest

from mcd.evaluation.metrics import detection_metrics
from mcd.evaluation.statistics import bootstrap_ci, holm, paired_wilcoxon
from mcd.simulation.ground_truth import AttackRecord, GroundTruth


def _gt():
    gt = GroundTruth(window=60)
    gt.attacks["a1"] = AttackRecord("a1", "x", ["host:h1", "user:u1"], 600, 1800, 620.0, 1200.0, 10, [], None, None)
    for b in range(0, 60):
        for e in ("host:h1", "host:h2", "host:h3", "user:u1"):
            gt.activity.add((e, b))
    return gt


def test_detection_metrics_tp_fp_latency():
    decisions = [
        {"sim_time": 700.0, "wall_time": 0.0, "targets": ["host:h1"]},
        {"sim_time": 760.0, "wall_time": 0.0, "targets": ["user:u1", "host:h2"]},
        {"sim_time": 3000.0, "wall_time": 0.0, "targets": ["host:h1"]},  # after attack + grace -> FP
    ]
    m = detection_metrics(_gt(), decisions)
    assert m["recall"] == 1.0
    assert m["tp_pairs"] == 2 and m["fp_pairs"] == 2
    assert m["precision"] == pytest.approx(0.5)
    assert m["latency_sim_mean_s"] == pytest.approx(80.0)
    assert 0 < m["fpr"] < 0.05


def test_no_decisions_gives_zero_recall_and_f1():
    m = detection_metrics(_gt(), [])
    assert m["recall"] == 0.0 and m["f1"] == 0.0 and math.isnan(m["precision"])


def test_bootstrap_ci_contains_mean():
    mean, lo, hi = bootstrap_ci(np.random.default_rng(0).normal(5, 1, 50))
    assert lo < mean < hi and abs(mean - 5) < 0.5
    assert bootstrap_ci([float("nan")])[0] != bootstrap_ci([float("nan")])[0]


def test_paired_wilcoxon_and_holm():
    a = np.arange(10, dtype=float) + 1.0
    t1 = paired_wilcoxon("m", "A", "B", a, a - 1.0)
    t2 = paired_wilcoxon("m2", "A", "B", a, a)
    assert t1.p_value < 0.05 and t1.effect_r == pytest.approx(1.0)
    assert t2.p_value == 1.0
    holm([t1, t2])
    assert t1.p_holm >= t1.p_value
