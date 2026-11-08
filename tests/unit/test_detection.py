import numpy as np
import pytest

from mcd.core.enums import Domain, Severity
from mcd.core.models import Observation
from mcd.detection.anomaly_detector import HybridAnomalyDetector, _Calibrator
from mcd.detection.pipeline import DomainPipeline
from mcd.detection.rule_engine import Rule, RuleEngine
from mcd.detection.threat_scoring import classify, fuse_local, local_status, noisy_or, severity_from
from mcd.simulation.topology import build_topology


def test_rule_engine_all_any_semantics():
    r = Rule(id="R", domain="auth", alert_type="X", confidence=0.5,
             all=[("a", ">=", 2)], any=[("b", "==", 1), ("c", ">", 0)])
    assert r.matches({"a": 2, "b": 1, "c": 0})
    assert not r.matches({"a": 1, "b": 1, "c": 1})
    assert not r.matches({"a": 3, "b": 0, "c": 0})


def test_rule_validation():
    with pytest.raises(ValueError):
        Rule(id="R", domain="auth", alert_type="X", confidence=0.5, all=[("a", "~", 1)])
    with pytest.raises(ValueError):
        Rule(id="R", domain="auth", alert_type="X", confidence=1.5)


def test_default_rules_load_per_domain():
    for d in ("network", "auth", "config"):
        eng = RuleEngine.from_yaml(domain=d)
        assert eng.rules and all(r.domain == d for r in eng.rules)


def test_calibrator_monotonic_and_bounded():
    cal = _Calibrator(np.arange(100.0), q=0.9)
    s = np.array([-5, 50, 89, 95, 99, 500.0])
    out = cal(s)
    assert np.all(np.diff(out) >= 0)
    assert out[0] == 0 and out[1] == 0 and out[-1] == 1.0
    assert 0 < out[3] < 1


def test_detector_ranks_outliers_higher():
    rng = np.random.default_rng(0)
    X = rng.normal(0, 1, size=(400, 3))
    det = HybridAnomalyDetector(["a", "b", "c"], seed=0).fit(X)
    normal, outlier = det.score_batch(np.array([[0.1, -0.2, 0.0], [8.0, 8.0, -8.0]]))
    assert outlier.score > 0.9 > normal.score
    assert outlier.top_features and outlier.top_features[0][0] in {"a", "b", "c"}
    assert set(outlier.components) == {"iforest", "lof", "stat"}


def test_detector_falls_back_to_stat_with_little_data():
    det = HybridAnomalyDetector(["a"], min_train=15).fit(np.zeros((5, 1)))
    assert not det.ml_enabled
    (r,) = det.score_batch(np.array([[3.0]]))
    assert set(r.components) == {"stat"}


def test_entity_ewma_adapts():
    det = HybridAnomalyDetector(["a"], components=("stat",), ewma_alpha=0.5).fit(np.random.default_rng(1).normal(0, 1, (200, 1)))
    before = det.score_batch(np.array([[6.0]]), ["e"])[0].score
    for _ in range(30):
        det.update_entity("e", np.array([6.0]))
    after = det.score_batch(np.array([[6.0]]), ["e"])[0].score
    assert after < before


def test_fusion_and_severity():
    assert fuse_local(0.0, 0.0) == 0.0
    assert fuse_local(1.0, 0.0, alpha=0.6) == pytest.approx(0.6)
    assert fuse_local(1.0, 0.5, alpha=0.6) == pytest.approx(1 - 0.4 * 0.5)
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert severity_from(0.9, 3) == Severity.CRITICAL
    assert severity_from(0.6, 3) == Severity.HIGH
    assert severity_from(0.6, 1) == Severity.LOW
    assert severity_from(0.1, 2) == Severity.INFO


def test_status_and_classification():
    assert local_status(0.5, []) == "ANOMALY"
    assert local_status(0.95, []) == "SUSPICIOUS"
    assert classify(Domain.AUTH, [])[0] == "AUTH.UNCLASSIFIED_ANOMALY"


def _flow(t, src, dst, port, status="ok", i=[0]):
    i[0] += 1
    return Observation(event_id=f"x{i[0]}", domain=Domain.NETWORK, sim_time=t,
                       attrs={"src": src, "dst": dst, "dst_port": port, "proto": "tcp", "bytes_out": 100.0,
                              "bytes_in": 100.0, "duration": 1.0, "status": status})


def test_pipeline_windows_late_events_and_rules():
    topo = build_topology(seed=0)
    p = DomainPipeline(Domain.NETWORK, topo.inventory)
    ws = topo.workstations[0]
    train = [_flow(t * 30.0, ws, topo.usual_servers[ws][0], 445) for t in range(200)]
    p.train(train)
    targets = topo.servers[:4]
    for k, dst in enumerate(targets):
        p.add(_flow(1000 + k, ws, dst, 3389))
    assert p.close_until(1019) == []          # window [960,1020) is still open
    scores = p.close_until(1020)
    assert len(scores) == 1
    s = scores[0]
    assert s.entity.id == ws and "NET-001" in [h.rule_id for h in s.hits]
    assert s.confidence >= 0.45 and s.explanation
    assert not p.add(_flow(1001, ws, targets[0], 3389))  # late event
    assert p.late_events == 1
