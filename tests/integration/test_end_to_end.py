"""End-to-end runs of the full multi-agent system over the in-memory broker."""

import pytest

from mcd.runtime.system import FailureSpec, ScenarioCfg, SystemConfig, run_system

pytestmark = pytest.mark.slow


def _cfg(strategy, **kw):
    base = dict(strategy=strategy, seed=1, duration=3600, train_duration=4 * 3600,
                scenarios=[ScenarioCfg(type="multi_stage", params={"start": 600, "duration": 2400})])
    base.update(kw)
    return SystemConfig(**base)


@pytest.mark.parametrize("strategy", ["independent", "cooperative", "centralized"])
def test_strategies_run_and_produce_consistent_artifacts(strategy):
    r = run_system(_cfg(strategy))
    assert r["audit_ok"]
    m = r["metrics"]
    assert m["detection"]["n_attacks"] == 1
    assert 0.0 <= m["detection"]["recall"] <= 1.0
    for aid, am in r["agent_metrics"].items():
        assert am["failed"] == 0, aid
        assert am["dead_lettered"] == 0, aid
    if strategy == "cooperative":
        assert m["distributed"]["messages_by_class"].get("alerts", 0) > 0
        assert "alerts.direct" not in m["distributed"]["messages_by_class"]
    if strategy == "independent":
        assert "assessments" not in m["distributed"]["messages_by_class"]


def test_sensors_never_publish_raw_observations():
    r = run_system(_cfg("cooperative"))
    by_sender = r["broker"]["by_sender"]
    for sender, topics in by_sender.items():
        if sender == "env":
            continue
        assert not any(t.startswith("sim.") for t in topics), sender


def test_critical_actions_never_execute_without_approval():
    r = run_system(_cfg("cooperative", approver=None, response={"approval_timeout_s": 0.3}, drain_timeout=3.0))
    high = [a for a in r["actions"] if a["blast_radius"] == "high"]
    for a in high:
        assert a["executed_at"] is None
        assert a["outcome"] in ("TIMED_OUT", "PENDING")
    applied = {x["action_id"] for x in r["env"]["actions_applied"]}
    assert not applied & {a["action_id"] for a in high}


def test_coordinator_crash_and_restart_recovers():
    r = run_system(_cfg("cooperative", failures=[FailureSpec(agent="intel-0", at=700, restart_after=600)]))
    assert r["agent_metrics"]["intel-0"]["processed"] > 0
    assert r["audit_ok"]


def test_sharded_deployment_routes_by_entity():
    r = run_system(_cfg("cooperative", n_sensors=6))
    assert r["shards"] == {"network": 2, "auth": 2, "config": 2}
    scored = [d["windows_scored"] for a, d in r["agent_details"].items() if a.startswith("net-")]
    assert len(scored) == 2 and all(s > 0 for s in scored)
