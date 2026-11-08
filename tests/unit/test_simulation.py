import hashlib
import json

from mcd.core.enums import ActionType
from mcd.core.models import ContainmentCommand, EntityRef
from mcd.simulation.attack_base import AttackParams
from mcd.simulation.environment import EnvConfig, Environment, ScenarioSpec
from mcd.simulation.topology import TopologyConfig, build_topology

FORBIDDEN = {"label", "attack", "attack_id", "malicious", "is_malicious", "scenario", "stage"}


def _digest(events):
    h = hashlib.sha256()
    for e in events:
        h.update(json.dumps([e.event_id, str(e.domain), e.sim_time, e.attrs], sort_keys=True).encode())
    return h.hexdigest()


def test_topology_segments_and_scale():
    t = build_topology(seed=0)
    segs = {h.segment for h in t.inventory.hosts.values()}
    assert segs == {"DMZ", "CORP", "SERVERS", "OT"}
    assert t.inventory.criticality(t.server_by_role("dc")) == 3
    big = build_topology(TopologyConfig(scale=2.0), seed=0)
    assert len(big.inventory.hosts) > len(t.inventory.hosts)


def test_generation_is_deterministic_per_seed():
    def run(seed):
        env = Environment(EnvConfig(seed=seed, duration=1800), [ScenarioSpec("multi_stage", AttackParams(start=300, duration=1200))])
        return _digest(env.generate_offline())

    assert run(5) == run(5)
    assert run(5) != run(6)


def test_no_label_leakage_in_observations():
    for sc in ("credential_compromise", "lateral_movement", "configuration_tampering", "multi_stage"):
        env = Environment(EnvConfig(seed=2, duration=3600), [ScenarioSpec(sc, AttackParams(start=300))])
        events = env.generate_offline()
        assert env.gt.n_malicious > 0
        for e in events:
            assert not FORBIDDEN & set(e.attrs), (sc, e.attrs)
        ids = [e.event_id for e in events]
        mal = set(env.gt.event_attack)
        # malicious and benign events share the same opaque id scheme
        assert all(i.startswith("e") for i in ids) and mal <= set(ids)


def test_each_scenario_has_expected_footprint():
    expected = {
        "credential_compromise": {"auth", "network"},
        "lateral_movement": {"auth", "network"},
        "configuration_tampering": {"auth", "config"},
    }
    for sc, domains in expected.items():
        env = Environment(EnvConfig(seed=3, duration=3600), [ScenarioSpec(sc, AttackParams(start=300))])
        events = env.generate_offline()
        mal = {str(e.domain) for e in events if e.event_id in env.gt.event_attack}
        assert domains <= mal, (sc, mal)


def test_frequency_and_affected_hosts():
    env = Environment(EnvConfig(seed=4, duration=5400),
                      [ScenarioSpec("configuration_tampering", AttackParams(start=300, duration=1200, n_hosts=4), count=2, spacing=2400)])
    env.generate_offline()
    recs = list(env.gt.attacks.values())
    assert len(recs) == 2
    assert recs[1].scheduled_start - recs[0].scheduled_start == 2400
    assert sum(1 for e in recs[0].entities if e.startswith("host:")) >= 4


def test_containment_halts_attack():
    env = Environment(EnvConfig(seed=1, duration=3600), [ScenarioSpec("credential_compromise", AttackParams(start=300))])
    atk = env.attacks[0]
    env.apply(ContainmentCommand(action_id="x", incident_id="i", action=ActionType.ISOLATE_HOST,
                                 target=EntityRef.host(atk.foothold)))
    env.generate_offline()
    rec = env.gt.attacks[atk.attack_id]
    assert rec.halt_reason == "foothold_isolated" and rec.n_events == 0


def test_suspension_produces_failed_logins():
    env = Environment(EnvConfig(seed=1, duration=3600), [ScenarioSpec("lateral_movement", AttackParams(start=300))])
    atk = env.attacks[0]
    env.state.suspended.add(atk.account)
    events = env.generate_offline()
    logins = [e for e in events if e.event_id in env.gt.event_attack and str(e.domain) == "auth"]
    assert logins and all(e.attrs["result"] == "failure" for e in logins)
    assert env.gt.attacks[atk.attack_id].halt_reason == "account_suspended"


def test_missing_observations_channel():
    from mcd.simulation.environment import ObservationChannel

    env = Environment(EnvConfig(seed=1, duration=1800, channel=ObservationChannel(drop_prob=0.5)))
    events = env.generate_offline()
    assert env.gt.dropped_observations > 0
    assert len(events) + env.gt.dropped_observations == env.gt.n_events
