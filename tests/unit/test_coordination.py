import pytest

from mcd.communication.coordination import CorrelatedAlert, Correlator, FusionConfig, longest_stage_chain
from mcd.core.enums import AssessmentStatus, Domain
from mcd.core.models import EntityRef
from mcd.simulation.topology import build_topology

TOPO = build_topology(seed=0)
WS = TOPO.workstations[0]
DC = TOPO.server_by_role("dc")


def ca(aid, domain, primary, conf, t, tactic=None, rule=0.0, related=(), source="alert", atype=None):
    return CorrelatedAlert(alert_id=aid, domain=Domain(domain), agent_id=f"{domain}-0",
                           alert_type=atype or f"{domain}.{aid}", tactic=tactic, primary=primary,
                           entities=[primary, *related], confidence=conf, rule_confidence=rule, t=t, source=source)


def corr(**kw):
    cfg = FusionConfig(domain_weights={"network": 1.0, "auth": 1.0, "config": 1.0}, **kw)
    return Correlator(cfg, TOPO.inventory)


def test_noisy_or_and_dedup():
    c = corr(gamma=1.0)
    u = EntityRef.user("u")
    inc = c.add(ca("a", "auth", u, 0.5, 100))
    c.add(ca("b", "auth", u, 0.5, 100, atype="auth.other"))  # different alert type -> both count
    res = c.evaluate(inc, 100)
    assert res.score == pytest.approx(0.75)
    # exact duplicate key -> only the max counts
    c2 = corr(gamma=1.0)
    inc2 = c2.add(ca("a", "auth", u, 0.5, 100, atype="T"))
    c2.add(ca("b", "auth", u, 0.4, 100, atype="T"))
    assert c2.evaluate(inc2, 100).score == pytest.approx(0.5)


def test_time_decay_half_life():
    c = corr(gamma=1.0, half_life=600)
    inc = c.add(ca("a", "auth", EntityRef.user("u"), 0.8, 0))
    assert c.evaluate(inc, 600).score == pytest.approx(0.4)


def test_kill_chain_chain_length():
    assert longest_stage_chain([(0, 0), (10, 2), (20, 3)]) == 3
    assert longest_stage_chain([(0, 3), (10, 2), (20, 0)]) == 1
    assert longest_stage_chain([]) == 0


def test_kill_chain_bonus_increases_score():
    c = corr(gamma=0.7)
    h = EntityRef.host(WS)
    inc = c.add(ca("a", "auth", EntityRef.user("u"), 0.5, 0, "credential_access", related=[h]))
    c.add(ca("b", "network", h, 0.5, 60, "lateral_movement"))
    res = c.evaluate(inc, 60)
    assert res.coherent_stages == 2
    assert res.s_prime > res.score


def test_single_domain_never_corroborated_without_high_fidelity():
    c = corr()
    h = EntityRef.host(WS)
    inc = c.add(ca("a", "network", h, 0.95, 0, "lateral_movement", rule=0.6))
    res = c.evaluate(inc, 0)
    assert res.s_prime >= 0.75 and res.status == AssessmentStatus.SUSPICIOUS
    inc2 = c.add(ca("b", "config", EntityRef.host(TOPO.servers[2]), 0.97, 0, "defense_evasion", rule=0.96))
    assert c.evaluate(inc2, 0).status == AssessmentStatus.CORROBORATED


def test_two_domains_same_stage_weak_rules_not_corroborated():
    """Two views of one single-step event (e.g. a legit admin session) are not enough."""
    c = corr()
    h = EntityRef.host(WS)
    inc = c.add(ca("a", "network", h, 0.8, 0, "lateral_movement", rule=0.55))
    c.add(ca("b", "auth", EntityRef.user("admin"), 0.6, 0, "lateral_movement", rule=0.5, related=[h]))
    assert c.evaluate(inc, 0).status == AssessmentStatus.SUSPICIOUS


def test_multi_domain_multi_stage_is_actionable():
    c = corr()
    h = EntityRef.host(WS)
    inc = c.add(ca("a", "auth", EntityRef.user("u"), 0.7, 0, "credential_access", rule=0.7, related=[h]))
    c.add(ca("b", "network", h, 0.6, 60, "lateral_movement", rule=0.45))
    res = c.evaluate(inc, 60)
    assert res.actionable and res.status in (AssessmentStatus.CORROBORATED, AssessmentStatus.CONFIRMED)
    assert {t.entity.key() for t in res.targets} == {"user:u", f"host:{WS}"}


def test_hubs_do_not_merge_incidents():
    c = corr()
    dc = EntityRef.host(DC)
    i1 = c.add(ca("a", "auth", EntityRef.user("u1"), 0.6, 0, related=[dc]))
    i2 = c.add(ca("b", "auth", EntityRef.user("u2"), 0.6, 0, related=[dc]))
    assert i1.incident_id != i2.incident_id


def test_sweep_alerts_link_only_via_primary():
    c = corr(max_related_links=3)
    victim = EntityRef.host(TOPO.workstations[1])
    i1 = c.add(ca("a", "network", victim, 0.6, 0))
    many = [EntityRef.host(w) for w in TOPO.workstations[1:6]]
    i2 = c.add(ca("b", "network", EntityRef.host(TOPO.scanner), 0.9, 0, related=many))
    assert i1.incident_id != i2.incident_id


def test_context_answers_corroborate_but_never_become_targets():
    c = corr()
    h = EntityRef.host(WS)
    inc = c.add(ca("a", "auth", EntityRef.user("u"), 0.7, 0, "credential_access", rule=0.7, related=[h]))
    c.add_to(inc.incident_id, ca("ctx", "network", h, 0.9, 30, "lateral_movement", source="context"))
    res = c.evaluate(inc, 30)
    assert res.actionable
    assert f"host:{WS}" not in {t.entity.key() for t in res.targets}


def test_voi_gate():
    c = corr(tau_confirm=0.75, voi_answer_cap=0.6)
    assert c.voi_worth_querying(0.6, "auth")
    assert not c.voi_worth_querying(0.2, "auth")
    c.cfg.voi = False
    assert c.voi_worth_querying(0.0, "auth")


def test_publish_only_on_upgrade_or_new_targets():
    c = corr()
    h = EntityRef.host(WS)
    inc = c.add(ca("a", "auth", EntityRef.user("u"), 0.7, 0, "credential_access", rule=0.7, related=[h]))
    c.add(ca("b", "network", h, 0.6, 60, "lateral_movement", rule=0.45))
    res = c.evaluate(inc, 60)
    assert c.should_publish(inc, res)
    c.mark_published(inc, res)
    assert not c.should_publish(inc, c.evaluate(inc, 60))
    c.add(ca("c", "network", EntityRef.host(TOPO.workstations[3]), 0.8, 90, "lateral_movement", related=[h]))
    assert c.should_publish(inc, c.evaluate(inc, 90))


def test_expire_old_incidents():
    c = corr(corr_window=100)
    c.add(ca("a", "auth", EntityRef.user("u"), 0.7, 0))
    assert c.expire(1000) == 1 and not c.incidents
