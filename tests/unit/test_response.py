from mcd.core.enums import ActionType, AssessmentStatus, Domain, Severity
from mcd.core.models import EntityRef, TargetRef, ThreatAssessment
from mcd.response.audit_logger import AuditLogger
from mcd.response.response_engine import ResponseEngine
from mcd.simulation.topology import build_topology

TOPO = build_topology(seed=0)


def _assessment(targets, actionable=True, severity=Severity.HIGH):
    return ThreatAssessment(
        incident_id="inc", status=AssessmentStatus.CORROBORATED if actionable else AssessmentStatus.SUSPICIOUS,
        actionable=actionable, decision_source="coordinator", threat_class="MULTI_STAGE", global_confidence=0.9,
        severity=severity, entities=[t.entity for t in targets], targets=targets,
    )


def test_plan_maps_entities_to_actions():
    ws, srv = TOPO.workstations[0], TOPO.servers[3]
    plan = ResponseEngine(TOPO.inventory).plan(_assessment([
        TargetRef(entity=EntityRef.user(TOPO.standard_users[0]), domain=Domain.AUTH),
        TargetRef(entity=EntityRef.host(ws), domain=Domain.NETWORK),
        TargetRef(entity=EntityRef.host(srv), domain=Domain.CONFIG),
    ]))
    assert [p.action for p in plan] == [ActionType.SUSPEND_ACCOUNT, ActionType.ISOLATE_HOST, ActionType.REVERT_CONFIG]
    assert not any(p.requires_approval for p in plan)  # standard user, criticality-1 workstation


def test_high_blast_radius_requires_approval():
    eng = ResponseEngine(TOPO.inventory)
    plan = eng.plan(_assessment([
        TargetRef(entity=EntityRef.user(TOPO.admin_users[0]), domain=Domain.AUTH),
        TargetRef(entity=EntityRef.host(TOPO.ot_hosts[0]), domain=Domain.NETWORK),
    ]))
    assert all(p.blast_radius == "high" and p.requires_approval for p in plan)


def test_non_actionable_only_increases_monitoring():
    plan = ResponseEngine(TOPO.inventory).plan(_assessment(
        [TargetRef(entity=EntityRef.host(TOPO.workstations[0]), domain=Domain.NETWORK)], actionable=False, severity=Severity.MEDIUM))
    assert [p.action for p in plan] == [ActionType.INCREASE_MONITORING]
    low = ResponseEngine(TOPO.inventory).plan(_assessment(
        [TargetRef(entity=EntityRef.host(TOPO.workstations[0]), domain=Domain.NETWORK)], actionable=False, severity=Severity.LOW))
    assert low == []


def test_audit_chain_verifies_and_detects_tampering(tmp_path):
    log = AuditLogger(tmp_path / "audit.jsonl")
    for i in range(3):
        log.log(incident_id=f"i{i}", responsible_agent="intel-0", threat="X", evidence="e", confidence=0.9,
                action="ISOLATE_HOST", target="host:a", approval="approved", outcome="EXECUTED", sim_time=float(i))
    recs = AuditLogger.load(tmp_path / "audit.jsonl")
    assert AuditLogger.verify(recs) == (True, None)
    recs[1]["threat_confidence"] = 0.1
    assert AuditLogger.verify(recs) == (False, 1)
    recs = AuditLogger.load(tmp_path / "audit.jsonl")
    del recs[0]
    assert AuditLogger.verify(recs)[0] is False
