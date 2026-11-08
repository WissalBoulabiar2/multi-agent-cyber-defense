import time

import pytest

from mcd.communication.message import Envelope
from mcd.core.enums import Domain, MessageType, Priority, Severity, priority_for
from mcd.core.models import EntityRef, Evidence, LocalAlert, Observation


def _alert(conf=0.6):
    return LocalAlert(
        alert_id="a1", domain=Domain.AUTH, agent_id="auth-0",
        entities=[EntityRef.user("u1"), EntityRef.host("h1")],
        alert_type="AUTH.X", tactic="credential_access", anomaly_score=0.5,
        rule_confidence=0.4, confidence=conf, status="SUSPICIOUS", severity=Severity.MEDIUM,
        window_start=0, window_end=60, evidence=Evidence(rule_ids=["R1"]),
    )


def test_envelope_roundtrip_preserves_payload():
    env = Envelope.build(MessageType.LOCAL_ALERT, "auth-0", "alerts.p1", _alert(), priority=Priority.P1, ttl_s=5)
    back = Envelope.from_bytes(env.to_bytes())
    assert back.message_id == env.message_id
    alert = back.parse(LocalAlert)
    assert alert.entities[0] == EntityRef.user("u1")
    assert isinstance(back.typed(), LocalAlert)
    assert back.expires_at == pytest.approx(env.created_at + 5)


def test_envelope_expiry():
    env = Envelope.build(MessageType.WATERMARK, "env", "sim.clock", {"t": 1.0}, ttl_s=0.01)
    assert not env.expired(env.created_at)
    assert env.expired(time.time() + 1)


def test_message_ids_unique():
    ids = {Envelope.build(MessageType.WATERMARK, "x", "t", {"t": 0}).message_id for _ in range(2000)}
    assert len(ids) == 2000


def test_observation_has_no_label_fields():
    fields = set(Observation.model_fields)
    assert not fields & {"label", "attack_id", "is_malicious", "scenario"}


def test_priority_mapping():
    assert priority_for(Severity.CRITICAL) == Priority.P0
    assert priority_for(Severity.HIGH) == Priority.P0
    assert priority_for(Severity.MEDIUM) == Priority.P1
    assert priority_for(Severity.LOW) == Priority.P2


def test_entity_ref_hashable():
    assert len({EntityRef.host("a"), EntityRef.host("a"), EntityRef.user("a")}) == 2
