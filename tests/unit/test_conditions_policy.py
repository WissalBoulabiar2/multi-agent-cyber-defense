import asyncio
import time

from mcd.communication.conditions import ConditionedBroker, NetworkConditions, PartitionRule
from mcd.communication.message import Envelope
from mcd.communication.policy import CommunicationPolicy, PolicyConfig
from mcd.communication.transports import create_broker
from mcd.core.enums import Domain, MessageType, Priority, Severity
from mcd.core.models import EntityRef, LocalAlert
from tests.conftest import run


def _env(sender="net-0"):
    return Envelope.build(MessageType.WATERMARK, sender, "alerts.p1", {"t": 0.0})


def test_loss_drops_messages_deterministically():
    async def go():
        b = ConditionedBroker(create_broker("memory"), NetworkConditions(loss_prob=0.5, seed=1))
        for _ in range(200):
            await b.publish("alerts.p1", _env())
        delivered = len(await b.range("alerts.p1"))
        assert 60 < delivered < 140
        assert delivered + b.dropped["alerts.p1"] == 200

    run(go())


def test_out_of_scope_topics_unaffected():
    async def go():
        b = ConditionedBroker(create_broker("memory"), NetworkConditions(loss_prob=1.0))
        await b.publish("sim.net.events.0", _env())
        assert len(await b.range("sim.net.events.0")) == 1

    run(go())


def test_delay_postpones_delivery():
    async def go():
        b = ConditionedBroker(create_broker("memory"), NetworkConditions(delay_ms=80))
        t0 = time.perf_counter()
        await b.publish("alerts.p1", _env())
        assert len(await b.range("alerts.p1")) == 0
        await asyncio.sleep(0.15)
        assert len(await b.range("alerts.p1")) == 1
        assert time.perf_counter() - t0 >= 0.08

    run(go())


def test_partition_blocks_selected_senders():
    async def go():
        rule = PartitionRule(senders=["net-*"], topics=["alerts.*"])
        b = ConditionedBroker(create_broker("memory"), NetworkConditions(partitions=[rule]))
        await b.publish("alerts.p1", _env("net-0"))
        await b.publish("alerts.p1", _env("auth-0"))
        got = await b.range("alerts.p1")
        assert [d.envelope.sender for d in got] == ["auth-0"]

    run(go())


def _alert(conf, t_end, entity="u1"):
    return LocalAlert(
        alert_id=f"a{t_end}", domain=Domain.AUTH, agent_id="auth-0", entities=[EntityRef.user(entity)],
        alert_type="AUTH.X", anomaly_score=0.0, rule_confidence=conf, confidence=conf,
        status="SUSPICIOUS", severity=Severity.MEDIUM, window_start=t_end - 60, window_end=t_end,
    )


def test_policy_threshold_suppression_and_merge():
    p = CommunicationPolicy(PolicyConfig(share_threshold=0.5, suppression_window=300))
    assert p.evaluate(_alert(0.4, 60)) == (False, "below_threshold")
    a = _alert(0.7, 60)
    assert p.evaluate(a)[0] and p.admit(a, Priority.P1, 100)[0]
    for t in (120, 180):
        assert p.evaluate(_alert(0.7, t)) == (False, "suppressed")
    later = _alert(0.7, 400)
    assert p.evaluate(later)[0] and p.admit(later, Priority.P1, 100)[0]
    assert later.count == 3  # 1 + two merged repeats
    assert p.evaluate(_alert(0.7, 410, entity="u2"))[0]  # other entity independent


def test_policy_rate_limit_spares_p0():
    p = CommunicationPolicy(PolicyConfig(share_threshold=0.0, rate_msgs_per_s=0.0, burst=2, suppression_window=0))
    results = [p.admit(_alert(0.9, i, entity=f"u{i}"), Priority.P2, 10)[0] for i in range(4)]
    assert results == [True, True, False, False]
    assert p.admit(_alert(0.9, 99, entity="z"), Priority.P0, 10)[0]
    assert p.admit(_alert(0.9, 98, entity="y"), Priority.P1, 10**6) == (False, "oversize")
