"""Real agents over the broker: context request/response and advisories."""

import asyncio

from mcd.agents.intelligence_agent import IntelConfig, ThreatIntelligenceAgent
from mcd.agents.sensor_agent import SensorAgent, _HistItem
from mcd.communication import topics as T
from mcd.communication.transports import create_broker
from mcd.core.enums import Domain, MessageType
from mcd.core.models import ContextRequest, EntityRef
from mcd.simulation.topology import build_topology
from tests.conftest import run


async def _wait(pred, timeout=3.0):
    for _ in range(int(timeout / 0.01)):
        if pred():
            return True
        await asyncio.sleep(0.01)
    return False


def test_sensor_answers_context_request_with_bounded_summary():
    async def go():
        topo = build_topology(seed=0)
        b = create_broker("memory")
        s = SensorAgent(Domain.NETWORK, 0, b, topo.inventory, heartbeat_interval=0.1)
        await s.start()
        host = EntityRef.host(topo.workstations[0])
        s.history[host].append(_HistItem(100.0, 0.33, "NETWORK.X", "lateral_movement", True))
        req = ContextRequest(request_id="r1", incident_id="i1", entity=host, window_start=0, window_end=200)
        from mcd.communication.message import Envelope

        await b.publish(T.inbox(s.agent_id), Envelope.build(MessageType.CONTEXT_REQUEST, "intel-0", T.inbox(s.agent_id), req))
        await b.ensure_group(T.inbox("intel-0"), "probe")
        got = []
        for _ in range(100):
            got += await b.read(T.inbox("intel-0"), "probe", "p", block_ms=20)
            if got:
                break
        await s.stop()
        assert got and got[0].envelope.type == MessageType.CONTEXT_RESPONSE
        p = got[0].envelope.payload
        assert p["max_confidence"] == 0.33 and p["alert_types"] == ["NETWORK.X"]
        assert "attrs" not in p and "events" not in p  # no raw observations leave the agent

    run(go())


def test_coordinator_owner_mapping_and_down_agents_skipped():
    topo = build_topology(seed=0)
    intel = ThreatIntelligenceAgent(create_broker("memory"), topo.inventory,
                                    IntelConfig(shards={"network": 2, "auth": 3, "config": 1}))
    owners = intel.owners(EntityRef.host("ws-000"))
    assert {d for _, d in owners} == {Domain.NETWORK, Domain.CONFIG, Domain.AUTH}
    assert sum(1 for _, d in owners if d == Domain.AUTH) == 3
    assert sum(1 for _, d in owners if d == Domain.NETWORK) == 1
    u = intel.owners(EntityRef.user("user-001"))
    assert sum(1 for _, d in u if d == Domain.AUTH) == 1
    intel.health["net-1"] = type("H", (), {"state": "DOWN"})()
    assert intel.is_down("net-1") and not intel.is_down("net-0")
