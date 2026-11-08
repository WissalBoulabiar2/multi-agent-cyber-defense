import asyncio

from mcd.agents.base_agent import BaseAgent, Subscription
from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.communication.transports import create_broker
from mcd.core.enums import MessageType, Priority
from tests.conftest import run


class Echo(BaseAgent):
    def __init__(self, *a, fail_times=0, **kw):
        super().__init__(*a, heartbeat_interval=0.05, **kw)
        self.seen: list[float] = []
        self.order: list[str] = []
        self.fail_times = fail_times

    def subscriptions(self):
        return [Subscription("in.low", priority=2), Subscription("in.high", priority=0)]

    async def handle(self, env: Envelope):
        if self.fail_times:
            self.fail_times -= 1
            raise RuntimeError("boom")
        self.seen.append(env.payload["t"])
        self.order.append(env.topic)
        await self.send("out", MessageType.WATERMARK, {"t": env.payload["t"]})


def _env(t, topic="in.low", sender="src"):
    return Envelope.build(MessageType.WATERMARK, sender, topic, {"t": float(t)})


async def _wait(pred, timeout=2.0):
    for _ in range(int(timeout / 0.01)):
        if pred():
            return True
        await asyncio.sleep(0.01)
    return False


def test_agents_communicate_only_via_broker():
    async def go():
        b = create_broker("memory")
        a = Echo("echo", b)
        await a.start()
        await b.publish("in.low", _env(1))
        assert await _wait(lambda: a.seen == [1.0])
        out = await b.range("out")
        assert out[0].envelope.sender == "echo"
        assert any(d.envelope.type == MessageType.HEARTBEAT for d in await b.range(T.HEARTBEAT))
        await a.stop()

    run(go())


def test_duplicate_messages_processed_once():
    async def go():
        b = create_broker("memory")
        a = Echo("echo", b)
        await a.start()
        env = _env(5)
        await b.publish("in.low", env)
        await b.publish("in.low", env)  # same message_id redelivered
        assert await _wait(lambda: a.metrics.duplicates == 1)
        assert a.seen == [5.0]
        await a.stop()

    run(go())


def test_priority_lane_processed_first():
    async def go():
        b = create_broker("memory")
        a = Echo("echo", b)
        for i in range(20):
            await b.publish("in.low", _env(i))
        await b.publish("in.high", _env(100, "in.high"))
        await a.start()
        assert await _wait(lambda: len(a.seen) == 21)
        assert a.order.index("in.high") < 10
        await a.stop()

    run(go())


def test_failed_handler_retried_then_dead_lettered():
    async def go():
        b = create_broker("memory")
        a = Echo("echo", b, fail_times=100, max_deliveries=3)
        await a.start()
        await b.publish("in.low", _env(1))
        assert await _wait(lambda: a.metrics.dead_lettered == 1, 3.0)
        assert len(await b.range(T.dlq("in.low"))) == 1
        assert await b.lag("in.low", "echo") == 0
        await a.stop()

    run(go())


def test_transient_failure_recovers():
    async def go():
        b = create_broker("memory")
        a = Echo("echo", b, fail_times=1)
        await a.start()
        await b.publish("in.low", _env(3))
        assert await _wait(lambda: a.seen == [3.0], 3.0)
        await a.stop()

    run(go())


def test_crash_and_restart_recovers_pending_messages():
    async def go():
        b = create_broker("memory")
        a = Echo("echo", b)
        await a.start()
        a.crash()
        await asyncio.sleep(0.05)
        # messages delivered while down stay in the stream for the group
        for i in range(3):
            await b.publish("in.low", _env(i))
        assert a.seen == []
        await a.start()
        assert await _wait(lambda: sorted(a.seen) == [0.0, 1.0, 2.0])
        await a.stop()

    run(go())


def test_expired_messages_dropped():
    async def go():
        b = create_broker("memory")
        a = Echo("echo", b)
        env = _env(1)
        env.expires_at = env.created_at - 1
        await b.publish("in.low", env)
        await a.start()
        assert await _wait(lambda: a.metrics.expired == 1)
        assert a.seen == []
        await a.stop()

    run(go())
