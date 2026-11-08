"""Contract tests run against every available transport (Redis only if REDIS_URL is set)."""

import asyncio
import uuid

import pytest

from mcd.communication.message import Envelope
from mcd.communication.transports import create_broker
from mcd.core.enums import MessageType
from tests.conftest import redis_url, run


def _brokers():
    kinds = [("memory", None)]
    url = redis_url()
    if url:
        kinds.append(("redis", url))
    return kinds


def _env(i, sender="s"):
    return Envelope.build(MessageType.WATERMARK, sender, "t", {"t": float(i)})


@pytest.fixture(params=_brokers(), ids=lambda p: p[0])
def broker_factory(request):
    kind, url = request.param
    if kind == "redis":
        pytest.importorskip("redis")
    return lambda: create_broker(kind, url)


def test_publish_read_ack(broker_factory):
    async def go():
        b = broker_factory()
        topic = f"test.{uuid.uuid4().hex}"
        await b.ensure_group(topic, "g")
        for i in range(5):
            await b.publish(topic, _env(i))
        got = await b.read(topic, "g", "c1", count=10, block_ms=50)
        assert [d.envelope.payload["t"] for d in got] == [0.0, 1.0, 2.0, 3.0, 4.0]
        assert await b.lag(topic, "g") == 5  # all pending
        await b.ack(topic, "g", [d.entry_id for d in got])
        assert await b.lag(topic, "g") == 0
        assert await b.read(topic, "g", "c1", block_ms=10) == []
        await b.close()

    run(go())


def test_each_group_sees_every_message(broker_factory):
    async def go():
        b = broker_factory()
        topic = f"test.{uuid.uuid4().hex}"
        await b.ensure_group(topic, "g1")
        await b.ensure_group(topic, "g2")
        await b.publish(topic, _env(1))
        a = await b.read(topic, "g1", "c", block_ms=10)
        c = await b.read(topic, "g2", "c", block_ms=10)
        assert len(a) == len(c) == 1
        await b.close()

    run(go())


def test_unacked_messages_are_reclaimed_with_delivery_count(broker_factory):
    async def go():
        b = broker_factory()
        topic = f"test.{uuid.uuid4().hex}"
        await b.ensure_group(topic, "g")
        await b.publish(topic, _env(7))
        first = await b.read(topic, "g", "c1", block_ms=10)
        assert len(first) == 1
        reclaimed = await b.claim_stale(topic, "g", "c2", min_idle_ms=0)
        assert len(reclaimed) == 1 and reclaimed[0].deliveries == 2
        assert reclaimed[0].envelope.message_id == first[0].envelope.message_id
        await b.close()

    run(go())


def test_blocking_read_wakes_on_publish():
    async def go():
        b = create_broker("memory")
        await b.ensure_group("t", "g")

        async def later():
            await asyncio.sleep(0.05)
            await b.publish("t", _env(1))

        task = asyncio.create_task(later())
        got = await b.read("t", "g", "c", block_ms=2000)
        await task
        assert len(got) == 1

    run(go())


def test_replay_range_and_stats():
    async def go():
        b = create_broker("memory")
        for i in range(3):
            await b.publish("t", _env(i, sender="a1"))
        assert len(await b.range("t")) == 3
        assert len(await b.range("t", count=2)) == 2
        assert b.stats.published_msgs["t"] == 3
        assert b.stats.by_sender["a1"]["t"][0] == 3

    run(go())


def test_memory_broker_does_not_share_objects():
    async def go():
        b = create_broker("memory")
        env = _env(1)
        await b.publish("t", env)
        env.payload["t"] = 999.0
        got = await b.read("t", "g", "c", block_ms=10)
        assert got[0].envelope.payload["t"] == 1.0
        assert got[0].envelope is not env

    run(go())


def test_maxlen_trimming():
    async def go():
        b = create_broker("memory", maxlen=3)
        await b.ensure_group("t", "g")
        for i in range(10):
            await b.publish("t", _env(i))
        got = await b.read("t", "g", "c", block_ms=10)
        assert [d.envelope.payload["t"] for d in got] == [7.0, 8.0, 9.0]

    run(go())
