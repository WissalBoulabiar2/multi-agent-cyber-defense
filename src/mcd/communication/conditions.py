"""Fault-injection middleware: delay, jitter, loss and partitions on the publish path.

Wraps any MessageBroker. Agent code is unchanged; experiments only swap the
conditions object. Applied only to topics matching ``applies_to``.
"""

from __future__ import annotations

import asyncio
import fnmatch
import random
from dataclasses import dataclass, field

from mcd.communication.message import Envelope
from mcd.communication.message_broker import Delivery, MessageBroker

DEFAULT_SCOPE = ["alerts.*", "agent.*", "assessments", "response.*", "approvals.*", "env.actions"]


@dataclass
class PartitionRule:
    """Drop messages from senders matching ``senders`` to topics matching ``topics``."""

    senders: list[str]
    topics: list[str]
    drop_prob: float = 1.0
    start_wall: float | None = None  # optional activation window (relative seconds)
    end_wall: float | None = None


@dataclass
class NetworkConditions:
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_prob: float = 0.0
    partitions: list[PartitionRule] = field(default_factory=list)
    applies_to: list[str] = field(default_factory=lambda: list(DEFAULT_SCOPE))
    seed: int = 0

    @property
    def is_noop(self) -> bool:
        return self.delay_ms == 0 and self.jitter_ms == 0 and self.loss_prob == 0 and not self.partitions


def _match(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


class ConditionedBroker(MessageBroker):
    def __init__(self, inner: MessageBroker, conditions: NetworkConditions | None = None) -> None:
        super().__init__()
        self.inner = inner
        self.stats = inner.stats  # delivered traffic is accounted by the inner broker
        self.conditions = conditions or NetworkConditions()
        self._rng = random.Random(self.conditions.seed)
        self._inflight: set[asyncio.Task] = set()
        self.dropped: dict[str, int] = {}
        self.delayed = 0
        self._t0: float | None = None

    async def connect(self) -> None:
        await self.inner.connect()

    async def close(self) -> None:
        for t in list(self._inflight):
            t.cancel()
        await self.inner.close()

    def _partitioned(self, sender: str, topic: str) -> bool:
        loop_t = asyncio.get_running_loop().time()
        if self._t0 is None:
            self._t0 = loop_t
        rel = loop_t - self._t0
        for rule in self.conditions.partitions:
            if rule.start_wall is not None and rel < rule.start_wall:
                continue
            if rule.end_wall is not None and rel > rule.end_wall:
                continue
            if _match(sender, rule.senders) and _match(topic, rule.topics):
                if self._rng.random() < rule.drop_prob:
                    return True
        return False

    async def publish(self, topic: str, envelope: Envelope) -> str:
        c = self.conditions
        if c.is_noop or not _match(topic, c.applies_to):
            return await self.inner.publish(topic, envelope)
        if self._partitioned(envelope.sender, topic) or (c.loss_prob and self._rng.random() < c.loss_prob):
            self.dropped[topic] = self.dropped.get(topic, 0) + 1
            return ""
        delay = c.delay_ms + (self._rng.uniform(-c.jitter_ms, c.jitter_ms) if c.jitter_ms else 0.0)
        if delay <= 0:
            return await self.inner.publish(topic, envelope)
        self.delayed += 1

        async def _later() -> None:
            await asyncio.sleep(delay / 1000)
            await self.inner.publish(topic, envelope)

        task = asyncio.create_task(_later())
        self._inflight.add(task)
        task.add_done_callback(self._inflight.discard)
        return "delayed"

    @property
    def inflight(self) -> int:
        return len(self._inflight)

    # ---------------------------------------------------------- delegation
    async def ensure_group(self, topic: str, group: str, start: str = "0") -> None:
        await self.inner.ensure_group(topic, group, start)

    async def read(self, topic, group, consumer, count=100, block_ms=100) -> list[Delivery]:
        return await self.inner.read(topic, group, consumer, count, block_ms)

    async def ack(self, topic, group, entry_ids) -> None:
        await self.inner.ack(topic, group, entry_ids)

    async def claim_stale(self, topic, group, consumer, min_idle_ms, count=100) -> list[Delivery]:
        return await self.inner.claim_stale(topic, group, consumer, min_idle_ms, count)

    async def range(self, topic, count=None) -> list[Delivery]:
        return await self.inner.range(topic, count)

    async def lag(self, topic, group) -> int:
        return await self.inner.lag(topic, group)

    async def topics(self) -> list[str]:
        return await self.inner.topics()

    async def groups(self, topic) -> list[str]:
        return await self.inner.groups(topic)
