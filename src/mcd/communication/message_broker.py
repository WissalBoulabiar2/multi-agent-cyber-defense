"""Broker abstraction with stream + consumer-group semantics (Redis Streams model).

Both transports implement the same contract so agent code is broker-agnostic:

* ``publish``  appends a message to a stream (topic).
* ``read``     returns new messages for a consumer group (each group sees every
               message once; consumers in one group share the work).
* ``ack``      marks a delivered message as processed (at-least-once delivery).
* ``claim_stale`` re-delivers messages that were delivered but never acked
               (crash recovery), incrementing their delivery counter.
* ``range``    replays a stream (dashboard history, offline evaluation).
"""

from __future__ import annotations

import abc
from collections import defaultdict
from dataclasses import dataclass, field

from mcd.communication.message import Envelope


@dataclass
class Delivery:
    topic: str
    entry_id: str
    envelope: Envelope
    deliveries: int = 1
    size: int = 0


@dataclass
class BrokerStats:
    published_msgs: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    published_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # sender -> topic -> [msgs, bytes]
    by_sender: dict[str, dict[str, list[int]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(lambda: [0, 0]))
    )

    def record(self, topic: str, sender: str, size: int) -> None:
        self.published_msgs[topic] += 1
        self.published_bytes[topic] += size
        entry = self.by_sender[sender][topic]
        entry[0] += 1
        entry[1] += size

    def snapshot(self) -> dict:
        return {
            "published_msgs": dict(self.published_msgs),
            "published_bytes": dict(self.published_bytes),
            "by_sender": {s: {t: list(v) for t, v in d.items()} for s, d in self.by_sender.items()},
        }


class MessageBroker(abc.ABC):
    def __init__(self) -> None:
        self.stats = BrokerStats()

    async def connect(self) -> None:  # pragma: no cover - default no-op
        return None

    async def close(self) -> None:  # pragma: no cover - default no-op
        return None

    @abc.abstractmethod
    async def publish(self, topic: str, envelope: Envelope) -> str: ...

    @abc.abstractmethod
    async def ensure_group(self, topic: str, group: str, start: str = "0") -> None: ...

    @abc.abstractmethod
    async def read(
        self, topic: str, group: str, consumer: str, count: int = 100, block_ms: int = 100
    ) -> list[Delivery]: ...

    @abc.abstractmethod
    async def ack(self, topic: str, group: str, entry_ids: list[str]) -> None: ...

    @abc.abstractmethod
    async def claim_stale(
        self, topic: str, group: str, consumer: str, min_idle_ms: int, count: int = 100
    ) -> list[Delivery]: ...

    @abc.abstractmethod
    async def range(self, topic: str, count: int | None = None) -> list[Delivery]: ...

    @abc.abstractmethod
    async def lag(self, topic: str, group: str) -> int:
        """Number of messages not yet delivered to the group plus pending (unacked)."""

    @abc.abstractmethod
    async def topics(self) -> list[str]: ...

    @abc.abstractmethod
    async def groups(self, topic: str) -> list[str]: ...

    async def total_lag(self, prefixes: tuple[str, ...] | None = None) -> int:
        total = 0
        for t in await self.topics():
            if prefixes is not None and not t.startswith(prefixes):
                continue
            for g in await self.groups(t):
                total += await self.lag(t, g)
        return total
