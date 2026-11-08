"""In-process broker reproducing Redis Streams consumer-group semantics.

Messages are stored as **serialized bytes** and decoded on every read, so no
Python object is ever shared between agents (no hidden shared memory).
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field

from mcd.communication.message import Envelope
from mcd.communication.message_broker import Delivery, MessageBroker


@dataclass
class _Pending:
    consumer: str
    delivered_at: float
    deliveries: int
    data: bytes


@dataclass
class _Group:
    last_seq: int
    pending: dict[int, _Pending] = field(default_factory=dict)


class _Stream:
    def __init__(self) -> None:
        self.entries: deque[tuple[int, bytes]] = deque()
        self.next_seq = 1
        self.groups: dict[str, _Group] = {}
        self.cond = asyncio.Condition()

    @property
    def first_seq(self) -> int:
        return self.entries[0][0] if self.entries else self.next_seq


def _eid(seq: int) -> str:
    return f"{seq}-0"


def _seq(entry_id: str) -> int:
    return int(entry_id.split("-")[0])


class InMemoryBroker(MessageBroker):
    def __init__(self, maxlen: int | None = None) -> None:
        super().__init__()
        self.maxlen = maxlen
        self._streams: dict[str, _Stream] = {}

    def _stream(self, topic: str) -> _Stream:
        s = self._streams.get(topic)
        if s is None:
            s = self._streams[topic] = _Stream()
        return s

    async def publish(self, topic: str, envelope: Envelope) -> str:
        data = envelope.to_bytes()
        s = self._stream(topic)
        seq = s.next_seq
        s.next_seq += 1
        s.entries.append((seq, data))
        if self.maxlen is not None:
            while len(s.entries) > self.maxlen:
                s.entries.popleft()
        self.stats.record(topic, envelope.sender, len(data))
        async with s.cond:
            s.cond.notify_all()
        return _eid(seq)

    async def ensure_group(self, topic: str, group: str, start: str = "0") -> None:
        s = self._stream(topic)
        if group not in s.groups:
            last = 0 if start == "0" else s.next_seq - 1
            s.groups[group] = _Group(last_seq=last)

    def _take_new(self, s: _Stream, g: _Group, consumer: str, count: int) -> list[Delivery]:
        out: list[Delivery] = []
        start = max(g.last_seq + 1, s.first_seq)
        idx = start - s.first_seq
        now = time.time()
        while idx < len(s.entries) and len(out) < count:
            seq, data = s.entries[idx]
            g.pending[seq] = _Pending(consumer, now, 1, data)
            g.last_seq = seq
            out.append(Delivery("", _eid(seq), Envelope.from_bytes(data), 1, len(data)))
            idx += 1
        if not out and s.entries and g.last_seq < s.first_seq - 1:
            g.last_seq = s.first_seq - 1  # trimmed past the cursor
        return out

    async def read(
        self, topic: str, group: str, consumer: str, count: int = 100, block_ms: int = 100
    ) -> list[Delivery]:
        s = self._stream(topic)
        if group not in s.groups:
            await self.ensure_group(topic, group)
        g = s.groups[group]
        out = self._take_new(s, g, consumer, count)
        if not out and block_ms > 0:
            try:
                async with s.cond:
                    await asyncio.wait_for(
                        s.cond.wait_for(lambda: s.next_seq - 1 > g.last_seq), block_ms / 1000
                    )
            except asyncio.TimeoutError:
                return []
            out = self._take_new(s, g, consumer, count)
        for d in out:
            d.topic = topic
        return out

    async def ack(self, topic: str, group: str, entry_ids: list[str]) -> None:
        g = self._stream(topic).groups.get(group)
        if g is None:
            return
        for eid in entry_ids:
            g.pending.pop(_seq(eid), None)

    async def claim_stale(
        self, topic: str, group: str, consumer: str, min_idle_ms: int, count: int = 100
    ) -> list[Delivery]:
        g = self._stream(topic).groups.get(group)
        if g is None:
            return []
        now = time.time()
        out: list[Delivery] = []
        for seq, p in sorted(g.pending.items()):
            if len(out) >= count:
                break
            if (now - p.delivered_at) * 1000 >= min_idle_ms:
                p.consumer = consumer
                p.delivered_at = now
                p.deliveries += 1
                out.append(Delivery(topic, _eid(seq), Envelope.from_bytes(p.data), p.deliveries, len(p.data)))
        return out

    async def range(self, topic: str, count: int | None = None) -> list[Delivery]:
        s = self._streams.get(topic)
        if s is None:
            return []
        items = list(s.entries)
        if count is not None:
            items = items[-count:]
        return [Delivery(topic, _eid(seq), Envelope.from_bytes(d), 0, len(d)) for seq, d in items]

    async def lag(self, topic: str, group: str) -> int:
        s = self._streams.get(topic)
        if s is None or group not in s.groups:
            return 0
        g = s.groups[group]
        undelivered = max(0, (s.next_seq - 1) - max(g.last_seq, s.first_seq - 1))
        return undelivered + len(g.pending)

    async def topics(self) -> list[str]:
        return list(self._streams)

    async def groups(self, topic: str) -> list[str]:
        s = self._streams.get(topic)
        return list(s.groups) if s else []

    def pending_count(self, topic: str, group: str) -> int:
        g = self._stream(topic).groups.get(group)
        return len(g.pending) if g else 0
