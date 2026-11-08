"""Redis Streams transport (requires ``redis>=5``; not needed for local tests).

Mapping:  publish -> XADD (approximate MAXLEN trimming)
          ensure_group -> XGROUP CREATE ... MKSTREAM
          read -> XREADGROUP (">")       ack -> XACK
          claim_stale -> XAUTOCLAIM + XPENDING (delivery counter)
          range -> XRANGE                lag -> XINFO GROUPS (lag + pending)
"""

from __future__ import annotations

import logging

from mcd.communication.message import Envelope
from mcd.communication.message_broker import Delivery, MessageBroker

try:  # optional dependency
    import redis.asyncio as aioredis
    from redis.exceptions import ResponseError
except ImportError:  # pragma: no cover - exercised only when redis is missing
    aioredis = None
    ResponseError = Exception

log = logging.getLogger(__name__)
FIELD = "m"


class RedisStreamsBroker(MessageBroker):
    def __init__(self, url: str = "redis://localhost:6379/0", maxlen: int | None = 100_000) -> None:
        if aioredis is None:
            raise RuntimeError("redis-py is not installed: pip install 'redis>=5'")
        super().__init__()
        self.url = url
        self.maxlen = maxlen
        self._r = aioredis.from_url(url, decode_responses=False)
        self._groups: dict[str, set[str]] = {}

    async def connect(self) -> None:
        await self._r.ping()

    async def close(self) -> None:
        await self._r.aclose()

    async def publish(self, topic: str, envelope: Envelope) -> str:
        data = envelope.to_bytes()
        kwargs = {"maxlen": self.maxlen, "approximate": True} if self.maxlen else {}
        eid = await self._r.xadd(topic, {FIELD: data}, **kwargs)
        self.stats.record(topic, envelope.sender, len(data))
        return eid.decode() if isinstance(eid, bytes) else eid

    async def ensure_group(self, topic: str, group: str, start: str = "0") -> None:
        try:
            await self._r.xgroup_create(topic, group, id=start, mkstream=True)
        except ResponseError as exc:  # BUSYGROUP: already exists
            if "BUSYGROUP" not in str(exc):
                raise
        self._groups.setdefault(topic, set()).add(group)

    def _decode(self, topic: str, eid, fields, deliveries: int = 1) -> Delivery | None:
        eid = eid.decode() if isinstance(eid, bytes) else eid
        raw = fields.get(FIELD.encode()) if fields else None
        if raw is None:
            return None
        try:
            env = Envelope.from_bytes(raw)
        except Exception:  # malformed -> caller sends to DLQ through deliveries counter
            log.warning("undecodable message %s on %s", eid, topic)
            return None
        return Delivery(topic, eid, env, deliveries, len(raw))

    async def read(
        self, topic: str, group: str, consumer: str, count: int = 100, block_ms: int = 100
    ) -> list[Delivery]:
        resp = await self._r.xreadgroup(group, consumer, {topic: ">"}, count=count, block=block_ms or None)
        out: list[Delivery] = []
        for _stream, entries in resp or []:
            for eid, fields in entries:
                d = self._decode(topic, eid, fields)
                if d is None:
                    await self._r.xack(topic, group, eid)
                    continue
                out.append(d)
        return out

    async def ack(self, topic: str, group: str, entry_ids: list[str]) -> None:
        if entry_ids:
            await self._r.xack(topic, group, *entry_ids)

    async def claim_stale(
        self, topic: str, group: str, consumer: str, min_idle_ms: int, count: int = 100
    ) -> list[Delivery]:
        res = await self._r.xautoclaim(topic, group, consumer, min_idle_time=min_idle_ms, start_id="0-0", count=count)
        entries = res[1] if len(res) > 1 else []
        out: list[Delivery] = []
        for eid, fields in entries:
            info = await self._r.xpending_range(topic, group, min=eid, max=eid, count=1)
            deliveries = int(info[0]["times_delivered"]) if info else 1
            d = self._decode(topic, eid, fields, deliveries)
            if d is not None:
                out.append(d)
        return out

    async def range(self, topic: str, count: int | None = None) -> list[Delivery]:
        if count is None:
            entries = await self._r.xrange(topic)
        else:
            entries = list(reversed(await self._r.xrevrange(topic, count=count)))
        return [d for eid, f in entries if (d := self._decode(topic, eid, f, 0)) is not None]

    async def lag(self, topic: str, group: str) -> int:
        try:
            infos = await self._r.xinfo_groups(topic)
        except ResponseError:
            return 0
        for info in infos:
            name = info.get("name")
            name = name.decode() if isinstance(name, bytes) else name
            if name == group:
                return int(info.get("lag") or 0) + int(info.get("pending") or 0)
        return 0

    async def topics(self) -> list[str]:
        return list(self._groups)

    async def groups(self, topic: str) -> list[str]:
        return list(self._groups.get(topic, ()))
