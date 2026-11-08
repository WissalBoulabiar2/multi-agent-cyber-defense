"""BaseAgent: lifecycle, broker I/O, prioritisation, reliability and telemetry.

Each agent owns:
* one reader task per subscription (consumer group = agent's group name),
* a bounded local priority queue (back-pressure),
* one worker task that calls ``handle`` and acks only on success,
* a heartbeat/tick task (liveness, stale-message reclaim, periodic hooks).

Reliability: at-least-once delivery + idempotent processing (message_id LRU),
TTL expiry, poison messages moved to ``dlq.<topic>`` after ``max_deliveries``.
``crash()`` simulates an abrupt failure (tasks cancelled, nothing acked).
"""

from __future__ import annotations

import abc
import asyncio
import itertools
import logging
import os
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.communication.message_broker import Delivery, MessageBroker
from mcd.core.enums import AgentState, Domain, MessageType, Priority, Severity
from mcd.core.models import Heartbeat

log = logging.getLogger(__name__)

try:  # optional
    import psutil

    _PROC = psutil.Process(os.getpid())
except Exception:  # pragma: no cover
    _PROC = None


@dataclass
class Subscription:
    topic: str
    priority: int = 1  # lower = more urgent
    group: str | None = None  # defaults to the agent's group


@dataclass
class AgentMetrics:
    processed: int = 0
    failed: int = 0
    duplicates: int = 0
    expired: int = 0
    dead_lettered: int = 0
    handler_time_s: list[float] = field(default_factory=list)
    delivery_latency_s: list[float] = field(default_factory=list)
    sent_msgs: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    sent_bytes: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    recv_msgs: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def summary(self) -> dict[str, Any]:
        import numpy as np

        def pct(xs: list[float], q: float) -> float:
            return float(np.percentile(xs, q)) if xs else 0.0

        return {
            "processed": self.processed,
            "failed": self.failed,
            "duplicates": self.duplicates,
            "expired": self.expired,
            "dead_lettered": self.dead_lettered,
            "handler_ms_mean": 1000 * float(np.mean(self.handler_time_s)) if self.handler_time_s else 0.0,
            "handler_ms_p95": 1000 * pct(self.handler_time_s, 95),
            "handler_s_total": float(sum(self.handler_time_s)),
            "delivery_ms_p50": 1000 * pct(self.delivery_latency_s, 50),
            "delivery_ms_p95": 1000 * pct(self.delivery_latency_s, 95),
            "delivery_ms_mean": 1000 * float(np.mean(self.delivery_latency_s)) if self.delivery_latency_s else 0.0,
            "sent_msgs": dict(self.sent_msgs),
            "sent_bytes": dict(self.sent_bytes),
            "recv_msgs": dict(self.recv_msgs),
        }


class BaseAgent(abc.ABC):
    domain: Domain = Domain.OBSERVER

    def __init__(
        self,
        agent_id: str,
        broker: MessageBroker,
        *,
        heartbeat_interval: float = 1.0,
        queue_size: int = 5000,
        max_deliveries: int = 5,
        claim_idle_ms: int = 3000,
        read_block_ms: int = 50,
        read_count: int = 500,
        dedup_size: int = 20_000,
        group: str | None = None,
        max_latency_samples: int = 50_000,
    ) -> None:
        self.agent_id = agent_id
        self.broker = broker
        self.group = group or agent_id
        self.heartbeat_interval = heartbeat_interval
        self.max_deliveries = max_deliveries
        self.claim_idle_ms = claim_idle_ms
        self.read_block_ms = read_block_ms
        self.read_count = read_count
        self.state = AgentState.STARTING
        self.metrics = AgentMetrics()
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=queue_size)
        self._seq = itertools.count()
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._dedup_size = dedup_size
        self._tasks: list[asyncio.Task] = []
        self._retry: list[tuple[str, str, Delivery]] = []
        self._max_lat = max_latency_samples
        self._started_wall: float | None = None

    # ------------------------------------------------------------ to override
    @abc.abstractmethod
    def subscriptions(self) -> list[Subscription]: ...

    @abc.abstractmethod
    async def handle(self, env: Envelope) -> None: ...

    async def setup(self) -> None:
        """Called once before the agent starts consuming (e.g. local training)."""

    async def on_tick(self) -> None:
        """Called every heartbeat interval."""

    # -------------------------------------------------------------- lifecycle
    @property
    def running(self) -> bool:
        return any(not t.done() for t in self._tasks)

    async def start(self) -> None:
        if self.running:
            return
        self.state = AgentState.STARTING
        if self._started_wall is None:
            await self.setup()
        self._started_wall = time.time()
        self._queue = asyncio.PriorityQueue(maxsize=self._queue.maxsize)
        subs = self.subscriptions()
        for sub in subs:
            await self.broker.ensure_group(sub.topic, sub.group or self.group)
        await self._recover(subs)
        self._tasks = [asyncio.create_task(self._reader(s), name=f"{self.agent_id}:read:{s.topic}") for s in subs]
        self._tasks.append(asyncio.create_task(self._worker(), name=f"{self.agent_id}:worker"))
        self._tasks.append(asyncio.create_task(self._ticker(), name=f"{self.agent_id}:tick"))
        self.state = AgentState.RUNNING
        await self._heartbeat()

    async def stop(self) -> None:
        self.state = AgentState.STOPPING
        try:
            await self._heartbeat()
        except Exception:  # pragma: no cover
            pass
        await self._cancel_tasks()
        self.state = AgentState.DOWN

    def crash(self) -> None:
        """Abrupt failure: cancel everything; unacked messages stay pending."""
        for t in self._tasks:
            t.cancel()
        self.state = AgentState.DOWN

    async def _cancel_tasks(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []

    async def drained(self) -> bool:
        return self._queue.empty()

    # ------------------------------------------------------------------- I/O
    async def send(
        self,
        topic: str,
        mtype: MessageType,
        payload: BaseModel | dict,
        *,
        recipient: str | None = None,
        priority: Priority = Priority.P1,
        severity: Severity | None = None,
        sim_time: float = 0.0,
        correlation_id: str | None = None,
        causation_id: str | None = None,
        ttl_s: float | None = None,
    ) -> Envelope:
        env = Envelope.build(
            mtype,
            self.agent_id,
            topic,
            payload,
            recipient=recipient,
            priority=priority,
            severity=severity,
            sim_time=sim_time,
            correlation_id=correlation_id,
            causation_id=causation_id,
            ttl_s=ttl_s,
        )
        size = len(env.to_bytes())
        await self.broker.publish(topic, env)
        self.metrics.sent_msgs[topic] += 1
        self.metrics.sent_bytes[topic] += size
        return env

    async def _recover(self, subs: list[Subscription]) -> None:
        """Re-deliver messages left pending by a previous incarnation of this agent."""
        for sub in subs:
            stale = await self.broker.claim_stale(sub.topic, sub.group or self.group, self.agent_id, 0)
            for d in stale:
                await self._enqueue(sub, d)

    async def _enqueue(self, sub: Subscription, d: Delivery) -> None:
        group = sub.group or self.group
        if d.deliveries > self.max_deliveries:
            await self.broker.publish(T.dlq(sub.topic), d.envelope)
            await self.broker.ack(sub.topic, group, [d.entry_id])
            self.metrics.dead_lettered += 1
            return
        prio = min(sub.priority, int(d.envelope.priority)) if sub.topic.startswith("agent.") else sub.priority
        await self._queue.put((prio, next(self._seq), sub.topic, group, d))

    async def _reader(self, sub: Subscription) -> None:
        group = sub.group or self.group
        while True:
            try:
                batch = await self.broker.read(sub.topic, group, self.agent_id, self.read_count, self.read_block_ms)
            except asyncio.CancelledError:
                raise
            except Exception:  # broker hiccup: back off, keep going
                log.exception("%s read error on %s", self.agent_id, sub.topic)
                await asyncio.sleep(0.2)
                continue
            for d in batch:
                await self._enqueue(sub, d)
            if not batch:
                await asyncio.sleep(0)

    async def _worker(self) -> None:
        while True:
            _prio, _seq, topic, group, d = await self._queue.get()
            env = d.envelope
            now = time.time()
            self.metrics.recv_msgs[topic] += 1
            if env.message_id in self._seen:
                self.metrics.duplicates += 1
                await self.broker.ack(topic, group, [d.entry_id])
                continue
            if env.expired(now):
                self.metrics.expired += 1
                await self.broker.ack(topic, group, [d.entry_id])
                continue
            if len(self.metrics.delivery_latency_s) < self._max_lat:
                self.metrics.delivery_latency_s.append(max(0.0, now - env.created_at))
            t0 = time.perf_counter()
            try:
                await self.handle(env)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.metrics.failed += 1
                log.exception("%s failed handling %s from %s", self.agent_id, env.type, env.sender)
                # not acked: retried on next tick, dead-lettered after max_deliveries
                d.deliveries += 1
                self._retry.append((topic, group, d))
                continue
            dt = time.perf_counter() - t0
            if len(self.metrics.handler_time_s) < self._max_lat:
                self.metrics.handler_time_s.append(dt)
            self.metrics.processed += 1
            self._seen[env.message_id] = None
            if len(self._seen) > self._dedup_size:
                self._seen.popitem(last=False)
            await self.broker.ack(topic, group, [d.entry_id])

    async def _ticker(self) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            try:
                await self._heartbeat()
                await self.on_tick()
                retry, self._retry = self._retry, []
                for topic, group, d in retry:
                    await self._enqueue(Subscription(topic, priority=Priority.P2, group=group), d)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("%s tick error", self.agent_id)

    async def _heartbeat(self) -> None:
        cpu, rss = 0.0, 0.0
        if _PROC is not None:  # process-level (shared by co-located agents)
            ct = _PROC.cpu_times()
            cpu, rss = ct.user + ct.system, _PROC.memory_info().rss / 2**20
        hb = Heartbeat(
            agent_id=self.agent_id,
            domain=self.domain,
            state=str(self.state),
            queue_depth=self._queue.qsize(),
            processed=self.metrics.processed,
            failed=self.metrics.failed,
            cpu_time_s=cpu,
            rss_mb=rss,
            wall_time=time.time(),
        )
        await self.send(T.HEARTBEAT, MessageType.HEARTBEAT, hb, priority=Priority.P2, ttl_s=10 * self.heartbeat_interval)
