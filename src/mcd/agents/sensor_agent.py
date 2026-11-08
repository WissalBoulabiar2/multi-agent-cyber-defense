"""Generic sensor agent: observe -> analyse -> assess -> share -> answer queries.

Specialised by domain (network / auth / config). Raw observations and every
window score stay local; only alerts passing the communication policy and
bounded context summaries leave the agent.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable

from mcd.agents.base_agent import BaseAgent, Subscription
from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.communication.message_broker import MessageBroker
from mcd.communication.policy import CommunicationPolicy, PolicyConfig
from mcd.core.enums import CoordinationMode, Domain, MessageType, Priority, priority_for
from mcd.core.ids import new_id
from mcd.core.inventory import AssetInventory
from mcd.core.models import (
    ContextRequest, ContextResponse, EntityRef, Evidence, LocalAlert, Observation, ThreatAdvisory, Watermark,
)
from mcd.detection.pipeline import DomainPipeline, PipelineConfig, WindowScore


@dataclass
class SensorConfig:
    mode: CoordinationMode = CoordinationMode.COOPERATIVE
    tau_act: float = 0.7             # independent mode: local action threshold
    history_min: float = 0.15        # windows below this are not kept for context answers
    history_s: float = 3600.0
    related_discount: float = 0.8    # confidence attributed to related (non-primary) entities
    min_share_threshold: float = 0.2
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)


@dataclass
class _HistItem:
    t: float
    confidence: float
    alert_type: str
    tactic: str | None
    primary: bool


class SensorAgent(BaseAgent):
    def __init__(
        self,
        domain: Domain,
        shard: int,
        broker: MessageBroker,
        inventory: AssetInventory,
        training_data: Callable[[], list[Observation]] | None = None,
        cfg: SensorConfig | None = None,
        **kwargs,
    ) -> None:
        super().__init__(T.sensor_agent_id(domain, shard), broker, **kwargs)
        self.domain = Domain(domain)
        self.shard = shard
        self.cfg = cfg or SensorConfig()
        self.inventory = inventory
        self.pipeline = DomainPipeline(self.domain, inventory, cfg=self.cfg.pipeline)
        self.policy = CommunicationPolicy(self.cfg.policy)
        self._training_data = training_data
        self.history: dict[EntityRef, deque[_HistItem]] = defaultdict(deque)
        self.watch: dict[EntityRef, tuple[float, float]] = {}  # entity -> (expires sim t, delta)
        self.sim_now = 0.0
        self.windows_scored = 0
        self.alerts_emitted = 0
        self.context_answered = 0

    def subscriptions(self) -> list[Subscription]:
        return [Subscription(T.inbox(self.agent_id), priority=0), Subscription(T.sim_events(self.domain, self.shard), priority=1)]

    async def setup(self) -> None:
        events = self._training_data() if self._training_data else []
        self.pipeline.train(events)

    # ----------------------------------------------------------------- handle
    async def handle(self, env: Envelope) -> None:
        if env.type == MessageType.OBSERVATION:
            self.pipeline.add(env.parse(Observation))
        elif env.type == MessageType.WATERMARK:
            wm = env.parse(Watermark)
            self.sim_now = max(self.sim_now, wm.t)
            for score in self.pipeline.close_until(wm.t):
                await self._on_score(score)
            self._gc()
        elif env.type == MessageType.CONTEXT_REQUEST:
            await self._answer(env)
        elif env.type == MessageType.THREAT_ADVISORY:
            adv = env.parse(ThreatAdvisory)
            for e in adv.entities:
                self.watch[e] = (adv.issued_at + adv.ttl_seconds, adv.share_threshold_delta)

    # -------------------------------------------------------------- scoring
    def _threshold_delta(self, s: WindowScore) -> float:
        best = 0.0
        for e in [s.entity, *s.related]:
            w = self.watch.get(e)
            if w and w[0] >= s.window_end:
                best = min(best, w[1])
        return best

    def _remember(self, s: WindowScore) -> None:
        if s.confidence < self.cfg.history_min:
            return
        self.history[s.entity].append(_HistItem(s.window_end, s.confidence, s.alert_type, s.tactic, True))
        for e in s.related:
            self.history[e].append(
                _HistItem(s.window_end, s.confidence * self.cfg.related_discount, s.alert_type, s.tactic, False)
            )

    def _gc(self) -> None:
        horizon = self.sim_now - self.cfg.history_s
        for e in list(self.history):
            dq = self.history[e]
            while dq and dq[0].t < horizon:
                dq.popleft()
            if not dq:
                del self.history[e]
        self.watch = {e: w for e, w in self.watch.items() if w[0] >= self.sim_now}

    def _to_alert(self, s: WindowScore) -> LocalAlert:
        return LocalAlert(
            alert_id=new_id(f"{self.agent_id}-"), domain=self.domain, agent_id=self.agent_id,
            entities=[s.entity, *s.related], alert_type=s.alert_type, tactic=s.tactic,
            anomaly_score=round(s.anomaly.score, 4), rule_confidence=round(s.rule_confidence, 4),
            confidence=round(s.confidence, 4), status=s.status, severity=s.severity,
            window_start=s.window_start, window_end=s.window_end,
            evidence=Evidence(rule_ids=[h.rule_id for h in s.hits], top_features=s.anomaly.top_features,
                              event_ids=s.event_ids, summary=s.explanation),
        )

    async def _on_score(self, s: WindowScore) -> None:
        self.windows_scored += 1
        self._remember(s)
        if s.confidence < self.cfg.min_share_threshold:
            return
        alert = self._to_alert(s)
        prio = priority_for(s.severity)
        if self.cfg.mode == CoordinationMode.INDEPENDENT:
            ok, _ = self.policy.evaluate(alert, threshold=self.cfg.tau_act)
            topic = T.ALERTS_DIRECT
        else:
            thr = max(self.cfg.min_share_threshold, self.cfg.policy.share_threshold + self._threshold_delta(s))
            ok, _ = self.policy.evaluate(alert, threshold=thr)
            topic = T.alerts(prio)
        if not ok:
            return
        size = len(alert.model_dump_json()) + 512  # envelope overhead estimate
        ok, _ = self.policy.admit(alert, prio, size)
        if not ok:
            return
        self.alerts_emitted += 1
        await self.send(topic, MessageType.LOCAL_ALERT, alert, priority=prio, severity=s.severity,
                        sim_time=s.window_end, ttl_s=600.0)

    # ------------------------------------------------------- context answers
    async def _answer(self, env: Envelope) -> None:
        req = env.parse(ContextRequest)
        items = [h for h in self.history.get(req.entity, ()) if req.window_start <= h.t <= req.window_end]
        items_conf = [h.confidence for h in items]
        types = sorted({h.alert_type for h in items if h.confidence >= 0.2})
        tactics = sorted({h.tactic for h in items if h.tactic and h.confidence >= 0.2})
        resp = ContextResponse(
            request_id=req.request_id, incident_id=req.incident_id, responder=self.agent_id, domain=self.domain,
            entity=req.entity, max_confidence=round(max(items_conf, default=0.0), 4), alert_types=types[:5],
            tactics=tactics, summary_stats={"windows": float(len(items)),
                                            "mean_conf": float(sum(items_conf) / len(items_conf)) if items_conf else 0.0,
                                            "primary_windows": float(sum(1 for h in items if h.primary))},
            last_seen=max((h.t for h in items), default=None),
        )
        self.context_answered += 1
        await self.send(T.inbox(env.sender), MessageType.CONTEXT_RESPONSE, resp, recipient=env.sender,
                        priority=Priority.P0, sim_time=self.sim_now, correlation_id=req.incident_id,
                        causation_id=env.message_id, ttl_s=120.0)
