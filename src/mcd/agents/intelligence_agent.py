"""Agent 4 — Threat Intelligence & Coordination Agent.

Receives only *shared alerts*, context responses, response reports and
heartbeats — never raw observations. Correlates alerts into incidents,
estimates global severity, pulls targeted context from the owners of related
entities when the answer could change the decision (value of information),
issues sensitivity advisories, and publishes global threat assessments.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from mcd.agents.base_agent import BaseAgent, Subscription
from mcd.communication import topics as T
from mcd.communication.coordination import CorrelatedAlert, Correlator, FusionConfig, FusionResult, Incident
from mcd.communication.message import Envelope
from mcd.communication.message_broker import MessageBroker
from mcd.core.enums import AgentState, Domain, MessageType, Priority, priority_for
from mcd.core.ids import new_id
from mcd.core.inventory import AssetInventory
from mcd.core.models import (
    ContextRequest, ContextResponse, EntityRef, Heartbeat, LocalAlert, ResponseReport, ThreatAdvisory, Watermark,
)


@dataclass
class HealthEntry:
    agent_id: str
    domain: str
    last_seen: float
    state: str
    processed: int = 0


@dataclass
class IntelConfig:
    fusion: FusionConfig = field(default_factory=FusionConfig)
    shards: dict[str, int] = field(default_factory=lambda: {"network": 1, "auth": 1, "config": 1})
    degraded_after_s: float = 3.0
    down_after_s: float = 6.0
    query_window_s: float = 1800.0


class ThreatIntelligenceAgent(BaseAgent):
    domain = Domain.INTEL

    def __init__(self, broker: MessageBroker, inventory: AssetInventory, cfg: IntelConfig | None = None,
                 agent_id: str = "intel-0", **kwargs) -> None:
        super().__init__(agent_id, broker, **kwargs)
        self.cfg = cfg or IntelConfig()
        self.correlator = Correlator(self.cfg.fusion, inventory)
        self.health: dict[str, HealthEntry] = {}
        self.pending_queries: dict[str, str] = {}  # request_id -> incident_id
        self.sim_now = 0.0
        self.reports: list[ResponseReport] = []
        self.counters = {"alerts": 0, "queries": 0, "context_used": 0, "advisories": 0, "assessments": 0,
                         "queries_skipped_down": 0, "queries_skipped_voi": 0}

    def subscriptions(self) -> list[Subscription]:
        return [
            Subscription(T.inbox(self.agent_id), priority=0),
            Subscription(T.alerts(Priority.P0), priority=0),
            Subscription(T.alerts(Priority.P1), priority=1),
            Subscription(T.alerts(Priority.P2), priority=2),
            Subscription(T.RESPONSE_REPORTS, priority=1),
            Subscription(T.HEARTBEAT, priority=2),
            Subscription(T.SIM_CLOCK, priority=2),
        ]

    # ------------------------------------------------------------ ownership
    def owners(self, entity: EntityRef) -> list[tuple[str, Domain]]:
        """Which sensor agents hold local knowledge about ``entity`` (public sharding map)."""
        out: list[tuple[str, Domain]] = []
        sh = self.cfg.shards
        if entity.kind == "host":
            for d in (Domain.NETWORK, Domain.CONFIG):
                n = sh.get(str(d), 0)
                if n:
                    out.append((T.sensor_agent_id(d, T.shard_of(entity.id, n)), d))
            for s in range(sh.get("auth", 0)):  # auth is sharded by user: hosts appear in any shard
                out.append((T.sensor_agent_id(Domain.AUTH, s), Domain.AUTH))
        elif entity.kind == "user":
            n = sh.get("auth", 0)
            if n:
                out.append((T.sensor_agent_id(Domain.AUTH, T.shard_of(entity.id, n)), Domain.AUTH))
            for s in range(sh.get("config", 0)):  # config agents see actors of changes
                out.append((T.sensor_agent_id(Domain.CONFIG, s), Domain.CONFIG))
        return out

    def is_down(self, agent_id: str) -> bool:
        h = self.health.get(agent_id)
        return h is not None and h.state == str(AgentState.DOWN)

    # --------------------------------------------------------------- handle
    async def handle(self, env: Envelope) -> None:
        t = env.type
        if t == MessageType.LOCAL_ALERT:
            await self._on_alert(env.parse(LocalAlert))
        elif t == MessageType.CONTEXT_RESPONSE:
            await self._on_context(env.parse(ContextResponse))
        elif t == MessageType.HEARTBEAT:
            hb = env.parse(Heartbeat)
            self.health[hb.agent_id] = HealthEntry(hb.agent_id, str(hb.domain), time.time(), hb.state, hb.processed)
        elif t == MessageType.RESPONSE_REPORT:
            self.reports.append(env.parse(ResponseReport))
        elif t == MessageType.WATERMARK:
            self.sim_now = max(self.sim_now, env.parse(Watermark).t)
            self.correlator.expire(self.sim_now)

    async def on_tick(self) -> None:
        now = time.time()
        for h in self.health.values():
            if h.state in (str(AgentState.STOPPING),):
                continue
            age = now - h.last_seen
            if age > self.cfg.down_after_s:
                h.state = str(AgentState.DOWN)
            elif age > self.cfg.degraded_after_s:
                h.state = str(AgentState.DEGRADED)

    async def _on_alert(self, a: LocalAlert) -> None:
        self.counters["alerts"] += 1
        self.sim_now = max(self.sim_now, a.window_end)
        ca = CorrelatedAlert(
            alert_id=a.alert_id, domain=a.domain, agent_id=a.agent_id, alert_type=a.alert_type, tactic=a.tactic,
            primary=a.primary, entities=a.entities, confidence=a.confidence, rule_confidence=a.rule_confidence,
            t=a.window_end, source="alert",
        )
        inc = self.correlator.add(ca)
        await self._decide(inc)

    async def _on_context(self, r: ContextResponse) -> None:
        iid = self.pending_queries.pop(r.request_id, r.incident_id)
        if r.max_confidence < self.cfg.fusion.context_min:
            return
        self.counters["context_used"] += 1
        ca = CorrelatedAlert(
            alert_id=f"ctx-{r.request_id}", domain=r.domain, agent_id=r.responder,
            alert_type=f"CONTEXT:{r.alert_types[0] if r.alert_types else str(r.domain).upper()}",
            tactic=r.tactics[0] if r.tactics else None, primary=r.entity, entities=[r.entity],
            confidence=r.max_confidence, rule_confidence=0.0, t=r.last_seen or self.sim_now, source="context",
        )
        inc = self.correlator.add_to(iid, ca)
        if inc is not None:
            await self._decide(inc)

    # ------------------------------------------------------------- decision
    async def _decide(self, inc: Incident) -> None:
        res = self.correlator.evaluate(inc, self.sim_now)
        if self.correlator.should_publish(inc, res):
            assessment = self.correlator.to_assessment(inc, res, "coordinator", self.sim_now)
            self.correlator.mark_published(inc, res)
            self.counters["assessments"] += 1
            await self.send(T.ASSESSMENTS, MessageType.THREAT_ASSESSMENT, assessment,
                            priority=priority_for(res.severity), severity=res.severity, sim_time=self.sim_now,
                            correlation_id=inc.incident_id)
        if res.actionable:
            return
        f = self.cfg.fusion
        if res.s_prime >= f.tau_suspect or not f.voi:
            await self._query(inc, res)
            if f.advisories and res.s_prime >= f.tau_suspect:
                await self._advise(inc, res)

    async def _query(self, inc: Incident, res: FusionResult) -> None:
        f = self.cfg.fusion
        present = {str(d) for d in res.domains}
        for e in sorted(inc.entities, key=lambda x: x.key()):
            if self.correlator.is_hub(e):  # shared services carry little attributable signal
                continue
            for owner, dom in self.owners(e):
                if inc.n_queries >= f.max_queries_per_incident:
                    return
                key = (owner, e.key())
                if str(dom) in present or key in inc.queried:
                    continue
                if self.is_down(owner):
                    self.counters["queries_skipped_down"] += 1
                    continue
                if not self.correlator.voi_worth_querying(res.s_prime, dom):
                    self.counters["queries_skipped_voi"] += 1
                    continue
                inc.queried.add(key)
                inc.n_queries += 1
                rid = new_id("q-")
                self.pending_queries[rid] = inc.incident_id
                req = ContextRequest(request_id=rid, incident_id=inc.incident_id, entity=e,
                                     window_start=max(0.0, inc.first_seen - self.cfg.query_window_s),
                                     window_end=self.sim_now + 60.0)
                self.counters["queries"] += 1
                await self.send(T.inbox(owner), MessageType.CONTEXT_REQUEST, req, recipient=owner,
                                priority=Priority.P0, sim_time=self.sim_now, correlation_id=inc.incident_id, ttl_s=120.0)

    async def _advise(self, inc: Incident, res: FusionResult) -> None:
        f = self.cfg.fusion
        per_owner: dict[str, list[EntityRef]] = {}
        for tgt in res.targets:
            for owner, _dom in self.owners(tgt.entity):
                key = (owner, tgt.entity.key())
                if key in inc.advised or self.is_down(owner):
                    continue
                inc.advised.add(key)
                per_owner.setdefault(owner, []).append(tgt.entity)
        for owner, ents in per_owner.items():
            adv = ThreatAdvisory(incident_id=inc.incident_id, entities=ents, reason=f"{res.threat_class} suspected",
                                 share_threshold_delta=f.advisory_delta, ttl_seconds=f.advisory_ttl, issued_at=self.sim_now)
            self.counters["advisories"] += 1
            await self.send(T.inbox(owner), MessageType.THREAT_ADVISORY, adv, recipient=owner, priority=Priority.P1,
                            sim_time=self.sim_now, correlation_id=inc.incident_id, ttl_s=300.0)
