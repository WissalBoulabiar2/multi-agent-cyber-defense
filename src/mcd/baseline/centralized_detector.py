"""Centralized detection baseline (strategy S3).

A single node ingests *all raw observations* from every domain, runs the same
three domain pipelines and the same correlation/fusion math as the cooperative
coordinator, and publishes assessments. There is no partial information
sharing — it is the full-information, single-point-of-failure reference.
Raw-event ingestion is what a real deployment would have to ship from the
edge to the centre; it is reported as "ingest" traffic.
"""

from __future__ import annotations

from typing import Callable

from mcd.agents.base_agent import BaseAgent, Subscription
from mcd.communication import topics as T
from mcd.communication.coordination import CorrelatedAlert, Correlator, FusionConfig
from mcd.communication.message import Envelope
from mcd.core.enums import SENSOR_DOMAINS, Domain, MessageType, priority_for
from mcd.core.ids import new_id
from mcd.core.inventory import AssetInventory
from mcd.core.models import Observation, Watermark
from mcd.detection.pipeline import DomainPipeline, PipelineConfig


class CentralizedDetector(BaseAgent):
    domain = Domain.CENTRAL

    def __init__(self, broker, inventory: AssetInventory, shards: dict[str, int],
                 training_data: Callable[[], list[Observation]] | None = None,
                 fusion: FusionConfig | None = None, pipeline_cfg: PipelineConfig | None = None,
                 min_conf: float | None = None, agent_id: str = "central-0", **kw) -> None:
        super().__init__(agent_id, broker, **kw)
        self.shards = shards
        self.inventory = inventory
        self.pipelines = {d: DomainPipeline(d, inventory, cfg=pipeline_cfg) for d in SENSOR_DOMAINS}
        self.fusion = fusion or FusionConfig()
        self.correlator = Correlator(self.fusion, inventory)
        self.min_conf = self.fusion.context_min if min_conf is None else min_conf
        self._training_data = training_data
        self.sim_now = 0.0
        self.assessments = 0
        self._topic_domain = {}
        for d in SENSOR_DOMAINS:
            for s in range(shards.get(str(d), 0)):
                self._topic_domain[T.sim_events(d, s)] = d

    def subscriptions(self) -> list[Subscription]:
        return [Subscription(t, priority=1) for t in self._topic_domain]

    async def setup(self) -> None:
        events = self._training_data() if self._training_data else []
        for p in self.pipelines.values():
            p.train(events)

    async def handle(self, env: Envelope) -> None:
        if env.type == MessageType.OBSERVATION:
            obs = env.parse(Observation)
            self.pipelines[Domain(obs.domain)].add(obs)
        elif env.type == MessageType.WATERMARK:
            d = self._topic_domain.get(env.topic)
            if d is None:
                return
            t = env.parse(Watermark).t
            self.sim_now = max(self.sim_now, t)
            for s in self.pipelines[d].close_until(t):
                if s.confidence < self.min_conf:
                    continue
                ca = CorrelatedAlert(
                    alert_id=new_id("c-"), domain=s.domain, agent_id=f"{self.agent_id}/{s.domain}",
                    alert_type=s.alert_type, tactic=s.tactic, primary=s.entity, entities=[s.entity, *s.related],
                    confidence=s.confidence, rule_confidence=s.rule_confidence, t=s.window_end, source="local",
                )
                inc = self.correlator.add(ca)
                res = self.correlator.evaluate(inc, self.sim_now)
                if self.correlator.should_publish(inc, res):
                    a = self.correlator.to_assessment(inc, res, "central", self.sim_now)
                    self.correlator.mark_published(inc, res)
                    self.assessments += 1
                    await self.send(T.ASSESSMENTS, MessageType.THREAT_ASSESSMENT, a, priority=priority_for(res.severity),
                                    severity=res.severity, sim_time=self.sim_now, correlation_id=inc.incident_id)
            self.correlator.expire(self.sim_now)
