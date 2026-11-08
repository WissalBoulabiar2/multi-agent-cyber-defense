"""Assemble and run one complete experiment (environment + agents + broker).

All agents run as independent asyncio tasks that interact only via the broker.
The same classes run one-per-process under Docker (see runtime/launch.py).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import asdict, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mcd.agents.authentication_agent import AuthenticationSecurityAgent
from mcd.agents.base_agent import BaseAgent
from mcd.agents.configuration_agent import ConfigurationSecurityAgent
from mcd.agents.intelligence_agent import IntelConfig, ThreatIntelligenceAgent
from mcd.agents.network_agent import NetworkSecurityAgent
from mcd.agents.response_agent import ResponseAgent
from mcd.agents.sensor_agent import SensorAgent, SensorConfig
from mcd.baseline.centralized_detector import CentralizedDetector
from mcd.communication.conditions import ConditionedBroker, NetworkConditions
from mcd.communication.coordination import FusionConfig
from mcd.communication.transports import create_broker
from mcd.core.enums import SENSOR_DOMAINS, CoordinationMode, Domain
from mcd.response.approval import AutoApprover, AutoApproverConfig
from mcd.response.audit_logger import AuditLogger
from mcd.response.response_engine import ResponseConfig
from mcd.runtime.resources import cpu_time, peak_rss_mb
from mcd.simulation.attack_base import AttackParams
from mcd.simulation.environment import EnvConfig, Environment, ObservationChannel, ScenarioSpec
from mcd.simulation.normal_activity import NormalConfig
from mcd.simulation.topology import TopologyConfig
from mcd.simulation.training import benign_history

log = logging.getLogger(__name__)
SENSOR_CLASSES = {Domain.NETWORK: NetworkSecurityAgent, Domain.AUTH: AuthenticationSecurityAgent,
                  Domain.CONFIG: ConfigurationSecurityAgent}


class ScenarioCfg(BaseModel):
    type: str
    count: int = 1
    spacing: float = 1800.0
    params: dict[str, Any] = Field(default_factory=dict)


class FailureSpec(BaseModel):
    agent: str
    at: float                       # sim seconds
    restart_after: float | None = None


class SystemConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    run_name: str = "run"
    strategy: CoordinationMode = CoordinationMode.COOPERATIVE
    seed: int = 0
    train_seed: int = 0
    train_duration: float = 8 * 3600.0
    duration: float = 5400.0
    step: float = 60.0
    speedup: float | None = None
    lockstep: bool = True
    n_sensors: int | None = None
    shards: dict[str, int] = Field(default_factory=lambda: {"network": 1, "auth": 1, "config": 1})
    topology: TopologyConfig = Field(default_factory=TopologyConfig)
    topology_seed: int = 0
    normal: NormalConfig = Field(default_factory=NormalConfig)
    scenarios: list[ScenarioCfg] = Field(default_factory=list)
    channel: ObservationChannel = Field(default_factory=ObservationChannel)
    conditions: NetworkConditions = Field(default_factory=NetworkConditions)
    sensor: SensorConfig = Field(default_factory=SensorConfig)
    fusion: FusionConfig = Field(default_factory=FusionConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    approver: AutoApproverConfig | None = Field(default_factory=AutoApproverConfig)
    failures: list[FailureSpec] = Field(default_factory=list)
    broker: str = "memory"
    redis_url: str | None = None
    heartbeat_interval: float = 0.5
    drain_timeout: float = 10.0
    output_dir: str | None = None

    def resolved_shards(self) -> dict[str, int]:
        if self.n_sensors is None:
            return dict(self.shards)
        order = [str(d) for d in SENSOR_DOMAINS]
        out = {d: 0 for d in order}
        for i in range(self.n_sensors):
            out[order[i % 3]] += 1
        return out

    def config_hash(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()[:12]


def _jsonable(obj):
    try:
        return asdict(obj)
    except TypeError:
        return obj


class DefenseSystem:
    def __init__(self, cfg: SystemConfig) -> None:
        self.cfg = cfg
        self.shards = cfg.resolved_shards()
        inner = create_broker(cfg.broker, cfg.redis_url)
        self.broker = ConditionedBroker(inner, cfg.conditions)
        scen = [ScenarioSpec(s.type, AttackParams(**s.params), s.count, s.spacing) for s in cfg.scenarios]
        env_cfg = EnvConfig(seed=cfg.seed, topology_seed=cfg.topology_seed, duration=cfg.duration, step=cfg.step,
                            speedup=cfg.speedup, lockstep=cfg.lockstep, shards=self.shards, channel=cfg.channel,
                            topology=cfg.topology, normal=cfg.normal)
        self.env = Environment(env_cfg, scen, self.broker)
        self.inventory = self.env.topo.inventory
        out = Path(cfg.output_dir) if cfg.output_dir else None
        self.audit = AuditLogger(out / "audit.jsonl" if out else None)
        self.agents: dict[str, BaseAgent] = {}
        self.response: ResponseAgent | None = None
        self.intel: ThreatIntelligenceAgent | None = None
        self.central: CentralizedDetector | None = None
        self.step_wall: dict[float, float] = {}
        self._build()

    # ----------------------------------------------------------------- build
    def _train(self, domain: Domain | None, shard: int = 0, n: int = 1):
        c = self.cfg
        return lambda: benign_history(c.train_seed, c.train_duration, c.topology, c.topology_seed, domain, shard, n)

    def _build(self) -> None:
        c, kw = self.cfg, {"heartbeat_interval": self.cfg.heartbeat_interval}
        mode = c.strategy
        if mode in (CoordinationMode.INDEPENDENT, CoordinationMode.COOPERATIVE):
            for d in SENSOR_DOMAINS:
                n = self.shards.get(str(d), 0)
                for s in range(n):
                    scfg = c.sensor.__class__(**{**c.sensor.__dict__, "mode": mode})
                    a: SensorAgent = SENSOR_CLASSES[d](s, self.broker, self.inventory, self._train(d, s, n), scfg, **kw)
                    self.agents[a.agent_id] = a
        if mode == CoordinationMode.COOPERATIVE:
            self.intel = ThreatIntelligenceAgent(self.broker, self.inventory, IntelConfig(fusion=c.fusion, shards=self.shards), **kw)
            self.agents[self.intel.agent_id] = self.intel
        if mode == CoordinationMode.CENTRALIZED:
            self.central = CentralizedDetector(self.broker, self.inventory, self.shards, self._train(None), c.fusion,
                                               c.sensor.pipeline, **kw)
            self.agents[self.central.agent_id] = self.central
        self.response = ResponseAgent(self.broker, self.inventory, mode, c.response, self.audit, **kw)
        self.agents[self.response.agent_id] = self.response
        if c.approver is not None:
            ap = AutoApprover(self.broker, c.approver, **kw)
            self.agents[ap.agent_id] = ap

    # ------------------------------------------------------------------- run
    async def _failure_injector(self) -> None:
        pending = sorted(self.cfg.failures, key=lambda f: f.at)
        restarts: list[tuple[float, str]] = []
        while pending or restarts:
            t = self.env.t
            while pending and t >= pending[0].at:
                f = pending.pop(0)
                agent = self.agents.get(f.agent)
                if agent is not None:
                    log.info("injecting failure: %s at sim %.0f", f.agent, t)
                    agent.crash()
                    if f.restart_after is not None:
                        restarts.append((f.at + f.restart_after, f.agent))
            for item in list(restarts):
                if t >= item[0]:
                    restarts.remove(item)
                    await self.agents[item[1]].start()
            await asyncio.sleep(0.01)

    async def _record_steps(self) -> None:
        last = -1.0
        while True:
            if self.env.t != last:
                last = self.env.t
                self.step_wall.setdefault(last, time.time())
            await asyncio.sleep(0.001)

    async def _drain(self) -> None:
        prefixes = ("sim.", "alerts.", "agent.", "assessments", "approvals.", "response.")
        deadline = time.monotonic() + self.cfg.drain_timeout
        prev, stable = None, 0
        while time.monotonic() < deadline:
            lag = await self.broker.total_lag(prefixes) + self.broker.inflight
            pending_approvals = any(r.state == "awaiting_approval" for r in self.response.actions.values())
            if lag == 0 and not pending_approvals:
                return
            stable = stable + 1 if lag == prev else 0
            prev = lag
            if stable > 200 and not pending_approvals:  # remaining lag belongs to crashed agents
                return
            await asyncio.sleep(0.01)

    async def run(self) -> dict[str, Any]:
        t_setup = time.time()
        await self.broker.connect()
        for a in self.agents.values():
            await a.start()
        setup_s = time.time() - t_setup
        cpu0, wall0 = cpu_time(), time.time()
        helpers = [asyncio.create_task(self._failure_injector()), asyncio.create_task(self._record_steps())]
        try:
            gt = await self.env.run()
            await self._drain()
            await self.response.finalize()
            await asyncio.sleep(0.05)
        finally:
            for h in helpers:
                h.cancel()
            for a in self.agents.values():
                if a.running:
                    await a.stop()
        wall = time.time() - wall0
        cpu = cpu_time() - cpu0
        result = {
            "config": json.loads(self.cfg.model_dump_json()),
            "config_hash": self.cfg.config_hash(),
            "shards": self.shards,
            "n_sensor_agents": sum(self.shards.values()) if self.cfg.strategy != CoordinationMode.CENTRALIZED else 0,
            "agents": list(self.agents),
            "ground_truth": gt.to_dict(),
            "decisions": self.response.decisions,
            "actions": self.response.history(),
            "audit_ok": AuditLogger.verify(self.audit.records)[0],
            "audit_records": len(self.audit.records),
            "env": {"blocked_events": self.env.state.blocked_events, "blocked_benign": self.env.state.blocked_benign,
                    "actions_applied": self.env.actions_applied, "isolated": sorted(self.env.state.isolated),
                    "suspended": sorted(self.env.state.suspended)},
            "step_wall": {str(k): v for k, v in self.step_wall.items()},
            "broker": self.broker.stats.snapshot(),
            "conditions": {"dropped": self.broker.dropped, "delayed": self.broker.delayed},
            "agent_metrics": {aid: a.metrics.summary() for aid, a in self.agents.items()},
            "agent_details": self._details(),
            "resources": {"wall_s": wall, "setup_s": setup_s, "cpu_s": cpu, "peak_rss_mb": peak_rss_mb()},
        }
        await self.broker.close()
        from mcd.evaluation.metrics import evaluate_run  # local import: evaluation depends on runtime outputs

        result["metrics"] = evaluate_run(result, self.env.gt, self.step_wall)
        if self.cfg.output_dir:
            out = Path(self.cfg.output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "result.json").write_text(json.dumps(result, indent=1, default=str))
            gt.save(out / "ground_truth.json")
        return result

    def _details(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for aid, a in self.agents.items():
            if isinstance(a, SensorAgent):
                d[aid] = {"windows_scored": a.windows_scored, "alerts_emitted": a.alerts_emitted,
                          "context_answered": a.context_answered, "late_events": a.pipeline.late_events,
                          "train_rows": a.pipeline.n_train_rows, "policy": asdict(a.policy.counters)}
        if self.intel is not None:
            d[self.intel.agent_id] = {**self.intel.counters, "incidents_open": len(self.intel.correlator.incidents)}
        if self.central is not None:
            d[self.central.agent_id] = {"assessments": self.central.assessments}
        return d


def run_system(cfg: SystemConfig) -> dict[str, Any]:
    return asyncio.run(DefenseSystem(cfg).run())
