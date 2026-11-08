"""Simulated infrastructure engine.

Each step (default 60 sim-s): apply pending containment commands, generate
benign + attack events, pass them through the observation channel (drop /
noise), publish each observation to the owning sensor shard, then publish a
watermark to every sensor stream and to ``sim.clock``.

Pacing: ``speedup`` = simulated seconds per wall second (None = as fast as
possible). With ``lockstep`` the engine also waits until the defensive system
has consumed the backlog (consumer-group lag == 0), which makes sim-time
results largely independent of host speed.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import numpy as np

from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.communication.message_broker import MessageBroker
from mcd.core.enums import ActionType, Domain, MessageType, Priority
from mcd.core.models import ActionAck, ContainmentCommand, Observation, Watermark
from mcd.simulation.attack_base import AttackParams, AttackScenario
from mcd.simulation.configuration_tampering import ConfigurationTampering
from mcd.simulation.credential_compromise import CredentialCompromise
from mcd.simulation.events import EnvState, EventFactory
from mcd.simulation.ground_truth import GroundTruth
from mcd.simulation.lateral_movement import LateralMovement
from mcd.simulation.multi_stage import MultiStage
from mcd.simulation.normal_activity import NormalActivity, NormalConfig
from mcd.simulation.topology import Topology, TopologyConfig, build_topology

SCENARIOS: dict[str, type[AttackScenario]] = {
    "credential_compromise": CredentialCompromise,
    "lateral_movement": LateralMovement,
    "configuration_tampering": ConfigurationTampering,
    "multi_stage": MultiStage,
}


@dataclass
class ScenarioSpec:
    type: str
    params: AttackParams = field(default_factory=AttackParams)
    count: int = 1            # frequency: number of campaigns in the run
    spacing: float = 1800.0   # sim seconds between campaign starts


@dataclass
class ObservationChannel:
    drop_prob: float = 0.0          # missing observations
    noise_sigma: float = 0.0        # multiplicative noise on numeric attributes
    benign_burst_prob: float = 0.0  # per step: random benign bursts (noisy input)


@dataclass
class EnvConfig:
    seed: int = 0
    topology_seed: int = 0
    duration: float = 5400.0
    step: float = 60.0
    speedup: float | None = None
    lockstep: bool = True
    max_lockstep_wait: float = 5.0
    shards: dict[str, int] = field(default_factory=lambda: {"network": 1, "auth": 1, "config": 1})
    channel: ObservationChannel = field(default_factory=ObservationChannel)
    topology: TopologyConfig = field(default_factory=TopologyConfig)
    normal: NormalConfig = field(default_factory=NormalConfig)


def shard_key(obs: Observation) -> str:
    a = obs.attrs
    if obs.domain == Domain.NETWORK:
        return a["src"]
    if obs.domain == Domain.AUTH:
        return a["user"]
    return a["host"]


class Environment:
    agent_id = "env"

    def __init__(self, cfg: EnvConfig, scenarios: list[ScenarioSpec] | None = None,
                 broker: MessageBroker | None = None, topology: Topology | None = None) -> None:
        self.cfg = cfg
        self.broker = broker
        self.topo = topology or build_topology(cfg.topology, seed=cfg.topology_seed)
        ss = np.random.SeedSequence(cfg.seed)
        s_normal, s_attack, s_channel = ss.spawn(3)
        self.factory = EventFactory()
        self.normal = NormalActivity(self.topo, np.random.default_rng(s_normal), self.factory, cfg.normal)
        self.channel_rng = np.random.default_rng(s_channel)
        self.state = EnvState()
        self.gt = GroundTruth(window=cfg.step)
        self.attacks: list[AttackScenario] = []
        attack_rngs = s_attack.spawn(max(1, sum(s.count for s in scenarios or [])))
        i = 0
        for spec in scenarios or []:
            cls = SCENARIOS[spec.type]
            for c in range(spec.count):
                p = AttackParams(**{**spec.params.__dict__, "start": spec.params.start + c * spec.spacing})
                self.attacks.append(cls(attack_id=f"atk-{i:03d}-{spec.type}", params=p, topo=self.topo,
                                        rng=np.random.default_rng(attack_rngs[i]), factory=self.factory))
                i += 1
        self.t = 0.0
        self.actions_applied: list[dict] = []
        self.done = asyncio.Event() if broker is not None else None
        self.wall_started: float | None = None

    # ------------------------------------------------------------ generation
    def _noise(self, obs: Observation) -> Observation:
        sigma = self.cfg.channel.noise_sigma
        if sigma > 0 and obs.domain == Domain.NETWORK:
            for k in ("bytes_out", "bytes_in", "duration"):
                obs.attrs[k] = round(float(obs.attrs[k] * self.channel_rng.lognormal(0.0, sigma)), 3)
        return obs

    def _bursts(self, t0: float, t1: float) -> list[Observation]:
        p = self.cfg.channel.benign_burst_prob
        rng, topo, f = self.channel_rng, self.topo, self.factory
        out: list[Observation] = []
        if p > 0 and rng.random() < p:
            src = str(rng.choice(topo.workstations))
            for dst in rng.choice(topo.all_hosts, size=3, replace=False):
                out.append(f.flow(float(rng.uniform(t0, t1)), src, str(dst), int(rng.choice([80, 443, 445, 8080])), rng))
        if p > 0 and rng.random() < p:
            u = str(rng.choice(topo.standard_users))
            home = topo.inventory.users[u].home_host
            for k in range(int(rng.integers(2, 5))):
                out.append(f.login(float(rng.uniform(t0, t1)), u, home, topo.server_by_role("dc"), "failure"))
        return out

    def generate_step(self, t0: float, t1: float) -> list[tuple[Observation, str | None]]:
        """Deterministic for a given seed and containment state."""
        items: list[tuple[Observation, str | None]] = [(o, None) for o in self.normal.generate(t0, t1)]
        items += [(o, None) for o in self._bursts(t0, t1)]
        for atk in self.attacks:
            items += [(o, atk.attack_id) for o in atk.step(t0, t1, self.state)]
        out = []
        for obs, aid in items:
            if self.state.blocks(obs):
                self.state.blocked_events += 1
                if aid is None:
                    self.state.blocked_benign += 1
                else:
                    self.gt.malicious_blocked += 1
                continue
            self.gt.record(obs, aid)
            if self.cfg.channel.drop_prob and self.channel_rng.random() < self.cfg.channel.drop_prob:
                self.gt.dropped_observations += 1
                continue
            out.append((self._noise(obs), aid))
        out.sort(key=lambda x: x[0].sim_time)
        return out

    def generate_offline(self, duration: float | None = None) -> list[Observation]:
        """Generate a full event stream without a broker (training data, tests)."""
        events: list[Observation] = []
        t, end = 0.0, duration or self.cfg.duration
        while t < end:
            events += [o for o, _ in self.generate_step(t, t + self.cfg.step)]
            t += self.cfg.step
        self.gt.finalize(self.attacks)
        return events

    # ------------------------------------------------------------ containment
    def apply(self, cmd: ContainmentCommand) -> tuple[bool, str]:
        tgt = cmd.target.id
        if cmd.action == ActionType.ISOLATE_HOST:
            self.state.isolated.add(tgt)
        elif cmd.action == ActionType.SUSPEND_ACCOUNT:
            self.state.suspended.add(tgt)
        elif cmd.action == ActionType.REVERT_CONFIG:
            self.state.reverts.append((self.t, tgt))
        elif cmd.action == ActionType.INCREASE_MONITORING:
            self.state.monitoring.add(tgt)
        else:
            return True, "logged"
        self.actions_applied.append({"t": self.t, "action": str(cmd.action), "target": tgt, "action_id": cmd.action_id})
        return True, "applied"

    def _revert_events(self, t: float) -> list[Observation]:
        out = []
        for tr, host in self.state.reverts:
            if tr == t:
                for key in ("firewall", "sudoers", "admin_group", "services", "audit_policy"):
                    out.append(self.factory.config(t + 1, host, key, "response-agent", host, self.channel_rng,
                                                   change_type="revert", ticket="IR-REVERT", value="baseline"))
        return out

    async def _consume_actions(self) -> None:
        assert self.broker is not None
        batch = await self.broker.read(T.ENV_ACTIONS, "env", "env", count=500, block_ms=0)
        for d in batch:
            cmd = d.envelope.parse(ContainmentCommand)
            ok, detail = self.apply(cmd)
            await self.broker.ack(T.ENV_ACTIONS, "env", [d.entry_id])
            if cmd.reply_to:
                ack = ActionAck(action_id=cmd.action_id, applied=ok, sim_time=self.t, detail=detail)
                await self._send(T.inbox(cmd.reply_to), MessageType.ACTION_ACK, ack, priority=Priority.P0)

    async def _send(self, topic: str, mtype: MessageType, payload, priority=Priority.P1) -> None:
        env = Envelope.build(mtype, self.agent_id, topic, payload, priority=priority, sim_time=self.t)
        await self.broker.publish(topic, env)

    def sensor_topics(self) -> list[str]:
        return [T.sim_events(d, s) for d, n in self.cfg.shards.items() for s in range(n)]

    async def _wait_quiescent(self) -> None:
        if not self.cfg.lockstep:
            return
        deadline = time.monotonic() + self.cfg.max_lockstep_wait
        while time.monotonic() < deadline:
            lag = await self.broker.total_lag(prefixes=("sim.", "alerts.", "agent.", "assessments"))
            if lag == 0:
                return
            await asyncio.sleep(0.002)

    async def run(self) -> GroundTruth:
        assert self.broker is not None, "Environment.run requires a broker"
        await self.broker.ensure_group(T.ENV_ACTIONS, "env")
        self.wall_started = time.time()
        step, t = self.cfg.step, 0.0
        while t < self.cfg.duration:
            t_wall = time.monotonic()
            self.t = t
            await self._consume_actions()
            batch = self.generate_step(t, t + step)
            for obs in self._revert_events(t):
                self.gt.record(obs, None)
                batch.append((obs, None))
            for obs, _aid in batch:
                n = self.cfg.shards.get(str(obs.domain), 0)
                if n <= 0:
                    continue
                topic = T.sim_events(obs.domain, T.shard_of(shard_key(obs), n))
                await self._send(topic, MessageType.OBSERVATION, obs)
            t += step
            self.t = t
            wm = Watermark(t=t)
            for topic in self.sensor_topics() + [T.SIM_CLOCK]:
                await self._send(topic, MessageType.WATERMARK, wm, priority=Priority.P2)
            await self._wait_quiescent()
            if self.cfg.speedup:
                remaining = step / self.cfg.speedup - (time.monotonic() - t_wall)
                if remaining > 0:
                    await asyncio.sleep(remaining)
            else:
                await asyncio.sleep(0)
        await self._consume_actions()
        self.gt.finalize(self.attacks)
        if self.done is not None:
            self.done.set()
        return self.gt
