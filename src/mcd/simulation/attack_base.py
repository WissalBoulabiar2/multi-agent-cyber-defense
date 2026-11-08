"""Base class for synthetic attack campaigns (isolated, purely generative)."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

import numpy as np

from mcd.core.models import Observation
from mcd.simulation.events import EnvState, EventFactory
from mcd.simulation.topology import Topology


@dataclass
class AttackParams:
    start: float = 900.0          # sim seconds
    duration: float = 2400.0
    intensity: float = 1.0        # scales events per step
    n_hosts: int = 3              # affected hosts
    n_users: int = 3              # targeted accounts
    stealth: float = 0.0          # 0 = noisy, 1 = low-and-slow
    dwell_steps: int = 3


@dataclass
class AttackScenario(abc.ABC):
    attack_id: str
    params: AttackParams
    topo: Topology
    rng: np.random.Generator
    factory: EventFactory
    entities: set[str] = field(default_factory=set, init=False)
    stages: list[tuple[float, str]] = field(default_factory=list, init=False)
    halted_at: float | None = field(default=None, init=False)
    halt_reason: str | None = field(default=None, init=False)
    n_events: int = field(default=0, init=False)
    first_event: float | None = field(default=None, init=False)
    last_event: float | None = field(default=None, init=False)

    scenario: str = field(default="base", init=False)

    @property
    def end(self) -> float:
        return self.params.start + self.params.duration

    def active(self, t0: float) -> bool:
        return self.halted_at is None and self.params.start <= t0 < self.end

    def halt(self, t: float, reason: str) -> None:
        if self.halted_at is None:
            self.halted_at, self.halt_reason = t, reason

    def stage(self, t: float, name: str) -> None:
        if not self.stages or self.stages[-1][1] != name:
            self.stages.append((t, name))

    def add_host(self, h: str) -> None:
        self.entities.add(f"host:{h}")

    def add_user(self, u: str) -> None:
        self.entities.add(f"user:{u}")

    def step(self, t0: float, t1: float, state: EnvState) -> list[Observation]:
        if not self.active(t0):
            return []
        events = self._step(t0, t1, state)
        if events:
            self.n_events += len(events)
            ts = [e.sim_time for e in events]
            self.first_event = min(ts) if self.first_event is None else min(self.first_event, min(ts))
            self.last_event = max(ts) if self.last_event is None else max(self.last_event, max(ts))
        return events

    def u(self, t0: float, t1: float) -> float:
        return float(self.rng.uniform(t0, t1 - 0.5))

    @abc.abstractmethod
    def _step(self, t0: float, t1: float, state: EnvState) -> list[Observation]: ...
