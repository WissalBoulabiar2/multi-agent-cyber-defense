"""Composite campaign A -> B -> C sharing foothold and stolen account."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from mcd.core.models import Observation
from mcd.simulation.attack_base import AttackScenario
from mcd.simulation.configuration_tampering import ConfigurationTampering
from mcd.simulation.credential_compromise import CredentialCompromise
from mcd.simulation.events import EnvState
from mcd.simulation.lateral_movement import LateralMovement


@dataclass
class MultiStage(AttackScenario):
    children: list[AttackScenario] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.scenario = "multi_stage"
        p, d = self.params, self.params.duration
        common = dict(attack_id=self.attack_id, topo=self.topo, rng=self.rng, factory=self.factory)
        a = CredentialCompromise(params=replace(p, duration=0.4 * d, n_users=max(2, p.n_users)), **common)
        b = LateralMovement(params=replace(p, start=p.start + 0.3 * d, duration=0.45 * d),
                            start_host=a.foothold, account=a.compromised, **common)
        c = ConfigurationTampering(params=replace(p, start=p.start + 0.65 * d, duration=0.35 * d, n_hosts=2),
                                   actor=a.compromised, foothold=a.foothold, hosts=b.path[-2:], **common)
        self.children = [a, b, c]

    def _step(self, t0: float, t1: float, state: EnvState) -> list[Observation]:
        ev: list[Observation] = []
        for ch in self.children:
            ev.extend(ch.step(t0, t1, state))
            self.entities |= ch.entities
        self.stages = sorted({s for ch in self.children for s in ch.stages})
        # All stages share the foothold and the stolen account, so containing one
        # stage (isolation of the foothold/pivot or account suspension) stops the chain.
        halted = [ch for ch in self.children if ch.halted_at is not None]
        if halted:
            first = min(halted, key=lambda c: c.halted_at)
            self.halt(first.halted_at, f"{first.scenario}:{first.halt_reason}")
        return ev
