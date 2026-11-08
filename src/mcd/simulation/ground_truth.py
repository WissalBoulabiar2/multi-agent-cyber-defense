"""Ground-truth store. Written by the environment, read ONLY by the evaluator.

Agents never receive a reference to this object; observations carry no labels.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mcd.core.models import Observation
from mcd.simulation.events import entity_keys


@dataclass
class AttackRecord:
    attack_id: str
    scenario: str
    entities: list[str]
    scheduled_start: float
    scheduled_end: float
    t_start: float | None
    t_end: float | None
    n_events: int
    stages: list[tuple[float, str]]
    halted_at: float | None
    halt_reason: str | None


@dataclass
class GroundTruth:
    window: float = 60.0
    attacks: dict[str, AttackRecord] = field(default_factory=dict)
    event_attack: dict[str, str] = field(default_factory=dict)
    activity: set[tuple[str, int]] = field(default_factory=set)
    n_events: int = 0
    n_malicious: int = 0
    malicious_blocked: int = 0
    dropped_observations: int = 0

    def record(self, obs: Observation, attack_id: str | None) -> None:
        self.n_events += 1
        b = int(obs.sim_time // self.window)
        for k in entity_keys(obs):
            self.activity.add((k, b))
        if attack_id is not None:
            self.n_malicious += 1
            self.event_attack[obs.event_id] = attack_id

    def finalize(self, scenarios) -> None:
        for s in scenarios:
            self.attacks[s.attack_id] = AttackRecord(
                attack_id=s.attack_id, scenario=s.scenario, entities=sorted(s.entities),
                scheduled_start=s.params.start, scheduled_end=s.end,
                t_start=s.first_event, t_end=s.last_event, n_events=s.n_events,
                stages=list(s.stages), halted_at=s.halted_at, halt_reason=s.halt_reason,
            )

    def to_dict(self) -> dict:
        return {
            "window": self.window,
            "attacks": {k: asdict(v) for k, v in self.attacks.items()},
            "n_events": self.n_events,
            "n_malicious": self.n_malicious,
            "malicious_blocked": self.malicious_blocked,
            "dropped_observations": self.dropped_observations,
            "n_entity_windows": len(self.activity),
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
