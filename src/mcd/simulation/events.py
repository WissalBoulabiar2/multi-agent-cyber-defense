"""Event factory and the mutable simulated-infrastructure state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from mcd.core.enums import Domain
from mcd.core.models import Observation


class EventFactory:
    """Creates Observations with opaque sequential ids (no label information)."""

    def __init__(self) -> None:
        self._n = 0

    def _id(self) -> str:
        self._n += 1
        return f"e{self._n:09d}"

    def flow(self, t: float, src: str, dst: str, port: int, rng: np.random.Generator, *,
             status: str = "ok", bytes_scale: float = 1.0) -> Observation:
        out = float(rng.lognormal(8.0, 1.0) * bytes_scale) if status == "ok" else 60.0
        inn = float(rng.lognormal(8.5, 1.0)) if status == "ok" else 0.0
        attrs = {"src": src, "dst": dst, "dst_port": int(port), "proto": "tcp", "bytes_out": round(out, 1),
                 "bytes_in": round(inn, 1), "duration": round(float(rng.exponential(5.0)), 3), "status": status}
        return Observation(event_id=self._id(), domain=Domain.NETWORK, sim_time=t, attrs=attrs)

    def login(self, t: float, user: str, src: str, dst: str, result: str, method: str = "kerberos") -> Observation:
        attrs = {"user": user, "src_host": src, "dst_host": dst, "result": result, "method": method}
        return Observation(event_id=self._id(), domain=Domain.AUTH, sim_time=t, attrs=attrs)

    def config(self, t: float, host: str, key: str, actor: str, src: str, rng: np.random.Generator, *,
               change_type: str = "modify", ticket: str | None = None, value: str | None = None) -> Observation:
        attrs: dict[str, Any] = {"host": host, "key": key, "actor": actor, "src_host": src,
                                 "change_type": change_type, "ticket": ticket,
                                 "value_hash": value or f"{int(rng.integers(0, 2**32)):08x}"}
        return Observation(event_id=self._id(), domain=Domain.CONFIG, sim_time=t, attrs=attrs)


@dataclass
class EnvState:
    """Containment state applied by the Response agent through env.actions."""

    isolated: set[str] = field(default_factory=set)
    suspended: set[str] = field(default_factory=set)
    monitoring: set[str] = field(default_factory=set)
    reverts: list[tuple[float, str]] = field(default_factory=list)
    blocked_events: int = 0
    blocked_benign: int = 0

    def blocks(self, obs: Observation) -> bool:
        a = obs.attrs
        if obs.domain == Domain.NETWORK:
            return a["src"] in self.isolated or a["dst"] in self.isolated
        if obs.domain == Domain.AUTH:
            return a["src_host"] in self.isolated or a["dst_host"] in self.isolated
        return a["host"] in self.isolated or a.get("src_host") in self.isolated


def entity_keys(obs: Observation) -> list[str]:
    a = obs.attrs
    if obs.domain == Domain.NETWORK:
        return [f"host:{a['src']}", f"host:{a['dst']}"]
    if obs.domain == Domain.AUTH:
        return [f"user:{a['user']}", f"host:{a['src_host']}", f"host:{a['dst_host']}"]
    return [f"host:{a['host']}", f"user:{a['actor']}"]
