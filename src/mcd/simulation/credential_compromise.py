"""Scenario A — credential compromise.

Brute force / spraying against several accounts from a foothold workstation,
then a successful login on one (privileged) account, then use of that account
to reach servers it never used before (cross-domain footprint: auth + network).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcd.core.models import Observation
from mcd.simulation.attack_base import AttackScenario
from mcd.simulation.events import EnvState


@dataclass
class CredentialCompromise(AttackScenario):
    foothold: str | None = None
    compromised: str | None = None
    targets: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.scenario = "credential_compromise"
        rng, topo = self.rng, self.topo
        self.foothold = self.foothold or str(rng.choice(topo.workstations))
        n_std = max(0, min(self.params.n_users - 1, len(topo.standard_users)))
        std = [str(u) for u in rng.choice(topo.standard_users, size=n_std, replace=False)] if n_std else []
        admin = self.compromised or str(rng.choice(topo.admin_users))
        self.targets = std + [admin]
        self.compromised = admin
        self.needed = 6 * len(self.targets)
        self.failures = 0
        self.phase = "bruteforce"
        self.dc = topo.server_by_role("dc")
        home = topo.inventory.users[admin].home_host
        usual = set(topo.usual_servers.get(home, []))
        self.candidates = [s for s in topo.servers if s not in usual and s != self.dc] + list(topo.ot_hosts[:1])
        self.add_host(self.foothold)
        for u in self.targets:
            self.add_user(u)

    def _step(self, t0: float, t1: float, state: EnvState) -> list[Observation]:
        f, rng, p = self.factory, self.rng, self.params
        if self.foothold in state.isolated:
            self.halt(t0, "foothold_isolated")
            return []
        ev: list[Observation] = []
        if self.phase == "bruteforce":
            self.stage(t0, "credential_access")
            k = max(1, int(round(p.intensity * 5 * (1 - 0.6 * p.stealth))))
            for i in range(k):
                user = self.targets[(self.failures + i) % len(self.targets)]
                ev.append(f.login(self.u(t0, t1), user, self.foothold, self.dc, "failure"))
            self.failures += k
            if self.failures >= self.needed:
                ok = self.compromised not in state.suspended
                ev.append(f.login(t1 - 0.4, self.compromised, self.foothold, self.dc, "success" if ok else "failure"))
                if ok:
                    self.phase = "access"
            return ev
        # access phase
        if self.compromised in state.suspended:
            ev.append(f.login(self.u(t0, t1), self.compromised, self.foothold, self.dc, "failure"))
            self.halt(t0, "account_suspended")
            return ev
        if rng.random() < min(1.0, 0.6 * p.intensity) and self.candidates:
            dst = str(rng.choice(self.candidates))
            self.stage(t0, "lateral_movement")
            tt = self.u(t0, t1 - 5)
            ev.append(f.login(tt, self.compromised, self.foothold, dst, "success", "rdp"))
            port = 3389 if p.stealth < 0.5 else 443
            for j in range(int(rng.integers(2, 5))):
                ev.append(f.flow(tt + 1 + j, self.foothold, dst, port, rng))
            if rng.random() < 0.5:
                ev.append(f.flow(tt + 4.5, self.foothold, dst, 445, rng, bytes_scale=20.0))
            self.add_host(dst)
        return ev
