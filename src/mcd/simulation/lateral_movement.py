"""Scenario B — lateral movement.

From a compromised workstation the attacker scans the next segment on admin
ports, authenticates with stolen credentials, pivots, dwells, and repeats —
progressing CORP -> SERVERS -> OT (network + auth footprint).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcd.core.inventory import ADMIN_PORTS
from mcd.core.models import Observation
from mcd.simulation.attack_base import AttackScenario
from mcd.simulation.events import EnvState


@dataclass
class LateralMovement(AttackScenario):
    start_host: str | None = None
    account: str | None = None
    path: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.scenario = "lateral_movement"
        rng, topo = self.rng, self.topo
        self.start_host = self.start_host or str(rng.choice(topo.workstations))
        self.account = self.account or str(rng.choice(topo.admin_users))
        n = max(2, self.params.n_hosts)
        n_ot = min(2, n - 1, len(topo.ot_hosts))
        n_srv = n - n_ot
        dc = topo.server_by_role("dc")
        jump = topo.server_by_role("jump")
        others = [s for s in topo.servers if s not in (dc, jump)]
        srv = [jump] + [str(x) for x in rng.choice(others, size=min(max(0, n_srv - 1), len(others)), replace=False)]
        hmi = [h for h in topo.ot_hosts if "hmi" in h]
        scada = [h for h in topo.ot_hosts if "scada" in h]
        ot_route = ([str(rng.choice(hmi))] if hmi else []) + ([str(rng.choice(scada))] if scada else [])
        self.path = srv[:n_srv] + ot_route[:n_ot]
        self.current = self.start_host
        self.hop = 0
        self.phase = "scan"
        self.wait = 0
        self.add_host(self.start_host)
        self.add_user(self.account)

    def _step(self, t0: float, t1: float, state: EnvState) -> list[Observation]:
        f, rng, p, topo = self.factory, self.rng, self.params, self.topo
        if self.current in state.isolated:
            self.halt(t0, "pivot_isolated")
            return []
        ev: list[Observation] = []
        if self.phase == "dwell":
            self.wait -= 1
            if rng.random() < 0.5:
                ev.append(f.flow(self.u(t0, t1), self.current, topo.server_by_role("dc"), 389, rng))
            if self.wait <= 0:
                self.phase = "scan"
            return ev
        if self.hop >= len(self.path):
            # objective reached: unusual control traffic from the last pivot
            if rng.random() < 0.5:
                plc = [h for h in topo.ot_hosts if "plcgw" in h] or topo.ot_hosts
                ev.append(f.flow(self.u(t0, t1), self.current, str(rng.choice(plc)), 502, rng, bytes_scale=5.0))
            return ev
        nxt = self.path[self.hop]
        if self.phase == "scan":
            self.stage(t0, "discovery")
            seg = topo.inventory.segment(nxt)
            pool = [h for h, info in topo.inventory.hosts.items() if info.segment == seg and h not in (nxt, self.current)]
            k = max(1, int(round((2 + 3 * p.intensity) * (1 - 0.6 * p.stealth))))
            targets = [str(x) for x in rng.choice(pool, size=min(k, len(pool)), replace=False)] + [nxt]
            ports = sorted(ADMIN_PORTS)
            for d in targets:
                for port in rng.choice(ports, size=2, replace=False):
                    ok = d == nxt or rng.random() < 0.2
                    ev.append(f.flow(self.u(t0, t1), self.current, d, int(port), rng,
                                     status="ok" if ok else "failed", bytes_scale=0.02))
            self.phase = "move"
            return ev
        # move
        self.stage(t0, "lateral_movement")
        if nxt in state.isolated:
            self.halt(t0, "target_isolated")
            return ev
        tt = self.u(t0, t1 - 4)
        method = "rdp" if "ot-" in nxt or rng.random() < 0.5 else "ssh"
        if self.account in state.suspended:
            ev.append(f.login(tt, self.account, self.current, nxt, "failure", method))
            self.halt(t0, "account_suspended")
            return ev
        ev.append(f.login(tt, self.account, self.current, nxt, "success", method))
        port = 3389 if method == "rdp" else 22
        for j in range(int(rng.integers(2, 4))):
            ev.append(f.flow(tt + 1 + j, self.current, nxt, port, rng))
        self.add_host(nxt)
        self.current = nxt
        self.hop += 1
        self.phase = "dwell"
        self.wait = p.dwell_steps
        return ev
