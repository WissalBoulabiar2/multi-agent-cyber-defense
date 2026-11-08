"""Benign background activity, including deliberate *confounders*:

* a vulnerability scanner sweeping random hosts on admin ports,
* hourly backups (fan-out + service-account logins),
* administrators opening sessions on servers and making config changes
  (mostly ticketed, a few emergency changes without ticket),
* users mistyping passwords, occasional late-evening work,
* rare visits to servers outside a workstation's usual set.

Without these, false-positive rates would be trivially (and misleadingly) low.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from mcd.core.models import Observation
from mcd.simulation.events import EventFactory
from mcd.simulation.topology import CONFIG_KEYS, SERVER_PORTS, Topology


@dataclass
class NormalConfig:
    ws_flow_rate_work: float = 1.0      # flows / workstation / minute in work hours
    ws_flow_rate_off: float = 0.1
    novel_server_prob: float = 0.03
    login_prob: float = 0.02            # per user per minute (work hours)
    typo_prob: float = 0.08
    admin_session_prob: float = 0.03    # per admin per minute
    admin_change_prob: float = 0.35
    unticketed_change_prob: float = 0.08
    scanner_period_s: float = 2700.0
    scanner_targets: int = 10
    backup_period_s: float = 3600.0
    late_worker_prob: float = 0.002


class NormalActivity:
    def __init__(self, topo: Topology, rng: np.random.Generator, factory: EventFactory,
                 cfg: NormalConfig | None = None) -> None:
        self.topo, self.rng, self.f, self.cfg = topo, rng, factory, cfg or NormalConfig()
        inv = topo.inventory
        self.dc = topo.server_by_role("dc")
        self.fs = topo.server_by_role("fs")
        self.backup = topo.server_by_role("backup")
        self.db = topo.server_by_role("db")
        self._hmi = [h for h in topo.ot_hosts if inv.hosts[h].role == "hmi"]
        self._scada = [h for h in topo.ot_hosts if inv.hosts[h].role == "scada"]
        self._plc = [h for h in topo.ot_hosts if inv.hosts[h].role == "plcgw"]

    def _work(self, t: float) -> bool:
        h = self.topo.inventory.hour_of(t)
        return 8.0 <= h < 18.0

    def _t(self, t0: float, t1: float) -> float:
        return float(self.rng.uniform(t0, t1))

    def generate(self, t0: float, t1: float) -> list[Observation]:
        rng, f, topo, c = self.rng, self.f, self.topo, self.cfg
        dt_min = (t1 - t0) / 60.0
        work = self._work(t0)
        ev: list[Observation] = []

        # -- workstation traffic
        rate = (c.ws_flow_rate_work if work else c.ws_flow_rate_off) * dt_min
        for ws in topo.workstations + topo.admin_workstations:
            for _ in range(rng.poisson(rate)):
                if rng.random() < c.novel_server_prob:
                    dst = str(rng.choice(topo.servers))
                else:
                    dst = str(rng.choice(topo.usual_servers[ws]))
                port = int(rng.choice(SERVER_PORTS[topo.server_role[dst]]))
                ev.append(f.flow(self._t(t0, t1), ws, dst, port, rng))

        # -- server <-> server and OT process traffic (steady)
        for _ in range(rng.poisson(2 * dt_min)):
            src = topo.server_by_role(str(rng.choice(["web", "app"])))
            ev.append(f.flow(self._t(t0, t1), src, self.db, 5432, rng))
        for srv in topo.servers:
            if srv != self.dc and rng.random() < 0.3 * dt_min:
                ev.append(f.flow(self._t(t0, t1), srv, self.dc, 88, rng))
        for hmi in self._hmi:
            for _ in range(rng.poisson(2 * dt_min)):
                ev.append(f.flow(self._t(t0, t1), hmi, str(rng.choice(self._scada)), 502, rng, bytes_scale=0.1))
        for sc in self._scada:
            for _ in range(rng.poisson(3 * dt_min)):
                ev.append(f.flow(self._t(t0, t1), sc, str(rng.choice(self._plc)), 502, rng, bytes_scale=0.1))
        for dmz in topo.dmz_hosts:
            for _ in range(rng.poisson(1.5 * dt_min)):
                ev.append(f.flow(self._t(t0, t1), dmz, topo.server_by_role("app"), 8443, rng))

        # -- confounder: vulnerability scanner sweep
        if _periodic(t0, t1, c.scanner_period_s, offset=600.0):
            hosts = [h for h in topo.all_hosts if h != topo.scanner]
            for dst in rng.choice(hosts, size=min(c.scanner_targets, len(hosts)), replace=False):
                for port in (22, 80, 443, 445, 3389, 5985):
                    ev.append(f.flow(self._t(t0, t1), topo.scanner, str(dst), port, rng,
                                     status="ok" if rng.random() < 0.2 else "failed", bytes_scale=0.01))

        # -- confounder: hourly backup (fan-out + service logins)
        if _periodic(t0, t1, c.backup_period_s, offset=1800.0):
            for srv in topo.servers:
                if srv == self.backup:
                    continue
                tt = self._t(t0, t1)
                ev.append(f.login(tt, "svc-backup", self.backup, srv, "success", "ntlm"))
                ev.append(f.flow(tt + 0.5, self.backup, srv, 445, rng, bytes_scale=50.0))

        # -- user logins (with typos) and late workers
        p_login = (c.login_prob if work else c.late_worker_prob) * dt_min
        for uid in topo.standard_users:
            if rng.random() < p_login:
                home = topo.inventory.users[uid].home_host
                tt = self._t(t0, t1 - 1)
                if rng.random() < c.typo_prob:
                    for k in range(int(rng.integers(1, 4))):
                        ev.append(f.login(tt + 0.1 * k, uid, home, self.dc, "failure"))
                ev.append(f.login(tt + 0.5, uid, home, self.dc, "success"))
                if rng.random() < 0.3:
                    ev.append(f.login(tt + 0.8, uid, home, self.fs, "success", "ntlm"))

        # -- admin sessions (+ config changes, some emergency/unticketed)
        for uid in topo.admin_users:
            if rng.random() >= c.admin_session_prob * dt_min * (1.0 if work else 0.2):
                continue
            home = topo.inventory.users[uid].home_host
            dst = str(rng.choice(topo.servers + self._hmi))
            tt = self._t(t0, t1 - 2)
            if rng.random() < 0.05:
                ev.append(f.login(tt, uid, home, dst, "failure", "ssh"))
            ev.append(f.login(tt + 0.2, uid, home, dst, "success", "ssh"))
            port = int(rng.choice([22, 3389]))
            for k in range(int(rng.integers(1, 4))):
                ev.append(f.flow(tt + 0.3 + k, home, dst, port, rng))
            if rng.random() < c.admin_change_prob:
                key = str(rng.choice(CONFIG_KEYS, p=_KEY_P))
                ticket = None if rng.random() < c.unticketed_change_prob else f"CHG-{int(rng.integers(1000, 9999))}"
                ctype = "privilege_grant" if key == "admin_group" else "modify"
                ev.append(f.config(tt + 1.5, dst, key, uid, home, rng, change_type=ctype, ticket=ticket))

        # -- automated deployments (ticketed app_config drift)
        if rng.random() < 0.05 * dt_min:
            web = topo.service_users["svc-web"]
            ev.append(f.config(self._t(t0, t1), web, "app_config", "svc-web", web, rng, ticket="AUTO-DEPLOY"))
        return ev


def _periodic(t0: float, t1: float, period: float, offset: float = 0.0) -> bool:
    """True if some instant offset + k*period (k >= 0 integer) falls in [t0, t1)."""
    k = math.ceil((t0 - offset) / period)
    return offset + k * period < t1 and offset + k * period >= t0


_KEY_WEIGHTS = {"sudoers": 1, "firewall": 3, "audit_policy": 0.3, "admin_group": 1, "ssh_config": 1,
                "services": 3, "app_config": 4, "ntp": 1, "log_rotation": 2}
_KEY_P = np.array([_KEY_WEIGHTS[k] for k in CONFIG_KEYS], dtype=float)
_KEY_P /= _KEY_P.sum()
