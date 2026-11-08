"""Scenario C — configuration tampering.

A compromised administrator account, used from an unusual workstation, makes
unticketed changes: firewall/sudoers/services modifications, privilege grants
(admin_group), drift of application config, and possibly disables auditing.
Re-tampers after a revert (persistence) unless the account is suspended.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcd.core.models import Observation
from mcd.simulation.attack_base import AttackScenario
from mcd.simulation.events import EnvState


@dataclass
class ConfigurationTampering(AttackScenario):
    actor: str | None = None
    foothold: str | None = None
    hosts: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.scenario = "configuration_tampering"
        rng, topo = self.rng, self.topo
        self.actor = self.actor or str(rng.choice(topo.admin_users))
        home = topo.inventory.users[self.actor].home_host
        self.foothold = self.foothold or str(rng.choice([w for w in topo.workstations if w != home]))
        if not self.hosts:
            pool = [s for s in topo.servers if topo.server_role[s] != "dc"] + topo.ot_hosts
            self.hosts = [str(h) for h in rng.choice(pool, size=min(self.params.n_hosts, len(pool)), replace=False)]
        self.queue: list[tuple[str, str, str]] = []
        for h in self.hosts:
            ops = [("firewall", "modify"), ("sudoers", "modify"), ("admin_group", "privilege_grant"),
                   ("services", "modify"), ("app_config", "modify"), ("log_rotation", "modify")]
            if rng.random() < 0.6 * (1 - self.params.stealth):
                ops.append(("audit_policy", "disable"))
            order = rng.permutation(len(ops))
            self.queue.extend((h, ops[i][0], ops[i][1]) for i in order)
        self.logged_in: set[str] = set()
        self.tampered: set[str] = set()
        self.add_user(self.actor)
        self.add_host(self.foothold)

    def _stage_for(self, key: str, ctype: str) -> str:
        if ctype == "privilege_grant" or key == "sudoers":
            return "privilege_escalation"
        if key == "audit_policy":
            return "defense_evasion"
        return "persistence"

    def _step(self, t0: float, t1: float, state: EnvState) -> list[Observation]:
        f, rng, p = self.factory, self.rng, self.params
        if self.foothold in state.isolated:
            self.halt(t0, "foothold_isolated")
            return []
        ev: list[Observation] = []
        if self.actor in state.suspended:
            target = self.hosts[0]
            ev.append(f.login(self.u(t0, t1), self.actor, self.foothold, target, "failure", "ssh"))
            self.halt(t0, "account_suspended")
            return ev
        n_ops = max(1, int(round(1.5 * p.intensity * (1 - 0.5 * p.stealth))))
        tt = self.u(t0, t1 - 5)
        for _ in range(n_ops):
            if not self.queue:
                reverted = [h for _, h in state.reverts if h in self.tampered]
                if reverted and rng.random() < 0.3:
                    self.queue.append((reverted[-1], "firewall", "modify"))
                else:
                    break
            host, key, ctype = self.queue.pop(0)
            if host in state.isolated:
                continue
            if host not in self.logged_in:
                ev.append(f.login(tt, self.actor, self.foothold, host, "success", "ssh"))
                ev.append(f.flow(tt + 0.2, self.foothold, host, 22, rng))
                self.logged_in.add(host)
                self.add_host(host)
            self.stage(t0, self._stage_for(key, ctype))
            ev.append(f.config(tt + 1, host, key, self.actor, self.foothold, rng, change_type=ctype))
            self.tampered.add(host)
            tt += 1.5
        return ev
