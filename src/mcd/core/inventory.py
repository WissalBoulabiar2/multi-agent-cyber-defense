"""Asset inventory: *public* organisational knowledge every agent may hold.

It contains no observations — only what a real SOC would have in a CMDB:
hosts, segments, criticality, which users are privileged, which actors are
authorised administrators. Agents use it for severity and feature context.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ADMIN_PORTS = frozenset({22, 3389, 445, 5985})
CRITICAL_CONFIG_KEYS = frozenset({"sudoers", "firewall", "audit_policy", "admin_group", "ssh_config", "services"})


@dataclass
class HostInfo:
    id: str
    segment: str
    criticality: int  # 1 (low) .. 3 (critical)
    role: str


@dataclass
class UserInfo:
    id: str
    role: str  # standard | admin | service
    home_host: str

    @property
    def privileged(self) -> bool:
        return self.role in ("admin", "service")


@dataclass
class AssetInventory:
    hosts: dict[str, HostInfo] = field(default_factory=dict)
    users: dict[str, UserInfo] = field(default_factory=dict)
    start_hour: float = 8.0

    def criticality(self, host_id: str) -> int:
        h = self.hosts.get(host_id)
        return h.criticality if h else 1

    def segment(self, host_id: str) -> str:
        h = self.hosts.get(host_id)
        return h.segment if h else "UNKNOWN"

    def is_privileged(self, user_id: str) -> bool:
        u = self.users.get(user_id)
        return bool(u and u.privileged)

    def admins(self) -> set[str]:
        return {u.id for u in self.users.values() if u.role == "admin"}

    def hour_of(self, sim_time: float) -> float:
        return (self.start_hour + sim_time / 3600.0) % 24.0

    def off_hours(self, sim_time: float) -> bool:
        h = self.hour_of(sim_time)
        return h < 7.0 or h >= 20.0
