"""Synthetic critical-infrastructure topology (DMZ / CORP / SERVERS / OT)."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from mcd.core.inventory import AssetInventory, HostInfo, UserInfo

SEGMENT_CRITICALITY = {"DMZ": 1, "CORP": 1, "SERVERS": 2, "OT": 3}
SERVER_ROLES = ["dc", "fs", "web", "db", "app", "mail", "backup", "jump"]
SERVER_PORTS = {
    "dc": [53, 88, 389], "fs": [445], "web": [443, 80], "db": [5432], "app": [8443],
    "mail": [443, 25], "backup": [445], "jump": [3389, 22],
}
CONFIG_KEYS = ["sudoers", "firewall", "audit_policy", "admin_group", "ssh_config", "services", "app_config", "ntp", "log_rotation"]


@dataclass(frozen=True)
class TopologyConfig:
    n_workstations: int = 24
    n_admins: int = 4
    n_servers: int = 8
    n_ot: int = 6
    n_dmz: int = 2
    scale: float = 1.0
    start_hour: float = 8.0


@dataclass
class Topology:
    inventory: AssetInventory
    workstations: list[str]
    admin_workstations: list[str]
    servers: list[str]
    ot_hosts: list[str]
    dmz_hosts: list[str]
    scanner: str
    server_role: dict[str, str]
    usual_servers: dict[str, list[str]] = field(default_factory=dict)
    standard_users: list[str] = field(default_factory=list)
    admin_users: list[str] = field(default_factory=list)
    service_users: dict[str, str] = field(default_factory=dict)  # name -> home server

    def server_by_role(self, role: str) -> str:
        return next(h for h, r in self.server_role.items() if r == role)

    @property
    def all_hosts(self) -> list[str]:
        return list(self.inventory.hosts)


def build_topology(cfg: TopologyConfig | None = None, seed: int = 0) -> Topology:
    cfg = cfg or TopologyConfig()
    rng = np.random.default_rng(seed)
    s = cfg.scale
    n_ws = max(4, int(round(cfg.n_workstations * s)))
    n_srv = max(len(SERVER_ROLES), int(round(cfg.n_servers * s)))
    n_ot = max(3, int(round(cfg.n_ot * s)))
    n_dmz = max(1, int(round(cfg.n_dmz * s)))
    n_adm = max(2, int(round(cfg.n_admins * s)))

    inv = AssetInventory(start_hour=cfg.start_hour)

    def add(hid: str, seg: str, role: str, crit: int | None = None) -> str:
        inv.hosts[hid] = HostInfo(hid, seg, crit or SEGMENT_CRITICALITY[seg], role)
        return hid

    workstations = [add(f"ws-{i:03d}", "CORP", "workstation") for i in range(n_ws)]
    admin_ws = [add(f"ws-adm-{i:02d}", "CORP", "admin_workstation") for i in range(n_adm)]
    scanner = add("sec-scanner-01", "CORP", "scanner")
    server_role: dict[str, str] = {}
    servers = []
    for i in range(n_srv):
        role = SERVER_ROLES[i % len(SERVER_ROLES)]
        idx = i // len(SERVER_ROLES) + 1
        hid = add(f"srv-{role}-{idx:02d}", "SERVERS", role, 3 if role == "dc" else None)
        server_role[hid] = role
        servers.append(hid)
    ot_roles = ["hmi", "scada", "plcgw"]
    ot_hosts = [add(f"ot-{ot_roles[i % 3]}-{i // 3 + 1:02d}", "OT", ot_roles[i % 3]) for i in range(n_ot)]
    dmz_hosts = [add(f"dmz-{'web' if i % 2 == 0 else 'vpn'}-{i // 2 + 1:02d}", "DMZ", "dmz") for i in range(n_dmz)]

    topo = Topology(inv, workstations, admin_ws, servers, ot_hosts, dmz_hosts, scanner, server_role)
    common = [h for h in servers if server_role[h] in ("dc", "fs", "mail")]
    optional = [h for h in servers if server_role[h] in ("web", "app")]
    for ws in workstations + admin_ws:
        k = int(rng.integers(1, 3))
        extra = list(rng.choice(optional, size=min(k, len(optional)), replace=False)) if optional else []
        topo.usual_servers[ws] = common + [str(x) for x in extra]

    for i, ws in enumerate(workstations):
        uid = f"user-{i:03d}"
        inv.users[uid] = UserInfo(uid, "standard", ws)
        topo.standard_users.append(uid)
    for i, ws in enumerate(admin_ws):
        uid = f"admin-{i:02d}"
        inv.users[uid] = UserInfo(uid, "admin", ws)
        topo.admin_users.append(uid)
    for name, role in (("svc-backup", "backup"), ("svc-web", "web")):
        home = topo.server_by_role(role)
        inv.users[name] = UserInfo(name, "service", home)
        topo.service_users[name] = home
    return topo
