from __future__ import annotations

from collections import defaultdict

from mcd.core.enums import Domain
from mcd.core.inventory import CRITICAL_CONFIG_KEYS, AssetInventory
from mcd.core.models import EntityRef, Observation
from mcd.detection.features.base import FeatureExtractor


class ConfigFeatures(FeatureExtractor):
    """Per host, per window: unticketed / critical / privilege changes, drift, actor context."""

    domain = Domain.CONFIG
    feature_names = [
        "n_changes", "n_unticketed", "critical_unticketed", "unticketed_priv", "audit_disabled",
        "drift_keys", "unknown_actor", "novel_actor_src", "off_hours",
    ]

    def __init__(self, inventory: AssetInventory) -> None:
        super().__init__(inventory)
        self.drift: dict[str, set[str]] = defaultdict(set)
        self.actor_src: dict[str, set[str]] = defaultdict(set)
        # an administrator's own workstation is a known source (CMDB knowledge)
        for u in inventory.users.values():
            if u.privileged:
                self.actor_src[u.id].add(u.home_host)
        self.authorized = {u.id for u in inventory.users.values() if u.privileged} | {"response-agent"}

    def entity_of(self, obs: Observation) -> EntityRef:
        return EntityRef.host(obs.attrs["host"])

    def extract(self, entity, events, t_end):
        host = entity.id
        unt = [e for e in events if not e.attrs.get("ticket")]
        for e in events:  # drift bookkeeping (ticketed changes and reverts re-baseline the key)
            if e.attrs.get("ticket"):
                self.drift[host].discard(e.attrs["key"])
            else:
                self.drift[host].add(e.attrs["key"])
        actors = {e.attrs["actor"] for e in events}
        novel_src = {e.attrs["src_host"] for e in events if e.attrs["src_host"] not in self.actor_src[e.attrs["actor"]]}
        n = len(events)
        feats = {
            "n_changes": float(n),
            "n_unticketed": float(len(unt)),
            "critical_unticketed": float(sum(1 for e in unt if e.attrs["key"] in CRITICAL_CONFIG_KEYS)),
            "unticketed_priv": float(sum(1 for e in unt if e.attrs["change_type"] == "privilege_grant")),
            "audit_disabled": float(sum(1 for e in unt if e.attrs["key"] == "audit_policy" and e.attrs["change_type"] == "disable")),
            "drift_keys": float(len(self.drift[host])),
            "unknown_actor": float(len(actors - self.authorized)),
            "novel_actor_src": float(len(novel_src)),
            "off_hours": sum(1 for e in events if self.inv.off_hours(e.sim_time)) / n if n else 0.0,
        }
        related = [EntityRef.user(a) for a in sorted(actors)] + [EntityRef.host(h) for h in sorted(novel_src)]
        return feats, related[:10]

    def update(self, entity, events, flagged):
        if flagged:
            return
        for e in events:
            self.actor_src[e.attrs["actor"]].add(e.attrs["src_host"])
