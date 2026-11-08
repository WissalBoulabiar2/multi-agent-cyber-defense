from __future__ import annotations

from collections import defaultdict, deque

from mcd.core.enums import Domain
from mcd.core.inventory import AssetInventory
from mcd.core.models import EntityRef, Observation
from mcd.detection.features.base import FeatureExtractor


class AuthFeatures(FeatureExtractor):
    """Per user, per window: failures (incl. multi-window memory), novelty, timing, privilege."""

    domain = Domain.AUTH
    feature_names = [
        "n_fail", "n_success", "fail_ratio", "recent_fail", "success_after_fail", "uniq_src", "uniq_dst",
        "novel_src", "novel_dst", "off_hours", "privileged", "dst_crit_max", "novel_dst_crit",
    ]

    def __init__(self, inventory: AssetInventory, memory_s: float = 300.0, saf_threshold: int = 5) -> None:
        super().__init__(inventory)
        self.user_src: dict[str, set[str]] = defaultdict(set)
        self.user_dst: dict[str, set[str]] = defaultdict(set)
        self.recent: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.memory_s = memory_s
        self.saf_threshold = saf_threshold

    def entity_of(self, obs: Observation) -> EntityRef:
        return EntityRef.user(obs.attrs["user"])

    def extract(self, entity, events, t_end):
        u = entity.id
        events = sorted(events, key=lambda e: e.sim_time)
        fails = [e for e in events if e.attrs["result"] != "success"]
        succ = [e for e in events if e.attrs["result"] == "success"]
        dq = self.recent[u]
        while dq and t_end - dq[0][0] > self.memory_s:
            dq.popleft()
        prior = sum(c for _, c in dq)
        saf = 0.0
        running = prior
        for e in events:
            if e.attrs["result"] == "success":
                if running >= self.saf_threshold:
                    saf = 1.0
            else:
                running += 1
        dq.append((t_end, len(fails)))
        srcs = {e.attrs["src_host"] for e in events}
        dsts = {e.attrs["dst_host"] for e in events}
        novel_src = srcs - self.user_src[u]
        novel_dst = {e.attrs["dst_host"] for e in succ} - self.user_dst[u]
        n = len(events)
        feats = {
            "n_fail": float(len(fails)),
            "n_success": float(len(succ)),
            "fail_ratio": len(fails) / n if n else 0.0,
            "recent_fail": float(prior + len(fails)),
            "success_after_fail": saf,
            "uniq_src": float(len(srcs)),
            "uniq_dst": float(len(dsts)),
            "novel_src": float(len(novel_src)),
            "novel_dst": float(len(novel_dst)),
            "off_hours": sum(1 for e in events if self.inv.off_hours(e.sim_time)) / n if n else 0.0,
            "privileged": 1.0 if self.inv.is_privileged(u) else 0.0,
            "dst_crit_max": float(max([self.inv.criticality(d) for d in dsts] + [0])),
            "novel_dst_crit": float(max([self.inv.criticality(d) for d in novel_dst] + [0])),
        }
        related = [EntityRef.host(h) for h in sorted(novel_src) + sorted(srcs - novel_src) + sorted(novel_dst)][:10]
        return feats, related

    def update(self, entity, events, flagged):
        if flagged:
            return
        u = entity.id
        for e in events:
            if e.attrs["result"] == "success":
                self.user_src[u].add(e.attrs["src_host"])
                self.user_dst[u].add(e.attrs["dst_host"])
