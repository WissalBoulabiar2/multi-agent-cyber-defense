from __future__ import annotations

import math

from mcd.core.enums import Domain
from mcd.core.inventory import ADMIN_PORTS, AssetInventory
from mcd.core.models import EntityRef, Observation
from mcd.detection.features.base import FeatureExtractor


class NetworkFeatures(FeatureExtractor):
    """Per source host, per window: volume, fan-out, admin ports, novelty, segment jumps."""

    domain = Domain.NETWORK
    feature_names = [
        "n_flows", "uniq_dst", "uniq_ports", "admin_flows", "log_bytes_out", "out_in_log_ratio",
        "failed_ratio", "new_pair_ratio", "new_pairs", "new_admin_pairs", "cross_segment_ratio", "crit_jump",
    ]

    def __init__(self, inventory: AssetInventory) -> None:
        super().__init__(inventory)
        self.known_pairs: set[tuple[str, str]] = set()
        self.known_admin_pairs: set[tuple[str, str]] = set()

    def entity_of(self, obs: Observation) -> EntityRef:
        return EntityRef.host(obs.attrs["src"])

    def extract(self, entity, events, t_end):
        src = entity.id
        n = len(events)
        dsts = {e.attrs["dst"] for e in events}
        ports = {e.attrs["dst_port"] for e in events}
        admin = [e for e in events if e.attrs["dst_port"] in ADMIN_PORTS]
        out_b = sum(e.attrs["bytes_out"] for e in events)
        in_b = sum(e.attrs["bytes_in"] for e in events)
        failed = sum(1 for e in events if e.attrs["status"] != "ok")
        new = {d for d in dsts if (src, d) not in self.known_pairs}
        new_admin = {e.attrs["dst"] for e in admin if (src, e.attrs["dst"]) not in self.known_admin_pairs}
        seg = self.inv.segment(src)
        cross = sum(1 for e in events if self.inv.segment(e.attrs["dst"]) != seg)
        crit_src = self.inv.criticality(src)
        jump = max([self.inv.criticality(d) - crit_src for d in new_admin] + [0])
        feats = {
            "n_flows": float(n),
            "uniq_dst": float(len(dsts)),
            "uniq_ports": float(len(ports)),
            "admin_flows": float(len(admin)),
            "log_bytes_out": math.log1p(out_b),
            "out_in_log_ratio": math.log1p(out_b) - math.log1p(in_b),
            "failed_ratio": failed / n if n else 0.0,
            "new_pair_ratio": len(new) / len(dsts) if dsts else 0.0,
            "new_pairs": float(len(new)),
            "new_admin_pairs": float(len(new_admin)),
            "cross_segment_ratio": cross / n if n else 0.0,
            "crit_jump": float(jump),
        }
        ordered = sorted(new_admin) + sorted(new - new_admin) + sorted(dsts - new)
        related = [EntityRef.host(d) for d in ordered[:10]]
        return feats, related

    def update(self, entity, events, flagged):
        if flagged:
            return
        src = entity.id
        for e in events:
            if e.attrs["status"] != "ok":
                continue
            self.known_pairs.add((src, e.attrs["dst"]))
            if e.attrs["dst_port"] in ADMIN_PORTS:
                self.known_admin_pairs.add((src, e.attrs["dst"]))
