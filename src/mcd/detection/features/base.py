from __future__ import annotations

import abc

from mcd.core.enums import Domain
from mcd.core.inventory import AssetInventory
from mcd.core.models import EntityRef, Observation


class FeatureExtractor(abc.ABC):
    """Turns one entity's observations in one window into a numeric feature vector.

    Extractors may hold *local* baselines (e.g. known communication pairs);
    ``update`` lets them learn online from windows that were not flagged, so
    an attacker cannot poison the baseline with flagged activity.
    """

    domain: Domain
    feature_names: list[str]

    def __init__(self, inventory: AssetInventory) -> None:
        self.inv = inventory

    @abc.abstractmethod
    def entity_of(self, obs: Observation) -> EntityRef: ...

    def fit_baseline(self, events: list[Observation]) -> None:
        """Learn baselines from a benign history (default: online updates)."""
        by_entity: dict[EntityRef, list[Observation]] = {}
        for e in events:
            by_entity.setdefault(self.entity_of(e), []).append(e)
        for ent, evs in by_entity.items():
            self.update(ent, evs, flagged=False)

    @abc.abstractmethod
    def extract(self, entity: EntityRef, events: list[Observation], t_end: float) -> tuple[dict[str, float], list[EntityRef]]:
        """Return (features, related entities)."""

    def update(self, entity: EntityRef, events: list[Observation], flagged: bool) -> None:
        return None

    def vector(self, feats: dict[str, float]) -> list[float]:
        return [float(feats[n]) for n in self.feature_names]
