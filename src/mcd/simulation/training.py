"""Benign training history for local model fitting.

Each sensor agent trains only on *its own shard* of a benign history generated
with a seed disjoint from evaluation seeds — equivalent to an agent reading
its own historical logs. No agent sees another agent's raw training data.
"""

from __future__ import annotations

from functools import lru_cache

from mcd.communication.topics import shard_of
from mcd.core.enums import Domain
from mcd.core.models import Observation
from mcd.simulation.environment import EnvConfig, Environment, shard_key
from mcd.simulation.topology import TopologyConfig

TRAIN_SEED_OFFSET = 1_000_000


@lru_cache(maxsize=8)
def _history(seed: int, duration: float, topology: TopologyConfig, topology_seed: int) -> tuple[Observation, ...]:
    env = Environment(EnvConfig(seed=seed + TRAIN_SEED_OFFSET, duration=duration, topology=topology,
                                topology_seed=topology_seed))
    return tuple(env.generate_offline())


def benign_history(seed: int, duration: float, topology: TopologyConfig, topology_seed: int = 0,
                   domain: Domain | None = None, shard: int = 0, n_shards: int = 1) -> list[Observation]:
    events = _history(seed, duration, topology, topology_seed)
    out = []
    for e in events:
        if domain is not None and e.domain != domain:
            continue
        if n_shards > 1 and shard_of(shard_key(e), n_shards) != shard:
            continue
        out.append(e.model_copy(deep=True))
    return out
