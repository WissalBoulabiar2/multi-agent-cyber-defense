"""Agent 2 — Authentication Security Agent.

Observes login events of the users in its shard. Detects repeated failures
(brute force), success after failures (likely credential compromise),
privileged accounts used from novel sources, access to never-used critical
destinations, off-hours novelty.
"""

from __future__ import annotations

from mcd.agents.sensor_agent import SensorAgent
from mcd.core.enums import Domain


class AuthenticationSecurityAgent(SensorAgent):
    def __init__(self, shard: int, broker, inventory, training_data=None, cfg=None, **kw) -> None:
        super().__init__(Domain.AUTH, shard, broker, inventory, training_data, cfg, **kw)
