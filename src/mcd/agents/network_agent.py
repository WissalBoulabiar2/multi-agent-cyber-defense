"""Agent 1 — Network Security Agent.

Observes flow records of the hosts in its shard (keyed by source host).
Detects abnormal traffic volume/fan-out, communication with never-seen peers,
admin-port access towards more critical segments (lateral-movement
indicators), host/port sweeps.
"""

from __future__ import annotations

from mcd.agents.sensor_agent import SensorAgent
from mcd.core.enums import Domain


class NetworkSecurityAgent(SensorAgent):
    def __init__(self, shard: int, broker, inventory, training_data=None, cfg=None, **kw) -> None:
        super().__init__(Domain.NETWORK, shard, broker, inventory, training_data, cfg, **kw)
