"""Agent 3 — Configuration Security Agent.

Observes configuration change events of the hosts in its shard. Detects
unticketed changes to security-critical keys, unauthorised privilege grants,
configuration drift from baseline, changes from unusual sources, audit
disabling (high-fidelity signature) and changes by non-administrative actors.
"""

from __future__ import annotations

from mcd.agents.sensor_agent import SensorAgent
from mcd.core.enums import Domain


class ConfigurationSecurityAgent(SensorAgent):
    def __init__(self, shard: int, broker, inventory, training_data=None, cfg=None, **kw) -> None:
        super().__init__(Domain.CONFIG, shard, broker, inventory, training_data, cfg, **kw)
