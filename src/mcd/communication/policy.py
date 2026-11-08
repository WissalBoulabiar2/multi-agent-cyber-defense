"""Outbound communication constraints applied by each sensor agent.

1. share threshold (possibly lowered by an advisory for watched entities)
2. suppression window per (entity, alert_type), merging repeats into ``count``
3. token-bucket rate limit (P0 bypasses the bucket but is still counted)
4. maximum serialized payload size
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from mcd.core.enums import Priority
from mcd.core.models import LocalAlert


@dataclass
class PolicyConfig:
    share_threshold: float = 0.45
    suppression_window: float = 300.0  # sim seconds
    rate_msgs_per_s: float = 50.0
    burst: float = 100.0
    max_bytes: int = 16_384


@dataclass
class PolicyCounters:
    shared: int = 0
    below_threshold: int = 0
    suppressed: int = 0
    rate_limited: int = 0
    oversize: int = 0


@dataclass
class CommunicationPolicy:
    config: PolicyConfig = field(default_factory=PolicyConfig)
    counters: PolicyCounters = field(default_factory=PolicyCounters)

    def __post_init__(self) -> None:
        self._last_shared: dict[tuple[str, str], float] = {}
        self._merged: dict[tuple[str, str], int] = {}
        self._tokens = self.config.burst
        self._t_last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(self.config.burst, self._tokens + (now - self._t_last) * self.config.rate_msgs_per_s)
        self._t_last = now

    def evaluate(self, alert: LocalAlert, threshold: float | None = None) -> tuple[bool, str]:
        """Decide whether ``alert`` may be shared. Mutates ``alert.count`` on merge."""
        thr = self.config.share_threshold if threshold is None else threshold
        if alert.confidence < thr:
            self.counters.below_threshold += 1
            return False, "below_threshold"
        key = (alert.primary.key(), alert.alert_type)
        last = self._last_shared.get(key)
        if last is not None and alert.window_end - last < self.config.suppression_window:
            self._merged[key] = self._merged.get(key, 0) + 1
            self.counters.suppressed += 1
            return False, "suppressed"
        return True, "ok"

    def admit(self, alert: LocalAlert, priority: Priority, size_bytes: int) -> tuple[bool, str]:
        if size_bytes > self.config.max_bytes:
            self.counters.oversize += 1
            return False, "oversize"
        self._refill()
        if priority != Priority.P0:
            if self._tokens < 1:
                self.counters.rate_limited += 1
                return False, "rate_limited"
            self._tokens -= 1
        key = (alert.primary.key(), alert.alert_type)
        alert.count = 1 + self._merged.pop(key, 0)
        self._last_shared[key] = alert.window_end
        self.counters.shared += 1
        return True, "ok"
