"""Stream (topic) naming and entity ownership (sharding) helpers."""

from __future__ import annotations

import zlib

from mcd.core.enums import Domain, Priority

SIM_CLOCK = "sim.clock"
ALERTS_DIRECT = "alerts.direct"
ASSESSMENTS = "assessments"
ENV_ACTIONS = "env.actions"
RESPONSE_REPORTS = "response.reports"
APPROVAL_REQUESTS = "approvals.requests"
HEARTBEAT = "control.heartbeat"
TELEMETRY = "telemetry"
AUDIT = "audit"

DOMAIN_PREFIX = {Domain.NETWORK: "net", Domain.AUTH: "auth", Domain.CONFIG: "cfg"}


def sim_events(domain: Domain | str, shard: int) -> str:
    return f"sim.{DOMAIN_PREFIX[Domain(domain)]}.events.{shard}"


def alerts(priority: Priority | int) -> str:
    return f"alerts.p{int(priority)}"


ALERT_LANES = [alerts(p) for p in Priority]


def inbox(agent_id: str) -> str:
    return f"agent.{agent_id}.inbox"


def dlq(topic: str) -> str:
    return f"dlq.{topic}"


def sensor_agent_id(domain: Domain | str, shard: int) -> str:
    return f"{DOMAIN_PREFIX[Domain(domain)]}-{shard}"


def shard_of(entity_id: str, n_shards: int) -> int:
    """Deterministic, process-independent shard assignment (crc32)."""
    if n_shards <= 1:
        return 0
    return zlib.crc32(entity_id.encode("utf-8")) % n_shards


def topic_class(topic: str) -> str:
    """Coarse grouping used for overhead accounting."""
    if topic.startswith("sim."):
        return "ingest"
    if topic.startswith(("telemetry", "dlq.")):
        return "telemetry"
    if topic == HEARTBEAT:
        return "heartbeat"
    if topic.startswith("alerts."):
        return "alerts"
    if topic.startswith("agent."):
        return "directed"
    return topic
