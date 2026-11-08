"""Shared enumerations used across the protocol."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Priority(IntEnum):
    """Lower value = more urgent (P0 is read first)."""

    P0 = 0
    P1 = 1
    P2 = 2


def priority_for(severity: Severity | int | None) -> Priority:
    if severity is None:
        return Priority.P1
    severity = Severity(int(severity))
    if severity >= Severity.HIGH:
        return Priority.P0
    if severity == Severity.MEDIUM:
        return Priority.P1
    return Priority.P2


class Domain(StrEnum):
    NETWORK = "network"
    AUTH = "auth"
    CONFIG = "config"
    INTEL = "intel"
    RESPONSE = "response"
    ENV = "env"
    HUMAN = "human"
    OBSERVER = "observer"
    CENTRAL = "central"


SENSOR_DOMAINS = (Domain.NETWORK, Domain.AUTH, Domain.CONFIG)


class AssessmentStatus(StrEnum):
    ANOMALY = "ANOMALY"
    SUSPICIOUS = "SUSPICIOUS"
    CORROBORATED = "CORROBORATED"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"


STATUS_RANK = {
    AssessmentStatus.DISMISSED: -1,
    AssessmentStatus.ANOMALY: 0,
    AssessmentStatus.SUSPICIOUS: 1,
    AssessmentStatus.CORROBORATED: 2,
    AssessmentStatus.CONFIRMED: 3,
}


class MessageType(StrEnum):
    OBSERVATION = "OBSERVATION"
    WATERMARK = "WATERMARK"
    LOCAL_ALERT = "LOCAL_ALERT"
    CONTEXT_REQUEST = "CONTEXT_REQUEST"
    CONTEXT_RESPONSE = "CONTEXT_RESPONSE"
    THREAT_ADVISORY = "THREAT_ADVISORY"
    THREAT_ASSESSMENT = "THREAT_ASSESSMENT"
    CONTAINMENT_COMMAND = "CONTAINMENT_COMMAND"
    ACTION_ACK = "ACTION_ACK"
    RESPONSE_REPORT = "RESPONSE_REPORT"
    APPROVAL_REQUEST = "APPROVAL_REQUEST"
    APPROVAL_DECISION = "APPROVAL_DECISION"
    HEARTBEAT = "HEARTBEAT"
    TELEMETRY = "TELEMETRY"
    AUDIT = "AUDIT"


class ActionType(StrEnum):
    ALERT_ONLY = "ALERT_ONLY"
    SUSPEND_ACCOUNT = "SUSPEND_ACCOUNT"
    ISOLATE_HOST = "ISOLATE_HOST"
    REVERT_CONFIG = "REVERT_CONFIG"
    INCREASE_MONITORING = "INCREASE_MONITORING"
    ESCALATE_HUMAN = "ESCALATE_HUMAN"


class CoordinationMode(StrEnum):
    INDEPENDENT = "independent"
    COOPERATIVE = "cooperative"
    CENTRALIZED = "centralized"


class AgentState(StrEnum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    DOWN = "DOWN"
