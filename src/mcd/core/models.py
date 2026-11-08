"""Pydantic payload schemas — the single contract shared by every component.

Time convention: ``sim_time`` values are *simulated seconds since scenario start*
(floats). Wall-clock timestamps (``created_at`` etc.) are Unix epoch seconds.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from mcd.core.enums import ActionType, AssessmentStatus, Domain, MessageType, Severity

EntityKind = Literal["host", "user", "config_item", "segment"]


class EntityRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: EntityKind
    id: str

    def key(self) -> str:
        return f"{self.kind}:{self.id}"

    @classmethod
    def host(cls, host_id: str) -> "EntityRef":
        return cls(kind="host", id=host_id)

    @classmethod
    def user(cls, user_id: str) -> "EntityRef":
        return cls(kind="user", id=user_id)


# --------------------------------------------------------------------------- env
class Observation(BaseModel):
    """Raw synthetic security event. Environment -> owning sensor agent only.

    Never carries ground-truth labels (see simulation.ground_truth).
    """

    event_id: str
    domain: Domain
    sim_time: float
    attrs: dict[str, Any]


class Watermark(BaseModel):
    """Sim-time progress marker: no further events with sim_time < t will be sent."""

    t: float


# ---------------------------------------------------------------- sensor alerts
class Evidence(BaseModel):
    rule_ids: list[str] = Field(default_factory=list)
    top_features: list[tuple[str, float, float]] = Field(default_factory=list)  # (name, value, z)
    event_ids: list[str] = Field(default_factory=list)
    summary: str = ""


class LocalAlert(BaseModel):
    alert_id: str
    domain: Domain
    agent_id: str
    entities: list[EntityRef]          # entities[0] is the primary (window) entity
    alert_type: str
    tactic: str | None = None
    anomaly_score: float
    rule_confidence: float
    confidence: float
    status: Literal["ANOMALY", "SUSPICIOUS"]
    severity: Severity
    window_start: float
    window_end: float
    count: int = 1
    evidence: Evidence = Field(default_factory=Evidence)

    @property
    def primary(self) -> EntityRef:
        return self.entities[0]


class ContextRequest(BaseModel):
    request_id: str
    incident_id: str
    entity: EntityRef
    window_start: float
    window_end: float
    question: Literal["recent_alerts", "activity_summary", "baseline_deviation"] = "recent_alerts"


class ContextResponse(BaseModel):
    request_id: str
    incident_id: str
    responder: str
    domain: Domain
    entity: EntityRef
    max_confidence: float
    alert_types: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    summary_stats: dict[str, float] = Field(default_factory=dict)
    last_seen: float | None = None


class ThreatAdvisory(BaseModel):
    incident_id: str
    entities: list[EntityRef]
    reason: str
    share_threshold_delta: float = -0.15
    ttl_seconds: float = 900.0
    issued_at: float = 0.0  # sim time


# --------------------------------------------------------------- coordinator
class TargetRef(BaseModel):
    entity: EntityRef
    domain: Domain  # domain whose evidence implicated this entity


class ThreatAssessment(BaseModel):
    incident_id: str
    status: AssessmentStatus
    actionable: bool
    decision_source: Literal["coordinator", "local", "central"]
    threat_class: str
    global_confidence: float
    severity: Severity
    entities: list[EntityRef]
    targets: list[TargetRef] = Field(default_factory=list)
    contributing_alerts: list[str] = Field(default_factory=list)
    contributing_agents: list[str] = Field(default_factory=list)
    domains: list[Domain] = Field(default_factory=list)
    tactics_observed: list[str] = Field(default_factory=list)
    explanation: str = ""
    first_seen: float = 0.0
    last_updated: float = 0.0


# ------------------------------------------------------------------ response
class ContainmentCommand(BaseModel):
    action_id: str
    incident_id: str
    action: ActionType
    target: EntityRef
    params: dict[str, Any] = Field(default_factory=dict)
    reply_to: str = ""


class ActionAck(BaseModel):
    action_id: str
    applied: bool
    sim_time: float
    detail: str = ""


class ApprovalRequest(BaseModel):
    action_id: str
    command: ContainmentCommand
    rationale: str
    confidence: float
    deadline_wall: float
    reply_to: str


class ApprovalDecision(BaseModel):
    action_id: str
    approved: bool
    operator: str
    comment: str | None = None


ResponseOutcome = Literal["MITIGATED", "PARTIAL", "INEFFECTIVE", "REJECTED", "TIMED_OUT", "PENDING", "LOGGED"]


class ResponseReport(BaseModel):
    action_id: str
    incident_id: str
    action: ActionType
    target: EntityRef
    executed_at: float | None
    outcome: ResponseOutcome
    post_action_signal: dict[str, float] = Field(default_factory=dict)


# ------------------------------------------------------------------- control
class Heartbeat(BaseModel):
    agent_id: str
    domain: Domain
    state: str
    queue_depth: int
    processed: int
    failed: int
    cpu_time_s: float = 0.0
    rss_mb: float = 0.0
    wall_time: float = 0.0


PAYLOAD_MODELS: dict[MessageType, type[BaseModel]] = {
    MessageType.OBSERVATION: Observation,
    MessageType.WATERMARK: Watermark,
    MessageType.LOCAL_ALERT: LocalAlert,
    MessageType.CONTEXT_REQUEST: ContextRequest,
    MessageType.CONTEXT_RESPONSE: ContextResponse,
    MessageType.THREAT_ADVISORY: ThreatAdvisory,
    MessageType.THREAT_ASSESSMENT: ThreatAssessment,
    MessageType.CONTAINMENT_COMMAND: ContainmentCommand,
    MessageType.ACTION_ACK: ActionAck,
    MessageType.RESPONSE_REPORT: ResponseReport,
    MessageType.APPROVAL_REQUEST: ApprovalRequest,
    MessageType.APPROVAL_DECISION: ApprovalDecision,
    MessageType.HEARTBEAT: Heartbeat,
}
