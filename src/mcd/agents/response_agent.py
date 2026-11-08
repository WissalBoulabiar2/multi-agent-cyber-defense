"""Agent 5 — Response Agent.

Consumes validated assessments (cooperative / centralized) or local actionable
alerts (independent), plans actions, requests human approval for high-blast-
radius actions, publishes simulated containment commands to the environment,
keeps an incident response history, evaluates mitigation outcomes and writes
the hash-chained audit log.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from mcd.agents.base_agent import BaseAgent, Subscription
from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.communication.message_broker import MessageBroker
from mcd.core.enums import ActionType, AssessmentStatus, CoordinationMode, Domain, MessageType, Priority
from mcd.core.ids import new_id
from mcd.core.inventory import AssetInventory
from mcd.core.models import (
    ActionAck, ApprovalDecision, ApprovalRequest, ContainmentCommand, LocalAlert, ResponseReport, TargetRef,
    ThreatAssessment, Watermark,
)
from mcd.response.audit_logger import AuditLogger
from mcd.response.response_engine import PlannedAction, ResponseConfig, ResponseEngine


@dataclass
class ActionRecord:
    action_id: str
    incident_id: str
    planned: PlannedAction
    assessment: ThreatAssessment
    decided_sim: float
    state: str = "planned"  # planned | awaiting_approval | dispatched | executed | evaluated | rejected | timed_out
    approval: str = "not_required"
    approval_deadline: float | None = None
    executed_at: float | None = None
    post_signals: int = 0
    outcome: str = "PENDING"
    history: list[str] = field(default_factory=list)


class ResponseAgent(BaseAgent):
    domain = Domain.RESPONSE

    def __init__(self, broker: MessageBroker, inventory: AssetInventory, mode: CoordinationMode,
                 cfg: ResponseConfig | None = None, audit: AuditLogger | None = None,
                 agent_id: str = "response-0", **kwargs) -> None:
        super().__init__(agent_id, broker, **kwargs)
        self.mode = CoordinationMode(mode)
        self.cfg = cfg or ResponseConfig()
        self.engine = ResponseEngine(inventory, self.cfg)
        self.audit = audit or AuditLogger()
        self.actions: dict[str, ActionRecord] = {}
        self.active: dict[tuple[str, str], str] = {}  # (action, target) -> action_id
        self.decisions: list[dict] = []  # every actionable decision received (for evaluation)
        self.sim_now = 0.0

    def subscriptions(self) -> list[Subscription]:
        subs = [Subscription(T.inbox(self.agent_id), priority=0), Subscription(T.SIM_CLOCK, priority=2)]
        if self.mode == CoordinationMode.INDEPENDENT:
            subs.append(Subscription(T.ALERTS_DIRECT, priority=1))
        else:
            subs.append(Subscription(T.ASSESSMENTS, priority=1))
        return subs

    # ---------------------------------------------------------------- handle
    async def handle(self, env: Envelope) -> None:
        t = env.type
        if t == MessageType.THREAT_ASSESSMENT:
            await self._on_assessment(env.parse(ThreatAssessment), env.sim_time, env.sender)
        elif t == MessageType.LOCAL_ALERT:
            await self._on_assessment(self._from_local(env.parse(LocalAlert)), env.sim_time, env.sender)
        elif t == MessageType.ACTION_ACK:
            await self._on_ack(env.parse(ActionAck))
        elif t == MessageType.APPROVAL_DECISION:
            await self._on_approval(env.parse(ApprovalDecision))
        elif t == MessageType.WATERMARK:
            self.sim_now = max(self.sim_now, env.parse(Watermark).t)
            await self._evaluate_due()

    async def on_tick(self) -> None:
        now = time.time()
        for rec in list(self.actions.values()):
            if rec.state == "awaiting_approval" and rec.approval_deadline and now > rec.approval_deadline:
                rec.state, rec.approval, rec.outcome = "timed_out", "timed_out", "TIMED_OUT"
                self._log(rec, "TIMED_OUT -> fallback INCREASE_MONITORING + ESCALATE_HUMAN")
                await self._report(rec)
                await self._dispatch_fallback(rec)

    @staticmethod
    def _from_local(a: LocalAlert) -> ThreatAssessment:
        return ThreatAssessment(
            incident_id=f"local-{a.alert_id}", status=AssessmentStatus.SUSPICIOUS, actionable=True,
            decision_source="local", threat_class=a.alert_type, global_confidence=a.confidence, severity=a.severity,
            entities=a.entities, targets=[TargetRef(entity=a.primary, domain=a.domain)],
            contributing_alerts=[a.alert_id], contributing_agents=[a.agent_id], domains=[a.domain],
            tactics_observed=[a.tactic] if a.tactic else [], explanation=a.evidence.summary,
            first_seen=a.window_start, last_updated=a.window_end,
        )

    # -------------------------------------------------------------- decide
    async def _on_assessment(self, a: ThreatAssessment, sim_t: float, sender: str) -> None:
        self.sim_now = max(self.sim_now, sim_t)
        if a.actionable:
            self.decisions.append({
                "sim_time": sim_t, "wall_time": time.time(), "incident_id": a.incident_id, "source": a.decision_source,
                "sender": sender, "status": str(a.status), "confidence": a.global_confidence,
                "severity": int(a.severity), "threat_class": a.threat_class,
                "targets": [t.entity.key() for t in a.targets], "domains": [str(d) for d in a.domains],
            })
        for rec in self.actions.values():  # post-action signal for outcome evaluation
            if rec.executed_at is not None and rec.state == "executed" and sim_t > rec.executed_at + 60 \
                    and any(t.entity == rec.planned.target for t in a.targets):
                rec.post_signals += 1
        for p in self.engine.plan(a):
            key = (p.action.value, p.target.key())
            if key in self.active:
                continue
            rec = ActionRecord(new_id("act-"), a.incident_id, p, a, sim_t)
            self.actions[rec.action_id] = rec
            self.active[key] = rec.action_id
            if p.requires_approval:
                await self._request_approval(rec)
            else:
                await self._dispatch(rec)

    async def _request_approval(self, rec: ActionRecord) -> None:
        rec.state, rec.approval = "awaiting_approval", "pending"
        rec.approval_deadline = time.time() + self.cfg.approval_timeout_s
        cmd = self._command(rec)
        req = ApprovalRequest(action_id=rec.action_id, command=cmd, rationale=rec.planned.rationale,
                              confidence=rec.assessment.global_confidence, deadline_wall=rec.approval_deadline,
                              reply_to=self.agent_id)
        await self.send(T.APPROVAL_REQUESTS, MessageType.APPROVAL_REQUEST, req, priority=Priority.P0,
                        sim_time=self.sim_now, correlation_id=rec.incident_id)

    async def _on_approval(self, d: ApprovalDecision) -> None:
        rec = self.actions.get(d.action_id)
        if rec is None or rec.state != "awaiting_approval":
            return
        rec.approval = f"{'approved' if d.approved else 'rejected'} by {d.operator}"
        if d.approved:
            await self._dispatch(rec)
        else:
            rec.state, rec.outcome = "rejected", "REJECTED"
            self._log(rec, "REJECTED")
            await self._report(rec)

    def _command(self, rec: ActionRecord) -> ContainmentCommand:
        return ContainmentCommand(action_id=rec.action_id, incident_id=rec.incident_id, action=rec.planned.action,
                                  target=rec.planned.target, params={"blast_radius": rec.planned.blast_radius},
                                  reply_to=self.agent_id)

    async def _dispatch(self, rec: ActionRecord) -> None:
        rec.state = "dispatched"
        if rec.planned.action in (ActionType.ALERT_ONLY, ActionType.ESCALATE_HUMAN):
            rec.state, rec.outcome = "evaluated", "LOGGED"
            self._log(rec, "LOGGED")
            await self._report(rec)
            return
        await self.send(T.ENV_ACTIONS, MessageType.CONTAINMENT_COMMAND, self._command(rec), priority=Priority.P0,
                        sim_time=self.sim_now, correlation_id=rec.incident_id)

    async def _dispatch_fallback(self, rec: ActionRecord) -> None:
        fb = PlannedAction(ActionType.INCREASE_MONITORING, rec.planned.target, "low", False,
                           f"fallback after approval timeout of {rec.action_id}", rec.planned.domain)
        key = (fb.action.value, fb.target.key())
        if key in self.active:
            return
        nrec = ActionRecord(new_id("act-"), rec.incident_id, fb, rec.assessment, self.sim_now)
        self.actions[nrec.action_id] = nrec
        self.active[key] = nrec.action_id
        await self._dispatch(nrec)

    async def _on_ack(self, ack: ActionAck) -> None:
        rec = self.actions.get(ack.action_id)
        if rec is None:
            return
        rec.state = "executed" if ack.applied else "failed"
        rec.executed_at = ack.sim_time
        self._log(rec, "EXECUTED" if ack.applied else "FAILED")

    async def _evaluate_due(self, force: bool = False) -> None:
        for rec in self.actions.values():
            if rec.state != "executed" or rec.executed_at is None:
                continue
            if force or self.sim_now >= rec.executed_at + self.cfg.eval_window:
                if rec.planned.action == ActionType.INCREASE_MONITORING:
                    rec.outcome = "LOGGED"
                else:
                    rec.outcome = "MITIGATED" if rec.post_signals == 0 else ("PARTIAL" if rec.post_signals <= 2 else "INEFFECTIVE")
                rec.state = "evaluated"
                self._log(rec, rec.outcome)
                await self._report(rec)

    async def finalize(self) -> None:
        """Evaluate outstanding actions at the end of a run."""
        await self._evaluate_due(force=True)

    # ------------------------------------------------------------- records
    def _log(self, rec: ActionRecord, outcome: str) -> None:
        a = rec.assessment
        rec.history.append(outcome)
        self.audit.log(
            incident_id=rec.incident_id, responsible_agent=",".join(a.contributing_agents) or a.decision_source,
            threat=f"{a.threat_class} [{a.status}]", evidence=a.explanation[:500], confidence=a.global_confidence,
            action=rec.planned.action.value, target=rec.planned.target.key(), approval=rec.approval,
            outcome=outcome, sim_time=self.sim_now, executed_at=rec.executed_at,
            extra={"action_id": rec.action_id, "blast_radius": rec.planned.blast_radius,
                   "decision_source": a.decision_source},
        )

    async def _report(self, rec: ActionRecord) -> None:
        rep = ResponseReport(action_id=rec.action_id, incident_id=rec.incident_id, action=rec.planned.action,
                             target=rec.planned.target, executed_at=rec.executed_at, outcome=rec.outcome,
                             post_action_signal={"related_decisions_after": float(rec.post_signals)})
        await self.send(T.RESPONSE_REPORTS, MessageType.RESPONSE_REPORT, rep, priority=Priority.P1,
                        sim_time=self.sim_now, correlation_id=rec.incident_id)
        if self.audit.records:
            await self.send(T.AUDIT, MessageType.AUDIT, self.audit.records[-1], priority=Priority.P2, sim_time=self.sim_now)

    def history(self) -> list[dict]:
        return [{
            "action_id": r.action_id, "incident_id": r.incident_id, "action": r.planned.action.value,
            "target": r.planned.target.key(), "blast_radius": r.planned.blast_radius, "approval": r.approval,
            "state": r.state, "decided_sim": r.decided_sim, "executed_at": r.executed_at, "outcome": r.outcome,
            "source": r.assessment.decision_source,
        } for r in self.actions.values()]
