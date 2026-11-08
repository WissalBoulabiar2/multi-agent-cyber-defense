"""Response policy: assessment -> planned containment actions with blast radius.

Mapping (by implicated entity and the domain whose evidence implicated it):
* user (any domain)            -> SUSPEND_ACCOUNT
* host implicated by network   -> ISOLATE_HOST  (the host is the *source* of suspicious traffic)
* host implicated by config    -> REVERT_CONFIG
Targets are only primary entities of real alerts (never context answers).
* non-actionable but >= MEDIUM -> INCREASE_MONITORING
Blast radius: high for isolating criticality >= 2 hosts and suspending
privileged accounts -> requires human approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcd.core.enums import ActionType, Domain, Severity
from mcd.core.inventory import AssetInventory
from mcd.core.models import EntityRef, ThreatAssessment

BLAST_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class ResponseConfig:
    approval_for_high: bool = True
    approval_timeout_s: float = 20.0      # wall seconds
    eval_window: float = 900.0            # sim seconds after execution
    max_targets: int = 6
    monitoring_min_severity: Severity = Severity.MEDIUM
    enabled_actions: set[str] = field(default_factory=lambda: {a.value for a in ActionType})


@dataclass
class PlannedAction:
    action: ActionType
    target: EntityRef
    blast_radius: str
    requires_approval: bool
    rationale: str
    domain: str = ""


class ResponseEngine:
    def __init__(self, inventory: AssetInventory, cfg: ResponseConfig | None = None) -> None:
        self.inv = inventory
        self.cfg = cfg or ResponseConfig()

    def blast_radius(self, action: ActionType, target: EntityRef) -> str:
        if action == ActionType.ISOLATE_HOST:
            return "high" if self.inv.criticality(target.id) >= 2 else "medium"
        if action == ActionType.SUSPEND_ACCOUNT:
            return "high" if self.inv.is_privileged(target.id) else "medium"
        if action == ActionType.REVERT_CONFIG:
            return "medium"
        return "low"

    def _make(self, action: ActionType, target: EntityRef, why: str, domain: str = "") -> PlannedAction:
        br = self.blast_radius(action, target)
        return PlannedAction(action, target, br, self.cfg.approval_for_high and br == "high", why, domain)

    def plan(self, a: ThreatAssessment) -> list[PlannedAction]:
        out: list[PlannedAction] = []
        if not a.actionable:
            if a.severity >= self.cfg.monitoring_min_severity:
                for t in a.targets[:3]:
                    out.append(self._make(ActionType.INCREASE_MONITORING, t.entity,
                                          f"{a.status} {a.threat_class} (conf {a.global_confidence:.2f})", str(t.domain)))
            return self._filter(out)
        why = f"{a.status} {a.threat_class} conf={a.global_confidence:.2f} via {a.decision_source}"
        seen: set[tuple[str, str]] = set()
        for t in a.targets:
            e, d = t.entity, Domain(t.domain)
            if e.kind == "user":
                act = ActionType.SUSPEND_ACCOUNT
            elif e.kind == "host" and d == Domain.CONFIG:
                act = ActionType.REVERT_CONFIG
            elif e.kind == "host":
                act = ActionType.ISOLATE_HOST
            else:
                continue
            key = (act.value, e.key())
            if key in seen:
                continue
            seen.add(key)
            out.append(self._make(act, e, why, str(d)))
            if len(out) >= self.cfg.max_targets:
                break
        if not out:
            out.append(self._make(ActionType.ESCALATE_HUMAN, a.entities[0] if a.entities else EntityRef.host("unknown"), why))
        return self._filter(out)

    def _filter(self, actions: list[PlannedAction]) -> list[PlannedAction]:
        return [p for p in actions if p.action.value in self.cfg.enabled_actions]
