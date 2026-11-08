"""Cooperative decision-making: entity-centric correlation and global threat fusion.

Used by the Intelligence & Coordination agent (cooperative strategy) and by the
centralized baseline (same math, different information flow).

Global confidence for an incident (see docs/ARCHITECTURE.md §5.3):
  1. dedup: keep max confidence per (domain, alert_type, primary entity)
  2. decay: c_i(t) = c_i * 2^(-(t - t_i)/half_life)
  3. reliability weights w_d per domain
  4. noisy-OR: S = 1 - prod(1 - w_d c_i)
  5. kill-chain coherence: k = longest time-ordered strictly increasing stage chain,
     S' = 1 - (1 - S) * gamma^(k-1)
Decision: CORROBORATED if S' >= tau_confirm and either (>=2 domains AND (k >= 2
or a rule >= strong_rule)) or a high-fidelity rule; CONFIRMED if additionally
S' >= tau_high and k >= 3; SUSPICIOUS if S' >= tau_suspect; ANOMALY otherwise.
Two domains seeing the same single-step event (e.g. a legitimate admin session)
are not treated as independent corroboration.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mcd.core.enums import STATUS_RANK, AssessmentStatus, Domain, Severity
from mcd.core.ids import new_id
from mcd.core.inventory import AssetInventory
from mcd.core.models import EntityRef, TargetRef, ThreatAssessment
from mcd.detection.threat_scoring import TACTIC_STAGE, severity_from, threat_class_for


@dataclass
class FusionConfig:
    half_life: float = 900.0
    gamma: float = 0.7
    tau_suspect: float = 0.45
    tau_confirm: float = 0.75
    tau_high: float = 0.9
    high_fidelity: float = 0.95
    corr_window: float = 1800.0
    eps: float = 0.05
    target_min: float = 0.55
    context_min: float = 0.25
    hub_degree: int = 4
    max_related_links: int = 3
    hub_roles: tuple[str, ...] = ("dc", "fs", "mail", "web", "app", "db", "backup")
    min_stages: int = 2          # multi-domain corroboration also needs a >=2-stage chain ...
    strong_rule: float = 0.7     # ... or at least one strong rule
    max_queries_per_incident: int = 8
    voi: bool = True
    voi_answer_cap: float = 0.6
    advisories: bool = True
    advisory_delta: float = -0.15
    advisory_ttl: float = 900.0
    domain_weights: dict[str, float] = field(
        default_factory=lambda: {"network": 0.85, "auth": 0.9, "config": 0.95}
    )

    def weight(self, domain: Domain | str) -> float:
        return self.domain_weights.get(str(domain), 0.8)


@dataclass
class CorrelatedAlert:
    alert_id: str
    domain: Domain
    agent_id: str
    alert_type: str
    tactic: str | None
    primary: EntityRef
    entities: list[EntityRef]
    confidence: float
    rule_confidence: float
    t: float
    source: str = "alert"  # alert | context | local


@dataclass
class Incident:
    incident_id: str
    alerts: dict[str, CorrelatedAlert] = field(default_factory=dict)
    entities: set[EntityRef] = field(default_factory=set)
    first_seen: float = 0.0
    last_updated: float = 0.0
    published_rank: int = -1
    published_sev: int = -1
    published_targets: set[str] = field(default_factory=set)
    queried: set[tuple[str, str]] = field(default_factory=set)
    advised: set[tuple[str, str]] = field(default_factory=set)
    n_queries: int = 0


@dataclass
class FusionResult:
    score: float
    s_prime: float
    coherent_stages: int
    domains: list[Domain]
    tactics: list[str]
    max_rule: float
    status: AssessmentStatus
    severity: Severity
    threat_class: str
    targets: list[TargetRef]

    @property
    def actionable(self) -> bool:
        return STATUS_RANK[self.status] >= STATUS_RANK[AssessmentStatus.CORROBORATED]


def longest_stage_chain(items: list[tuple[float, int]]) -> int:
    """Length of the longest strictly increasing (by stage) subsequence in time order."""
    seq = [s for _, s in sorted(items)]
    best: list[int] = []
    for i, s in enumerate(seq):
        best.append(1 + max([best[j] for j in range(i) if seq[j] < s], default=0))
    return max(best, default=0)


class Correlator:
    def __init__(self, cfg: FusionConfig, inventory: AssetInventory) -> None:
        self.cfg = cfg
        self.inv = inventory
        self.incidents: dict[str, Incident] = {}
        self._index: dict[EntityRef, str] = {}
        self._referrers: dict[EntityRef, set[str]] = {}

    # ------------------------------------------------------------- linking
    def is_hub(self, e: EntityRef) -> bool:
        """Shared-service hosts (CMDB role) or entities referenced by many unrelated alerts."""
        if e.kind == "host":
            info = self.inv.hosts.get(e.id)
            if info is not None and info.role in self.cfg.hub_roles:
                return True
        return len(self._referrers.get(e, ())) >= self.cfg.hub_degree

    def _link_entities(self, ca: CorrelatedAlert) -> list[EntityRef]:
        related = []
        for e in ca.entities[1:]:
            self._referrers.setdefault(e, set()).add(ca.primary.key())
            if not self.is_hub(e):  # hubs (domain controller, file server...) never merge incidents
                related.append(e)
        # sweep-like alerts (many destinations) only link through their primary entity
        if len(related) > self.cfg.max_related_links:
            related = []
        return [ca.primary, *related]

    def _merge(self, keep: Incident, other: Incident) -> None:
        keep.alerts.update(other.alerts)
        keep.entities |= other.entities
        keep.first_seen = min(keep.first_seen, other.first_seen)
        keep.last_updated = max(keep.last_updated, other.last_updated)
        keep.published_rank = max(keep.published_rank, other.published_rank)
        keep.published_sev = max(keep.published_sev, other.published_sev)
        keep.published_targets |= other.published_targets
        keep.queried |= other.queried
        keep.advised |= other.advised
        keep.n_queries += other.n_queries
        for e, iid in list(self._index.items()):
            if iid == other.incident_id:
                self._index[e] = keep.incident_id
        self.incidents.pop(other.incident_id, None)

    def add(self, ca: CorrelatedAlert) -> Incident:
        links = self._link_entities(ca)
        found: list[Incident] = []
        for e in links:
            iid = self._index.get(e)
            inc = self.incidents.get(iid) if iid else None
            if inc is not None and ca.t - inc.last_updated <= self.cfg.corr_window and inc not in found:
                found.append(inc)
        if found:
            found.sort(key=lambda i: i.first_seen)
            inc = found[0]
            for other in found[1:]:
                self._merge(inc, other)
        else:
            inc = Incident(incident_id=new_id("inc-"), first_seen=ca.t, last_updated=ca.t)
            self.incidents[inc.incident_id] = inc
        self._attach(inc, ca, links)
        return inc

    def add_to(self, incident_id: str, ca: CorrelatedAlert) -> Incident | None:
        inc = self.incidents.get(incident_id)
        if inc is None:
            return None
        self._attach(inc, ca, [ca.primary])
        return inc

    def _attach(self, inc: Incident, ca: CorrelatedAlert, links: list[EntityRef]) -> None:
        inc.alerts[ca.alert_id] = ca
        inc.entities.update(ca.entities)
        inc.last_updated = max(inc.last_updated, ca.t)
        for e in links:
            self._index[e] = inc.incident_id

    def expire(self, now: float) -> int:
        dead = [i for i, inc in self.incidents.items() if now - inc.last_updated > self.cfg.corr_window * 2]
        for iid in dead:
            self.incidents.pop(iid)
        if dead:
            self._index = {e: i for e, i in self._index.items() if i in self.incidents}
        return len(dead)

    # ------------------------------------------------------------- scoring
    def evaluate(self, inc: Incident, now: float) -> FusionResult:
        c = self.cfg
        best: dict[tuple, tuple[float, CorrelatedAlert]] = {}
        for a in inc.alerts.values():
            decayed = a.confidence * 2.0 ** (-max(0.0, now - a.t) / c.half_life)
            key = (str(a.domain), a.alert_type, a.primary.key())
            if key not in best or decayed > best[key][0]:
                best[key] = (decayed, a)
        prod = 1.0
        domains: set[Domain] = set()
        stage_items: list[tuple[float, int]] = []
        tactics: list[str] = []
        max_rule = 0.0
        targets: dict[str, TargetRef] = {}
        entity_domains: dict[EntityRef, set[str]] = {}
        for decayed, a in best.values():
            if decayed >= c.eps:
                entity_domains.setdefault(a.primary, set()).add(str(a.domain))
        for decayed, a in best.values():
            prod *= 1.0 - c.weight(a.domain) * decayed
            if decayed >= c.eps:
                domains.add(Domain(a.domain))
            if a.tactic in TACTIC_STAGE and decayed >= c.eps:
                stage_items.append((a.t, TACTIC_STAGE[a.tactic]))
                if a.tactic not in tactics:
                    tactics.append(a.tactic)
            max_rule = max(max_rule, a.rule_confidence)
            # Targets: entities individually implicated strongly, or seen by >= 2 domains.
            # Context answers corroborate but never designate targets by themselves
            # (avoids e.g. isolating a domain controller that merely appears in many logins).
            strong = decayed >= c.target_min or len(entity_domains.get(a.primary, ())) >= 2
            if a.source != "context" and strong and not self.is_hub(a.primary):
                targets.setdefault(f"{a.primary.key()}|{a.domain}", TargetRef(entity=a.primary, domain=a.domain))
        s = 1.0 - prod
        k = longest_stage_chain(stage_items)
        s_prime = 1.0 - (1.0 - s) * (c.gamma ** max(k - 1, 0))
        diverse = len(domains) >= 2 and (k >= c.min_stages or max_rule >= c.strong_rule)
        if s_prime >= c.tau_confirm and (diverse or max_rule >= c.high_fidelity):
            status = AssessmentStatus.CONFIRMED if (s_prime >= c.tau_high and k >= 3) else AssessmentStatus.CORROBORATED
        elif s_prime >= c.tau_suspect:
            status = AssessmentStatus.SUSPICIOUS
        else:
            status = AssessmentStatus.ANOMALY
        hosts = [e.id for e in inc.entities if e.kind == "host"]
        crit = max([self.inv.criticality(h) for h in hosts] + [1])
        return FusionResult(
            score=s, s_prime=s_prime, coherent_stages=k, domains=sorted(domains), tactics=tactics,
            max_rule=max_rule, status=status, severity=severity_from(s_prime, crit),
            threat_class=threat_class_for(tactics), targets=list(targets.values()),
        )

    # ---------------------------------------------------------- publishing
    def should_publish(self, inc: Incident, res: FusionResult) -> bool:
        rank = STATUS_RANK[res.status]
        if rank < STATUS_RANK[AssessmentStatus.SUSPICIOUS]:
            return False
        if rank > inc.published_rank:
            return True
        if res.actionable:
            new_targets = {t.entity.key() for t in res.targets} - inc.published_targets
            return bool(new_targets) or int(res.severity) > inc.published_sev
        return False

    def mark_published(self, inc: Incident, res: FusionResult) -> None:
        inc.published_rank = max(inc.published_rank, STATUS_RANK[res.status])
        inc.published_sev = max(inc.published_sev, int(res.severity))
        if res.actionable:
            inc.published_targets |= {t.entity.key() for t in res.targets}

    def to_assessment(self, inc: Incident, res: FusionResult, source: str, now: float) -> ThreatAssessment:
        alerts = sorted(inc.alerts.values(), key=lambda a: a.t)
        expl = (f"S={res.score:.2f}, S'={res.s_prime:.2f} over {len(res.domains)} domain(s) "
                f"{[str(d) for d in res.domains]}, kill-chain stages={res.coherent_stages}, "
                f"max rule conf={res.max_rule:.2f}; evidence: "
                + "; ".join(f"{a.agent_id}:{a.alert_type}@{a.primary.id}({a.confidence:.2f},{a.source})" for a in alerts[-8:]))
        return ThreatAssessment(
            incident_id=inc.incident_id, status=res.status, actionable=res.actionable, decision_source=source,
            threat_class=res.threat_class, global_confidence=round(res.s_prime, 4), severity=res.severity,
            entities=sorted(inc.entities, key=lambda e: e.key())[:50], targets=res.targets,
            contributing_alerts=[a.alert_id for a in alerts], contributing_agents=sorted({a.agent_id for a in alerts}),
            domains=res.domains, tactics_observed=res.tactics, explanation=expl,
            first_seen=inc.first_seen, last_updated=now,
        )

    def voi_worth_querying(self, s_prime: float, domain: Domain | str) -> bool:
        """Query only if a strong answer (confidence = ``voi_answer_cap``) from ``domain``
        could lift the incident to tau_confirm. With ``voi=False`` every incident is
        queried (ablation baseline)."""
        if not self.cfg.voi:
            return True
        gain = self.cfg.weight(domain) * self.cfg.voi_answer_cap
        return 1.0 - (1.0 - s_prime) * (1.0 - gain) >= self.cfg.tau_confirm
