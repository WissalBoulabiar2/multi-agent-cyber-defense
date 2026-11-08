"""Windowed local detection pipeline shared by sensor agents and the centralized baseline.

observations -> per-(window, entity) buckets -> features -> hybrid anomaly score
+ rule hits -> fused local confidence -> WindowScore (with explanation).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

from mcd.core.enums import Domain, Severity
from mcd.core.inventory import AssetInventory
from mcd.core.models import EntityRef, Observation
from mcd.detection.anomaly_detector import AnomalyResult, HybridAnomalyDetector
from mcd.detection.features import EXTRACTORS
from mcd.detection.rule_engine import RuleEngine, RuleHit
from mcd.detection.threat_scoring import classify, explain, fuse_local, local_status, rules_confidence, severity_from


@dataclass
class WindowScore:
    domain: Domain
    entity: EntityRef
    related: list[EntityRef]
    window_start: float
    window_end: float
    features: dict[str, float]
    anomaly: AnomalyResult
    hits: list[RuleHit]
    rule_confidence: float
    confidence: float
    alert_type: str
    tactic: str | None
    severity: Severity
    status: str
    explanation: str
    event_ids: list[str] = field(default_factory=list)


@dataclass
class PipelineConfig:
    window: float = 60.0
    alpha: float = 0.6               # weight of anomaly score in local confidence
    flag_threshold: float = 0.4      # windows above this do not update baselines
    components: tuple[str, ...] = ("iforest", "lof", "stat")
    use_rules: bool = True
    calib_q: float = 0.9
    seed: int = 0


class DomainPipeline:
    def __init__(self, domain: Domain, inventory: AssetInventory, rules: RuleEngine | None = None,
                 cfg: PipelineConfig | None = None) -> None:
        self.domain = Domain(domain)
        self.cfg = cfg or PipelineConfig()
        self.inv = inventory
        self.extractor = EXTRACTORS[self.domain](inventory)
        self.rules = rules if rules is not None else RuleEngine.from_yaml(domain=str(self.domain))
        if not self.cfg.use_rules:
            self.rules = RuleEngine([])
        self.detector = HybridAnomalyDetector(
            self.extractor.feature_names, components=self.cfg.components, calib_q=self.cfg.calib_q, seed=self.cfg.seed
        )
        self.buffers: dict[int, dict[EntityRef, list[Observation]]] = defaultdict(lambda: defaultdict(list))
        self.closed_upto = -1  # last closed bucket index
        self.late_events = 0
        self.n_train_rows = 0

    # ---------------------------------------------------------------- train
    def _bucket(self, t: float) -> int:
        return int(t // self.cfg.window)

    def train(self, events: list[Observation]) -> None:
        """First half: baseline learning. Second half: online feature rows -> model fit."""
        events = sorted((e for e in events if e.domain == self.domain), key=lambda e: e.sim_time)
        if not events:
            self.detector.fit(np.zeros((0, len(self.extractor.feature_names))))
            return
        t_mid = events[0].sim_time + (events[-1].sim_time - events[0].sim_time) / 2
        first = [e for e in events if e.sim_time < t_mid]
        second = [e for e in events if e.sim_time >= t_mid]
        self.extractor.fit_baseline(first)
        buckets: dict[int, dict[EntityRef, list[Observation]]] = defaultdict(lambda: defaultdict(list))
        for e in second:
            buckets[self._bucket(e.sim_time)][self.extractor.entity_of(e)].append(e)
        rows = []
        for b in sorted(buckets):
            t_end = (b + 1) * self.cfg.window
            for ent, evs in buckets[b].items():
                feats, _ = self.extractor.extract(ent, evs, t_end)
                rows.append(self.extractor.vector(feats))
                self.extractor.update(ent, evs, flagged=False)
        self.n_train_rows = len(rows)
        self.detector.fit(np.array(rows, dtype=float).reshape(-1, len(self.extractor.feature_names)))
        # streaming state starts fresh after training (time restarts at 0 in the test stream)
        if hasattr(self.extractor, "recent"):
            self.extractor.recent.clear()

    # ------------------------------------------------------------ streaming
    def add(self, obs: Observation) -> bool:
        b = self._bucket(obs.sim_time)
        if b <= self.closed_upto:
            self.late_events += 1
            return False
        self.buffers[b][self.extractor.entity_of(obs)].append(obs)
        return True

    def close_until(self, t: float) -> list[WindowScore]:
        """Close every window whose end <= t and score its entities."""
        last = int(t // self.cfg.window) - 1
        out: list[WindowScore] = []
        for b in sorted(k for k in list(self.buffers) if k <= last):
            out.extend(self._score_bucket(b, self.buffers.pop(b)))
        self.closed_upto = max(self.closed_upto, last)
        return out

    def _score_bucket(self, b: int, groups: dict[EntityRef, list[Observation]]) -> list[WindowScore]:
        w0, w1 = b * self.cfg.window, (b + 1) * self.cfg.window
        ents = list(groups)
        feats_rel = [self.extractor.extract(e, groups[e], w1) for e in ents]
        X = np.array([self.extractor.vector(f) for f, _ in feats_rel], dtype=float)
        anomalies = self.detector.score_batch(X, [e.key() for e in ents])
        out = []
        for i, ent in enumerate(ents):
            feats, related = feats_rel[i]
            an = anomalies[i]
            hits = self.rules.evaluate(feats)
            r = rules_confidence(hits)
            conf = fuse_local(an.score, r, self.cfg.alpha)
            atype, tactic = classify(self.domain, hits)
            hosts = [x.id for x in [ent, *related] if x.kind == "host"]
            crit = max([self.inv.criticality(h) for h in hosts] + [1])
            sev = severity_from(conf, crit)
            out.append(WindowScore(
                domain=self.domain, entity=ent, related=related, window_start=w0, window_end=w1,
                features=feats, anomaly=an, hits=hits, rule_confidence=r, confidence=conf,
                alert_type=atype, tactic=tactic, severity=sev, status=local_status(an.score, hits),
                explanation=explain(self.domain, ent.key(), hits, an.top_features, an.score, conf),
                event_ids=[o.event_id for o in groups[ent][:20]],
            ))
            flagged = conf >= self.cfg.flag_threshold
            self.extractor.update(ent, groups[ent], flagged)
            if not flagged:
                self.detector.update_entity(ent.key(), X[i])
        return out
