"""Local threat scoring: fusion, severity, classification, status, explanation."""

from __future__ import annotations

from mcd.core.enums import Domain, Severity
from mcd.detection.rule_engine import RuleHit

# kill-chain stage index used by the coordinator's coherence bonus
TACTIC_STAGE = {
    "credential_access": 0,
    "discovery": 1,
    "lateral_movement": 2,
    "privilege_escalation": 3,
    "persistence": 3,
    "defense_evasion": 3,
}

TACTIC_CLASS = {
    "credential_access": "CREDENTIAL_COMPROMISE",
    "discovery": "LATERAL_MOVEMENT",
    "lateral_movement": "LATERAL_MOVEMENT",
    "privilege_escalation": "CONFIG_TAMPERING",
    "persistence": "CONFIG_TAMPERING",
    "defense_evasion": "CONFIG_TAMPERING",
}


def noisy_or(values) -> float:
    p = 1.0
    for v in values:
        p *= 1.0 - max(0.0, min(1.0, float(v)))
    return 1.0 - p


def rules_confidence(hits: list[RuleHit]) -> float:
    return noisy_or(h.confidence for h in hits)


def fuse_local(anomaly: float, rule_conf: float, alpha: float = 0.6) -> float:
    """c = 1 - (1 - alpha*a)(1 - r). A pure anomaly can reach at most alpha."""
    return 1.0 - (1.0 - alpha * anomaly) * (1.0 - rule_conf)


def severity_from(confidence: float, criticality: int) -> Severity:
    if confidence < 0.3:
        level = Severity.INFO
    elif confidence < 0.5:
        level = Severity.LOW
    elif confidence < 0.7:
        level = Severity.MEDIUM
    elif confidence < 0.85:
        level = Severity.HIGH
    else:
        level = Severity.CRITICAL
    if criticality >= 3 and confidence >= 0.5:
        level = Severity(min(int(Severity.CRITICAL), int(level) + 1))
    elif criticality <= 1 and level > Severity.INFO and confidence < 0.85:
        level = Severity(level - 1)
    return Severity(level)


def local_status(anomaly: float, hits: list[RuleHit], high: float = 0.9) -> str:
    """Sensors may only claim ANOMALY (statistical) or SUSPICIOUS (rule / extreme anomaly)."""
    return "SUSPICIOUS" if hits or anomaly >= high else "ANOMALY"


def classify(domain: Domain | str, hits: list[RuleHit]) -> tuple[str, str | None]:
    if hits:
        best = max(hits, key=lambda h: h.confidence)
        return best.alert_type, best.tactic
    return f"{str(domain).upper()}.UNCLASSIFIED_ANOMALY", None


def threat_class_for(tactics: list[str]) -> str:
    classes = {TACTIC_CLASS[t] for t in tactics if t in TACTIC_CLASS}
    if len(classes) >= 2:
        return "MULTI_STAGE"
    return classes.pop() if classes else "UNKNOWN"


def explain(domain: Domain | str, entity: str, hits: list[RuleHit], top_features, anomaly: float, confidence: float) -> str:
    parts = [f"[{domain}] {entity}: confidence {confidence:.2f}"]
    if hits:
        parts.append("rules " + "; ".join(f"{h.rule_id} ({h.description})" for h in hits))
    if anomaly > 0:
        feats = ", ".join(f"{n}={v:.2f} (z={z:+.1f})" for n, v, z in top_features)
        parts.append(f"anomaly {anomaly:.2f}" + (f" driven by {feats}" if feats else ""))
    return " | ".join(parts)
