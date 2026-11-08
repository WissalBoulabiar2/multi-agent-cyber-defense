"""Declarative rule engine (rules in configs/rules.yaml).

Rule format::

    - id: AUTH-002
      domain: auth
      alert_type: AUTH.SUCCESS_AFTER_FAILURES
      tactic: credential_access
      confidence: 0.7
      description: "..."
      all: [[success_after_fail, ">=", 1]]     # every condition must hold
      any: [[novel_src, ">=", 1], [privileged, "==", 1]]   # optional: at least one
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le, "==": operator.eq, "!=": operator.ne}
DEFAULT_RULES = Path(__file__).resolve().parents[3] / "configs" / "rules.yaml"


@dataclass
class Rule:
    id: str
    domain: str
    alert_type: str
    confidence: float
    tactic: str | None = None
    description: str = ""
    all: list[tuple[str, str, float]] = field(default_factory=list)
    any: list[tuple[str, str, float]] = field(default_factory=list)

    def __post_init__(self) -> None:
        for feat, op, _ in self.all + self.any:
            if op not in _OPS:
                raise ValueError(f"rule {self.id}: unsupported operator {op!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"rule {self.id}: confidence must be in [0,1]")

    def matches(self, feats: dict[str, float]) -> bool:
        def ok(c):
            f, op, v = c
            return f in feats and _OPS[op](feats[f], v)

        if self.all and not all(ok(c) for c in self.all):
            return False
        if self.any and not any(ok(c) for c in self.any):
            return False
        return bool(self.all or self.any)


@dataclass
class RuleHit:
    rule_id: str
    alert_type: str
    tactic: str | None
    confidence: float
    description: str


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def from_yaml(cls, path: str | Path | None = None, domain: str | None = None) -> "RuleEngine":
        data = yaml.safe_load(Path(path or DEFAULT_RULES).read_text())
        rules = [Rule(**{**r, "all": [tuple(c) for c in r.get("all", [])], "any": [tuple(c) for c in r.get("any", [])]})
                 for r in data["rules"]]
        if domain is not None:
            rules = [r for r in rules if r.domain == domain]
        return cls(rules)

    def evaluate(self, feats: dict[str, float]) -> list[RuleHit]:
        return [RuleHit(r.id, r.alert_type, r.tactic, r.confidence, r.description) for r in self.rules if r.matches(feats)]
