"""Append-only, SHA-256 hash-chained audit log (tamper-evident JSONL)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(prev: str, body: dict[str, Any]) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        self._prev = GENESIS
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("")

    def log(self, *, incident_id: str, responsible_agent: str, threat: str, evidence: str, confidence: float,
            action: str, target: str, approval: str, outcome: str, sim_time: float | None,
            executed_at: float | None = None, extra: dict | None = None) -> dict[str, Any]:
        body = {
            "seq": len(self.records),
            "wall_time": time.time(),
            "sim_time": sim_time,
            "incident_id": incident_id,
            "detected_threat": threat,
            "responsible_agent": responsible_agent,
            "evidence": evidence,
            "threat_confidence": round(float(confidence), 4),
            "selected_response": action,
            "target": target,
            "approval": approval,
            "execution_time": executed_at,
            "response_outcome": outcome,
            "extra": extra or {},
            "prev_hash": self._prev,
        }
        body["hash"] = _digest(self._prev, body)
        self._prev = body["hash"]
        self.records.append(body)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, default=str) + "\n")
        return body

    @staticmethod
    def verify(records: list[dict[str, Any]]) -> tuple[bool, int | None]:
        """Return (ok, index of first broken record)."""
        prev = GENESIS
        for i, rec in enumerate(records):
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("prev_hash") != prev or _digest(prev, body) != rec.get("hash"):
                return False, i
            prev = rec["hash"]
        return True, None

    @staticmethod
    def load(path: str | Path) -> list[dict[str, Any]]:
        return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
