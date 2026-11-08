"""Read-only observer for the API/dashboard.

It consumes broker streams through its *own* consumer groups (so it never
steals messages from agents) and keeps bounded in-memory views. It is a
monitoring plane component: it never publishes to defensive topics and its
data is never used for detection decisions.
"""

from __future__ import annotations

import time
from collections import Counter, deque

from mcd.agents.base_agent import BaseAgent, Subscription
from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.core.enums import Domain, MessageType


class ObserverAgent(BaseAgent):
    domain = Domain.OBSERVER

    def __init__(self, broker, sim_topics: list[str], agent_id: str = "observer", **kw) -> None:
        super().__init__(agent_id, broker, group="observer", **kw)
        self.sim_topics = sim_topics
        self.events: deque[dict] = deque(maxlen=400)
        self.alerts: deque[dict] = deque(maxlen=500)
        self.assessments: deque[dict] = deque(maxlen=300)
        self.reports: deque[dict] = deque(maxlen=300)
        self.audit: deque[dict] = deque(maxlen=500)
        self.approvals: dict[str, dict] = {}
        self.heartbeats: dict[str, dict] = {}
        self.severity = Counter()
        self.counts = Counter()
        self.sim_time = 0.0

    def subscriptions(self) -> list[Subscription]:
        topics = [T.HEARTBEAT, *T.ALERT_LANES, T.ALERTS_DIRECT, T.ASSESSMENTS, T.RESPONSE_REPORTS,
                  T.APPROVAL_REQUESTS, T.AUDIT, T.SIM_CLOCK, *self.sim_topics]
        return [Subscription(t, priority=0 if t == T.APPROVAL_REQUESTS else 1) for t in topics]

    async def _heartbeat(self) -> None:  # the observer is not part of the defensive system
        return None

    async def handle(self, env: Envelope) -> None:
        t, p = env.type, env.payload
        self.counts[str(t)] += 1
        if t == MessageType.OBSERVATION:
            self.events.append({"sim_time": p["sim_time"], "domain": p["domain"], **{k: p["attrs"].get(k) for k in
                                ("src", "dst", "dst_port", "status", "user", "src_host", "dst_host", "result", "host", "key", "actor", "ticket")
                                if k in p["attrs"]}})
        elif t == MessageType.WATERMARK:
            self.sim_time = max(self.sim_time, p["t"])
        elif t == MessageType.HEARTBEAT:
            self.heartbeats[p["agent_id"]] = {**p, "received": time.time()}
        elif t == MessageType.LOCAL_ALERT:
            self.severity[int(p["severity"])] += 1
            self.alerts.append({"topic": env.topic, "sim_time": env.sim_time, **{k: p[k] for k in (
                "alert_id", "agent_id", "domain", "alert_type", "tactic", "confidence", "anomaly_score",
                "rule_confidence", "status", "severity", "count")}, "entity": p["entities"][0]["id"],
                "explanation": p["evidence"]["summary"]})
        elif t == MessageType.THREAT_ASSESSMENT:
            self.assessments.append({"sim_time": env.sim_time, "sender": env.sender, **p})
        elif t == MessageType.RESPONSE_REPORT:
            self.reports.append({"sim_time": env.sim_time, **p})
            if p["action_id"] in self.approvals and p["outcome"] in ("REJECTED", "TIMED_OUT"):
                self.approvals[p["action_id"]]["status"] = p["outcome"]
        elif t == MessageType.APPROVAL_REQUEST:
            self.approvals[p["action_id"]] = {**p, "status": "PENDING", "sim_time": env.sim_time}
        elif t == MessageType.AUDIT:
            self.audit.append(p)
            aid = (p.get("extra") or {}).get("action_id")
            if aid in self.approvals and self.approvals[aid]["status"] == "PENDING" and p.get("response_outcome") == "EXECUTED":
                self.approvals[aid]["status"] = "EXECUTED"
