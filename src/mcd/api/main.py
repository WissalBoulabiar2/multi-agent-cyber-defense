"""FastAPI service: start/stop simulations, observe the multi-agent system,
approve or reject critical actions (human-in-the-loop).

Run:  uvicorn mcd.api.main:app --port 8000      (requires uvicorn)
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from mcd.api.observer import ObserverAgent
from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.core.enums import MessageType, Priority
from mcd.core.models import ApprovalDecision
from mcd.runtime.system import DefenseSystem, ScenarioCfg, SystemConfig

ROOT = Path(__file__).resolve().parents[3]


class StartRequest(BaseModel):
    strategy: Literal["independent", "cooperative", "centralized"] = "cooperative"
    scenarios: list[str] = Field(default_factory=lambda: ["multi_stage"])
    seed: int = 1
    duration: float = 5400.0
    speedup: float | None = 60.0
    n_sensors: int | None = None
    approval_mode: Literal["auto", "human"] = "human"
    approval_timeout_s: float = 120.0


class DecisionRequest(BaseModel):
    approved: bool
    operator: str = "analyst"
    comment: str | None = None


class SimulationService:
    def __init__(self) -> None:
        self.system: DefenseSystem | None = None
        self.observer: ObserverAgent | None = None
        self.task: asyncio.Task | None = None
        self.result: dict[str, Any] | None = None
        self.error: str | None = None
        self.started_at: float | None = None
        self.request: StartRequest | None = None

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    async def start(self, req: StartRequest) -> None:
        if self.running:
            raise HTTPException(409, "a simulation is already running")
        cfg = SystemConfig(
            strategy=req.strategy, seed=req.seed, duration=req.duration, speedup=req.speedup, n_sensors=req.n_sensors,
            scenarios=[ScenarioCfg(type=s) for s in req.scenarios],
            approver=None if req.approval_mode == "human" else {"approve_prob": 1.0, "latency_s": 0.5},
            response={"approval_timeout_s": req.approval_timeout_s},
            drain_timeout=req.approval_timeout_s + 5 if req.approval_mode == "human" else 10.0,
            output_dir=str(ROOT / "results" / "live" / f"{int(time.time())}_{req.strategy}"),
        )
        self.system = DefenseSystem(cfg)
        self.observer = ObserverAgent(self.system.broker, self.system.env.sensor_topics(), heartbeat_interval=0.5)
        self.system.agents[self.observer.agent_id] = self.observer
        self.result, self.error, self.started_at, self.request = None, None, time.time(), req

        async def _run() -> None:
            try:
                self.result = await self.system.run()
            except Exception as exc:  # surfaced via /simulation/status
                self.error = repr(exc)

        self.task = asyncio.create_task(_run())

    async def stop(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
            if self.system:
                for a in self.system.agents.values():
                    if a.running:
                        await a.stop()

    # --------------------------------------------------------------- views
    def status(self) -> dict[str, Any]:
        sys_ = self.system
        return {
            "running": self.running, "error": self.error, "started_at": self.started_at,
            "request": self.request.model_dump() if self.request else None,
            "sim_time": self.observer.sim_time if self.observer else 0.0,
            "duration": sys_.cfg.duration if sys_ else None, "finished": self.result is not None,
        }

    def agents(self) -> list[dict[str, Any]]:
        if not self.system:
            return []
        now = time.time()
        out = []
        hbs = self.observer.heartbeats if self.observer else {}
        for aid, a in self.system.agents.items():
            if aid == "observer":
                continue
            hb = hbs.get(aid)
            age = now - hb["received"] if hb else None
            health = "UNKNOWN" if hb is None else ("DOWN" if age > 6 else "DEGRADED" if age > 3 else hb["state"])
            if not a.running and self.running:
                health = "DOWN"
            out.append({"agent_id": aid, "domain": str(a.domain), "health": health,
                        "last_heartbeat_age_s": age, "processed": a.metrics.processed, "failed": a.metrics.failed,
                        "queue_depth": hb["queue_depth"] if hb else None})
        return out

    def communications(self) -> dict[str, Any]:
        if not self.system:
            return {"edges": []}
        stats = self.system.broker.stats.snapshot()["by_sender"]
        consumers = self._consumers()
        edges: dict[tuple[str, str], list[int]] = {}
        for sender, topics in stats.items():
            for topic, (n, size) in topics.items():
                if topic in (T.HEARTBEAT, T.AUDIT, T.SIM_CLOCK) or topic.startswith("dlq."):
                    continue
                for dst in consumers(topic):
                    e = edges.setdefault((sender, dst), [0, 0, topic])
                    e[0] += n
                    e[1] += size
        return {"edges": [{"source": s, "target": d, "messages": v[0], "bytes": v[1], "topic": v[2]} for (s, d), v in edges.items()]}

    def _consumers(self):
        agents = list(self.system.agents) if self.system else []

        def f(topic: str) -> list[str]:
            if topic.startswith("agent.") and topic.endswith(".inbox"):
                return [topic[len("agent."):-len(".inbox")]]
            if topic.startswith("alerts.p"):
                return [a for a in agents if a.startswith("intel")]
            if topic in (T.ALERTS_DIRECT, T.ASSESSMENTS):
                return [a for a in agents if a.startswith("response")]
            if topic == T.ENV_ACTIONS:
                return ["env"]
            if topic == T.APPROVAL_REQUESTS:
                return ["operator"]
            if topic == T.RESPONSE_REPORTS:
                return [a for a in agents if a.startswith("intel")] or ["observer"]
            if topic.startswith("sim."):
                prefix = topic.split(".")[1]
                shard = topic.rsplit(".", 1)[-1]
                own = f"{prefix}-{shard}"
                return [own] if own in agents else [a for a in agents if a.startswith("central")]
            return []

        return f


service = SimulationService()
app = FastAPI(title="Multi-Agent Cyber Defense API", version="0.1.0",
              description="Research prototype. All events, attacks and responses are simulated.")


def _obs() -> ObserverAgent:
    if service.observer is None:
        raise HTTPException(404, "no simulation has been started")
    return service.observer


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "simulation_running": service.running}


@app.post("/simulation/start")
async def start(req: StartRequest) -> dict:
    await service.start(req)
    return service.status()


@app.post("/simulation/stop")
async def stop() -> dict:
    await service.stop()
    return service.status()


@app.get("/simulation/status")
async def status() -> dict:
    return service.status()


@app.get("/agents")
async def agents() -> list[dict]:
    return service.agents()


@app.get("/events/recent")
async def events(limit: int = 100) -> list[dict]:
    return list(_obs().events)[-limit:]


@app.get("/alerts")
async def alerts(limit: int = 200) -> list[dict]:
    return list(_obs().alerts)[-limit:]


@app.get("/assessments")
async def assessments(limit: int = 200) -> list[dict]:
    return list(_obs().assessments)[-limit:]


@app.get("/incidents")
async def incidents() -> list[dict]:
    latest: dict[str, dict] = {}
    for a in _obs().assessments:
        latest[a["incident_id"]] = a
    return sorted(latest.values(), key=lambda a: -a["global_confidence"])


@app.get("/actions")
async def actions() -> list[dict]:
    if service.system is None or service.system.response is None:
        return []
    return service.system.response.history()


@app.get("/approvals")
async def approvals(pending_only: bool = False) -> list[dict]:
    items = list(_obs().approvals.values())
    return [a for a in items if a["status"] == "PENDING"] if pending_only else items


@app.post("/approvals/{action_id}")
async def decide(action_id: str, body: DecisionRequest) -> dict:
    obs = _obs()
    req = obs.approvals.get(action_id)
    if req is None:
        raise HTTPException(404, "unknown action")
    if req["status"] != "PENDING":
        raise HTTPException(409, f"action already {req['status']}")
    dec = ApprovalDecision(action_id=action_id, approved=body.approved, operator=body.operator, comment=body.comment)
    env = Envelope.build(MessageType.APPROVAL_DECISION, f"human:{body.operator}", T.inbox(req["reply_to"]), dec,
                         recipient=req["reply_to"], priority=Priority.P0)
    await service.system.broker.publish(T.inbox(req["reply_to"]), env)
    req["status"] = "APPROVED" if body.approved else "REJECTED"
    return req


@app.get("/audit")
async def audit(limit: int = 200) -> list[dict]:
    return list(_obs().audit)[-limit:]


@app.get("/communications")
async def communications() -> dict:
    return service.communications()


@app.get("/metrics")
async def metrics() -> dict:
    obs = service.observer
    live = {
        "events_seen": obs.counts.get("OBSERVATION", 0) if obs else 0,
        "alerts_seen": obs.counts.get("LOCAL_ALERT", 0) if obs else 0,
        "assessments_seen": obs.counts.get("THREAT_ASSESSMENT", 0) if obs else 0,
        "severity_distribution": {str(k): v for k, v in sorted(obs.severity.items())} if obs else {},
    }
    final = service.result["metrics"] if service.result else None
    return {"live": live, "final": final}


@app.get("/experiments")
async def experiments() -> list[dict]:
    out = []
    for summary in sorted((ROOT / "results").glob("e*/summary.csv")):
        out.append({"suite": summary.parent.name, "summary_csv": str(summary.relative_to(ROOT)),
                    "report": str((summary.parent / "report.md").relative_to(ROOT))})
    return out


@app.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            payload = {"status": service.status(), "agents": service.agents(), "metrics": await metrics()}
            await websocket.send_text(json.dumps(payload, default=str))
            await asyncio.sleep(1.0)
    except (WebSocketDisconnect, RuntimeError):
        return
