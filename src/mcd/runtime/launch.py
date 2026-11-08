"""Process launcher: one agent (or the environment) per OS process over Redis.

Used by docker-compose. Examples:

    python -m mcd.runtime.launch --role env       --config configs/system.yaml
    python -m mcd.runtime.launch --role sensor --domain network --shard 0
    python -m mcd.runtime.launch --role intel
    python -m mcd.runtime.launch --role response
    python -m mcd.runtime.launch --role local     # everything in one process, in-memory broker

Every process builds the same public configuration (topology, shard map) from
the shared YAML; agents still exchange information only through Redis Streams.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
from pathlib import Path

import yaml

from mcd.agents.intelligence_agent import IntelConfig, ThreatIntelligenceAgent
from mcd.agents.response_agent import ResponseAgent
from mcd.baseline.centralized_detector import CentralizedDetector
from mcd.communication.conditions import ConditionedBroker
from mcd.communication.transports import create_broker
from mcd.core.enums import CoordinationMode, Domain
from mcd.response.approval import AutoApprover
from mcd.response.audit_logger import AuditLogger
from mcd.runtime.system import SENSOR_CLASSES, DefenseSystem, SystemConfig
from mcd.simulation.attack_base import AttackParams
from mcd.simulation.environment import EnvConfig, Environment, ScenarioSpec
from mcd.simulation.topology import build_topology
from mcd.simulation.training import benign_history

log = logging.getLogger("mcd.launch")


def load_config(path: str | None) -> SystemConfig:
    data = yaml.safe_load(Path(path).read_text()) if path else {}
    return SystemConfig.model_validate(data or {})


async def _serve(agent) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # Windows
            pass
    await agent.start()
    log.warning("%s running", agent.agent_id)
    await stop.wait()
    await agent.stop()


async def main_async(args) -> None:
    cfg = load_config(args.config)
    if args.role == "local":
        cfg = cfg.model_copy(update={"broker": "memory"})
        result = await DefenseSystem(cfg).run()
        print(json.dumps(result["metrics"]["detection"], indent=1, default=str))
        return
    url = args.redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    broker = ConditionedBroker(create_broker("redis", url), cfg.conditions)
    await broker.connect()
    shards = cfg.resolved_shards()
    topo = build_topology(cfg.topology, seed=cfg.topology_seed)
    inv = topo.inventory
    kw = {"heartbeat_interval": cfg.heartbeat_interval}
    mode = CoordinationMode(cfg.strategy)
    if args.role == "env":
        scen = [ScenarioSpec(s.type, AttackParams(**s.params), s.count, s.spacing) for s in cfg.scenarios]
        env = Environment(EnvConfig(seed=cfg.seed, topology_seed=cfg.topology_seed, duration=cfg.duration,
                                    step=cfg.step, speedup=cfg.speedup or 60.0, lockstep=False, shards=shards,
                                    channel=cfg.channel, topology=cfg.topology, normal=cfg.normal), scen, broker, topo)
        await asyncio.sleep(args.start_delay)
        gt = await env.run()
        out = Path(args.output or "results/live")
        out.mkdir(parents=True, exist_ok=True)
        gt.save(out / "ground_truth.json")
        return
    if args.role == "sensor":
        d = Domain(args.domain)
        n = shards[str(d)]
        scfg = cfg.sensor.__class__(**{**cfg.sensor.__dict__, "mode": mode})
        train = lambda: benign_history(cfg.train_seed, cfg.train_duration, cfg.topology, cfg.topology_seed, d, args.shard, n)
        agent = SENSOR_CLASSES[d](args.shard, broker, inv, train, scfg, **kw)
    elif args.role == "intel":
        agent = ThreatIntelligenceAgent(broker, inv, IntelConfig(fusion=cfg.fusion, shards=shards), **kw)
    elif args.role == "central":
        agent = CentralizedDetector(broker, inv, shards, lambda: benign_history(
            cfg.train_seed, cfg.train_duration, cfg.topology, cfg.topology_seed), cfg.fusion, cfg.sensor.pipeline, **kw)
    elif args.role == "response":
        audit = AuditLogger(Path(args.output or "results/live") / "audit.jsonl")
        agent = ResponseAgent(broker, inv, mode, cfg.response, audit, **kw)
    elif args.role == "approver":
        agent = AutoApprover(broker, cfg.approver, **kw)
    else:
        raise SystemExit(f"unknown role {args.role}")
    await _serve(agent)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True, choices=["env", "sensor", "intel", "central", "response", "approver", "local"])
    ap.add_argument("--domain", choices=["network", "auth", "config"])
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--config", default=os.environ.get("MCD_CONFIG"))
    ap.add_argument("--redis-url")
    ap.add_argument("--output")
    ap.add_argument("--start-delay", type=float, default=float(os.environ.get("START_DELAY", "20")))
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
