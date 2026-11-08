"""Human-in-the-loop plumbing.

Real operators approve/reject through the API (POST /approvals/{id}), which
publishes an ApprovalDecision to the Response agent's inbox. For unattended
experiments ``AutoApprover`` stands in for the operator with a configurable
approval probability and latency — results produced with it are reported as such.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass

from mcd.agents.base_agent import BaseAgent, Subscription
from mcd.communication import topics as T
from mcd.communication.message import Envelope
from mcd.core.enums import Domain, MessageType, Priority
from mcd.core.models import ApprovalDecision, ApprovalRequest


@dataclass
class AutoApproverConfig:
    approve_prob: float = 1.0
    latency_s: float = 0.2
    seed: int = 0


class AutoApprover(BaseAgent):
    domain = Domain.HUMAN

    def __init__(self, broker, cfg: AutoApproverConfig | None = None, agent_id: str = "operator-stub", **kw) -> None:
        super().__init__(agent_id, broker, **kw)
        self.cfg = cfg or AutoApproverConfig()
        self._rng = random.Random(self.cfg.seed)
        self.decisions = 0

    def subscriptions(self) -> list[Subscription]:
        return [Subscription(T.APPROVAL_REQUESTS, priority=0)]

    async def handle(self, env: Envelope) -> None:
        req = env.parse(ApprovalRequest)

        async def decide() -> None:
            await asyncio.sleep(self.cfg.latency_s)
            ok = self._rng.random() < self.cfg.approve_prob
            dec = ApprovalDecision(action_id=req.action_id, approved=ok, operator=self.agent_id,
                                   comment="auto-approver (simulated operator)")
            self.decisions += 1
            await self.send(T.inbox(req.reply_to), MessageType.APPROVAL_DECISION, dec, recipient=req.reply_to,
                            priority=Priority.P0, sim_time=env.sim_time)

        asyncio.create_task(decide())
