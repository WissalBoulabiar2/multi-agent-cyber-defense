"""Message envelope: the only thing that crosses agent boundaries."""

from __future__ import annotations

import time
from typing import Any, TypeVar

from pydantic import BaseModel, Field

from mcd.core.enums import MessageType, Priority, Severity
from mcd.core.ids import new_id
from mcd.core.models import PAYLOAD_MODELS

T = TypeVar("T", bound=BaseModel)

SCHEMA_VERSION = "1.0"


class Envelope(BaseModel):
    message_id: str = Field(default_factory=new_id)
    correlation_id: str | None = None
    causation_id: str | None = None
    schema_version: str = SCHEMA_VERSION
    type: MessageType
    sender: str
    recipient: str | None = None
    topic: str
    priority: Priority = Priority.P1
    severity: Severity | None = None
    sim_time: float = 0.0
    created_at: float = Field(default_factory=time.time)
    expires_at: float | None = None
    hop_count: int = 0
    payload: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------ build
    @classmethod
    def build(
        cls,
        type: MessageType,
        sender: str,
        topic: str,
        payload: BaseModel | dict[str, Any],
        *,
        ttl_s: float | None = None,
        **kwargs: Any,
    ) -> "Envelope":
        data = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else dict(payload)
        env = cls(type=type, sender=sender, topic=topic, payload=data, **kwargs)
        if ttl_s is not None:
            env.expires_at = env.created_at + ttl_s
        return env

    # ------------------------------------------------------------ (de)serial
    def to_bytes(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes | str) -> "Envelope":
        return cls.model_validate_json(data)

    # ---------------------------------------------------------------- access
    def parse(self, model: type[T]) -> T:
        return model.model_validate(self.payload)

    def typed(self) -> BaseModel:
        model = PAYLOAD_MODELS.get(self.type)
        if model is None:
            raise ValueError(f"no payload model registered for {self.type}")
        return model.model_validate(self.payload)

    def expired(self, now: float | None = None) -> bool:
        return self.expires_at is not None and (now or time.time()) > self.expires_at
