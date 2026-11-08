from mcd.communication.transports.memory import InMemoryBroker

__all__ = ["InMemoryBroker", "create_broker"]


def create_broker(kind: str = "memory", url: str | None = None, maxlen: int | None = None):
    """Factory: ``memory`` (no external dependency) or ``redis`` (requires redis-py)."""
    if kind == "memory":
        return InMemoryBroker(maxlen=maxlen)
    if kind == "redis":
        from mcd.communication.transports.redis_streams import RedisStreamsBroker

        return RedisStreamsBroker(url or "redis://localhost:6379/0", maxlen=maxlen)
    raise ValueError(f"unknown broker kind: {kind}")
