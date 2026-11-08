import asyncio
import os

import pytest


def run(coro):
    """Run a coroutine in a fresh event loop (no pytest-asyncio dependency)."""
    return asyncio.run(coro)


@pytest.fixture
def arun():
    return run


def redis_url() -> str | None:
    return os.environ.get("REDIS_URL")
