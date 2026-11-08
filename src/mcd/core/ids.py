"""Time-sortable unique identifiers (ULID-like, hex encoded)."""

from __future__ import annotations

import itertools
import os
import time

_counter = itertools.count()


def new_id(prefix: str = "") -> str:
    """48-bit ms timestamp + 16-bit process counter + 32 random bits."""
    ts = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    cnt = next(_counter) & 0xFFFF
    rnd = int.from_bytes(os.urandom(4), "big")
    return f"{prefix}{ts:012x}{cnt:04x}{rnd:08x}"
