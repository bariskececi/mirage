"""Event model + a tiny async pub/sub bus shared by decoys and the dashboard."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, asdict, field
from typing import Any


@dataclass
class Interaction:
    """A single thing an attacker did against a decoy service."""
    ts: float
    protocol: str           # modbus | s7comm
    src_ip: str
    src_port: int
    dst_port: int
    session_id: str
    action: str             # e.g. "read_holding_registers", "connect", "write_single_register"
    detail: str             # human-readable summary
    severity: str           # info | notice | high
    raw_hex: str            # captured bytes, truncated
    # Enriched later:
    country: str | None = None
    country_code: str | None = None
    lat: float | None = None
    lon: float | None = None
    isp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventBus:
    """Fan-out async bus. Decoys publish; dashboard websockets subscribe."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def publish(self, event: Interaction) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Slow consumer: drop oldest, keep the stream live.
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass


# One bus per process.
bus = EventBus()


def new_session_id(ip: str, port: int) -> str:
    return f"{ip}:{port}:{int(time.time()*1000) & 0xffffff:x}"
