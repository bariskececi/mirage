"""Shared machinery for every decoy: accept a connection, hand each request to
the subclass, log + enrich + publish whatever the attacker did."""
from __future__ import annotations

import asyncio
import time

from ..config import settings
from ..events import Interaction, bus, new_session_id
from ..geoip import enrich
from ..storage import Storage


class BaseDecoy:
    protocol = "base"
    default_port = 0

    def __init__(self, storage: Storage, port: int) -> None:
        self.storage = storage
        self.port = port

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = peer[0], peer[1]
        session = new_session_id(src_ip, src_port)
        await self.emit(src_ip, src_port, session, "connect",
                        f"TCP connection opened to {self.protocol}:{self.port}",
                        "notice", b"")
        try:
            await self.converse(reader, writer, src_ip, src_port, session)
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def converse(self, reader, writer, src_ip, src_port, session) -> None:
        raise NotImplementedError

    async def emit(self, src_ip: str, src_port: int, session: str,
                   action: str, detail: str, severity: str, raw: bytes) -> None:
        geo = await enrich(src_ip)
        ev = Interaction(
            ts=time.time(),
            protocol=self.protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=self.port,
            session_id=session,
            action=action,
            detail=detail,
            severity=severity,
            raw_hex=raw[:256].hex(),
            country=geo.get("country"),
            country_code=geo.get("country_code"),
            lat=geo.get("lat"),
            lon=geo.get("lon"),
            isp=geo.get("isp"),
        )
        await self.storage.save(ev)
        await bus.publish(ev)
