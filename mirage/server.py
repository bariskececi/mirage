"""Launches every configured decoy listener on one asyncio loop."""
from __future__ import annotations

import asyncio
import importlib
import logging

from .config import settings
from .storage import Storage

log = logging.getLogger("mirage")


def _resolve(path: str):
    module_path, _, cls_name = path.partition(":")
    module = importlib.import_module(module_path)
    return getattr(module, cls_name)


async def run_decoys(storage: Storage) -> list[asyncio.AbstractServer]:
    servers: list[asyncio.AbstractServer] = []
    for lc in settings.build_listeners():
        decoy_cls = _resolve(lc.handler)
        decoy = decoy_cls(storage, lc.port)
        try:
            server = await asyncio.start_server(decoy.handle, lc.host, lc.port)
        except PermissionError:
            log.error("No permission to bind %s:%d (ports <1024 need privilege). "
                      "Set MIRAGE_%s_PORT or run with CAP_NET_BIND_SERVICE.",
                      lc.host, lc.port, lc.name.upper())
            continue
        except OSError as e:
            log.error("Could not bind %s:%d (%s)", lc.host, lc.port, e)
            continue
        servers.append(server)
        log.info("decoy '%s' listening on %s:%d", lc.name, lc.host, lc.port)
    return servers


async def serve_forever(storage: Storage) -> None:
    servers = await run_decoys(storage)
    if not servers:
        log.warning("No decoys started.")
        return
    await asyncio.gather(*(s.serve_forever() for s in servers))
