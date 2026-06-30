#!/usr/bin/env python3
"""Run the decoys and the dashboard in one process.

    python run.py                 # everything
    python run.py --decoys-only   # just the traps (headless sensor)
    python run.py --dash-only     # just the dashboard (read existing db)
"""
from __future__ import annotations

import argparse
import asyncio
import logging

import uvicorn

from mirage import PROJECT_NAME, __version__
from mirage.config import settings
from mirage.server import serve_forever
from mirage.storage import Storage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mirage")

BANNER = rf"""
   __  __ _
  |  \/  (_)_ __ __ _ __ _ ___    {PROJECT_NAME} v{__version__}
  | |\/| | | '__/ _` / _` / -_)   OT/ICS deception sensor
  |_|  |_|_|_|  \__,_\__, \___|
                     |___/        decoys: modbus:{settings.modbus_port}  s7:{settings.s7_port}  dash:{settings.dashboard_port}
"""


async def _run(decoys: bool, dash: bool) -> None:
    storage = Storage(settings.db_path)
    tasks = []
    if decoys:
        tasks.append(asyncio.create_task(serve_forever(storage)))
    if dash:
        config = uvicorn.Config(
            "dashboard.app:app",
            host=settings.dashboard_host,
            port=settings.dashboard_port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        tasks.append(asyncio.create_task(server.serve()))
        log.info("dashboard on http://%s:%d", settings.dashboard_host, settings.dashboard_port)
    if not tasks:
        return
    await asyncio.gather(*tasks)


def main() -> None:
    ap = argparse.ArgumentParser(description=f"{PROJECT_NAME} OT/ICS honeynet")
    ap.add_argument("--decoys-only", action="store_true")
    ap.add_argument("--dash-only", action="store_true")
    args = ap.parse_args()

    decoys = not args.dash_only
    dash = not args.decoys_only
    print(BANNER)
    try:
        asyncio.run(_run(decoys, dash))
    except KeyboardInterrupt:
        log.info("shutting down")


if __name__ == "__main__":
    main()
