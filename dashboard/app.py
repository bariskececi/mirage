"""Dashboard: REST stats/history, a live WebSocket feed, and the map UI."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from mirage.config import PROJECT_NAME, settings
from mirage.events import bus
from mirage.personas import load_persona
from mirage.storage import Storage

_STATIC = Path(__file__).parent / "static"
_persona = load_persona()

app = FastAPI(title=f"{PROJECT_NAME} Dashboard")
storage = Storage(settings.db_path)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/api/meta")
async def meta() -> JSONResponse:
    return JSONResponse({
        "project": PROJECT_NAME,
        "persona": _persona.name,
        "process": [
            {"name": rp.name, "unit": rp.unit, "addr": rp.addr, "writable": rp.writable}
            for rp in _persona.holding_registers
        ],
    })


@app.get("/api/stats")
async def stats() -> JSONResponse:
    return JSONResponse(await storage.stats())


@app.get("/api/recent")
async def recent(limit: int = 200) -> JSONResponse:
    return JSONResponse(await storage.recent(limit))


@app.get("/api/process")
async def process() -> JSONResponse:
    """Live snapshot of the decoy plant's process values (what attackers poll)."""
    return JSONResponse([
        {"name": rp.name, "unit": rp.unit, "addr": rp.addr,
         "value": _persona.register_value(rp.addr), "writable": rp.writable}
        for rp in _persona.holding_registers
    ])


@app.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    await websocket.accept()
    q = bus.subscribe()
    try:
        # Replay recent history so a fresh tab isn't empty.
        for row in await storage.recent(80):
            await websocket.send_text(json.dumps({"type": "interaction", "data": row}))
        while True:
            ev = await q.get()
            await websocket.send_text(json.dumps({"type": "interaction", "data": ev.to_dict()}))
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        bus.unsubscribe(q)


app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
