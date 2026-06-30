"""Durable storage for interactions. Plain SQLite, no external service."""
from __future__ import annotations

import asyncio
import json
import sqlite3
from contextlib import closing
from typing import Any

from .events import Interaction

_SCHEMA = """
CREATE TABLE IF NOT EXISTS interactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL    NOT NULL,
    protocol     TEXT    NOT NULL,
    src_ip       TEXT    NOT NULL,
    src_port     INTEGER NOT NULL,
    dst_port     INTEGER NOT NULL,
    session_id   TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    detail       TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    raw_hex      TEXT    NOT NULL,
    country      TEXT,
    country_code TEXT,
    lat          REAL,
    lon          REAL,
    isp          TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts ON interactions(ts);
CREATE INDEX IF NOT EXISTS idx_ip ON interactions(src_ip);
CREATE INDEX IF NOT EXISTS idx_proto ON interactions(protocol);
"""


class Storage:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        with closing(sqlite3.connect(self._path)) as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        return conn

    async def save(self, ev: Interaction) -> None:
        async with self._lock:
            await asyncio.to_thread(self._save_sync, ev)

    def _save_sync(self, ev: Interaction) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """INSERT INTO interactions
                   (ts, protocol, src_ip, src_port, dst_port, session_id, action,
                    detail, severity, raw_hex, country, country_code, lat, lon, isp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ev.ts, ev.protocol, ev.src_ip, ev.src_port, ev.dst_port,
                 ev.session_id, ev.action, ev.detail, ev.severity, ev.raw_hex,
                 ev.country, ev.country_code, ev.lat, ev.lon, ev.isp),
            )
            conn.commit()

    async def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._recent_sync, limit)

    def _recent_sync(self, limit: int) -> list[dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM interactions ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows][::-1]

    async def stats(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._stats_sync)

    def _stats_sync(self) -> dict[str, Any]:
        with closing(self._connect()) as conn:
            total = conn.execute("SELECT COUNT(*) c FROM interactions").fetchone()["c"]
            uniq = conn.execute("SELECT COUNT(DISTINCT src_ip) c FROM interactions").fetchone()["c"]
            writes = conn.execute(
                "SELECT COUNT(*) c FROM interactions WHERE severity='high'"
            ).fetchone()["c"]
            by_country = conn.execute(
                """SELECT country_code, COUNT(*) c FROM interactions
                   WHERE country_code IS NOT NULL
                   GROUP BY country_code ORDER BY c DESC LIMIT 10"""
            ).fetchall()
            by_proto = conn.execute(
                "SELECT protocol, COUNT(*) c FROM interactions GROUP BY protocol ORDER BY c DESC"
            ).fetchall()
            top_ips = conn.execute(
                """SELECT src_ip, country_code, COUNT(*) c FROM interactions
                   GROUP BY src_ip ORDER BY c DESC LIMIT 10"""
            ).fetchall()
            return {
                "total": total,
                "unique_ips": uniq,
                "write_attempts": writes,
                "by_country": [dict(r) for r in by_country],
                "by_protocol": [dict(r) for r in by_proto],
                "top_sources": [dict(r) for r in top_ips],
            }
