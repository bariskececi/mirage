"""Turn a source IP into map coordinates.

Online: queries a free geolocation endpoint (cached per-IP).
Offline / private IPs / lookup failure: a deterministic pseudo-location so the
map is never empty during demos. Fallback coords are clearly flagged isp="(unresolved)".
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import urllib.request
from typing import Any

from .config import settings

_cache: dict[str, dict[str, Any]] = {}
_lock = asyncio.Lock()


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _deterministic(ip: str) -> dict[str, Any]:
    """Hash an IP into a stable point on land-ish latitudes."""
    h = hashlib.sha256(ip.encode()).digest()
    lat = (h[0] / 255.0) * 120.0 - 60.0      # -60..60
    lon = (h[1] / 255.0) * 360.0 - 180.0     # -180..180
    return {
        "country": "Unknown",
        "country_code": "ZZ",
        "lat": round(lat, 4),
        "lon": round(lon, 4),
        "isp": "(unresolved)",
    }


def _lookup_sync(ip: str) -> dict[str, Any]:
    url = settings.geoip_endpoint.format(ip=ip)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "mirage-honeynet"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
            }
    except Exception:
        pass
    return _deterministic(ip)


async def enrich(ip: str) -> dict[str, Any]:
    if ip in _cache:
        return _cache[ip]
    async with _lock:
        if ip in _cache:  # double-checked after awaiting the lock
            return _cache[ip]
        if not settings.geoip_enabled or _is_private(ip):
            result = _deterministic(ip)
        else:
            result = await asyncio.to_thread(_lookup_sync, ip)
        _cache[ip] = result
        return result
