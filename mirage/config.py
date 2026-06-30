"""Runtime configuration. Override anything via environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


# The deployment identity. Rename here once and it propagates everywhere.
PROJECT_NAME = "Mirage"

# Which fake plant the decoy pretends to be. See mirage/personas/.
PERSONA = os.getenv("MIRAGE_PERSONA", "water_treatment")


@dataclass
class ListenerConfig:
    name: str
    host: str
    port: int
    handler: str  # dotted path resolved in server.py


@dataclass
class Settings:
    # Where the decoy services bind. 0.0.0.0 to face the internet.
    bind_host: str = os.getenv("MIRAGE_BIND", "0.0.0.0")

    # Industrial protocol decoys. Standard ports make the trap look real.
    modbus_port: int = int(os.getenv("MIRAGE_MODBUS_PORT", "502"))
    s7_port: int = int(os.getenv("MIRAGE_S7_PORT", "102"))
    enable_modbus: bool = _env_bool("MIRAGE_MODBUS", True)
    enable_s7: bool = _env_bool("MIRAGE_S7", True)

    # Dashboard / API.
    dashboard_host: str = os.getenv("MIRAGE_DASH_HOST", "0.0.0.0")
    dashboard_port: int = int(os.getenv("MIRAGE_DASH_PORT", "3000"))

    # Storage.
    db_path: str = os.getenv("MIRAGE_DB", "mirage.db")

    # GeoIP enrichment. Disabled offline -> deterministic fallback coords.
    geoip_enabled: bool = _env_bool("MIRAGE_GEOIP", True)
    geoip_endpoint: str = os.getenv(
        "MIRAGE_GEOIP_URL", "http://ip-api.com/json/{ip}?fields=status,country,countryCode,lat,lon,isp"
    )

    # Safety rail: refuse to ever forward, proxy, or execute attacker input.
    # The decoy only ever *responds with synthetic data*. Hard-coded on.
    interaction_mode: str = "low"  # low | medium ; never "high"

    listeners: list[ListenerConfig] = field(default_factory=list)

    def build_listeners(self) -> list[ListenerConfig]:
        out: list[ListenerConfig] = []
        if self.enable_modbus:
            out.append(ListenerConfig("modbus", self.bind_host, self.modbus_port,
                                      "mirage.protocols.modbus:ModbusDecoy"))
        if self.enable_s7:
            out.append(ListenerConfig("s7comm", self.bind_host, self.s7_port,
                                      "mirage.protocols.s7comm:S7Decoy"))
        self.listeners = out
        return out


settings = Settings()
