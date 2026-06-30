#!/usr/bin/env python3
"""Seed the database with a realistic spread of synthetic interactions so the
map and stats look alive for a screenshot or recording.

This writes *fabricated* events for presentation only — it does not represent
real attacks. Use it on a fresh demo database, never on a production sensor.

    python scripts/seed_demo.py --count 600
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mirage.config import settings
from mirage.storage import Storage
from mirage.events import Interaction

# A spread of source regions with plausible coordinates and ISPs.
SOURCES = [
    ("CN", "China", 39.9, 116.4, "China Telecom"),
    ("RU", "Russia", 55.7, 37.6, "Rostelecom"),
    ("US", "United States", 38.0, -97.0, "DigitalOcean"),
    ("BR", "Brazil", -15.8, -47.9, "Claro NXT"),
    ("IN", "India", 28.6, 77.2, "Reliance Jio"),
    ("IR", "Iran", 35.7, 51.4, "Mobin Net"),
    ("NL", "Netherlands", 52.4, 4.9, "Leaseweb"),
    ("DE", "Germany", 50.1, 8.7, "Hetzner"),
    ("VN", "Vietnam", 21.0, 105.8, "Viettel"),
    ("KP", "North Korea", 39.0, 125.7, "Star JV"),
    ("UA", "Ukraine", 50.4, 30.5, "Kyivstar"),
    ("FR", "France", 48.9, 2.3, "OVH"),
    ("TR", "Türkiye", 41.0, 28.9, "Turk Telekom"),
    ("ID", "Indonesia", -6.2, 106.8, "Telkom"),
    ("RO", "Romania", 44.4, 26.1, "RCS & RDS"),
]

ACTIONS = [
    ("modbus", "connect", "TCP connection opened to modbus:502", "notice", 502),
    ("modbus", "read_holding_registers", "polled 10 regs from address 0", "info", 502),
    ("modbus", "read_coils", "polled 8 coils from address 0", "info", 502),
    ("modbus", "read_device_identification",
     "fingerprinted device as Schneider Electric Modicon M340", "notice", 502),
    ("modbus", "write_single_register",
     "ATTEMPTED WRITE: register 2 -> 0 (rejected, value unchanged)", "high", 502),
    ("modbus", "write_multiple_registers",
     "ATTEMPTED WRITE: 4 registers from 10 (rejected, value unchanged)", "high", 502),
    ("s7comm", "s7_connect", "COTP connection request (ISO-on-TCP setup)", "notice", 102),
    ("s7comm", "s7_setup", "S7 setup communication negotiated", "notice", 102),
    ("s7comm", "s7_szl_read",
     "identification query -> answered as 6ES7 214-1AG40-0XB0", "notice", 102),
    ("s7comm", "s7_write_var",
     "ATTEMPTED WRITE to data block (rejected, value unchanged)", "high", 102),
]
WEIGHTS = [10, 22, 8, 9, 4, 2, 7, 6, 5, 2]


def rand_ip(seed_octet: int) -> str:
    return f"{seed_octet}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=500)
    ap.add_argument("--hours", type=float, default=24.0, help="spread events over the last N hours")
    args = ap.parse_args()

    storage = Storage(settings.db_path)
    now = time.time()
    # A handful of recurring "noisy" hosts per region, plus one-offs.
    host_pool = {cc: [rand_ip(i + 11) for _ in range(random.randint(2, 5))]
                 for i, (cc, *_rest) in enumerate(SOURCES)}

    import asyncio

    async def run():
        for _ in range(args.count):
            cc, country, lat, lon, isp = random.choice(SOURCES)
            ip = random.choice(host_pool[cc]) if random.random() < 0.7 else rand_ip(random.randint(20, 200))
            proto, action, detail, sev, dport = random.choices(ACTIONS, weights=WEIGHTS, k=1)[0]
            ev = Interaction(
                ts=now - random.uniform(0, args.hours * 3600),
                protocol=proto, src_ip=ip, src_port=random.randint(1024, 65000),
                dst_port=dport, session_id=f"{ip}:seed",
                action=action, detail=detail, severity=sev, raw_hex="",
                country=country, country_code=cc,
                lat=lat + random.uniform(-2.5, 2.5), lon=lon + random.uniform(-2.5, 2.5),
                isp=isp,
            )
            await storage.save(ev)

    asyncio.run(run())
    print(f"seeded {args.count} demo events into {settings.db_path}")


if __name__ == "__main__":
    main()
