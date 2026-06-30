#!/usr/bin/env python3
"""Generate realistic-looking traffic against the local decoys, so you can fill
the map for a screenshot or screen-recording without exposing anything to the
internet. Speaks raw Modbus + S7 just like a scanner would.

    python scripts/attacker_sim.py            # steady trickle, forever
    python scripts/attacker_sim.py --burst 50 # 50 quick hits then exit
"""
from __future__ import annotations

import argparse
import random
import socket
import struct
import time

MODBUS = ("127.0.0.1", 502)
S7 = ("127.0.0.1", 102)


def modbus_frame(tid, pdu):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def hit_modbus():
    tid = random.randint(1, 0xFFFF)
    choice = random.random()
    if choice < 0.45:                       # read holding registers
        pdu = struct.pack(">BHH", 0x03, random.randint(0, 12), random.randint(1, 10))
    elif choice < 0.65:                     # read device identification
        pdu = struct.pack(">BBB", 0x2B, 0x0E, 0x01)
    elif choice < 0.85:                     # read coils
        pdu = struct.pack(">BHH", 0x01, 0, 8)
    else:                                   # write single register (the spicy one)
        pdu = struct.pack(">BHH", 0x06, random.choice([2, 3, 12]), random.randint(0, 1))
    try:
        s = socket.create_connection(MODBUS, timeout=2)
        s.sendall(modbus_frame(tid, pdu))
        s.recv(512)
        s.close()
    except OSError:
        pass


def hit_s7():
    # COTP connection request, then S7 setup communication.
    cr = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
    setup = bytes.fromhex("0300001902f08032010000000000080000f0000001000101e0")
    try:
        s = socket.create_connection(S7, timeout=2)
        s.sendall(cr); s.recv(256)
        s.sendall(setup); s.recv(256)
        s.close()
    except OSError:
        pass


def one_hit():
    (hit_modbus if random.random() < 0.7 else hit_s7)()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--burst", type=int, default=0, help="send N hits then exit")
    ap.add_argument("--rate", type=float, default=1.5, help="avg seconds between hits")
    args = ap.parse_args()

    if args.burst:
        for i in range(args.burst):
            one_hit()
            time.sleep(random.uniform(0.05, 0.25))
        print(f"sent {args.burst} hits")
        return

    print("trickling traffic at the decoys — Ctrl-C to stop")
    while True:
        one_hit()
        time.sleep(random.expovariate(1 / args.rate))


if __name__ == "__main__":
    main()
