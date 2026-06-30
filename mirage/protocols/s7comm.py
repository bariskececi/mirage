"""Siemens S7comm decoy (port 102).

Speaks the ISO-on-TCP stack a real S7 PLC uses:
  TPKT (RFC1006) -> COTP (ISO 8073) -> S7 PDU

Handled:
  - COTP Connection Request  -> Connection Confirm
  - S7 Setup Communication   -> Setup ack with believable PDU sizes
  - S7 userdata SZL read      -> module / component identification (the order
                                 number that makes scanners label it a Siemens)
  - Any read/write job        -> acknowledged, logged; nothing is ever applied
"""
from __future__ import annotations

import asyncio
import struct

from ..personas import load_persona
from .base import BaseDecoy

_PERSONA = load_persona()


def _tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def _cotp_cc(src_ref: int, dst_ref: int) -> bytes:
    # Connection Confirm: len, 0xD0, dst-ref, src-ref, class/option, params.
    params = bytes([0xC0, 0x01, 0x0A,         # tpdu size 1024
                    0xC1, 0x02, 0x01, 0x00,   # src tsap
                    0xC2, 0x02, 0x01, 0x02])  # dst tsap
    body = struct.pack(">BHHB", 0xD0, dst_ref, src_ref, 0x00) + params
    return bytes([len(body)]) + body


def _cotp_dt(s7: bytes) -> bytes:
    # COTP data header: len(2), pdu-type 0xF0, eot 0x80.
    return bytes([0x02, 0xF0, 0x80]) + s7


class S7Decoy(BaseDecoy):
    protocol = "s7comm"
    default_port = 102

    async def converse(self, reader, writer, src_ip, src_port, session) -> None:
        while True:
            head = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            if head[0] != 0x03:
                break
            total = struct.unpack(">H", head[2:4])[0]
            body = await asyncio.wait_for(reader.readexactly(max(0, total - 4)), timeout=30)
            raw = head + body
            resp = self._dispatch(body, raw, src_ip, src_port, session)
            if resp is None:
                # log + best-effort keepalive handled inside dispatch
                continue
            writer.write(resp)
            await writer.drain()

    def _dispatch(self, body, raw, src_ip, src_port, session):
        if not body:
            return None
        cotp_type = body[1] if len(body) > 1 else 0
        # COTP Connection Request -> Confirm
        if cotp_type == 0xE0:
            dst_ref, src_ref = 0x0001, struct.unpack(">H", body[4:6])[0] if len(body) >= 6 else 0
            self._log_sync(src_ip, src_port, session, "s7_connect",
                           "COTP connection request (ISO-on-TCP setup)", "notice", raw)
            return _tpkt(_cotp_cc(src_ref or 0x0001, dst_ref))
        # COTP Data -> inspect S7 PDU
        if cotp_type == 0xF0:
            return self._s7(body[3:], raw, src_ip, src_port, session)
        self._log_sync(src_ip, src_port, session, "s7_unknown_cotp",
                       f"unhandled COTP type 0x{cotp_type:02x}", "info", raw)
        return None

    def _s7(self, s7, raw, src_ip, src_port, session):
        if len(s7) < 10 or s7[0] != 0x32:
            return None
        rosctr = s7[1]
        pdu_ref = s7[4:6]
        param_len = struct.unpack(">H", s7[6:8])[0]
        params = s7[10:10 + param_len]
        func = params[0] if params else 0

        if func == 0xF0:  # Setup communication
            self._log_sync(src_ip, src_port, session, "s7_setup",
                           "S7 setup communication negotiated", "notice", raw)
            ack_params = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x01E0)
            return self._s7_ack(pdu_ref, ack_params, b"")

        if rosctr == 0x07:  # userdata (SZL reads = identification queries)
            self._log_sync(src_ip, src_port, session, "s7_szl_read",
                           f"identification query -> answered as {_PERSONA.s7_module}",
                           "notice", raw)
            return self._s7_szl(pdu_ref)

        if func in (0x04, 0x05):  # read/write var
            action = "s7_read_var" if func == 0x04 else "s7_write_var"
            sev = "info" if func == 0x04 else "high"
            detail = ("read request to data block" if func == 0x04
                      else "ATTEMPTED WRITE to data block (rejected, value unchanged)")
            self._log_sync(src_ip, src_port, session, action, detail, sev, raw)
            ack_params = struct.pack(">BB", func, 0x01)
            return self._s7_ack(pdu_ref, ack_params, struct.pack(">B", 0xFF))

        self._log_sync(src_ip, src_port, session, "s7_job",
                       f"S7 job function 0x{func:02x}", "info", raw)
        return self._s7_ack(pdu_ref, struct.pack(">B", func), b"")

    def _s7_ack(self, pdu_ref, params, data):
        # ROSCTR 0x03 = ack_data, plus 2 error bytes (0,0 = no error).
        s7 = struct.pack(">BBHH", 0x32, 0x03, 0x0000, struct.unpack(">H", pdu_ref)[0])
        s7 += struct.pack(">HH", len(params), len(data))
        s7 += b"\x00\x00" + params + data
        return _tpkt(_cotp_dt(s7))

    def _s7_szl(self, pdu_ref):
        # Component identification: order number / module name strings.
        order = _PERSONA.s7_module.encode().ljust(20, b"\x00")[:20]
        serial = _PERSONA.s7_serial.encode().ljust(32, b"\x00")[:32]
        szl_data = struct.pack(">HHH", 0x001C, 0x0000, 0x0001) + order + serial
        params = struct.pack(">BBBB", 0x00, 0x01, 0x12, 0x08)
        return self._s7_ack(pdu_ref, params, szl_data)

    def _log_sync(self, src_ip, src_port, session, action, detail, severity, raw):
        # converse() runs in the loop; schedule the async emit without awaiting.
        asyncio.create_task(
            self.emit(src_ip, src_port, session, action, detail, severity, raw)
        )
