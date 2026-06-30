"""Modbus TCP decoy (port 502).

Implements enough of the spec to satisfy real reconnaissance tools:
  - MBAP header framing
  - FC 0x01/0x02/0x03/0x04 reads -> live persona values
  - FC 0x05/0x06/0x0F/0x10 writes -> acknowledged but NEVER applied (logged 'high')
  - FC 0x2B / MEI 0x0E Read Device Identification -> vendor fingerprint

Writes are the interesting part: a real attacker trying to flip a pump or valve
gets a perfectly normal ACK while we record the exact register and value they
tried to set. Nothing is ever actually changed.
"""
from __future__ import annotations

import asyncio
import struct

from ..personas import load_persona
from .base import BaseDecoy

_PERSONA = load_persona()

_FC_NAMES = {
    0x01: "read_coils",
    0x02: "read_discrete_inputs",
    0x03: "read_holding_registers",
    0x04: "read_input_registers",
    0x05: "write_single_coil",
    0x06: "write_single_register",
    0x0F: "write_multiple_coils",
    0x10: "write_multiple_registers",
    0x2B: "encapsulated_interface_transport",
}
_WRITE_FCS = {0x05, 0x06, 0x0F, 0x10}


def _mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    # transaction id, protocol id (0), length (unit+pdu), unit id
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def _exception(fc: int, code: int) -> bytes:
    return struct.pack(">BB", fc | 0x80, code)


class ModbusDecoy(BaseDecoy):
    protocol = "modbus"
    default_port = 502

    async def converse(self, reader, writer, src_ip, src_port, session) -> None:
        while True:
            header = await asyncio.wait_for(reader.readexactly(7), timeout=30)
            tid, pid, length, unit = struct.unpack(">HHHB", header)
            remaining = max(0, length - 1)
            pdu = await asyncio.wait_for(reader.readexactly(remaining), timeout=30)
            if not pdu:
                break
            fc = pdu[0]
            resp_pdu, action, detail, severity = self._dispatch(fc, pdu)
            await self.emit(src_ip, src_port, session, action, detail, severity, header + pdu)
            writer.write(_mbap(tid, unit, resp_pdu))
            await writer.drain()

    def _dispatch(self, fc: int, pdu: bytes):
        name = _FC_NAMES.get(fc, f"function_0x{fc:02x}")
        try:
            if fc in (0x01, 0x02, 0x03, 0x04):
                return self._read(fc, pdu, name)
            if fc in (0x05, 0x06):
                return self._write_single(fc, pdu, name)
            if fc in (0x0F, 0x10):
                return self._write_multiple(fc, pdu, name)
            if fc == 0x2B:
                return self._device_id(pdu)
        except (struct.error, IndexError):
            pass
        return _exception(fc, 0x01), name, f"unsupported/malformed {name}", "info"

    def _read(self, fc, pdu, name):
        start, count = struct.unpack(">HH", pdu[1:5])
        count = max(1, min(count, 125))
        if fc in (0x01, 0x02):  # bit reads
            nbytes = (count + 7) // 8
            bits = bytearray(nbytes)
            for i in range(count):
                if _PERSONA.register_value(start + i) & 1:
                    bits[i // 8] |= (1 << (i % 8))
            body = struct.pack(">BB", fc, nbytes) + bytes(bits)
        else:                   # word reads
            vals = b"".join(struct.pack(">H", _PERSONA.register_value(start + i))
                            for i in range(count))
            body = struct.pack(">BB", fc, count * 2) + vals
        detail = f"polled {count} regs from address {start}"
        return body, name, detail, "info"

    def _write_single(self, fc, pdu, name):
        addr, value = struct.unpack(">HH", pdu[1:5])
        detail = f"ATTEMPTED WRITE: register {addr} -> {value} (rejected, value unchanged)"
        # Echo the request back, exactly like a real PLC ack. We change nothing.
        return pdu, name, detail, "high"

    def _write_multiple(self, fc, pdu, name):
        start, count = struct.unpack(">HH", pdu[1:5])
        detail = f"ATTEMPTED WRITE: {count} registers from {start} (rejected, value unchanged)"
        body = struct.pack(">BHH", fc, start, count)
        return body, name, detail, "high"

    def _device_id(self, pdu):
        # MEI type 0x0E = Read Device Identification.
        if len(pdu) < 2 or pdu[1] != 0x0E:
            return _exception(0x2B, 0x01), "encapsulated_interface_transport", "unknown MEI type", "info"
        objects = {
            0x00: _PERSONA.modbus_vendor.encode(),
            0x01: _PERSONA.modbus_product_code.encode(),
            0x02: _PERSONA.modbus_revision.encode(),
            0x03: _PERSONA.modbus_vendor_url.encode(),
            0x04: _PERSONA.modbus_product_name.encode(),
            0x05: _PERSONA.modbus_model.encode(),
        }
        body = struct.pack(">BBBBBB", 0x2B, 0x0E, 0x01, 0x01, 0x00, len(objects))
        for oid, val in objects.items():
            body += struct.pack(">BB", oid, len(val)) + val
        return body, "read_device_identification", \
            f"fingerprinted device as {_PERSONA.modbus_vendor} {_PERSONA.modbus_product_name}", "notice"
