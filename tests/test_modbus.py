"""Protocol-level tests for the Modbus decoy. No network: drives the handler
through in-memory stream stubs."""
import asyncio
import struct

import pytest

from mirage.protocols.modbus import ModbusDecoy, _mbap


class FakeStorage:
    async def save(self, ev):  # noqa: D401
        pass


class Reader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise asyncio.IncompleteReadError(self._data[self._pos:], n)
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk


class Writer:
    def __init__(self):
        self.out = bytearray()

    def write(self, b):
        self.out += b

    async def drain(self):
        pass

    def get_extra_info(self, _):
        return ("203.0.113.7", 51000)

    def close(self):
        pass

    async def wait_closed(self):
        pass


def _frame(pdu: bytes, tid=1) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def run(pdu: bytes) -> bytes:
    decoy = ModbusDecoy(FakeStorage(), 502)
    reader = Reader(_frame(pdu))
    writer = Writer()
    asyncio.run(decoy.handle(reader, writer))
    return bytes(writer.out)


def test_read_holding_registers_returns_values():
    out = run(struct.pack(">BHH", 0x03, 0, 4))
    # MBAP(7) + fc + bytecount + 4*2 bytes
    assert out[7] == 0x03
    assert out[8] == 8
    assert len(out) == 7 + 2 + 8


def test_device_identification_includes_vendor():
    out = run(struct.pack(">BBB", 0x2B, 0x0E, 0x01))
    assert b"Schneider Electric" in out


def test_write_single_register_is_echoed_not_applied():
    pdu = struct.pack(">BHH", 0x06, 2, 1)
    out = run(pdu)
    # A real PLC echoes the write request; we do the same but never store it.
    assert out[7:] == pdu


def test_unsupported_function_returns_exception():
    out = run(struct.pack(">B", 0x63))
    assert out[7] == 0x63 | 0x80  # exception bit set
