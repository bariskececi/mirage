"""A small municipal water-treatment plant.

The register map below mirrors what a real SCADA poll would see: tank levels,
pump run states, chlorine dosing, flow. Values drift slowly so a returning
scanner sees a *living* process, which is what separates a convincing decoy
from an obvious stub.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


@dataclass
class RegisterPoint:
    addr: int
    name: str
    unit: str
    base: float
    amplitude: float = 0.0      # sinusoidal drift
    period_s: float = 600.0
    writable: bool = False


@dataclass
class Persona:
    name: str
    # Returned to Modbus "Read Device Identification" (FC 0x2B / MEI 0x0E).
    modbus_vendor: str
    modbus_product_code: str
    modbus_revision: str
    modbus_vendor_url: str
    modbus_product_name: str
    modbus_model: str
    # Returned in the S7 SZL module-identification response.
    s7_module: str
    s7_serial: str
    s7_plant_id: str
    s7_copyright: str
    holding_registers: list[RegisterPoint] = field(default_factory=list)

    def register_value(self, addr: int) -> int:
        """Current 16-bit value for a holding register address."""
        for rp in self.holding_registers:
            if rp.addr == addr:
                drift = 0.0
                if rp.amplitude:
                    drift = rp.amplitude * math.sin(2 * math.pi * (time.time() % rp.period_s) / rp.period_s)
                return int(max(0, min(0xFFFF, round(rp.base + drift)))) & 0xFFFF
        # Unknown address: return a low, stable value rather than erroring.
        return (addr * 7) % 97


PERSONA = Persona(
    name="Riverside Municipal Water Treatment",
    modbus_vendor="Schneider Electric",
    modbus_product_code="BMXP342020",
    modbus_revision="V3.10",
    modbus_vendor_url="https://www.se.com",
    modbus_product_name="Modicon M340",
    modbus_model="BMX P34 2020",
    s7_module="6ES7 214-1AG40-0XB0",
    s7_serial="S C-X4U299302021",
    s7_plant_id="WTP-RIVERSIDE-01",
    s7_copyright="Original Siemens Equipment",
    holding_registers=[
        RegisterPoint(0,  "clearwell_level_pct",   "%",   72.0, 6.0, 900),
        RegisterPoint(1,  "raw_intake_flow_m3h",   "m3/h", 540.0, 40.0, 1200),
        RegisterPoint(2,  "pump_1_run",            "bool", 1.0, writable=True),
        RegisterPoint(3,  "pump_2_run",            "bool", 0.0, writable=True),
        RegisterPoint(4,  "pump_3_run",            "bool", 1.0, writable=True),
        RegisterPoint(5,  "chlorine_dose_ppm_x100","ppm", 80.0, 8.0, 700),
        RegisterPoint(6,  "turbidity_ntu_x100",    "NTU",  35.0, 10.0, 500),
        RegisterPoint(7,  "filter_dp_kpa",         "kPa",  22.0, 4.0, 800),
        RegisterPoint(8,  "uv_intensity_pct",      "%",    91.0, 3.0, 650),
        RegisterPoint(9,  "ph_x100",               "pH",  721.0, 6.0, 1000),
        RegisterPoint(10, "tank_a_level_pct",      "%",    64.0, 9.0, 1100),
        RegisterPoint(11, "tank_b_level_pct",      "%",    58.0, 7.0, 1300),
        RegisterPoint(12, "backwash_valve",        "bool", 0.0, writable=True),
        RegisterPoint(13, "scada_comm_ok",         "bool", 1.0),
    ],
)
