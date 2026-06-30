"""Decoy personalities. Each persona defines the fake plant's identity and live
process values so the trap reads like a real running site, not an empty stub."""
from __future__ import annotations

import importlib

from ..config import PERSONA


def load_persona():
    mod = importlib.import_module(f"mirage.personas.{PERSONA}")
    return mod.PERSONA
