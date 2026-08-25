"""
ORBITAL_SHIELD - Firmware Simulation Module

Provides models, artifact registration, and update event generators for satellite firmware.
"""

from .models import FirmwareData, FirmwareEvent, FirmwareStatus
from .simulator import FirmwareSimulator

__all__ = [
    "FirmwareData",
    "FirmwareEvent",
    "FirmwareStatus",
    "FirmwareSimulator",
]
