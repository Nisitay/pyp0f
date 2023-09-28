from dataclasses import InitVar, dataclass, field
from typing import Optional

from pyp0f.net.packet import Packet
from pyp0f.utils.slots import add_slots

BAD_TPS = -1


@add_slots
@dataclass
class Uptime:
    timestamp: InitVar[int]

    raw_frequency: float
    """Raw frequency for timestamp clock (Hz)."""

    frequency: int = field(init=False)
    """Rounded frequency (Hz)."""

    total_minutes: int = field(init=False)
    """Computed uptime (seconds)."""

    modulo_days: int = field(init=False)
    """Uptime modulo (days)."""

    def __post_init__(self, timestamp: int):
        self.frequency = round_frequency(self.raw_frequency)
        self.total_minutes = timestamp // self.frequency // 60
        self.modulo_days = 0xFFFFFFFF // (self.frequency * 60 * 60 * 24)

    @property
    def days(self) -> int:
        return self.total_minutes // 60 // 24

    @property
    def hours(self) -> int:
        return self.total_minutes // 60 % 24

    @property
    def minutes(self) -> int:
        return self.total_minutes % 60


@add_slots
@dataclass
class UptimeResult:
    packet: Packet
    """Fingerprinted packet."""

    tps: Optional[int] = None
    "Computed TS divisor (bad = -1)."

    uptime: Optional[Uptime] = None
    """Computed uptime."""


def round_frequency(raw_frequency: float) -> int:
    """
    Round raw frequency neatly.
    """
    frequency = int(raw_frequency)

    if frequency == 0:
        return 1
    if 1 <= frequency <= 10:
        return frequency
    if 11 <= frequency <= 50:
        return (frequency + 3) // 5 * 5
    if 51 <= frequency <= 100:
        return (frequency + 7) // 10 * 10
    if 101 <= frequency <= 500:
        return (frequency + 33) // 50 * 50
    return (frequency + 67) // 100 * 100
