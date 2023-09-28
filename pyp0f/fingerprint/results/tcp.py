from dataclasses import dataclass, field
from enum import Enum, auto

from pyp0f.database.records import TCPRecord
from pyp0f.net.signatures import TCPPacketSignature
from pyp0f.utils.slots import add_slots

from .base import Result


class TCPMatchType(Enum):
    EXACT = auto()
    FUZZY_TTL = auto()
    FUZZY_QUIRKS = auto()


@add_slots
@dataclass
class TCPMatch:
    """
    Match for a TCP fingerprint.
    """

    type: TCPMatchType
    """Match type."""

    record: TCPRecord
    """Matched record."""

    @property
    def is_fuzzy(self) -> bool:
        """Approximate match?"""
        return self.type != TCPMatchType.EXACT


@add_slots
@dataclass
class TCPResult(Result[TCPMatch, TCPPacketSignature]):
    """
    TCP fingerprint result.
    """

    distance: int = field(init=False)
    """Estimated distance (TTL)."""

    def __post_init__(self):
        self.distance = (
            guess_distance(self.packet_signature.ttl)
            if self.match is None or self.match.type == TCPMatchType.FUZZY_TTL
            else self.match.record.signature.ttl - self.packet_signature.ttl
        )


def guess_distance(ttl: int) -> int:
    """
    Figure out what the TTL distance might have been for a packet.
    """
    return next(
        (initial_ttl - ttl for initial_ttl in (32, 64, 128) if ttl <= initial_ttl),
        255 - ttl,
    )
