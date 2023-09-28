from dataclasses import dataclass, field

from pyp0f.database.records import HTTPRecord
from pyp0f.net.layers.http import BufferLike
from pyp0f.net.signatures import HTTPPacketSignature
from pyp0f.utils.slots import add_slots

from .base import Result


@add_slots
@dataclass
class HTTPResult(Result[HTTPRecord, HTTPPacketSignature]):
    """
    HTTP fingerprint result.
    """

    packet: BufferLike
    """Origin HTTP payload."""

    dishonest: bool = field(init=False)
    """Software string (User-Agent or Server) looks forged?"""

    def __post_init__(self):
        self.dishonest = (
            self.match is not None
            and self.packet_signature.software is not None
            and self.match.signature.expected_software is not None
            and self.match.signature.expected_software
            not in self.packet_signature.software
        )
