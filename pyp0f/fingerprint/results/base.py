from abc import ABCMeta
from dataclasses import dataclass
from typing import Generic, Optional, TypeVar

from pyp0f.net.packet import Packet
from pyp0f.net.signatures import PacketSignature
from pyp0f.utils.slots import add_slots

TMatch = TypeVar("TMatch")
TSignature = TypeVar("TSignature", bound=PacketSignature)


@add_slots
@dataclass
class Result(Generic[TMatch, TSignature], metaclass=ABCMeta):
    """
    Fingerprint result.
    """

    packet: Packet
    """Origin packet."""

    packet_signature: TSignature
    """Origin packet signature."""

    match: Optional[TMatch] = None
    """Fingerprint match, if any."""
