from abc import ABCMeta
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, TypeVar, Generic

from pyp0f.utils.slots import add_slots
from pyp0f.net.packet import Packet
from pyp0f.net.http import BufferLike
from pyp0f.net.ip import guess_distance
from pyp0f.records import MtuRecord, TcpRecord, HttpRecord
from pyp0f.signatures import PacketSig, MtuPacketSig, TcpPacketSig, HttpPacketSig


M = TypeVar("M")
S = TypeVar("S", bound=PacketSig)


@add_slots
@dataclass
class Result(Generic[M, S], metaclass=ABCMeta):
    """
    Fingerprint result, consisting of the origin packet, its' signature, and
    the match (if any)
    """

    packet: Packet
    packet_sig: S
    match: Optional[M] = None


@add_slots
@dataclass
class MtuResult(Result[MtuRecord, MtuPacketSig]):
    """
    MTU fingerprint result
    """


class TcpMatchType(Enum):
    EXACT = auto()
    FUZZY_TTL = auto()
    FUZZY_QUIRKS = auto()


@add_slots
@dataclass
class TcpMatch:
    """
    Match for a TCP fingerprint, consisting of the match type and matched record
    """

    type: TcpMatchType
    record: TcpRecord

    @property
    def is_fuzzy(self) -> bool:
        return self.type != TcpMatchType.EXACT


@add_slots
@dataclass
class TcpResult(Result[TcpMatch, TcpPacketSig]):
    """
    TCP fingerprint result, including the estimated distance
    """

    distance: int = field(init=False)

    def __post_init__(self):
        if self.match is None or self.match.type == TcpMatchType.FUZZY_TTL:
            self.distance = guess_distance(self.packet_sig.ttl)
        else:
            self.distance = self.match.record.signature.ttl - self.packet_sig.ttl


@add_slots
@dataclass
class HttpResult(Result[HttpRecord, HttpPacketSig]):
    """
    HTTP fingerprint result, including dishonest status
    """

    packet: BufferLike
    dishonest: bool = field(init=False)

    def __post_init__(self):
        self.dishonest = (
            self.match is not None
            and self.packet_sig.sw is not None
            and self.match.signature.expected_sw is not None
            and self.match.signature.expected_sw not in self.packet_sig.sw
        )
