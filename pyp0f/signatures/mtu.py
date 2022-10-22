from dataclasses import dataclass

from pyp0f.exceptions import PacketError
from pyp0f.utils.slots import add_slots
from pyp0f.utils.parse import range_num_parser
from pyp0f.net.ip import IPV4
from pyp0f.net.packet import Packet
from pyp0f.net.tcp.base import MIN_TCP4, MIN_TCP6

from .base import DatabaseSig, PacketSig

_parse_mtu = range_num_parser(min=1, max=65535, wildcard=False)


@add_slots
@dataclass
class _MtuSig:
    """
    Common fields for database & packet MTU signatures.
    """
    mtu: int


@add_slots
@dataclass
class MtuSig(DatabaseSig, _MtuSig):

    @classmethod
    def parse(cls, raw_signature: str):
        return cls(_parse_mtu(raw_signature))


@add_slots
@dataclass
class MtuPacketSig(PacketSig, _MtuSig):

    @classmethod
    def from_mss(cls, mss: int, ip_version: int):
        return cls(mss + (MIN_TCP4 if ip_version == IPV4 else MIN_TCP6))

    @classmethod
    def from_packet(cls, packet: Packet):
        if packet.tcp.options.mss <= 0:
            raise PacketError("MTU signature requires MSS value")
        return cls.from_mss(packet.tcp.options.mss, packet.ip.version)
