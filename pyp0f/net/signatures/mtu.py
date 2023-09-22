from dataclasses import dataclass

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.ip import IPV4
from pyp0f.net.layers.tcp import MIN_TCP4, MIN_TCP6
from pyp0f.net.packet import Packet
from pyp0f.utils.slots import add_slots

from .base import PacketSignature


@add_slots
@dataclass
class MTUPacketSignature(PacketSignature):
    mtu: int

    @classmethod
    def from_mss(cls, mss: int, ip_version: int):
        if mss <= 0:
            raise PacketError("MTU signature requires MSS value")
        return cls(mss + (MIN_TCP4 if ip_version == IPV4 else MIN_TCP6))

    @classmethod
    def from_packet(cls, packet: Packet):
        return cls.from_mss(packet.tcp.options.mss, packet.ip.version)
