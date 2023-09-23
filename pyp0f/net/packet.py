from dataclasses import dataclass
from enum import Enum, auto
from typing import Tuple, Union

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.base import Layer
from pyp0f.net.layers.ip import IP
from pyp0f.net.layers.tcp import TCP, TCPFlag
from pyp0f.net.scapy import ScapyPacket, copy_packet

Address = Tuple[str, int]
PacketLike = Union[ScapyPacket, "Packet"]


class Direction(Enum):
    CLIENT_TO_SERVER = auto()
    SERVER_TO_CLIENT = auto()


@dataclass
class Packet(Layer):
    """
    Packet data relevant for p0f.
    """

    ip: IP
    tcp: TCP

    @property
    def src_address(self) -> Address:
        return (self.ip.src, self.tcp.src_port)

    @property
    def dst_address(self) -> Address:
        return (self.ip.dst, self.tcp.dst_port)

    @property
    def should_fingerprint(self) -> bool:
        """
        Packets with silly combination of TCP flags or with MF or non-zero fragment
        offset specified should be ignored.
        """
        return (
            not self.ip.is_fragment
            and self.tcp.type != 0
            and (TCPFlag.SYN | TCPFlag.FIN) not in self.tcp.type
            and (TCPFlag.SYN | TCPFlag.RST) not in self.tcp.type
            and (TCPFlag.FIN | TCPFlag.RST) not in self.tcp.type
        )

    @classmethod
    def from_packet(cls, packet: ScapyPacket):
        return cls(IP.from_packet(packet), TCP.from_packet(packet))


def parse_packet(packet: PacketLike) -> Packet:
    """
    Parse packet from one of the supported formats: ``Packet``, ``scapy.packet.Packet``

    Args:
        packet: Packet to parse

    Raises:
        PacketError: Unsupported packet format

    Returns:
        Parsed packet object
    """
    if isinstance(packet, Packet):
        return packet
    elif isinstance(packet, ScapyPacket):
        return Packet.from_packet(copy_packet(packet, assemble=True))
    else:
        raise PacketError(f"Unsupported packet format {type(packet).__name__}.")
