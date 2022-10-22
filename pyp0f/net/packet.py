from enum import Enum, auto
from dataclasses import dataclass
from typing import Union, Tuple

from scapy.packet import Packet as ScapyPacket

from pyp0f.exceptions import PacketError

from .ip import IP
from .tcp import TCP, TcpFlag
from .layer import Layer


Address = Tuple[str, int]
PacketLike = Union[ScapyPacket, "Packet"]


class Direction(Enum):
    CLI_TO_SRV = auto()  # client -> server
    SRV_TO_CLI = auto()  # server -> client


@dataclass
class Packet(Layer):
    """
    Packet data relevant for p0f.
    """
    ip: IP
    tcp: TCP

    @property
    def src_address(self) -> Address:
        return (self.ip.src, self.tcp.sport)

    @property
    def dst_address(self) -> Address:
        return (self.ip.dst, self.tcp.dport)

    @property
    def should_fingerprint(self) -> bool:
        """
        Packets with silly combination of TCP flags or with MF or non-zero fragment
        offset specified should be ignored.
        """
        return (
            not self.ip.is_fragment
            and self.tcp.type != 0
            and (TcpFlag.SYN | TcpFlag.FIN) not in self.tcp.type
            and (TcpFlag.SYN | TcpFlag.RST) not in self.tcp.type
            and (TcpFlag.FIN | TcpFlag.RST) not in self.tcp.type
        )

    @classmethod
    def from_packet(cls, packet: ScapyPacket):
        return cls(
            IP.from_packet(packet),
            TCP.from_packet(packet)
        )


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
        return Packet.from_packet(packet)
    else:
        raise PacketError(f"Unsupported packet format {type(packet).__name__}.")


def format_address(address: Address) -> str:
    """
    Convert a TCP address to str.

    >>> format_address(("127.0.0.1", 80))
    "127.0.0.1:80"
    >>> format_address(("2001:0DB8:AC10:FE01", 8080))
    "[2001:0DB8:AC10:FE01]:8080"
    """
    ip, port = address
    if ":" in ip:
        ip = f"[{ip}]"
    return f"{ip}:{port}"
