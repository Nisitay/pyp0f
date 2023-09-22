from dataclasses import dataclass

from scapy.layers.inet import TCP as TCPLayer
from scapy.packet import Packet as ScapyPacket

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.base import Layer
from pyp0f.net.layers.ip import IPV4_HEADER_LENGTH, IPV6_HEADER_LENGTH
from pyp0f.net.layers.tcp import TCPFlag, TCPOptions
from pyp0f.net.quirks import Quirk

TCP_HEADER_LENGTH = 20

# Minimum lengths of IPv4/IPv6 + TCP headers
MIN_TCP4 = IPV4_HEADER_LENGTH + TCP_HEADER_LENGTH
MIN_TCP6 = IPV6_HEADER_LENGTH + TCP_HEADER_LENGTH


@dataclass
class TCP(Layer):
    type: TCPFlag  # SYN | ACK | FIN | RST
    src_port: int
    dst_port: int
    window: int
    seq: int
    options: TCPOptions
    payload: bytes
    header_length: int
    quirks: Quirk

    def __post_init__(self):
        self.type &= TCPFlag.SYN | TCPFlag.ACK | TCPFlag.FIN | TCPFlag.RST
        self.quirks |= self.options.quirks

    @classmethod
    def from_packet(cls, packet: ScapyPacket):
        if TCPLayer not in packet:
            raise PacketError("Packet doesn't have an TCP layer!")

        tcp = packet[TCPLayer]
        flags: TCPFlag = TCPFlag(int(tcp.flags))
        header_length: int = tcp.dataofs * 4
        options_buffer = bytes(tcp)[TCP_HEADER_LENGTH:header_length]
        options = TCPOptions.parse(options_buffer, is_syn=(flags == TCPFlag.SYN))

        quirks = Quirk(0)

        if tcp.flags.E or tcp.flags.C or tcp.flags.N:
            quirks |= Quirk.ECN

        if not tcp.seq:
            quirks |= Quirk.ZERO_SEQ

        if tcp.flags.A:
            if not tcp.ack:
                quirks |= Quirk.ZERO_ACK
        elif tcp.ack and not tcp.flags.R:
            quirks |= Quirk.NZ_ACK

        if tcp.flags.U:
            quirks |= Quirk.URG
        elif tcp.urgptr:
            quirks |= Quirk.NZ_URG

        if tcp.flags.P:
            quirks |= Quirk.PUSH

        return cls(
            type=flags,
            src_port=tcp.sport,
            dst_port=tcp.dport,
            window=tcp.window,
            seq=tcp.seq,
            options=options,
            payload=bytes(tcp.payload),
            header_length=header_length,
            quirks=quirks,
        )
