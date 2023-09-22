from dataclasses import dataclass

from scapy.layers.inet import IP as IPv4
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet as ScapyPacket

from pyp0f.exceptions import PacketError
from pyp0f.net.quirks import Quirk

from .base import Layer

IPV4 = 0x04
IPV6 = 0x06

IP_TOS_CE = 0x01  # Congestion encountered
IP_TOS_ECT = 0x02  # ECN supported

IPV4_HEADER_LENGTH = 20
IPV6_HEADER_LENGTH = 40


@dataclass
class IP(Layer):
    version: int
    src: str
    dst: str
    ttl: int
    tos: int
    options_length: int
    header_length: int
    is_fragment: bool  # MF or non-zero fragment offset specified
    quirks: Quirk

    @classmethod
    def from_packet(cls, packet: ScapyPacket):
        if IPv4 in packet:
            return cls._from_ipv4(packet[IPv4])
        elif IPv6 in packet:
            return cls._from_ipv6(packet[IPv6])
        else:
            raise PacketError("Packet doesn't have an IP layer!")

    @classmethod
    def _from_ipv4(cls, ip: IPv4):
        quirks = Quirk(0)

        if ip.tos & (IP_TOS_CE | IP_TOS_ECT):
            quirks |= Quirk.ECN

        if ip.flags.evil:
            quirks |= Quirk.NZ_MBZ

        if ip.flags.DF:
            quirks |= Quirk.DF

            if ip.id:
                quirks |= Quirk.NZ_ID

        elif not ip.id:
            quirks |= Quirk.ZERO_ID

        header_length: int = ip.ihl * 4

        return cls(
            version=ip.version,
            src=ip.src,
            dst=ip.dst,
            ttl=ip.ttl,
            tos=ip.tos >> 2,
            options_length=header_length - IPV4_HEADER_LENGTH,
            header_length=header_length,
            is_fragment=ip.flags.MF or ip.frag,
            quirks=quirks,
        )

    @classmethod
    def _from_ipv6(cls, ip: IPv6):
        quirks = Quirk(0)

        if ip.fl:
            quirks |= Quirk.FLOW

        if ip.tc & (IP_TOS_CE | IP_TOS_ECT):
            quirks |= Quirk.ECN

        return cls(
            version=ip.version,
            src=ip.src,
            dst=ip.dst,
            ttl=ip.hlim,
            tos=ip.tc >> 2,
            options_length=0,
            header_length=IPV6_HEADER_LENGTH,
            is_fragment=False,
            quirks=quirks,
        )
