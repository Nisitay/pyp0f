import binascii

from scapy.layers.inet import IP as IPv4
from scapy.layers.inet6 import IPv6

from pyp0f.net.packet import Packet, parse_packet


def from_hex(packet: str, *, ip_version: int = 4) -> Packet:
    ip_cls = IPv4 if ip_version == 4 else IPv6
    return parse_packet(ip_cls(binascii.unhexlify(packet)))
