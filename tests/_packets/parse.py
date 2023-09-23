import binascii

from pyp0f.net.packet import Packet, parse_packet
from pyp0f.net.scapy import ScapyIPv4, ScapyIPv6


def from_hex(packet: str, *, ip_version: int = 4) -> Packet:
    ip_cls = ScapyIPv4 if ip_version == 4 else ScapyIPv6
    return parse_packet(ip_cls(binascii.unhexlify(packet)))
