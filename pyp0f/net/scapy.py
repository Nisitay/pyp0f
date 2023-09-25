from scapy.layers.inet import IP as ScapyIPv4
from scapy.layers.inet import TCP as ScapyTCP
from scapy.layers.inet6 import IPv6 as ScapyIPv6
from scapy.packet import Packet as ScapyPacket


def copy_packet(packet: ScapyPacket, *, assemble: bool = False) -> ScapyPacket:
    """
    Create a deep copy of `packet`.

    Args:
        packet: Packet to copy.
        assemble: Return an assembled version of the packet, so that automatic fields are calculated (checksums, etc.). Defaults to False.

    Returns:
        ScapyPacket: Copied packet
    """
    return packet.__class__(bytes(packet)) if assemble else packet.copy()


__all__ = ["ScapyPacket", "ScapyIPv4", "ScapyIPv6", "ScapyTCP", "copy_packet"]
