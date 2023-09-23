import random
import string

from pyp0f.exceptions import PacketError
from pyp0f.net.scapy import ScapyIPv4, ScapyIPv6, ScapyPacket, ScapyTCP, copy_packet

_DEFAULT_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits


def random_string(*, size: int, chars=_DEFAULT_CHARS) -> str:
    return "".join(random.choice(chars) for _ in range(size))


def validate_for_impersonation(packet: ScapyPacket) -> ScapyPacket:
    """
    Validates that the packet is an IPv4/IPv6 and TCP packet.

    Args:
        packet: Scapy packet to validate

    Raises:
        PacketError: Packet is invalid.

    Returns:
        ScapyPacket: Copy of the original packet.
    """

    is_valid = ScapyTCP in packet and (ScapyIPv4 in packet or ScapyIPv6 in packet)

    if not is_valid:
        raise PacketError("Not a TCP/IP packet")

    return copy_packet(packet)
