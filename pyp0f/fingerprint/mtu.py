from typing import Optional

from pyp0f.database import Database
from pyp0f.database.records import MTURecord
from pyp0f.database.signatures import MTUSignature
from pyp0f.exceptions import PacketError
from pyp0f.fingerprint.results import MTUResult
from pyp0f.net.packet import Packet, PacketLike, parse_packet
from pyp0f.net.signatures import MTUPacketSignature
from pyp0f.options import OPTIONS, Options


def valid_for_fingerprint(packet: Packet) -> bool:
    """
    Check if the given packet is valid for MTU fingerprint.
    Packets with MSS value are valid for fingerprint.
    """
    return packet.should_fingerprint and packet.tcp.options.mss > 0


def signatures_match(
    signature: MTUSignature, packet_signature: MTUPacketSignature
) -> bool:
    """
    Check if MTU signatures match by comparing their MTU values.
    """
    return signature.mtu == packet_signature.mtu


def find_match(
    packet_signature: MTUPacketSignature, database: Database
) -> Optional[MTURecord]:
    """
    Search through the database for a match for the given MTU signature.
    """
    return next(
        (
            mtu_record
            for mtu_record in database.iter_values(MTURecord)
            if signatures_match(mtu_record.signature, packet_signature)
        ),
        None,
    )


def fingerprint(packet: PacketLike, options: Options = OPTIONS) -> MTUResult:
    """
    Fingerprint the given packet for MTU.

    Args:
        packet: Packet to fingerprint
        options: Fingerprint options. Defaults to OPTIONS.

    Raises:
        PacketError: The packet is invalid for MTU fingerprint

    Returns:
        MTU fingerprint result
    """
    parsed_packet = parse_packet(packet)

    if not valid_for_fingerprint(parsed_packet):
        raise PacketError("Packet is invalid for MTU fingerprint")

    packet_signature = MTUPacketSignature.from_packet(parsed_packet)

    return MTUResult(
        parsed_packet, packet_signature, find_match(packet_signature, options.database)
    )
