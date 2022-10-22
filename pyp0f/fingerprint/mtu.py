from typing import Optional

from pyp0f.exceptions import PacketError
from pyp0f.records import MtuRecord
from pyp0f.options import Options, OPTIONS
from pyp0f.signatures import MtuSig, MtuPacketSig
from pyp0f.net.packet import Packet, PacketLike, parse_packet

from .results import MtuResult


def valid_for_fingerprint(packet: Packet) -> bool:
    """
    Check if the given packet is valid for MTU fingerprint.
    Packets with MSS value are valid for fingerprint.
    """
    return packet.should_fingerprint and packet.tcp.options.mss > 0


def signatures_match(sig: MtuSig, pkt_sig: MtuPacketSig) -> bool:
    """
    Check if MTU signatures match by comparing their MTU values.
    """
    return sig.mtu == pkt_sig.mtu


def find_match(pkt_sig: MtuPacketSig, options: Options) -> Optional[MtuRecord]:
    """
    Search through the database for a match for the given MTU signature.
    """
    return next(
        (
            mtu_record
            for mtu_record in options.database(MtuRecord)
            if signatures_match(mtu_record.signature, pkt_sig)
        ),
        None,
    )


def fingerprint(packet: PacketLike, options: Options = OPTIONS) -> MtuResult:
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
    pkt = parse_packet(packet)
    if not valid_for_fingerprint(pkt):
        raise PacketError("Packet is invalid for MTU fingerprint")

    pkt_sig = MtuPacketSig.from_packet(pkt)
    return MtuResult(pkt, pkt_sig, find_match(pkt_sig, options))
