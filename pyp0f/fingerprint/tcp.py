from typing import Optional

from pyp0f.database.parse.utils import WILDCARD
from pyp0f.database.records import TCPRecord
from pyp0f.database.signatures import TCPSignature, WindowType
from pyp0f.exceptions import PacketError
from pyp0f.fingerprint.results import TCPMatch, TCPMatchType, TCPResult
from pyp0f.net.layers.ip import IPV4
from pyp0f.net.layers.tcp import TCPFlag
from pyp0f.net.packet import Direction, Packet, PacketLike, parse_packet
from pyp0f.net.quirks import Quirk
from pyp0f.net.signatures import TCPPacketSignature
from pyp0f.options import OPTIONS, Options


def valid_for_fingerprint(packet: Packet) -> bool:
    """
    Check if the given packet is valid for TCP fingerprint.
    SYN/SYN+ACK packets are valid for fingerprint.
    """
    return packet.should_fingerprint and packet.tcp.type in (
        TCPFlag.SYN,
        TCPFlag.SYN | TCPFlag.ACK,
    )


def signatures_match(
    signature: TCPSignature, packet_signature: TCPPacketSignature, options: Options
) -> Optional[TCPMatchType]:
    """
    Check if TCP signatures match.
    """
    match_type: TCPMatchType = TCPMatchType.EXACT

    if signature.options.layout != packet_signature.options.layout:
        return None

    signature_quirks = signature.quirks

    # If the database signature has no IP version specified, remove
    # IPv6-specific quirks when matching IPv4 packets and vice versa.
    if signature.ip_version == WILDCARD:
        if packet_signature.ip_version == IPV4:
            signature_quirks &= ~(Quirk.FLOW)
        else:
            signature_quirks &= ~(Quirk.DF | Quirk.NZ_ID | Quirk.ZERO_ID)

    if signature_quirks != packet_signature.quirks:
        deleted = (signature_quirks ^ packet_signature.quirks) & signature_quirks
        added = (signature_quirks ^ packet_signature.quirks) & packet_signature.quirks

        # If there is a difference in quirks, but it's 'df' or 'id+' disappearing,
        # or 'id-' or 'ecn' appearing, allow a fuzzy match.
        if deleted & ~(Quirk.DF | Quirk.NZ_ID) or added & ~(Quirk.ZERO_ID | Quirk.ECN):
            return None

        match_type = TCPMatchType.FUZZY_QUIRKS

    # Fixed parameters.
    if (
        signature.options.eol_padding_length
        != packet_signature.options.eol_padding_length
        or signature.ip_options_length != packet_signature.ip_options_length
    ):
        return None

    # TTL matching, with a provision to allow fuzzy match.
    if signature.is_bad_ttl:
        if signature.ttl < packet_signature.ttl:
            return None
    elif (
        signature.ttl < packet_signature.ttl
        or signature.ttl - packet_signature.ttl > options.max_dist
    ):
        match_type = TCPMatchType.FUZZY_TTL

    # Simple wildcards
    if (
        signature.options.mss != WILDCARD
        and signature.options.mss != packet_signature.options.mss
        or signature.window.scale != WILDCARD
        and signature.window.scale != packet_signature.options.window_scale
        or signature.payload_class != WILDCARD
        and signature.payload_class != packet_signature.has_payload
    ):
        return None

    # Window size
    if (
        signature.window.type == WindowType.NORMAL
        and signature.window.size != packet_signature.window_size
        or signature.window.type == WindowType.MOD
        and packet_signature.window_size % signature.window.size
        or (
            signature.window.type == WindowType.MSS
            and (
                packet_signature.window_multiplier.is_mtu
                or signature.window.size != packet_signature.window_multiplier.value
            )
        )
        or (
            signature.window.type == WindowType.MTU
            and (
                not packet_signature.window_multiplier.is_mtu
                or signature.window.size != packet_signature.window_multiplier.value
            )
        )
    ):
        return None

    return match_type


def find_match(
    packet_signature: TCPPacketSignature, direction: Direction, options: Options
) -> Optional[TCPMatch]:
    """
    Search through the database for a match for the given TCP signature.
    """
    fuzzy_match: Optional[TCPMatch] = None
    generic_match: Optional[TCPMatch] = None

    for tcp_record in options.database.iter_values(TCPRecord, direction):
        match_type = signatures_match(tcp_record.signature, packet_signature, options)

        if match_type is None:
            continue

        match = TCPMatch(match_type, tcp_record)

        if match_type == TCPMatchType.EXACT:
            if not tcp_record.is_generic:
                return match

            if generic_match is None:
                generic_match = match

        elif fuzzy_match is None:
            fuzzy_match = match

    # Found a generic signature and nothing better
    if generic_match is not None:
        return generic_match

    # No fuzzy matching for userland tools.
    if fuzzy_match is not None and fuzzy_match.record.label.is_user_app:
        return None

    return fuzzy_match


def fingerprint(
    packet: PacketLike, options: Options = OPTIONS, syn_mss: Optional[int] = None
) -> TCPResult:
    """
    Fingerprint the given TCP packet.

    Args:
        packet: Packet to fingerprint
        options: Fingerprint options. Defaults to OPTIONS.
        syn_mss: Value of MSS option in SYN packet, if known. Defaults to None.

    Raises:
        PacketError: The packet is invalid for TCP fingerprint

    Returns:
        TCP fingerprint result
    """
    parsed_packet = parse_packet(packet)

    if not valid_for_fingerprint(parsed_packet):
        raise PacketError("Packet is invalid for TCP fingerprint")

    direction = (
        Direction.CLIENT_TO_SERVER
        if parsed_packet.tcp.type == TCPFlag.SYN
        else Direction.SERVER_TO_CLIENT
    )

    packet_signature = TCPPacketSignature.from_packet(parsed_packet, syn_mss)

    return TCPResult(
        parsed_packet,
        packet_signature,
        find_match(packet_signature, direction, options),
    )
