from typing import Optional

from pyp0f.exceptions import PacketError
from pyp0f.utils.parse import WILDCARD
from pyp0f.net.ip import IPV4
from pyp0f.net.tcp import TcpFlag
from pyp0f.net.quirks import Quirk
from pyp0f.records import TcpRecord
from pyp0f.options import Options, OPTIONS
from pyp0f.signatures import TcpSig, TcpPacketSig, WinType
from pyp0f.net.packet import Packet, Direction, PacketLike, parse_packet

from .results import TcpMatchType, TcpMatch, TcpResult


def valid_for_fingerprint(packet: Packet) -> bool:
    """
    Check if the given packet is valid for TCP fingerprint.
    SYN/SYN+ACK packets are valid for fingerprint.
    """
    return packet.should_fingerprint and packet.tcp.type in (
        TcpFlag.SYN,
        TcpFlag.SYN | TcpFlag.ACK,
    )


def signatures_match(
    sig: TcpSig,
    pkt_sig: TcpPacketSig,
    options: Options
) -> Optional[TcpMatchType]:
    """
    Check if TCP signatures match.
    """
    match_type: TcpMatchType = TcpMatchType.EXACT
    win_multi, use_mtu = pkt_sig.window_multiplier

    if sig.options_layout != pkt_sig.options.layout:
        return None

    sig_quirks = sig.quirks

    # If the database signature has no IP version specified, remove
    # IPv6-specific quirks when matching IPv4 packets and vice versa.
    if sig.ip_version == WILDCARD:
        if pkt_sig.ip_version == IPV4:
            sig_quirks &= ~(Quirk.FLOW)
        else:
            sig_quirks &= ~(Quirk.DF | Quirk.NZ_ID | Quirk.ZERO_ID)

    if sig_quirks != pkt_sig.quirks:
        deleted = (sig_quirks ^ pkt_sig.quirks) & sig_quirks
        added = (sig_quirks ^ pkt_sig.quirks) & pkt_sig.quirks

        # If there is a difference in quirks, but it's 'df' or 'id+' disappearing,
        # or 'id-' or 'ecn' appearing, allow a fuzzy match.
        if deleted & ~(Quirk.DF | Quirk.NZ_ID) or added & ~(Quirk.ZERO_ID | Quirk.ECN):
            return None

        match_type = TcpMatchType.FUZZY_QUIRKS

    # Fixed parameters.
    if (
        sig.eol_pad_length != pkt_sig.options.eol_pad_length
        or sig.ip_options_length != pkt_sig.ip_options_length
    ):
        return None

    # TTL matching, with a provision to allow fuzzy match.
    if sig.is_bad_ttl:
        if sig.ttl < pkt_sig.ttl:
            return None
    elif sig.ttl < pkt_sig.ttl or sig.ttl - pkt_sig.ttl > options.max_dist:
        match_type = TcpMatchType.FUZZY_TTL

    # Simple wildcards
    if (
        sig.mss != WILDCARD and sig.mss != pkt_sig.options.mss
        or sig.win_scale != WILDCARD and sig.win_scale != pkt_sig.options.window_scale
        or sig.payload_class != WILDCARD and sig.payload_class != pkt_sig.has_payload
    ):
        return None

    # Window size
    if (
        sig.win_type == WinType.NORMAL and sig.win_size != pkt_sig.win_size
        or sig.win_type == WinType.MOD and pkt_sig.win_size % sig.win_size
        or (sig.win_type == WinType.MSS and (use_mtu or sig.win_size != win_multi))
        or (sig.win_type == WinType.MTU and (not use_mtu or sig.win_size != win_multi))
    ):
        return None

    return match_type


def find_match(
    pkt_sig: TcpPacketSig,
    direction: Direction,
    options: Options
) -> Optional[TcpMatch]:
    """
    Search through the database for a match for the given TCP signature.
    """
    fuzzy_match: Optional[TcpMatch] = None
    generic_match: Optional[TcpMatch] = None

    for tcp_record in options.database(TcpRecord, direction):
        match_type = signatures_match(tcp_record.signature, pkt_sig, options)

        if match_type is None:
            continue

        match = TcpMatch(match_type, tcp_record)

        if match_type == TcpMatchType.EXACT:
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
    packet: PacketLike,
    options: Options = OPTIONS,
    syn_mss: Optional[int] = None
) -> TcpResult:
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
    pkt = parse_packet(packet)
    if not valid_for_fingerprint(pkt):
        raise PacketError("Packet is invalid for TCP fingerprint")

    direction = (
        Direction.CLI_TO_SRV if pkt.tcp.type == TcpFlag.SYN else Direction.SRV_TO_CLI
    )

    pkt_sig = TcpPacketSig.from_packet(pkt, syn_mss)
    return TcpResult(pkt, pkt_sig, find_match(pkt_sig, direction, options))
