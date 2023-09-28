from pyp0f.exceptions import PacketError
from pyp0f.fingerprint.results import BAD_TPS, Uptime, UptimeResult
from pyp0f.net.layers.tcp import TCPFlag
from pyp0f.net.packet import Packet, PacketLike, parse_packet
from pyp0f.net.signatures import TCPPacketSignature
from pyp0f.options import OPTIONS, Options
from pyp0f.utils.time import get_unix_time_ms


def valid_for_uptime_fingerprint(packet: Packet) -> bool:
    """
    Checks if the packet is valid for uptime fingerprint.
    SYN/SYN+ACK/ACK packets are valid for fingerprint.
    """
    return packet.should_fingerprint and packet.tcp.type in (
        TCPFlag.SYN,
        TCPFlag.SYN | TCPFlag.ACK,
        TCPFlag.ACK,
    )


def fingerprint_uptime(
    packet: PacketLike,
    last_packet_signature: TCPPacketSignature,
    *,
    options: Options = OPTIONS,
):
    """
    Perform uptime detection. This is the only fingerprint function that works not
    only on SYN or SYN+ACK, but also on ACK traffic.

    Args:
        packet: Packet to fingerprint
        last_packet_signature: Last packet TCP signature, to calculate diff off of
        options: Fingerprint options. Defaults to OPTIONS

    Raises:
        PacketError: The packet is invalid for uptime fingerprint

    Returns:
        Uptime fingerprint result
    """
    packet = parse_packet(packet)

    if not valid_for_uptime_fingerprint(packet):
        raise PacketError(
            "Packet is invalid for uptime fingerprint. "
            "Packet must be SYN/SYN+ACK/ACK."
        )

    if not packet.tcp.options.timestamp or not last_packet_signature.options.timestamp:
        return UptimeResult(packet)

    ms_diff = get_unix_time_ms() - last_packet_signature.received
    ts_diff = packet.tcp.options.timestamp - last_packet_signature.options.timestamp

    # Wait at least 25 ms, and not more than 10 minutes, for at least 5
    # timestamp ticks. Allow the timestamp to go back slightly within
    # a short window, too - we may be receiving packets a bit out of
    # order.
    if not options.min_timestamp_wait <= ms_diff <= options.max_timestamp_wait or (
        ts_diff < 5
        or (
            ms_diff < options.timestamp_grace
            and ~ts_diff // 1000 < options.max_timestamp_scale / options.timestamp_grace
        )
    ):
        return UptimeResult(packet)

    if ts_diff > ~ts_diff:
        raw_frequency = ~ts_diff * -1000.0 / ms_diff
    else:
        raw_frequency = ts_diff * 1000.0 / ms_diff

    if not options.min_timestamp_scale <= raw_frequency <= options.max_timestamp_scale:
        # Allow bad reading on SYN, as this may be just an artifact of IP
        # sharing or OS change.
        return UptimeResult(
            packet, tps=BAD_TPS if packet.tcp.type != TCPFlag.SYN else None
        )

    uptime = Uptime(packet.tcp.options.timestamp, raw_frequency)

    return UptimeResult(packet, tps=uptime.frequency, uptime=uptime)
