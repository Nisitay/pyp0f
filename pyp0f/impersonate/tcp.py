import random
from typing import Any, Optional, Tuple, Union

from scapy.packet import NoPayload, Raw

from pyp0f.database import Database
from pyp0f.database.parse.utils import WILDCARD
from pyp0f.database.records import TCPRecord
from pyp0f.database.signatures import TCPSignature, WindowType
from pyp0f.impersonate.utils import random_string, validate_for_impersonation
from pyp0f.net.layers.ip import IPV4
from pyp0f.net.layers.tcp import TCPFlag, TCPOption
from pyp0f.net.packet import Direction
from pyp0f.net.quirks import Quirk
from pyp0f.net.scapy import ScapyIPv4, ScapyIPv6, ScapyPacket, ScapyTCP
from pyp0f.options import OPTIONS


def _impersonate_ip(
    ip: Union[ScapyIPv4, ScapyIPv6], signature: TCPSignature, extra_hops: int = 0
) -> None:
    if ip.version == IPV4:
        ip.ttl = signature.ttl - extra_hops

        if signature.ip_options_length != 0:
            # FIXME: Non-zero IPv4 options not handled
            pass
        else:
            ip.options = []

        if Quirk.DF in signature.quirks:
            ip.flags |= 0x02  # set DF flag

            if Quirk.NZ_ID in signature.quirks:
                # ID should not be zero, overwrite if not already positive
                if ip.id == 0:
                    ip.id = random.randrange(1, 2**16)
            else:
                ip.id = 0
        else:
            ip.flags &= ~(0x02)  # DF flag not set

            if Quirk.ZERO_ID in signature.quirks:
                ip.id = 0
            elif ip.id == 0:
                # ID should not be zero, overwrite if not already positive
                ip.id = random.randrange(1, 2**16)

        if Quirk.ECN in signature.quirks:
            ip.tos |= random.randrange(0x01, 0x04)

        if Quirk.NZ_MBZ in signature.quirks:
            ip.flags |= 0x04
        else:
            ip.flags &= ~(0x04)
    else:
        ip.hlim = signature.ttl - extra_hops

        if Quirk.FLOW in signature.quirks:
            ip.fl = random.randrange(1, 2**20)

        if Quirk.ECN in signature.quirks:
            ip.tc |= random.randrange(0x01, 0x04)


def _impersonate_options(
    tcp: ScapyTCP, signature: TCPSignature, uptime: Optional[int] = None
) -> None:
    tcp_type = tcp.flags & (TCPFlag.SYN | TCPFlag.ACK)  # SYN / SYN+ACK

    def int_only(val: Optional[int]):
        return val if isinstance(val, int) else None

    # Take the options already set as "hints" to use in the new packet if we can.
    original_options = dict(tcp.options)
    mss_hint = int_only(original_options.get("MSS"))
    window_scale_hint = int_only(original_options.get("WScale"))
    timestamp_hint = [
        int_only(value) for value in original_options.get("Timestamp", (None, None))
    ]

    options = []

    for option in signature.options.layout:
        impersonated_option: Optional[Tuple[str, Any]] = None

        if option == TCPOption.MSS:
            # MSS might have a maximum size because of WindowType.MSS
            max_mss = (2**16) // (
                signature.window.size if signature.window.type == WindowType.MSS else 1
            )

            if signature.options.mss == WILDCARD:
                if mss_hint and 0 <= mss_hint <= max_mss:
                    impersonated_option = ("MSS", mss_hint)
                else:
                    # invalid hint, generate new value
                    impersonated_option = ("MSS", random.randrange(100, max_mss))
            else:
                impersonated_option = ("MSS", signature.options.mss)

        elif option == TCPOption.WS:
            if signature.window.scale == WILDCARD:
                max_window_scale = 2**8

                if Quirk.OPT_EXWS in signature.quirks:  # window_scale > 14
                    if window_scale_hint and 14 < window_scale_hint < max_window_scale:
                        impersonated_option = ("WScale", window_scale_hint)
                    else:
                        # invalid hint, generate new value > 14
                        impersonated_option = (
                            "WScale",
                            random.randrange(15, max_window_scale),
                        )
                else:
                    if window_scale_hint and 0 <= window_scale_hint < max_window_scale:
                        impersonated_option = ("WScale", window_scale_hint)
                    else:
                        # invalid hint, generate new value
                        impersonated_option = (
                            "WScale",
                            random.randrange(1, 14),
                        )
            else:
                impersonated_option = ("WScale", signature.window.scale)

        elif option == TCPOption.TS:
            max_ts = 2**32
            ts1, ts2 = timestamp_hint

            if (
                Quirk.OPT_ZERO_TS1 in signature.quirks
            ):  # own timestamp specified as zero
                ts1 = 0
            elif uptime is not None:  # if specified uptime, override
                ts1 = uptime
            elif ts1 is None or not (0 <= ts1 < max_ts):  # invalid hint
                ts1 = random.randint(120, 100 * 60 * 60 * 24 * 365)

            # non-zero peer timestamp on initial SYN
            if Quirk.OPT_NZ_TS2 in signature.quirks and tcp_type == TCPFlag.SYN:
                if ts2 is None or not (0 < ts2 < max_ts):  # invalid hint
                    ts2 = random.randrange(1, max_ts)
            else:
                ts2 = 0

            impersonated_option = ("Timestamp", (ts1, ts2))

        elif option == TCPOption.NOP:
            impersonated_option = ("NOP", None)

        elif option == TCPOption.SACKOK:
            impersonated_option = ("SAckOK", "")

        elif option == TCPOption.EOL:
            impersonated_option = ("EOL", None)
            # FIXME: eol+n & opt+ not handled

        elif option == TCPOption.SACK:
            # Randomize SAck value in range 10 <= val <= 34
            sack_len = random.choice(range(10, 34 + 1, 8))
            impersonated_option = ("SAck", b"\x00" * sack_len)

        if impersonated_option is not None:
            options.append(impersonated_option)

    tcp.options = options


def _impersonate_window(
    tcp: ScapyTCP, signature: TCPSignature, mtu: int = 1500
) -> None:
    if signature.window.type == WindowType.NORMAL:
        tcp.window = signature.window.size

    elif signature.window.type == WindowType.MSS:
        mss = dict(tcp.options).get("MSS")

        if mss is None:
            raise ValueError("TCP window value requires MSS, and MSS option not set")

        tcp.window = mss * signature.window.size

    elif signature.window.type == WindowType.MOD:
        tcp.window = signature.window.size * random.randrange(
            1, 2**16 // signature.window.size
        )

    elif signature.window.type == WindowType.MTU:
        tcp.window = mtu * signature.window.size


def _impersonate_flags(
    tcp: ScapyTCP,
    signature: TCPSignature,
) -> None:
    if Quirk.ZERO_SEQ in signature.quirks:
        tcp.seq = 0
    elif tcp.seq == 0:
        tcp.seq = random.randrange(1, 2**32)

    if Quirk.NZ_ACK in signature.quirks:
        tcp.flags &= ~(TCPFlag.ACK)  # ACK flag not set
        if tcp.ack == 0:
            tcp.ack = random.randrange(1, 2**32)
    elif Quirk.ZERO_ACK in signature.quirks:
        tcp.flags |= TCPFlag.ACK  # ACK flag set
        tcp.ack = 0

    if Quirk.NZ_URG in signature.quirks:
        tcp.flags &= ~(TCPFlag.URG)  # URG flag not set
        if tcp.urgptr == 0:
            tcp.urgptr = random.randrange(1, 2**16)
    elif Quirk.URG in signature.quirks:
        tcp.flags |= TCPFlag.URG  # URG flag used

    if Quirk.PUSH in signature.quirks:
        tcp.flags |= TCPFlag.PSH  # PSH flag used
    else:
        tcp.flags &= ~(TCPFlag.PSH)  # PSH flag not set


def _impersonate_payload(
    tcp: ScapyTCP,
    signature: TCPSignature,
) -> None:
    """
    Impersonate TCP payload if it is not specified as wildcard in the signature.
    """
    if signature.payload_class != WILDCARD:
        if not signature.payload_class:
            tcp.payload = NoPayload()
        elif not tcp.payload:
            tcp.payload = Raw(load=random_string(size=random.randint(1, 10)))


def impersonate(
    packet: ScapyPacket,
    *,
    mtu: int = 1500,
    extra_hops: int = 0,
    uptime: Optional[int] = None,
    raw_label: Optional[str] = None,
    raw_signature: Optional[str] = None,
    database: Database = OPTIONS.database,
) -> ScapyPacket:
    """
    Creates a new copied instance of `packet` and modifies it so that p0f will
    think it has been sent by a specific OS. Either `raw_label` or `raw_signature` is required.

    If `raw_signature` is specified, we use the signature.
    signature format:
        `{ip_ver}:{ttl}:{ip_opt_len}:{mss}:{window,wscale}:{opt_layout}:{quirks}:{pay_class}`

    If `raw_label` is specified, we randomly pick a signature with a label
    that matches `raw_label` (case sensitive!).

    Only TCP SYN/SYN+ACK packets are supported.
    """
    packet = validate_for_impersonation(packet)

    tcp = packet[ScapyTCP]
    tcp_type = tcp.flags & (TCPFlag.SYN | TCPFlag.ACK)  # SYN / SYN+ACK

    if raw_signature is not None:
        signature = TCPSignature.parse(raw_signature)
    else:
        if raw_label is None:
            raise ValueError("raw_label or raw_signature is required to impersonate!")

        direction = (
            Direction.CLIENT_TO_SERVER
            if tcp_type == TCPFlag.SYN
            else Direction.SERVER_TO_CLIENT
        )

        signature = database.get_random(raw_label, TCPRecord, direction).signature

    if signature.ip_version != WILDCARD and packet.version != signature.ip_version:
        raise ValueError("Can't convert between IPv4 and IPv6")

    _impersonate_ip(packet, signature, extra_hops)
    _impersonate_options(tcp, signature, uptime)
    _impersonate_window(tcp, signature, mtu)
    _impersonate_flags(tcp, signature)
    _impersonate_payload(tcp, signature)

    return packet
