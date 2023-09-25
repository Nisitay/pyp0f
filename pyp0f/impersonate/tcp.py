import random
from typing import Any, List, Optional, Tuple, TypeVar

from scapy.packet import NoPayload, Raw

from pyp0f.database import Database
from pyp0f.database.parse.utils import WILDCARD
from pyp0f.database.records import TCPRecord
from pyp0f.database.signatures import TCPSignature, WindowType
from pyp0f.impersonate.utils import random_string, validate_for_impersonation
from pyp0f.net.layers.ip import IPV6
from pyp0f.net.layers.tcp import TCPFlag, TCPOption
from pyp0f.net.packet import Direction
from pyp0f.net.quirks import Quirk
from pyp0f.net.scapy import ScapyIPv4, ScapyIPv6, ScapyPacket, ScapyTCP
from pyp0f.options import OPTIONS

T = TypeVar("T", bound=ScapyPacket)


def _impersonate_ip(ip: T, signature: TCPSignature, extra_hops: int = 0) -> T:
    if ip.version == IPV6:
        return ScapyIPv6(
            src=ip.src,
            dst=ip.dst,
            hlim=signature.ttl - extra_hops,
            fl=random.randrange(0x01, 2**20)
            if Quirk.FLOW in signature.quirks
            else 0x0,
            tc=random.randrange(0x01, 0x04) if Quirk.ECN in signature.quirks else 0x0,
        )

    flags = ip.flags
    identification = ip.id

    if Quirk.DF in signature.quirks:
        flags |= 0x02  # set DF flag

        if Quirk.NZ_ID in signature.quirks:
            # ID should not be zero, overwrite if not already positive
            if identification == 0:
                identification = random.randrange(0x01, 2**16)
        else:
            identification = 0
    else:
        flags &= ~(0x02)  # DF flag not set

        if Quirk.ZERO_ID in signature.quirks:
            identification = 0
        elif identification == 0:
            # ID should not be zero, overwrite if not already positive
            identification = random.randrange(0x01, 2**16)

    if Quirk.NZ_MBZ in signature.quirks:
        flags |= 0x04
    else:
        flags &= ~(0x04)

    return ScapyIPv4(
        src=ip.src,
        dst=ip.dst,
        frag=ip.frag,
        proto=ip.proto,
        flags=flags,
        id=identification,
        ttl=signature.ttl - extra_hops,
        tos=random.randrange(0x01, 0x04) if Quirk.ECN in signature.quirks else 0x0,
        options=[],  # FIXME: Non-zero IPv4 options not handled -> signature.ip_options_length != 0
    )


def _impersonate_options(
    tcp: ScapyTCP, signature: TCPSignature, uptime: Optional[int] = None
) -> List[Tuple[str, Any]]:
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

    return options


def _impersonate_window(
    tcp: ScapyTCP,
    signature: TCPSignature,
    new_options: List[Tuple[str, Any]],
    mtu: int = 1500,
) -> int:
    if signature.window.type == WindowType.NORMAL:
        return signature.window.size

    if signature.window.type == WindowType.MSS:
        mss = dict(new_options).get("MSS")

        if mss is None:
            raise ValueError(
                "TCP window value requires MSS, but MSS option is not set on packet"
            )

        return mss * signature.window.size

    if signature.window.type == WindowType.MOD:
        return signature.window.size * random.randrange(
            1, 2**16 // signature.window.size
        )

    if signature.window.type == WindowType.MTU:
        return mtu * signature.window.size

    # WindowType.ANY -> Return existing window
    return tcp.window


def _impersonate_tcp(
    tcp: ScapyTCP,
    signature: TCPSignature,
    mtu: int = 1500,
    uptime: Optional[int] = None,
) -> ScapyTCP:
    seq = tcp.seq
    ack = tcp.ack
    flags = tcp.flags
    urgptr = tcp.urgptr

    if Quirk.ZERO_SEQ in signature.quirks:  # Must remove existing seq
        seq = 0
    elif seq == 0:  # Must have seq, generate random
        seq = random.randrange(1, 2**32)

    if Quirk.NZ_ACK in signature.quirks:
        flags &= ~(TCPFlag.ACK)  # ACK flag not set
        if ack == 0:  # Must have ack, generate random
            ack = random.randrange(1, 2**32)
    elif Quirk.ZERO_ACK in signature.quirks:
        flags |= TCPFlag.ACK  # ACK flag set
        ack = 0  # Must remove existing ack

    if Quirk.NZ_URG in signature.quirks:
        flags &= ~(TCPFlag.URG)  # URG flag not set
        if urgptr == 0:  # Must have urgptr, generate random
            urgptr = random.randrange(1, 2**16)
    elif Quirk.URG in signature.quirks:
        flags |= TCPFlag.URG  # URG flag used

    if Quirk.PUSH in signature.quirks:
        flags |= TCPFlag.PSH  # PSH flag used
    else:
        flags &= ~(TCPFlag.PSH)  # PSH flag not set

    options = _impersonate_options(tcp, signature, uptime)

    return ScapyTCP(
        sport=tcp.sport,
        dport=tcp.dport,
        seq=seq,
        ack=ack,
        flags=flags,
        urgptr=urgptr,
        options=options,
        window=_impersonate_window(tcp, signature, options, mtu),
    )


def _impersonate_payload(tcp: ScapyTCP, signature: TCPSignature) -> ScapyPacket:
    if signature.payload_class == WILDCARD:  # Any payload, return existing payload
        return tcp.payload

    if not signature.payload_class:  # Must remove existing payload
        return NoPayload()

    # Must have payload, generate random or return existing.
    return (
        tcp.payload
        if tcp.payload
        else Raw(load=random_string(size=random.randint(1, 10)))
    )


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
    Creates a new instance of `packet` with modified fields so that p0f will
    think it has been sent by a specific OS. Either `raw_label` or `raw_signature` is required.

    If `raw_signature` is specified, we use the signature.
    signature format (as appears in database):
        `{ip_ver}:{ttl}:{ip_opt_len}:{mss}:{window,wscale}:{opt_layout}:{quirks}:{pay_class}`

    If only `raw_label` is specified, we randomly pick a signature with a label
    that matches `raw_label` (case sensitive!).

    Only TCP SYN/SYN+ACK packets are supported.
    """
    validate_for_impersonation(packet)

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

    return (
        _impersonate_ip(packet, signature, extra_hops)
        / _impersonate_tcp(tcp, signature, mtu, uptime)
        / _impersonate_payload(tcp, signature)
    )
