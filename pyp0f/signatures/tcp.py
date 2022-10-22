from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Tuple, List

from pyp0f.exceptions import FieldError
from pyp0f.utils.slots import add_slots
from pyp0f.utils.parse import (
    WILDCARD,
    split_parts,
    parse_from_options,
    parse_num_in_range,
    fixed_options_parser,
    range_num_parser
)
from pyp0f.net.ip import IPV4, IPV6
from pyp0f.net.packet import Packet
from pyp0f.net.quirks import Quirk, QUIRK_STRINGS
from pyp0f.net.tcp.base import MIN_TCP4, MIN_TCP6
from pyp0f.net.tcp.options import TcpOptions, TcpOption, OPTION_STRINGS

from .base import DatabaseSig, PacketSig


STRING_QUIRKS = {v: k for k, v in QUIRK_STRINGS.items()}
STRING_OPTIONS = {v: k for k, v in OPTION_STRINGS.items()}
INVALID_QUIRKS = {
    IPV4: Quirk.FLOW,
    IPV6: Quirk.DF | Quirk.NZ_ID | Quirk.ZERO_ID | Quirk.NZ_MBZ
}

_parse_ip_version = fixed_options_parser({
    "*": WILDCARD,
    "4": IPV4,
    "6": IPV6
})

_parse_payload_class = fixed_options_parser({
    "*": WILDCARD,
    "0": 0,
    "+": 1
})

_parse_mss = range_num_parser(min=0, max=65535, wildcard=True)
_parse_win_scale = range_num_parser(min=0, max=255, wildcard=True)
_parse_ip_options_length = range_num_parser(min=0, max=255, wildcard=False)


class WinType(Enum):
    NORMAL = auto()
    ANY = auto()
    MOD = auto()
    MSS = auto()
    MTU = auto()


@add_slots
@dataclass
class _TcpSig:
    """
    Common fields for database & packet TCP signatures.
    """
    ip_version: int
    ttl: int
    ip_options_length: int
    win_size: int
    quirks: Quirk


@add_slots
@dataclass
class TcpSig(DatabaseSig, _TcpSig):
    is_bad_ttl: bool
    mss: int
    win_type: WinType
    win_scale: int
    options_layout: List[int]
    payload_class: int
    eol_pad_length: int

    @classmethod
    def parse(cls, raw_signature: str):
        (
            ip_ver,
            ittl,
            ip_options_length,
            mss,
            window,
            options,
            quirks,
            payload_class
        ) = split_parts(raw_signature, parts=8)

        ip_version = _parse_ip_version(ip_ver)
        ttl, is_bad_ttl = _parse_ttl(ittl)
        options_layout, eol_pad_length = _parse_options(options)

        win, _, scale = window.partition(",")
        win_type, win_size = _parse_win_size(win)

        return cls(
            ip_version=ip_version,
            ttl=ttl,
            ip_options_length=_parse_ip_options_length(ip_options_length),
            win_size=win_size,
            quirks=_parse_quirks(quirks, ip_version),
            is_bad_ttl=is_bad_ttl,
            mss=_parse_mss(mss),
            win_type=win_type,
            win_scale=_parse_win_scale(scale),
            options_layout=options_layout,
            payload_class=_parse_payload_class(payload_class),
            eol_pad_length=eol_pad_length
        )


@add_slots
@dataclass
class TcpPacketSig(PacketSig, _TcpSig):
    has_payload: bool
    headers_length: int
    options: TcpOptions
    syn_mss: Optional[int] = None

    # Cached window multiplier
    _win_multi: Optional[Tuple[int, bool]] = field(init=False)

    def __post_init__(self):
        # Since dataclass with slots and field(default=None) don't work,
        # initialize the value here
        self._win_multi = None

    @classmethod
    def from_packet(cls, packet: Packet, syn_mss: Optional[int] = None):
        return cls(
            ip_version=packet.ip.version,
            ttl=packet.ip.ttl,
            ip_options_length=packet.ip.options_length,
            win_size=packet.tcp.window,
            quirks=packet.ip.quirks | packet.tcp.quirks,
            has_payload=bool(packet.tcp.payload),
            headers_length=packet.ip.header_length + packet.tcp.header_length,
            options=packet.tcp.options,
            syn_mss=syn_mss
        )

    @property
    def window_multiplier(self) -> Tuple[int, bool]:
        """
        Figure out if window size is a multiplier of MSS or MTU.
        Returns the multiplier and whether MTU should be used.
        Caches the calculated result for next calls.
        """
        if self._win_multi is None:
            self._win_multi = self._window_multiplier()
        return self._win_multi

    def _window_multiplier(self) -> Tuple[int, bool]:
        if not self.win_size or self.options.mss < 100:
            return WILDCARD, False

        divs: List[Tuple[int, bool]] = []

        def add_div(div: int, use_mtu: bool = False):
            divs.append((div, use_mtu))

        add_div(self.options.mss)

        # Some systems will sometimes subtract 12 bytes when timestamps are in use.
        if self.options.timestamp:
            add_div(self.options.mss - 12)

        # Some systems use MTU on the wrong interface
        add_div(1500 - MIN_TCP4)
        add_div(1500 - MIN_TCP4 - 12)

        if self.ip_version == IPV6:
            add_div(1500 - MIN_TCP6)
            add_div(1500 - MIN_TCP6 - 12)

        # Some systems use MTU instead of MSS:
        add_div(self.options.mss + MIN_TCP4, use_mtu=True)
        add_div(self.options.mss + self.headers_length, use_mtu=True)
        if self.ip_version == IPV6:
            add_div(self.options.mss + MIN_TCP6, use_mtu=True)
        add_div(1500, use_mtu=True)

        # On SYN+ACKs, some systems use of the peer:
        if self.syn_mss is not None:
            add_div(self.syn_mss)  # peer MSS
            add_div(self.syn_mss - 12)  # peer MSS - 12

        for div, use_mtu in divs:
            if div and not self.win_size % div:
                return self.win_size // div, use_mtu
        return WILDCARD, False


def _parse_ttl(field: str) -> Tuple[int, bool]:
    """
    Parse TTL field.
    Valid values:
        - ``ttl`` -> ``1 <= ttl <= 255``.
        - ``ttl+dist`` -> ``dist >= 0 && ttl+dist <= 255``.
        - ``ttl-``.
    """
    raw_ttl = field
    is_bad_ttl = False
    dist = 0

    if field[-1] == "-":
        is_bad_ttl = True
        raw_ttl = field[:-1]

    elif "+" in field:
        raw_ttl, _, raw_dist = field.partition("+")
        dist = int(raw_dist)

    ttl = parse_num_in_range(raw_ttl, min=1, max=255) + dist

    if dist < 0 or ttl > 255:
        raise FieldError("Invalid TTL field")

    return ttl, is_bad_ttl


def _parse_win_size(field: str) -> Tuple[WinType, int]:
    """
    Parse window size field.
    Valid values:
        - ``*``.
        - ``win`` -> ``0 <= win <= 65535``.
        - ``mss*win``/``mtu*win`` -> ``1 <= win <= 1000``.
        - ``%win`` -> ``2 <= win <= 65535``.
    """
    if field == "*":
        return WinType.ANY, WILDCARD

    if field.startswith(("mss*", "mtu*")):
        win_type = WinType.MSS if field[1] == "s" else WinType.MTU
        size = parse_num_in_range(field[4:], min=1, max=1000)

    elif field[0] == "%":
        win_type = WinType.MOD
        size = parse_num_in_range(field[1:], min=2, max=65535)

    else:
        win_type = WinType.NORMAL
        size = parse_num_in_range(field, min=0, max=65535)

    return win_type, size


def _parse_options(field: str) -> Tuple[List[int], int]:
    """
    Parse TCP options layout field.
    """
    options: List[int] = []
    eol_pad_length = 0
    raw_options = field.split(",") if field else []

    for raw_option in raw_options:
        if raw_option[0] == "?":
            option = parse_num_in_range(raw_option[1:], min=0, max=255)

        elif raw_option.startswith("eol+"):
            option = TcpOption.EOL
            eol_pad_length = parse_num_in_range(raw_option[4:], min=0, max=255)

        else:
            option = parse_from_options(raw_option, options=STRING_OPTIONS)

        options.append(option)

    return options, eol_pad_length


def _parse_quirks(field: str, ip_version: Optional[int] = None) -> Quirk:
    """
    Parse quirks field.
    """
    quirks = Quirk(0)
    raw_quirks = field.split(",") if field else []
    invalid_quirks = INVALID_QUIRKS.get(ip_version) if ip_version is not None else None

    for raw_quirk in raw_quirks:
        quirk = parse_from_options(raw_quirk, options=STRING_QUIRKS)

        if invalid_quirks is not None and quirk in invalid_quirks:
            raise FieldError(f"Quirk {raw_quirk!r} is invalid for IPv{ip_version}")

        quirks |= quirk

    return quirks
