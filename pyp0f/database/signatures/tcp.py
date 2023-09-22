from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Tuple

from pyp0f.database.parse.utils import (
    fixed_numerical_options_parser,
    parse_from_options,
    parse_number_in_range,
    range_number_parser,
    split_parts,
)
from pyp0f.database.parse.wildcard import WILDCARD, is_wildcard
from pyp0f.exceptions import FieldError
from pyp0f.net.layers.ip import IPV4, IPV6
from pyp0f.net.layers.tcp import OPTION_STRINGS, TCPOption
from pyp0f.net.quirks import QUIRK_STRINGS, Quirk
from pyp0f.utils.slots import add_slots

from .base import DatabaseSignature


class WindowType(Enum):
    NORMAL = auto()
    ANY = auto()
    MOD = auto()
    MSS = auto()
    MTU = auto()


@add_slots
@dataclass
class WindowSignature:
    type: WindowType
    size: int
    scale: int


@add_slots
@dataclass
class OptionsSignature:
    layout: List[int]
    mss: int
    eol_padding_length: int


@add_slots
@dataclass
class TCPSignature(DatabaseSignature):
    ip_version: int
    ip_options_length: int
    ttl: int
    is_bad_ttl: bool

    window: WindowSignature
    options: OptionsSignature

    payload_class: int
    quirks: Quirk

    @classmethod
    def parse(cls, raw_signature: str):
        (
            raw_ip_version,
            raw_ttl,
            raw_ip_options_length,
            raw_mss,
            raw_window,
            raw_options,
            raw_quirks,
            raw_payload_class,
        ) = split_parts(raw_signature, parts=8)

        ip_version = _parse_ip_version(raw_ip_version)
        ttl, is_bad_ttl = _parse_ttl(raw_ttl)
        mss = _parse_mss(raw_mss)
        options_layout, eol_padding_length = _parse_options(raw_options)

        options = OptionsSignature(options_layout, mss, eol_padding_length)

        return cls(
            ip_version=ip_version,
            ip_options_length=_parse_ip_options_length(raw_ip_options_length),
            ttl=ttl,
            is_bad_ttl=is_bad_ttl,
            window=_parse_window(raw_window),
            options=options,
            payload_class=_parse_payload_class(raw_payload_class),
            quirks=_parse_quirks(raw_quirks, ip_version),
        )


_STRING_QUIRKS = {v: k for k, v in QUIRK_STRINGS.items()}
_STRING_OPTIONS = {v: k for k, v in OPTION_STRINGS.items()}
_INVALID_QUIRKS = {
    IPV4: Quirk.FLOW,
    IPV6: Quirk.DF | Quirk.NZ_ID | Quirk.ZERO_ID | Quirk.NZ_MBZ,
}

_parse_ip_version = fixed_numerical_options_parser(
    {"4": IPV4, "6": IPV6}, wildcard=True
)
_parse_ip_options_length = range_number_parser(min=0, max=255, wildcard=False)
_parse_mss = range_number_parser(min=0, max=65535, wildcard=True)
_parse_payload_class = fixed_numerical_options_parser({"0": 0, "+": 1}, wildcard=True)


def _parse_ttl(field: str) -> Tuple[int, bool]:
    """
    Parse TTL field.
    Valid values:
        - ``ttl`` (``1 <= ttl <= 255``).
        - ``ttl+dist`` (``dist >= 0 && ttl+dist <= 255``).
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

    ttl = parse_number_in_range(raw_ttl, min=1, max=255) + dist

    if dist < 0 or ttl > 255:
        raise FieldError("Invalid TTL field")

    return ttl, is_bad_ttl


def _parse_window(field: str) -> WindowSignature:
    raw_window, _, raw_scale = field.partition(",")

    if is_wildcard(raw_window):
        type = WindowType.ANY
        size = WILDCARD

    elif raw_window.startswith(("mss*", "mtu*")):
        type = WindowType.MSS if raw_window[1] == "s" else WindowType.MTU
        size = parse_number_in_range(raw_window[4:], min=1, max=1000)

    elif raw_window[0] == "%":
        type = WindowType.MOD
        size = parse_number_in_range(raw_window[1:], min=2, max=65535)

    else:
        type = WindowType.NORMAL
        size = parse_number_in_range(raw_window, min=0, max=65535)

    scale = parse_number_in_range(raw_scale, min=0, max=255, wildcard=True)

    return WindowSignature(type, size, scale)


def _parse_options(field: str) -> Tuple[List[int], int]:
    options: List[int] = []
    eol_padding_length = 0
    raw_options = field.split(",") if field else []

    for raw_option in raw_options:
        if raw_option[0] == "?":
            option = parse_number_in_range(raw_option[1:], min=0, max=255)

        elif raw_option.startswith("eol+"):
            option = TCPOption.EOL
            eol_padding_length = parse_number_in_range(raw_option[4:], min=0, max=255)

        else:
            option = parse_from_options(raw_option, options=_STRING_OPTIONS)

        options.append(option)

    return options, eol_padding_length


def _parse_quirks(field: str, ip_version: int) -> Quirk:
    quirks = Quirk(0)
    raw_quirks = field.split(",") if field else []
    invalid_quirks = _INVALID_QUIRKS.get(ip_version)

    for raw_quirk in raw_quirks:
        quirk = parse_from_options(raw_quirk, options=_STRING_QUIRKS)

        if invalid_quirks is not None and quirk in invalid_quirks:
            raise FieldError(f"Quirk {raw_quirk!r} is invalid for IPv{ip_version}")

        quirks |= quirk

    return quirks
