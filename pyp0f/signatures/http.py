import re
from dataclasses import dataclass
from typing import Optional, Sequence, Set, List

from pyp0f.utils.slots import add_slots
from pyp0f.utils.parse import WILDCARD, split_parts, fixed_options_parser
from pyp0f.net.packet import Packet
from pyp0f.net.http import HTTP, SigHeader

from .base import DatabaseSig, PacketSig

_parse_version = fixed_options_parser({"*": WILDCARD, "0": 0, "1": 1})


@add_slots
@dataclass
class HttpSig(DatabaseSig):
    version: int
    headers: Sequence[SigHeader]
    absent_headers: Set[bytes]
    expected_sw: Optional[bytes] = None

    def header_names(self) -> Set[bytes]:
        return {header.lower_name for header in self.headers if not header.is_optional}

    @classmethod
    def parse(cls, raw_signature: str):
        version, headers, absent, sw = split_parts(raw_signature, parts=4)

        if absent:
            absent_headers = {name.lower() for name in absent.encode().split(b",")}
        else:
            absent_headers: Set[bytes] = set()

        return cls(
            version=_parse_version(version),
            headers=_parse_headers(headers),
            absent_headers=absent_headers,
            expected_sw=sw.encode() if sw else None,
        )


@add_slots
@dataclass
class HttpPacketSig(PacketSig, HTTP):
    def header_names(self) -> Set[bytes]:
        return {header.lower_name for header in self.headers}

    @classmethod
    def from_packet(cls, packet: Packet):
        return cls.from_buffer(packet.tcp.payload)


def _parse_headers(field: str) -> List[SigHeader]:
    headers: List[SigHeader] = []
    for header in re.split(rb",(?![^\[]*\])", field.encode()):
        if not header:  # Extra comma
            continue
        name, _, value = header.partition(b"=")
        is_optional = name[0:1] == b"?"
        headers.append(
            SigHeader(
                name=name[1:] if is_optional else name,
                value=value[1:-1] if value else None,
                is_optional=is_optional,
            )
        )
    return headers
