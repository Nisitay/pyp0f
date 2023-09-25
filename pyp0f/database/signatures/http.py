import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set

from pyp0f.database.parse.utils import fixed_numerical_options_parser, split_parts
from pyp0f.net.layers.http import Header
from pyp0f.utils.slots import add_slots

from .base import DatabaseSignature


@add_slots
@dataclass
class SignatureHeader(Header):
    is_optional: bool
    value: Optional[bytes] = None


@add_slots
@dataclass
class HTTPSignature(DatabaseSignature):
    version: int
    headers: Sequence[SignatureHeader]
    absent_headers: Set[bytes]
    expected_software: Optional[bytes] = None

    header_names: Set[bytes] = field(init=False)

    def __post_init__(self):
        self.header_names = {
            header.lower_name for header in self.headers if not header.is_optional
        }

    @classmethod
    def parse(cls, raw_signature: str):
        raw_version, raw_headers, raw_absent_headers, software = split_parts(
            raw_signature, parts=4
        )

        if raw_absent_headers:
            absent_headers = {
                name.lower() for name in raw_absent_headers.encode().split(b",")
            }
        else:
            absent_headers: Set[bytes] = set()

        return cls(
            version=_parse_version(raw_version),
            headers=_parse_headers(raw_headers),
            absent_headers=absent_headers,
            expected_software=software.encode() if software else None,
        )


_HEADER_PATTERN = re.compile(rb",(?![^\[]*\])")

_parse_version = fixed_numerical_options_parser({"0": 0, "1": 1}, wildcard=True)


def _parse_headers(field: str) -> List[SignatureHeader]:
    headers: List[SignatureHeader] = []

    for header in _HEADER_PATTERN.split(field.encode()):
        if not header:  # Extra comma
            continue

        name, _, value = header.partition(b"=")
        is_optional = name[0:1] == b"?"
        headers.append(
            SignatureHeader(
                name=name[1:] if is_optional else name,
                value=value[1:-1] if value else None,
                is_optional=is_optional,
            )
        )

    return headers
