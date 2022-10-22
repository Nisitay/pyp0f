from dataclasses import dataclass, field
from typing import Optional

from pyp0f.utils.slots import add_slots


@add_slots
@dataclass
class Header:
    name: bytes
    lower_name: bytes = field(init=False)

    def __post_init__(self):
        self.lower_name = self.name.lower()


@add_slots
@dataclass
class PacketHeader(Header):
    value: bytes


@add_slots
@dataclass
class SigHeader(Header):
    is_optional: bool
    value: Optional[bytes] = None
