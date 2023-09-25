from dataclasses import dataclass

from pyp0f.database.parse.utils import range_number_parser
from pyp0f.utils.slots import add_slots

from .base import DatabaseSignature


@add_slots
@dataclass
class MTUSignature(DatabaseSignature):
    mtu: int

    @classmethod
    def parse(cls, raw_signature: str):
        return cls(_parse_mtu(raw_signature))


_parse_mtu = range_number_parser(min=1, max=65535)
