from dataclasses import dataclass, field
from typing import Set

from pyp0f.net.layers.http import HTTP
from pyp0f.net.packet import Packet
from pyp0f.utils.slots import add_slots

from .base import PacketSignature


@add_slots
@dataclass
class HTTPPacketSignature(PacketSignature, HTTP):
    header_names: Set[bytes] = field(init=False)

    def __post_init__(self):
        self.header_names = {header.lower_name for header in self.headers}

    @classmethod
    def from_packet(cls, packet: Packet):
        return cls.from_buffer(packet.tcp.payload)
