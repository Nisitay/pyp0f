from datetime import datetime
from contextlib import suppress
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Optional, Sequence

from scapy.layers.inet import TCP as TCPLayer
from scapy.packet import Packet as ScapyPacket

from pyp0f.exceptions import PacketError

from ..layer import Layer
from .headers import PacketHeader
from .read import BufferLike, read_payload


@dataclass
class HTTP(Layer):
    version: int
    headers: Sequence[PacketHeader]

    def _find_value(self, name: bytes) -> Optional[bytes]:
        lower_name = name.lower()
        return next(
            (
                header.value
                for header in self.headers
                if header.lower_name == lower_name
            ),
            None,
        )

    @property
    def sw(self) -> Optional[bytes]:
        return self._find_value(b"User-Agent") or self._find_value(b"Server")

    @property
    def via(self) -> Optional[bytes]:
        return self._find_value(b"Via") or self._find_value(b"X-Forwarded-For")

    @property
    def lang(self) -> Optional[bytes]:
        return self._find_value(b"Accept-Language")

    @property
    def date(self) -> Optional[datetime]:
        value = self._find_value(b"Date")
        if value is not None:
            with suppress(TypeError, ValueError):
                return parsedate_to_datetime(value.decode())
        return None

    @classmethod
    def from_buffer(cls, buffer: BufferLike):
        _, version, headers = read_payload(buffer)
        return cls(version=version, headers=headers)

    @classmethod
    def from_packet(cls, packet: ScapyPacket):
        if TCPLayer not in packet:
            raise PacketError("Packet doesn't have an TCP layer!")
        return cls.from_buffer(bytes(packet[TCPLayer].payload))
