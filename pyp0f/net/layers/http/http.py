from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Optional, Sequence

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.base import Layer
from pyp0f.net.layers.http.header import PacketHeader
from pyp0f.net.layers.http.read import BufferLike, read_payload
from pyp0f.net.scapy import ScapyPacket, ScapyTCP


@dataclass
class HTTP(Layer):
    version: int

    # TODO: Use ordered dict for better lookup performance
    headers: Sequence[PacketHeader]

    def _get_header_value(self, name: bytes) -> Optional[bytes]:
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
    def software(self) -> Optional[bytes]:
        return self._get_header_value(b"User-Agent") or self._get_header_value(
            b"Server"
        )

    @property
    def via(self) -> Optional[bytes]:
        return self._get_header_value(b"Via") or self._get_header_value(
            b"X-Forwarded-For"
        )

    @property
    def language(self) -> Optional[bytes]:
        return self._get_header_value(b"Accept-Language")

    @property
    def date(self) -> Optional[datetime]:
        value = self._get_header_value(b"Date")

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
        if ScapyTCP not in packet or not packet[ScapyTCP].payload:
            raise PacketError("Packet doesn't have an TCP layer or payload!")

        return cls.from_buffer(bytes(packet[ScapyTCP].payload))
