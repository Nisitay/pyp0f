from typing import Type, TypeVar

from pyp0f.net.layers.ip import IP, IPV4, IPV4_HEADER_LENGTH
from pyp0f.net.layers.tcp import TCP, TCPFlag, TCPOptions
from pyp0f.net.quirks import Quirk
from pyp0f.net.scapy import ScapyPacket

T = TypeVar("T", bound=ScapyPacket)


def create_scapy_layer(layer_cls: Type[T], **kwargs) -> T:
    return layer_cls(bytes(layer_cls(**kwargs)))


def ip(**kwargs) -> IP:
    args = dict(
        version=IPV4,
        src="127.0.0.1",
        dst="127.0.0.1",
        ttl=64,
        tos=0,
        options_length=0,
        header_length=IPV4_HEADER_LENGTH,
        is_fragment=False,
        quirks=Quirk.DF | Quirk.NZ_ID,
    )

    args.update(**kwargs)

    return IP(**args)  # type: ignore


def tcp(**kwargs) -> TCP:
    args = dict(
        type=TCPFlag.SYN,
        src_port=80,
        dst_port=8080,
        window=8192,
        seq=123456,
        options=TCPOptions([], Quirk(0)),
        payload=b"",
        header_length=20,
        quirks=Quirk(0),
    )

    args.update(**kwargs)

    return TCP(**args)  # type: ignore
