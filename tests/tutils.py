from pyp0f.net.quirks import Quirk
from pyp0f.net.ip import IP, IPV4, IPV4_HEADER_LENGTH
from pyp0f.net.tcp import TCP, TcpOptions, TcpFlag


def ip(**kwargs) -> IP:
    default = dict(
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
    default.update(kwargs)
    return IP(**default)


def tcp(**kwargs) -> TCP:
    default = dict(
        type=TcpFlag.SYN,
        sport=80,
        dport=8080,
        window=8192,
        seq=123456,
        options=TcpOptions([], Quirk(0)),
        payload=b"",
        header_length=20,
        quirks=Quirk(0),
    )
    default.update(kwargs)
    return TCP(**default)
