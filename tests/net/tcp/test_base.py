import pytest

from scapy.layers.inet import IP as IPv4, TCP as TCPLayer

from pyp0f.exceptions import PacketError
from pyp0f.net.quirks import Quirk
from pyp0f.net.tcp import TCP, TcpFlag, TcpOptions
from pyp0f.net.tcp.base import TCP_HEADER_LENGTH

from tests.tutils import tcp


class TestTCP:
    def test_post_init(self):
        assert tcp(type=TcpFlag.PSH | TcpFlag.SYN).type == TcpFlag.SYN

        t = tcp(
            options=TcpOptions(layout=[], quirks=Quirk.OPT_BAD),
            quirks=Quirk.DF
        )
        assert t.quirks == Quirk.DF | Quirk.OPT_BAD

    def test_from_packet(self):
        with pytest.raises(PacketError):
            TCP.from_packet(IPv4())

        layer = TCP.from_packet(TCPLayer(bytes(TCPLayer(
            sport=80,
            dport=8080,
            seq=0,
            ack=1,
            flags="SEP",
            window=8192,
            urgptr=1,
            options=[]
        ))) / b"Payload")

        assert layer == TCP(
            type=TcpFlag.SYN,
            sport=80,
            dport=8080,
            window=8192,
            seq=0,
            options=TcpOptions([], Quirk(0)),
            payload=b"Payload",
            header_length=TCP_HEADER_LENGTH,
            quirks=Quirk.ZERO_SEQ | Quirk.NZ_ACK | Quirk.ECN | Quirk.PUSH | Quirk.NZ_URG
        )
