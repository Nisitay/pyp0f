import pytest
from scapy.layers.inet import IP as IPv4
from scapy.layers.inet import TCP as TCPLayer

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.tcp import TCP, TCP_HEADER_LENGTH, TCPFlag, TCPOptions
from pyp0f.net.quirks import Quirk
from tests.tutils import create_scapy_layer, tcp


class TestTCP:
    def test_post_init(self):
        assert tcp(type=TCPFlag.PSH | TCPFlag.SYN).type == TCPFlag.SYN

        t = tcp(options=TCPOptions(layout=[], quirks=Quirk.OPT_BAD), quirks=Quirk.DF)
        assert t.quirks == Quirk.DF | Quirk.OPT_BAD

    def test_from_packet(self):
        with pytest.raises(PacketError):
            TCP.from_packet(IPv4())

        layer = TCP.from_packet(
            create_scapy_layer(
                TCPLayer,
                sport=80,
                dport=8080,
                seq=0,
                ack=1,
                flags="SEP",
                window=8192,
                urgptr=1,
                options=[],
            )
            / b"Payload"
        )

        assert layer == TCP(
            type=TCPFlag.SYN,
            src_port=80,
            dst_port=8080,
            window=8192,
            seq=0,
            options=TCPOptions([], Quirk(0)),
            payload=b"Payload",
            header_length=TCP_HEADER_LENGTH,
            quirks=Quirk.ZERO_SEQ
            | Quirk.NZ_ACK
            | Quirk.ECN
            | Quirk.PUSH
            | Quirk.NZ_URG,
        )
