import pytest
from scapy.layers.inet import IP as IPv4
from scapy.layers.inet import TCP as TCPLayer
from scapy.layers.inet6 import IPv6

from pyp0f.exceptions import PacketError
from pyp0f.net.layers.ip import (
    IP,
    IP_TOS_CE,
    IPV4,
    IPV4_HEADER_LENGTH,
    IPV6,
    IPV6_HEADER_LENGTH,
)
from pyp0f.net.quirks import Quirk

from ...tutils import create_scapy_layer


class TestIP:
    def test_from_packet(self):
        IP.from_packet(create_scapy_layer(IPv4))
        IP.from_packet(create_scapy_layer(IPv6))

        with pytest.raises(PacketError):
            IP.from_packet(create_scapy_layer(TCPLayer))

    def test_from_ipv4(self):
        ip = IP._from_ipv4(
            create_scapy_layer(
                IPv4,
                src="1.1.1.1",
                dst="2.2.2.2",
                ttl=128,
                tos=IP_TOS_CE,
                frag=1,
                flags="DF",
                id=1,
                options=[],
            )
        )

        assert ip == IP(
            version=IPV4,
            src="1.1.1.1",
            dst="2.2.2.2",
            ttl=128,
            tos=0,
            options_length=0,
            header_length=IPV4_HEADER_LENGTH,
            is_fragment=True,
            quirks=Quirk.DF | Quirk.NZ_ID | Quirk.ECN,
        )

    def test_from_ipv6(self):
        ip = IP._from_ipv6(
            create_scapy_layer(
                IPv6,
                src="2001:1db8:85a3:0000:0000:8a2e:1370:7334",
                dst="2001:1db8:85a3:0000:0000:8a2e:1370:7335",
                hlim=128,
                tc=IP_TOS_CE,
                fl=1,
            )
        )

        assert ip == IP(
            version=IPV6,
            src="2001:1db8:85a3::8a2e:1370:7334",
            dst="2001:1db8:85a3::8a2e:1370:7335",
            ttl=128,
            tos=0,
            options_length=0,
            header_length=IPV6_HEADER_LENGTH,
            is_fragment=False,
            quirks=Quirk.FLOW | Quirk.ECN,
        )
