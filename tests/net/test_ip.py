import pytest

from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP as IPv4, TCP as TCPLayer

from pyp0f.exceptions import PacketError
from pyp0f.net.quirks import Quirk
from pyp0f.net.ip import (
    IP,
    IPV4,
    IPV6,
    IPV4_HEADER_LENGTH,
    IPV6_HEADER_LENGTH,
    IP_TOS_CE,
    guess_distance
)


class TestIP:
    def test_from_packet(self):
        IP.from_packet(IPv4(bytes(IPv4())))
        IP.from_packet(IPv6(bytes(IPv6())))

        with pytest.raises(PacketError):
            IP.from_packet(TCPLayer())

    def test_from_ipv4(self):
        ip = IP._from_ipv4(IPv4(bytes(IPv4(
            src="1.1.1.1",
            dst="2.2.2.2",
            ttl=128,
            tos=IP_TOS_CE,
            frag=1,
            flags="DF",
            id=1,
            options=[]
        ))))

        assert ip == IP(
            version=IPV4,
            src="1.1.1.1",
            dst="2.2.2.2",
            ttl=128,
            tos=0,
            options_length=0,
            header_length=IPV4_HEADER_LENGTH,
            is_fragment=True,
            quirks=Quirk.DF | Quirk.NZ_ID | Quirk.ECN
        )

    def test_from_ipv6(self):
        ip = IP._from_ipv6(IPv6(bytes(IPv6(
            src="2001:1db8:85a3:0000:0000:8a2e:1370:7334",
            dst="2001:1db8:85a3:0000:0000:8a2e:1370:7335",
            hlim=128,
            tc=IP_TOS_CE,
            fl=1,
        ))))

        assert ip == IP(
            version=IPV6,
            src="2001:1db8:85a3::8a2e:1370:7334",
            dst="2001:1db8:85a3::8a2e:1370:7335",
            ttl=128,
            tos=0,
            options_length=0,
            header_length=IPV6_HEADER_LENGTH,
            is_fragment=False,
            quirks=Quirk.FLOW | Quirk.ECN
        )


def test_guess_distance():
    assert guess_distance(32) == 0
    assert guess_distance(30) == 2
    assert guess_distance(60) == 4
    assert guess_distance(120) == 8
    assert guess_distance(155) == 100
