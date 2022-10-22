import pytest

from pyp0f.net.packet import Packet
from pyp0f.fingerprint.mtu import fingerprint

from tests._packets.mtu import (
    GOOGLE,
    IPIP_OR_SIT,
    IPSEC_OR_GRE,
    ETHERNET_OR_MODEM,
    GENERIC_TUNNEL_OR_VPN
)


@pytest.mark.parametrize(
    ("packet", "expected_label"),
    [
        (GOOGLE, "Google"),
        (IPIP_OR_SIT, "IPIP or SIT"),
        (IPSEC_OR_GRE, "IPSec or GRE"),
        (ETHERNET_OR_MODEM, "Ethernet or modem"),
        (GENERIC_TUNNEL_OR_VPN, "generic tunnel or VPN"),
    ]
)
def test_fingerprint(packet: Packet, expected_label: str):
    result = fingerprint(packet)
    assert result.match is not None
    assert result.match.label.name == expected_label
