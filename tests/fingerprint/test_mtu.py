import pytest

from pyp0f.fingerprint.mtu import fingerprint
from tests._packets import MTU_PACKETS, MTUTestPacket


@pytest.mark.parametrize(
    ("test_packet"),
    MTU_PACKETS,
)
def test_fingerprint(test_packet: MTUTestPacket):
    result = fingerprint(test_packet.packet)
    assert result.match is not None
    assert result.match.label.name == test_packet.expected_label
