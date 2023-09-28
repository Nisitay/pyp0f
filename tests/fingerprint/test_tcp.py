import pytest

from pyp0f.fingerprint.tcp import fingerprint_tcp
from tests._packets import TCP_PACKETS, TCPTestPacket


@pytest.mark.parametrize(
    ("test_packet"),
    TCP_PACKETS,
)
def test_fingerprint_tcp(test_packet: TCPTestPacket):
    result = fingerprint_tcp(test_packet.packet)
    assert result is not None
    assert result.match is not None
    assert result.match.type == test_packet.expected_match_type
    assert result.match.record.label.dump() == test_packet.expected_label
