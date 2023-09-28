from pyp0f.fingerprint.uptime import fingerprint_uptime
from pyp0f.net.signatures import TCPPacketSignature
from pyp0f.utils.time import get_unix_time_ms
from tests._packets.uptime import ACK_TIMESTAMP, SYN_TIMESTAMP, TIMESTAMP_MS_DIFF


def test_fingerprint_uptime():
    syn_signature = TCPPacketSignature.from_packet(SYN_TIMESTAMP)
    syn_signature.received = get_unix_time_ms() - TIMESTAMP_MS_DIFF

    result = fingerprint_uptime(ACK_TIMESTAMP, last_packet_signature=syn_signature)
    assert result.tps is not None
    assert result.uptime is not None
    assert result.tps == 100
    assert result.uptime.frequency == 100
    assert result.uptime.total_minutes == 257
    assert result.uptime.modulo_days == 497
