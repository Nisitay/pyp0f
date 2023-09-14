import pytest

from pyp0f.net.packet import Packet
from pyp0f.fingerprint.tcp import fingerprint
from pyp0f.fingerprint.results import TcpMatchType

from tests._packets.tcp import (
    LINUX_311,
    LINUX_22_3,
    WINDOWS_XP,
    LINUX_26_SYN,
    LINUX_26_SYN_ACK,
    WINDOWS_NT_KERNEL,
    WINDOWS_7_OR_8_EXACT,
    WINDOWS_7_OR_8_FUZZY_TTL,
    LINUX_26_SYN_ACK_ANOTHER,
)


@pytest.mark.parametrize(
    ("packet", "expected_label"),
    [
        (LINUX_311, "s:unix:Linux:3.11 and newer"),
        (LINUX_22_3, "g:unix:Linux:2.2.x-3.x"),
        (WINDOWS_XP, "s:win:Windows:XP"),
        (LINUX_26_SYN, "s:unix:Linux:2.6.x"),
        (LINUX_26_SYN_ACK, "s:unix:Linux:2.6.x"),
        (WINDOWS_NT_KERNEL, "g:win:Windows:NT kernel"),
        (WINDOWS_7_OR_8_EXACT, "s:win:Windows:7 or 8"),
        (LINUX_26_SYN_ACK_ANOTHER, "s:unix:Linux:2.6.x"),
    ],
)
def test_fingerprint_exact(packet: Packet, expected_label: str):
    result = fingerprint(packet)
    assert result is not None
    assert result.match is not None
    assert result.match.type == TcpMatchType.EXACT
    assert result.match.record.label.dump() == expected_label


def test_fingerprint_fuzzy():
    result = fingerprint(WINDOWS_7_OR_8_FUZZY_TTL)
    assert result is not None
    assert result.match is not None
    assert result.match.type == TcpMatchType.FUZZY_TTL
    assert result.match.record.label.dump() == "s:win:Windows:7 or 8"
