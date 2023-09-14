import pytest

from pyp0f.exceptions import FieldError
from pyp0f.utils.parse import WILDCARD
from pyp0f.net.quirks import Quirk
from pyp0f.net.tcp import TcpOption
from pyp0f.signatures.tcp import (
    WinType,
    _parse_ttl,
    _parse_quirks,
    _parse_options,
    _parse_win_size,
)


def test_parse_ttl():
    assert _parse_ttl("64") == (64, False)
    assert _parse_ttl("56+8") == (64, False)
    assert _parse_ttl("128-") == (128, True)

    with pytest.raises(FieldError):
        _parse_ttl("0")

    with pytest.raises(FieldError):
        _parse_ttl("256")

    with pytest.raises(FieldError):
        _parse_ttl("255+1")


def test_parse_win_size():
    assert _parse_win_size("*") == (WinType.ANY, WILDCARD)
    assert _parse_win_size("mss*8") == (WinType.MSS, 8)
    assert _parse_win_size("mtu*8") == (WinType.MTU, 8)
    assert _parse_win_size("%8192") == (WinType.MOD, 8192)
    assert _parse_win_size("1400") == (WinType.NORMAL, 1400)

    with pytest.raises(FieldError):
        _parse_win_size("-1")

    with pytest.raises(FieldError):
        _parse_win_size("mss*0")

    with pytest.raises(FieldError):
        _parse_win_size("%1")


def test_parse_options():
    assert _parse_options("ws,ts") == ([TcpOption.WS, TcpOption.TS], 0)
    assert _parse_options("nop,?6,eol+2") == ([TcpOption.NOP, 6, TcpOption.EOL], 2)

    with pytest.raises(FieldError):
        _parse_options("nop,?256")

    with pytest.raises(FieldError):
        _parse_options("nop,eol+256")


def test_parse_quirks():
    assert _parse_quirks("df,id+,ecn") == Quirk.DF | Quirk.NZ_ID | Quirk.ECN

    with pytest.raises(FieldError):
        _parse_quirks("d,f")

    with pytest.raises(FieldError):
        _parse_quirks("df,id+", ip_version=6)

    with pytest.raises(FieldError):
        _parse_quirks("df,flow", ip_version=4)
