import pytest

from pyp0f.database.parse.wildcard import WILDCARD
from pyp0f.database.signatures.tcp import (
    WindowSignature,
    WindowType,
    _parse_options,
    _parse_quirks,
    _parse_ttl,
    _parse_window,
)
from pyp0f.exceptions import FieldError
from pyp0f.net.layers.tcp import TCPOption
from pyp0f.net.quirks import Quirk


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


def test_parse_window():
    assert _parse_window("*,*") == WindowSignature(WindowType.ANY, WILDCARD, WILDCARD)
    assert _parse_window("mss*8,*") == WindowSignature(WindowType.MSS, 8, WILDCARD)
    assert _parse_window("mtu*8,*") == WindowSignature(WindowType.MTU, 8, WILDCARD)
    assert _parse_window("%8192,*") == WindowSignature(WindowType.MOD, 8192, WILDCARD)
    assert _parse_window("1400,*") == WindowSignature(WindowType.NORMAL, 1400, WILDCARD)

    with pytest.raises(FieldError):
        _parse_window("-1,*")

    with pytest.raises(FieldError):
        _parse_window("mss*0,*")

    with pytest.raises(FieldError):
        _parse_window("%1,*")


def test_parse_options():
    assert _parse_options("ws,ts") == ([TCPOption.WS, TCPOption.TS], 0)
    assert _parse_options("nop,?6,eol+2") == ([TCPOption.NOP, 6, TCPOption.EOL], 2)

    with pytest.raises(FieldError):
        _parse_options("nop,?256")

    with pytest.raises(FieldError):
        _parse_options("nop,eol+256")


def test_parse_quirks():
    assert (
        _parse_quirks("df,id+,ecn", ip_version=4) == Quirk.DF | Quirk.NZ_ID | Quirk.ECN
    )

    with pytest.raises(FieldError):
        _parse_quirks("d,f", ip_version=4)

    with pytest.raises(FieldError):
        _parse_quirks("df,id+", ip_version=6)

    with pytest.raises(FieldError):
        _parse_quirks("df,flow", ip_version=4)
