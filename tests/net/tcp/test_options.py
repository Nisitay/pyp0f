from typing import Sequence, Tuple, Any

from scapy.layers.inet import TCPOptionsField

from pyp0f.net.quirks import Quirk
from pyp0f.net.tcp.flags import TcpFlag
from pyp0f.net.tcp.options import TcpOptions, TcpOption


_options = TCPOptionsField("options", None)


class TestTcpOptions:
    @staticmethod
    def _raw(options: Sequence[Tuple[str, Any]]) -> bytes:
        return _options.i2m(None, options)

    def test_parse(self):
        opts = TcpOptions.parse(
            self._raw(
                (
                    ("NOP", ""),
                    ("MSS", 1460),
                    ("WScale", 8),
                    ("SAckOK", ""),
                    ("SAck", b"\x00" * 8),
                    ("Timestamp", (123456, 0)),
                    ("EOL", ""),
                )
            ),
            TcpFlag.SYN,
        )

        assert opts == TcpOptions(
            layout=[
                TcpOption.NOP,
                TcpOption.MSS,
                TcpOption.WS,
                TcpOption.SACKOK,
                TcpOption.SACK,
                TcpOption.TS,
                TcpOption.EOL,
            ],
            quirks=Quirk(0),
            mss=1460,
            timestamp=123456,
            window_scale=8,
            eol_pad_length=1,
        )

    def test_quirks(self):
        opts = TcpOptions.parse(
            self._raw(
                (("WScale", 15), ("Timestamp", (0, 123456)), ("EOL", ""), ("NOP", ""))
            ),
            TcpFlag.SYN,
        )

        assert opts == TcpOptions(
            layout=[TcpOption.WS, TcpOption.TS, TcpOption.EOL],
            quirks=(
                Quirk.OPT_EXWS
                | Quirk.OPT_ZERO_TS1
                | Quirk.OPT_NZ_TS2
                | Quirk.OPT_EOL_NZ
            ),
            window_scale=15,
            eol_pad_length=2,
        )

    def test_no_option_length(self):
        assert TcpOptions.parse(bytes([TcpOption.MSS]), TcpFlag.SYN) == TcpOptions(
            layout=[TcpOption.MSS], quirks=Quirk.OPT_BAD
        )

    def test_option_too_long(self):
        assert TcpOptions.parse(bytes([TcpOption.MSS, 4]), TcpFlag.SYN) == TcpOptions(
            layout=[TcpOption.MSS], quirks=Quirk.OPT_BAD
        )

    def test_unexpected_option_length(self):
        assert TcpOptions.parse(
            bytes([TcpOption.MSS, 3, 1]), TcpFlag.SYN
        ) == TcpOptions(layout=[TcpOption.MSS], quirks=Quirk.OPT_BAD)
