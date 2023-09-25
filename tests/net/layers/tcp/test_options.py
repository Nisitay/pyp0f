from typing import Any, Sequence, Tuple

from scapy.layers.inet import TCPOptionsField

from pyp0f.net.layers.tcp import TCPOption, TCPOptions
from pyp0f.net.quirks import Quirk

_options = TCPOptionsField("options", None)


class TestTCPOptions:
    @staticmethod
    def _raw(options: Sequence[Tuple[str, Any]]) -> bytes:
        return _options.i2m(None, options)

    def test_parse(self):
        opts = TCPOptions.parse(
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
            )
        )

        assert opts == TCPOptions(
            layout=[
                TCPOption.NOP,
                TCPOption.MSS,
                TCPOption.WS,
                TCPOption.SACKOK,
                TCPOption.SACK,
                TCPOption.TS,
                TCPOption.EOL,
            ],
            quirks=Quirk(0),
            mss=1460,
            timestamp=123456,
            window_scale=8,
            eol_padding_length=1,
        )

    def test_quirks(self):
        opts = TCPOptions.parse(
            self._raw(
                (("WScale", 15), ("Timestamp", (0, 123456)), ("EOL", ""), ("NOP", ""))
            ),
            is_syn=True,
        )

        assert opts == TCPOptions(
            layout=[TCPOption.WS, TCPOption.TS, TCPOption.EOL],
            quirks=(
                Quirk.OPT_EXWS
                | Quirk.OPT_ZERO_TS1
                | Quirk.OPT_NZ_TS2
                | Quirk.OPT_EOL_NZ
            ),
            window_scale=15,
            eol_padding_length=2,
        )

    def test_no_option_length(self):
        assert TCPOptions.parse(bytes([TCPOption.MSS])) == TCPOptions(
            layout=[TCPOption.MSS], quirks=Quirk.OPT_BAD
        )

    def test_option_too_long(self):
        assert TCPOptions.parse(bytes([TCPOption.MSS, 4])) == TCPOptions(
            layout=[TCPOption.MSS], quirks=Quirk.OPT_BAD
        )

    def test_unexpected_option_length(self):
        assert TCPOptions.parse(bytes([TCPOption.MSS, 3, 1])) == TCPOptions(
            layout=[TCPOption.MSS], quirks=Quirk.OPT_BAD
        )
