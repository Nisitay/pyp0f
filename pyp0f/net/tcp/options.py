from enum import IntEnum
from struct import Struct
from dataclasses import dataclass
from typing import Iterable, Optional, List

from ..quirks import Quirk
from .flags import TcpFlag


class TcpOption(IntEnum):
    EOL = 0  # End of options (1)
    NOP = 1  # No-op (1)
    MSS = 2  # Maximum segment size (4)
    WS = 3  # Window scaling (3)
    SACKOK = 4  # Selective ACK permitted (2)
    SACK = 5  # Actual selective ACK (10-34)
    TS = 8  # Timestamp (10)


OPTION_STRINGS = {
    TcpOption.EOL: "eol+{padding_length}",
    TcpOption.NOP: "nop",
    TcpOption.MSS: "mss",
    TcpOption.WS: "ws",
    TcpOption.SACKOK: "sok",
    TcpOption.SACK: "sack",
    TcpOption.TS: "ts",
}


OPTION_FORMATS = {
    TcpOption.WS: Struct("!B"),
    TcpOption.TS: Struct("!II"),
    TcpOption.MSS: Struct("!H"),
    TcpOption.SACKOK: Struct(""),
}


@dataclass
class TcpOptions:
    layout: List[int]
    quirks: Quirk
    mss: int = 0
    timestamp: int = 0
    window_scale: int = 0
    eol_pad_length: int = 0

    @classmethod
    def parse(cls, buffer: bytes, flags: TcpFlag):
        layout: List[int] = []
        quirks = Quirk(0)
        mss = timestamp = window_scale = eol_pad_length = 0

        i = 0
        options_end = len(buffer)

        while i < options_end:
            option_num = buffer[i]
            layout.append(option_num)
            i += 1

            if option_num == TcpOption.EOL:
                # Count how many bytes of option data are left, and if any are non-zero
                eol_pad_length = options_end - i

                while i < options_end and not buffer[i]:
                    i += 1

                if i != options_end:
                    quirks |= Quirk.OPT_EOL_NZ
                break

            elif option_num == TcpOption.NOP:
                continue

            if i == options_end:  # Option without room for length field
                quirks |= Quirk.OPT_BAD
                break

            option_length = buffer[i]  # Specified option length
            current_option_end = i - 1 + option_length
            i += 1

            if current_option_end > options_end:  # Option would end past end of headers
                quirks |= Quirk.OPT_BAD
                break

            if option_num == TcpOption.SACK:
                # SACK is a variable-length option of 10 to 34 bytes.
                if not 10 <= option_length <= 34:
                    quirks |= Quirk.OPT_BAD
                    break

            elif option_num in OPTION_FORMATS:
                option_format = OPTION_FORMATS[option_num]

                # Length doesn't match supposed option size
                if option_length != 2 + option_format.size:
                    quirks |= Quirk.OPT_BAD

                else:
                    option_value = option_format.unpack(buffer[i:current_option_end])

                    if option_num == TcpOption.MSS:
                        mss = option_value[0]

                    elif option_num == TcpOption.WS:
                        window_scale = option_value[0]
                        if window_scale > 14:
                            quirks |= Quirk.OPT_EXWS

                    elif option_num == TcpOption.TS:
                        timestamp, timestamp2 = option_value
                        if not timestamp:
                            quirks |= Quirk.OPT_ZERO_TS1
                        if timestamp2 and flags == TcpFlag.SYN:
                            quirks |= Quirk.OPT_NZ_TS2

            # Unknown option, presumably with specified size.
            elif not 2 <= option_length <= 40:
                quirks |= Quirk.OPT_BAD
                break

            i = current_option_end

        return cls(
            layout=layout,
            quirks=quirks,
            mss=mss,
            timestamp=timestamp,
            window_scale=window_scale,
            eol_pad_length=eol_pad_length,
        )

    def dump(self) -> str:
        """
        Dump TCP options to p0f representation.
        """
        return dump_options(self.layout, self.eol_pad_length)


def dump_options(options: Iterable[int], eol_pad_length: Optional[int] = None) -> str:
    """
    Dump TCP options to p0f representation.
    """
    eol_string = OPTION_STRINGS[TcpOption.EOL].format(
        padding_length=eol_pad_length if eol_pad_length is not None else "?"
    )

    return ",".join(
        OPTION_STRINGS.get(option, f"?{option}")  # type: ignore
        if option != TcpOption.EOL
        else eol_string
        for option in options
    )
