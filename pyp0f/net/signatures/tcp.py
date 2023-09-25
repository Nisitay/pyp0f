from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from pyp0f.database.parse.wildcard import WILDCARD
from pyp0f.net.layers.ip import IPV6
from pyp0f.net.layers.tcp import MIN_TCP4, MIN_TCP6, TCPOptions
from pyp0f.net.packet import Packet
from pyp0f.net.quirks import Quirk
from pyp0f.utils.slots import add_slots

from .base import PacketSignature


@add_slots
@dataclass
class WindowMultiplier:
    value: int
    is_mtu: bool


@add_slots
@dataclass
class TCPPacketSignature(PacketSignature):
    ip_version: int
    ip_options_length: int
    ttl: int

    window_size: int
    options: TCPOptions
    headers_length: int

    has_payload: bool
    quirks: Quirk
    syn_mss: Optional[int] = None

    # Cached window multiplier
    _window_multiplier: Optional[WindowMultiplier] = field(init=False)

    def __post_init__(self):
        # Since dataclass with slots and field(default=None) don't work,
        # initialize the value here
        self._window_multiplier = None

    @classmethod
    def from_packet(cls, packet: Packet, syn_mss: Optional[int] = None):
        return cls(
            ip_version=packet.ip.version,
            ip_options_length=packet.ip.options_length,
            ttl=packet.ip.ttl,
            window_size=packet.tcp.window,
            options=packet.tcp.options,
            headers_length=packet.ip.header_length + packet.tcp.header_length,
            has_payload=bool(packet.tcp.payload),
            quirks=packet.ip.quirks | packet.tcp.quirks,
            syn_mss=syn_mss,
        )

    @property
    def window_multiplier(self) -> WindowMultiplier:
        """
        Figure out if window size is a multiplier of MSS or MTU.
        Returns the multiplier and whether MTU should be used.
        Caches the calculated result for next calls.
        """
        if self._window_multiplier is None:
            self._window_multiplier = self.calculate_window_multiplier()
        return self._window_multiplier

    def calculate_window_multiplier(self) -> WindowMultiplier:
        if not self.window_size or self.options.mss < 100:
            return WindowMultiplier(WILDCARD, is_mtu=False)

        divs: List[Tuple[int, bool]] = []

        def add_div(div: int, use_mtu: bool = False):
            divs.append((div, use_mtu))

        add_div(self.options.mss)

        # Some systems will sometimes subtract 12 bytes when timestamps are in use.
        if self.options.timestamp:
            add_div(self.options.mss - 12)

        # Some systems use MTU on the wrong interface
        add_div(1500 - MIN_TCP4)
        add_div(1500 - MIN_TCP4 - 12)

        if self.ip_version == IPV6:
            add_div(1500 - MIN_TCP6)
            add_div(1500 - MIN_TCP6 - 12)

        # Some systems use MTU instead of MSS:
        add_div(self.options.mss + MIN_TCP4, use_mtu=True)
        add_div(self.options.mss + self.headers_length, use_mtu=True)
        if self.ip_version == IPV6:
            add_div(self.options.mss + MIN_TCP6, use_mtu=True)
        add_div(1500, use_mtu=True)

        # On SYN+ACKs, some systems use of the peer:
        if self.syn_mss is not None:
            add_div(self.syn_mss)  # peer MSS
            add_div(self.syn_mss - 12)  # peer MSS - 12

        for div, use_mtu in divs:
            if div and not self.window_size % div:
                return WindowMultiplier(self.window_size // div, use_mtu)

        return WindowMultiplier(WILDCARD, is_mtu=False)
