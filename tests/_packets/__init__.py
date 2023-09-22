"""
Packets from real-life captures, taken from:
    https://packetlife.net/captures/protocol/tcp/
"""


from .http import APACHE, NGINX, WGET, HTTPTestPacket
from .mtu import (
    ETHERNET_OR_MODEM,
    GENERIC_TUNNEL_OR_VPN,
    GOOGLE,
    IPIP_OR_SIT,
    IPSEC_OR_GRE,
    MTUTestPacket,
)
from .tcp import (
    LINUX_22_3,
    LINUX_26_SYN,
    LINUX_26_SYN_ACK,
    LINUX_26_SYN_ACK_ANOTHER,
    LINUX_311,
    WINDOWS_7_OR_8_EXACT,
    WINDOWS_7_OR_8_FUZZY_TTL,
    WINDOWS_NT_KERNEL,
    WINDOWS_XP,
    TCPTestPacket,
)

MTU_PACKETS = [
    GOOGLE,
    IPIP_OR_SIT,
    IPSEC_OR_GRE,
    ETHERNET_OR_MODEM,
    GENERIC_TUNNEL_OR_VPN,
]

TCP_PACKETS = [
    LINUX_311,
    LINUX_22_3,
    WINDOWS_XP,
    LINUX_26_SYN,
    LINUX_26_SYN_ACK,
    WINDOWS_NT_KERNEL,
    WINDOWS_7_OR_8_EXACT,
    WINDOWS_7_OR_8_FUZZY_TTL,
    LINUX_26_SYN_ACK_ANOTHER,
]

HTTP_PACKETS = [WGET, NGINX, APACHE]

__all__ = [
    "MTUTestPacket",
    "TCPTestPacket",
    "HTTPTestPacket",
    "MTU_PACKETS",
    "TCP_PACKETS",
    "HTTP_PACKETS",
]
