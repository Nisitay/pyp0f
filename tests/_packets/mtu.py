from dataclasses import dataclass

from pyp0f.net.packet import Packet

from .parse import from_hex


@dataclass
class MTUTestPacket:
    expected_label: str
    packet: Packet


ETHERNET_OR_MODEM = MTUTestPacket(
    expected_label="Ethernet or modem",
    packet=from_hex(
        "4500003000ea40008006f5d9010101020101010104120035d1f8c116000000007002faf0ecd30000020405b401010402"
    ),
)

IPIP_OR_SIT = MTUTestPacket(
    expected_label="IPIP or SIT",
    packet=from_hex(
        "600000000020064020010470e5bfdead49572174e82c48872607f8b0400c0c03000000000000001af9c7001903a088300000000080022000da4700000204058c0103030801010402",
        ip_version=6,
    ),
)

IPSEC_OR_GRE = MTUTestPacket(
    expected_label="IPSec or GRE",
    packet=from_hex(
        "45c0002c9a520000ff060aab0a0002010a00000eece002c756da161c0000000060021020157200000204059c"
    ),
)

GOOGLE = MTUTestPacket(
    expected_label="Google",
    packet=from_hex(
        "4500003c51490000310695ec4a7d831bc0a814460019d51d9956ad806b7fc72ea012a62cd5c10000020405960402080a03a588680a99443601030307"
    ),
)

GENERIC_TUNNEL_OR_VPN = MTUTestPacket(
    expected_label="generic tunnel or VPN",
    packet=from_hex(
        "45000030e17d00002f061744adc22337c0a8016501bbdd634ad26bcfdd0d6e377012a79467aa00000204057801010402"
    ),
)
