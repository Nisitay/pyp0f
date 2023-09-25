"""
This example shows how one can use `pyp0f.fingerprint` in a real world scenario - Passively fingerprint
remote hosts attempting to connect to our HTTP server.

We use `scapy` to sniff incoming packets and fingerprint them.
"""
from scapy.config import conf as scapy_config
from scapy.sendrecv import sniff

from pyp0f.database import DATABASE
from pyp0f.exceptions import PacketError
from pyp0f.fingerprint import fingerprint_http, fingerprint_mtu, fingerprint_tcp
from pyp0f.net.layers.tcp import TCPFlag
from pyp0f.net.scapy import ScapyIPv4, ScapyIPv6, ScapyPacket, ScapyTCP

DATABASE.load()


def handle_packet(packet: ScapyPacket) -> None:
    flags = TCPFlag(int(packet[ScapyTCP].flags))

    # SYN/SYN+ACK packet, fingerprint
    if flags in (TCPFlag.SYN, TCPFlag.SYN | TCPFlag.ACK):
        mtu_result = fingerprint_mtu(packet)
        tcp_result = fingerprint_tcp(packet)
        print(f"MTU fingerprint match: {mtu_result.match}")
        print(f"TCP fingerprint match: {tcp_result.match}")

    payload = packet[ScapyTCP].payload

    if payload:
        try:
            http_result = fingerprint_http(bytes(payload))
            print(f"HTTP fingerprint match: {http_result.match}")
        except PacketError:
            print("Not an HTTP payload, skipping fingerprint")


# Enable filtering to improve performance: only protocols necessary for p0f will be dissected
scapy_config.layers.filter([ScapyIPv4, ScapyIPv6, ScapyTCP])

# HTTP server was ran with 'python -m http.server 8080'
sniff(filter="ip and tcp dst port 8080", prn=handle_packet)
