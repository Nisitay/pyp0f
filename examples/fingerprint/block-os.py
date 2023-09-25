"""
This example shows how one can use `pyp0f.fingerprint` in a real world scenario - Block certain OS users
attempting to connect to our HTTP server (in this case - Windows).

We use `pydivert` to capture incoming packets before they enter the network stack,
fingerprint them, and drop every connection attempt to our server for certain OS.
"""
import pydivert
from scapy.layers.inet import IP, TCP

from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_tcp
from pyp0f.net.layers.tcp import TCPFlag

DATABASE.load()

# HTTP server was ran with 'python -m http.server 8080'
# Capture incoming packets to our HTTP server on 8080
with pydivert.WinDivert("inbound && tcp.DstPort == 8080") as w:
    for packet in w:
        # Convert packet to scapy format
        scapy_packet = IP(bytes(packet.raw))

        # Not a TCP packet, re-inject unmodified packet into the network stack
        if TCP not in scapy_packet:
            w.send(packet)
            continue

        flags = TCPFlag(int(scapy_packet[TCP].flags))

        # Not a SYN packet, re-inject unmodified packet into the network stack
        if flags != TCPFlag.SYN:
            w.send(packet)
            continue

        # Fingerprint the packet
        result = fingerprint_tcp(scapy_packet)

        # Block users on Windows
        if (
            result.match is not None
            and result.match.record.label.name.lower() == "windows"
        ):
            continue

        # re-inject packet into the network stack
        w.send(pydivert.Packet(bytes(scapy_packet), packet.interface, packet.direction))
