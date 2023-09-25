"""
This example shows how one can use `pyp0f.impersonate` in a real world scenario - Spoof running p0f
by impersonating a certain OS.

We use `pydivert` to capture packets before they leave the network stack,
create a new packet that impersonates an OS, and finally re-inject the impersonated packet
back to the network stack to spoof p0f on the other end.
"""
import pydivert
from scapy.layers.inet import IP, TCP

from pyp0f.database import DATABASE
from pyp0f.impersonate import impersonate_mtu, impersonate_tcp
from pyp0f.net.layers.tcp import TCPFlag

DATABASE.load()

# Remote IP address running p0f, i.e. https://browserleaks.com/ip
REMOTE_ADDRESS = "x.x.x.x"

# Capture outgoing packets
with pydivert.WinDivert(f"outbound && ip.DstAddr == {REMOTE_ADDRESS}") as w:
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

        # We're sending a SYN packet, impersonate!
        # Since MTU depends on MSS value in TCP options, impersonate TCP first and then MTU.
        solaris_packet = impersonate_tcp(
            scapy_packet,
            raw_label="g:unix:Linux:2.2.x-3.x (barebone)",
            raw_signature="*:64:0:*:*,0:mss:df,id+:0",
        )
        impersonated_packet = impersonate_mtu(solaris_packet, raw_label="Google")

        # re-inject impersonated packet into the network stack
        w.send(
            pydivert.Packet(
                bytes(impersonated_packet), packet.interface, packet.direction
            )
        )
