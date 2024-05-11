"""
This example shows how one can use `pyp0f.impersonate` in a real world scenario - Spoof running p0f
by impersonating a certain OS.

We use `pydivert` to capture packets before they leave the network stack,
create a new packet that impersonates an OS, and finally re-inject the impersonated packet
back to the network stack to spoof p0f on the other end.

To run the script:
- Install `pydivert`.
- Change the IP address "x.x.x.x" to your desired destination IP address.
- Run the script as administrator.
"""
import pydivert
from scapy.layers.inet import IP

from pyp0f.database import DATABASE
from pyp0f.impersonate import impersonate_mtu, impersonate_tcp

DATABASE.load()

# Remote IP address running p0f. For example, to get IP of "https://browserleaks.com/ip" run "ping browserleaks.com".
REMOTE_ADDRESS = "x.x.x.x"


def process_packets() -> None:
    # Capture outgoing SYN packets to our desired IP.
    with pydivert.WinDivert(
        f"outbound and tcp.Syn and ip.DstAddr == {REMOTE_ADDRESS}"
    ) as w:
        for packet in w:
            # Convert packet to scapy format
            scapy_packet = IP(bytes(packet.raw))

            # Since MTU depends on MSS value in TCP options, impersonate TCP first and then MTU.
            linux_packet = impersonate_tcp(
                scapy_packet,
                raw_label="g:unix:Linux:2.2.x-3.x (barebone)",
                raw_signature="*:64:0:*:*,0:mss:df,id+:0",
            )
            impersonated_packet = impersonate_mtu(linux_packet, raw_label="Google")

            # re-inject impersonated SYN packet into the network stack
            w.send(
                pydivert.Packet(
                    bytes(impersonated_packet), packet.interface, packet.direction
                )
            )


try:
    print("Starting packet processing...")
    process_packets()
except KeyboardInterrupt:
    print("Stopping...")
