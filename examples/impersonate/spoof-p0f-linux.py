"""
This example shows how one can use `pyp0f.impersonate` in Linux in a real world scenario - Spoof running p0f
by impersonating a certain OS.

We use `netfilterqueue` to capture packets before they leave the network stack,
create a new packet that impersonates an OS, and finally re-inject the impersonated packet
back to the network stack to spoof p0f on the other end.

To run the script:
- Install `NetfilterQueue` (https://pypi.org/project/NetfilterQueue/).
- Change the IP address "x.x.x.x" to your desired destination IP address.

- Before running the script, you must add a rule to iptables to capture packets and send them to the queue:
sudo iptables -I OUTPUT -p tcp --syn -d x.x.x.x -j NFQUEUE --queue-num 1

- After you are finised with impersonation, remove the iptable rule:
sudo iptables -D OUTPUT -p tcp --syn -d x.x.x.x -j NFQUEUE --queue-num 1

* Remember that x.x.x.x is the IP address of the destination.
"""

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP

from pyp0f.database import DATABASE
from pyp0f.impersonate import impersonate_mtu, impersonate_tcp

DATABASE.load()

# Remote IP address running p0f. For example, to get IP of "https://browserleaks.com/ip" run "ping browserleaks.com".
REMOTE_ADDRESS = "x.x.x.x"


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    # We're sending a SYN packet, impersonate!
    windows_packet = impersonate_tcp(
        scapy_packet,
        raw_label="s:win:Windows:XP",
        raw_signature="*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0",
    )
    impersonated_packet = impersonate_mtu(windows_packet, raw_label="Google")

    # Set the modified packet payload and accept it
    packet.set_payload(bytes(impersonated_packet))
    packet.accept()


# Create instance of NetfilterQueue
nfqueue = NetfilterQueue()

# Bind to the same queue number as used in your iptables rule
nfqueue.bind(1, process_packet)

try:
    print("Starting packet processing...")
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping...")
    nfqueue.unbind()
