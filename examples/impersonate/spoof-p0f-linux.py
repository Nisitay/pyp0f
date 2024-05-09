"""
This example shows how one can use `pyp0f.impersonate` in Linux in a real world scenario - Spoof running p0f
by impersonating a certain OS.

We use `netfilterqueue` to capture packets before they leave the network stack,
create a new packet that impersonates an OS, and finally re-inject the impersonated packet
back to the network stack to spoof p0f on the other end.

Instructions:

-You need to install NetfilterQueue (https://pypi.org/project/NetfilterQueue/)

-Before running the script, you must add a rule to iptables to capture packets and send them to the queue:
sudo iptables -I OUTPUT -d x.x.x.x -j NFQUEUE --queue-num 1

-After you are finised with impersonation, remove the iptable rule.

sudo iptables -D OUTPUT -d x.x.x.x -j NFQUEUE --queue-num 1


Remember that x.x.x.x is the IP address of the destination.

"""

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from pyp0f.database import DATABASE
from pyp0f.impersonate import impersonate_mtu, impersonate_tcp
from pyp0f.net.layers.tcp import TCPFlag

DATABASE.load()

# Remote IP address running p0f, i.e. https://browserleaks.com/ip
REMOTE_ADDRESS = "x.x.x.x"

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    
    # Not a TCP packet, accept the packet unchanged
    if TCP not in scapy_packet:
        packet.accept()
        return
    
    flags = TCPFlag(int(scapy_packet[TCP].flags))
    
    # Not a SYN packet, accept the packet unchanged
    if flags != TCPFlag.SYN:
        packet.accept()
        return
    
    # We're sending a SYN packet, impersonate!
    solaris_packet = impersonate_tcp(
        scapy_packet,
        raw_label="s:win:Windows:XP",
        raw_signature="*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0"
    )
    impersonated_packet = impersonate_mtu(solaris_packet, raw_label="Google")
    
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
