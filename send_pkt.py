#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers.inet import IP as IP
from scapy.layers.inet import UDP as UDP
from scapy.layers.dns import DNS as DNS

# you nust send the packets in the right order!
# if you change it, it will not work

sr1 = scapy.sr1
pkt1 = IP(dst='192.168.1.7')/UDP(sport=51014)/DNS(id=2)
pkt2 = IP(dst='192.168.1.7')/UDP(sport=51013)/DNS(id=2)
pkt3 = IP(dst='192.168.1.7')/UDP(sport=51012)/DNS(id=2)

print("Sending....")
sr1(pkt1)
sr1(pkt2)
sr1(pkt3)
print('Done!')