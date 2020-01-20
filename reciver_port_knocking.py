#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers.inet import IP as IP
from scapy.layers.inet import UDP as UDP
from scapy.layers.dns import DNS as DNS
from scapy.all import sniff
import os

bingo = [51014,51013,51012]
global ip_chklist
global port_list
global ip
ip_chklist = []
port_list = []
ip = ""

class port_knocking():
    def source_check(self):
        if ip_chklist[0] == ip_chklist[1] and ip_chklist[0] == ip_chklist[2]:
            source_ip = ip_chklist[0]
        else:
            print("There may be MITM attacker!, Be careful....")

    def packet_printer(self, pkt):
        dns_layer = pkt.getlayer(DNS)
        identifire = dns_layer.id
        if identifire == 2:
            udp_layer = pkt.getlayer(UDP)
            src_port = udp_layer.sport
            port_list.append(src_port)
            ip_layer = pkt.getlayer(IP)
            sender = ip_layer.src
            print (f"Packet has recived on port -->> {src_port}.")
            ip_chklist.append(sender)
            if len(ip_chklist) == 3:
                port_knocking.source_check(self)
                port_knocking.order(self)

    def order(self):
        for i in range(3):
            if port_list[i] == bingo[i]:
                if i == 2:
                    port_knocking.open_ssh(self)
            else:
                print("You didnt Knock on the right order! Try again later... ")

    def open_ssh(self):
        drop_all_ports = """sudo iptables -A INPUT -p tcp -m tcp ! --dport ssh -j DROP & 
                            sudo iptables -A INPUT -p udp -m udp ! --dport ssh -j DROP"""

        allow_ssh_ip =  f'''iptables -A INPUT -p tcp --dport 22 --source {ip_chklist[0]} -j ACCEPT
                            iptables -A INPUT -p tcp --dport 22 -j DROP''' 
                            
        os.system(allow_ssh_ip)
        os.system(drop_all_ports)

    def sniffer(self):
        print("Network is Listening.....")
        sniff(iface='eth0', count=3, filter='udp and portrange 40000-51100', prn=self.packet_printer)

run = port_knocking()
run.sniffer()