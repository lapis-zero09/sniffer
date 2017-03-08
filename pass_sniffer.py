#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
from scapy.all import *


def check_packet_detail(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            return 'FTP'
        elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
            return 'telnet'
        else:
            return False

def capture_ftp(packet):
    if 'user' in data.lower() or 'pass' in data.lower():
        return packet[IP].src, packet[IP].dst, packet[TCP].payload

def caputure_telnet(src_ip_port, dst_ip_port, data, ack, seq):
    global telnet_stream
    msg = None

    if src_ip_port in telnet_stream:
        # Do a utf decode in case the client sends telnet options before their username
        # No one would care to see that
        try:
            telnet_stream[src_ip_port] += load.decode('utf8')
        except UnicodeDecodeError:
            pass

        # \r or \r\n or \n terminate commands in telnet if my pcaps are to be believed
        if '\r' in telnet_stream[src_ip_port] or '\n' in telnet_stream[src_ip_port]:
            telnet_split = telnet_stream[src_ip_port].split(' ', 1)
            cred_type = telnet_split[0]
            value = telnet_split[1].replace('\r\n', '').replace('\r', '').replace('\n', '')
            # Create msg, the return variable
            msg = 'Telnet %s: %s' % (cred_type, value)
            printer(src_ip_port, dst_ip_port, msg)
            del telnet_stream[src_ip_port]

    # This part relies on the telnet packet ending in
    # "login:", "password:", or "username:" and being <750 chars
    # Haven't seen any false+ but this is pretty general
    # might catch some eventually
    # maybe use dissector.py telnet lib?
    if len(telnet_stream) > 100:
        telnet_stream.popitem(last=False)
    mod_load = load.lower().strip()
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
    # frag_remover(ack, load)
    # packet_frag_loads[src_ip_port] = frag_joiner(ack, src_ip_port, load)
    if app == 'FTP':
        src_ip_port, dst_ip_port, data = caputure_ftp(packet)
        print("\t[*] [%s -> %s] FTP  %s" % (src_ip_port, dst_ip_port, data))
    elif app == 'Telnet':
        data = packet[Raw].load
        caputure_telnet(data)

if __name__ == '__main__':
    print('[*] Sniffing Started ...')

    # try:
    sniff(prn=check_packet, store=0)
    # except Exception:
    #     print('[!] Error: Failed to Initialize Sniffing')
    #     sys.exit(1)

    print('[*] Sniffing Stopped')
