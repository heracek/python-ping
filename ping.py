#!/usr/bin/env python
import fcntl
import os
import re
import shared
import struct
import sys

import bpf
from utils import bin2hex
from wrappers import Ethernet, IPv4, UDP, DHCP, ICMP

LOCAL_DEVICE = None
LOCAL_MAC_ADDRESS = None
PACKET_COUNT = 1
PRINT_DEBUG = False

def print_debug(what, force=False):
    if PRINT_DEBUG:
        print what
    elif force:
        print what.__str__(parents=True)

def dhcp_packet_callback(eth_packet, ip_packet, udp_packet, dhcp_packet):
    print_debug(dhcp_packet, force=False)
    
def udp_packet_callback(eth_packet, ip_packet, udp_packet):
    print_debug(udp_packet)
    if (udp_packet.sport, udp_packet.dport) in UDP.COMM_DHCP:
        dhcp_packet_callback(eth_packet, ip_packet, udp_packet, DHCP(parent=udp_packet))        

def icmp_packet_callback(eth_packet, ip_packet, icmp_packet):
    print_debug(icmp_packet, force=True)

def ip_packet_callback(eth_packet, ip_packet):
    print_debug('packet #%d:' % PACKET_COUNT)
    print_debug(eth_packet)
    print_debug(ip_packet)
    
    if ip_packet.protocol == IPv4.PROTOCOL_UDP:
        udp_packet_callback(eth_packet, ip_packet, UDP(parent=ip_packet))
    if ip_packet.protocol == IPv4.PROTOCOL_ICMP:
        icmp_packet_callback(eth_packet, ip_packet, ICMP(parent=ip_packet))

def arp_packet_callback(arp_packet):
    print_debug('packet #%d:' % PACKET_COUNT)
    print_debug('ARP packet: ' + str(arp_packet))

def eth_packet_callback(eth_packet):
    global PACKET_COUNT
    
    if eth_packet.type == Ethernet.TYPE_IP:
        ip_packet_callback(eth_packet, IPv4(parent=eth_packet))
    elif eth_packet.type == Ethernet.TYPE_ARP:
        arp_packet_callback(eth_packet)

    PACKET_COUNT += 1
    
def my_listen(fd, packet_callback):
    # fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK) # nonblocking reading - slows down CPU
    blen = bpf.bpf_get_blen(fd)
    while True:
        buffer = os.read(fd, blen)
        if len(buffer) > 0:
            packet_index = 0
            while packet_index < len(buffer):
                header = bpf.get_header(buffer[packet_index:packet_index + 18])
                
                if header.bh_caplen != header.bh_datalen:
                    print 'Packet fraction at BPF level. - skipped'
                    packet_index += bpf.BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen)
                    continue
                
                data = buffer[packet_index + header.bh_hdrlen:packet_index + header.bh_caplen + header.bh_hdrlen]
                
                packet_callback(Ethernet(data))
                
                packet_index += bpf.BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen)

def main():
    if len(sys.argv) != 3:
        if len(sys.argv) == 1:
            sys.argv.extend(['en1', '192.168.1.1'])
            print 'using defaul args:', ' '.join(sys.argv)
        else:
            print 'usage: %s dev host' % sys.argv[0]
            print '\tdev ... device'
            print '\thost ... ip address of host'
            sys.exit(1)

    LOCAL_DEVICE = sys.argv[1]
    LOCAL_MAC_ADDRESS = shared.get_local_mac_addres_of_device(LOCAL_DEVICE)
    print 'LOCAL_MAC_ADDRESS: %s' % LOCAL_MAC_ADDRESS

    fd = -1
    fd = bpf.bpf_new()
    bpf.bpf_set_immediate(fd, 1)
    bpf.bpf_setif(fd, LOCAL_DEVICE)

    my_listen(fd, eth_packet_callback)

    bpf.bpf_dispose(fd)
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print
        sys.exit(0)
