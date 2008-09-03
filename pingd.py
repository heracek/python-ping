#!/usr/bin/env python
import fcntl
import os
import re
import shared
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
        # eth = what._parent._parent
        # print eth
        print what.__str__(parents=True)
        print repr(what.payload)

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
    print_debug(ip_packet, force=False)
    
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
    
    fd = bpf.get_bpf_fg(device=LOCAL_DEVICE)
    
    for bpf_packet in bpf.packet_reader(fd):
        eth_packet_callback(Ethernet(bpf_packet.data))

    bpf.bpf_dispose(fd)
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print
        sys.exit(0)
