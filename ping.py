#!/usr/bin/env python
import fcntl
import os
import re
import shared
import struct
import sys

import bpf
from utils import bin2hex
from wrappers import Ethernet, IPv4

LOCAL_DEVICE = None
LOCAL_MAC_ADDRESS = None
PACKET_COUNT = 1

def ip_packet_callback(eth_packet, ip_packet):
    print 'packet #%d:' % PACKET_COUNT
    print eth_packet
    print ip_packet.__str__(level = 1)

def arp_packet_callback(arp_packet):
    print 'packet #%d:' % PACKET_COUNT
    print 'ARP packet:', arp_packet

def eth_packet_callback(eth_packet):
    global PACKET_COUNT
    
    if eth_packet.type == Ethernet.TYPE_IP:
        ip_packet_callback(eth_packet, IPv4(eth_packet.payload))
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
            sys.argv.extend(['en0', '192.168.1.10'])
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
    main()
