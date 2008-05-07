#!/usr/bin/env python
import fcntl
import os
import re
import shared
import struct
import sys

import bpf

LOCAL_DEVICE = None
LOCAL_MAC_ADDRESS = None

def eth_packet_callback(eth_packet):
    print 'packet received - len:', len(eth_packet)

def my_listen(fd, packet_callback):
    # fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK) # slows down CPU
    blen = bpf.bpf_get_blen(fd)
    while True:
        buffer = os.read(fd, blen)
        if len(buffer) > 0:
            packet_index = 0
            while packet_index < len(buffer):
                header = bpf.get_header(buffer[packet_index:packet_index+18])
                
                if header.bh_caplen != header.bh_datalen:
                    print 'Packet fraction at BPF level. - skipped'
                    packet_index += bpf.BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen)
                    continue
                
                data = buffer[packet_index + header.bh_hdrlen:packet_index + header.bh_caplen + header.bh_hdrlen]
                
                packet_callback(data)
                
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
    try:
        fd = bpf.bpf_new()
        bpf.bpf_set_immediate(fd, 1)
        bpf.bpf_setif(fd, 'en1')
        
        my_listen(fd, eth_packet_callback)
        
        bpf.bpf_dispose(fd)
    except Exception, e:
        print e
        bpf.bpf_dispose(fd)

if __name__ == '__main__':
    main()