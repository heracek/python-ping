#!/usr/bin/env python
import fcntl
import os
import re
import shared
import sys

import bpf
from utils import bin2hex
from wrappers import Ethernet, IPv4, UDP, DHCP, ICMP
from fields import MACAddres, IPAddress

LOCAL_DEVICE = None
LOCAL_MAC_ADDRESS = None

def ping(fd):
    eth = Ethernet(data_dict=dict(
        smac=MACAddres(colon_hex_str='00:1a:92:62:31:4c'),
        dmac=MACAddres(colon_hex_str='00:19:e3:02:d9:2b'),
        type=0x0800
    ))
    
    ipv4 = IPv4(parent=eth, data_dict=dict(
        version=4,
        header_length=5,
        type_of_service=0x00,
        total_length=84,
        identification=0x0c25,
        flags=0x0,
        fragment_offset=0,
        time_to_live=64,
        protocol=0x01,
        header_checksum=0xeb30,
        saddr=IPAddress(str_val='192.168.1.2'),
        daddr=IPAddress(str_val='192.168.1.1')
    ))
    
    icmp = ICMP(parent=ipv4, data_dict=dict(
        type=8,
        code=0,
        checksum=0x7a33,
        id=0x1234,
        sequence=0
    ))
    
    icmp.payload = 'a' * 56
    
    for i in xrange(1):
        os.write(fd, icmp.raw_val() + icmp.payload)
        
        icmp.sequence.val += 1
        icmp.compute_checksum()
        
        ipv4.identification.val += 1
        ipv4.compute_checksum()

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
    
    ping(fd)
    
    bpf.bpf_dispose(fd)
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print
        sys.exit(0)
