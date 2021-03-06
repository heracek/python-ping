#!/usr/bin/env python
import fcntl
import os
import re
import shared
import sys
import time
import random

import bpf
from utils import bin2hex
from wrappers import Ethernet, IPv4, UDP, DHCP, ICMP
from fields import IPAddress

LOCAL_DEVICE = None
LOCAL_MAC_ADDRESS = None
LOCAL_IP_ADDRESS = None

REMOTE_MAC_ADDRESS = None
REMOTE_IP_ADDRESS = None

def ping(fd, timeout=1.0):
    
    eth = Ethernet(data_dict=dict(
        dmac=REMOTE_MAC_ADDRESS,
        smac=LOCAL_MAC_ADDRESS,
        type=0x0800
    ))
    
    ipv4 = IPv4(parent=eth, data_dict=dict(
        version=4,
        header_length=5,
        type_of_service=0x00,
        total_length=84,
        identification=random.getrandbits(16),
        flags=0x0,
        fragment_offset=0,
        time_to_live=64,
        protocol=0x01,
        header_checksum=0x0000,
        saddr=LOCAL_IP_ADDRESS,
        daddr=REMOTE_IP_ADDRESS
    ))
    
    icmp = ICMP(parent=ipv4, data_dict=dict(
        type=8,
        code=0,
        checksum=0x0000,
        id=random.getrandbits(16),
        sequence=0
    ))
    
    icmp.payload = 'a' * 56
    
    print "PING %s: %d data bytes" % (REMOTE_IP_ADDRESS, len(icmp.payload))
    
    while True:
        
        icmp.compute_checksum()
        ipv4.compute_checksum()
        
        out_packet = icmp.raw_val() + icmp.payload
        os.write(fd, out_packet)
        
        start_time = time.time()
        
        try:
            while True:
                packet = bpf.read_packet(fd, timeout=timeout)
                
                end_time = time.time()
                
                in_eth = Ethernet(packet.data)
                
                is_valid_icmp = False
                if in_eth.dmac == LOCAL_MAC_ADDRESS \
                    and in_eth.type == Ethernet.TYPE_IP:
                    # and in_eth.smac == REMOTE_MAC_ADDRESS
                    
                    in_ip = IPv4(parent=in_eth)
                    
                    if in_ip.version == 4 \
                        and in_ip.protocol == IPv4.PROTOCOL_ICMP \
                        and in_ip.saddr == REMOTE_IP_ADDRESS \
                        and in_ip.daddr == LOCAL_IP_ADDRESS:
                        
                        in_icmp = ICMP(parent=in_ip)
                        
                        if in_icmp.type == 0 \
                            and in_icmp.code == 0 \
                            and in_icmp.id == icmp.id \
                            and in_icmp.sequence == in_icmp.sequence:
                            
                            is_valid_icmp = True
                            
                            total_time = end_time - start_time
                            print "%d bytes from %s: icmp_seq=%s ttl=%s time=%.03f ms" % \
                                (in_icmp.len(), in_ip.saddr, in_icmp.sequence,
                                 in_ip.time_to_live, total_time * 1000)
                            
                            if total_time < timeout:
                                time.sleep(timeout - total_time)
                
                if is_valid_icmp:
                    break
        except bpf.BPFTimeout:
            print 'ping: sendto: Host is down (icmp_seq=%d)' % icmp.sequence.val
        
        icmp.sequence.val += 1
        ipv4.identification.val += 1
        

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
    
    global LOCAL_DEVICE, LOCAL_MAC_ADDRESS, LOCAL_IP_ADDRESS, \
        REMOTE_MAC_ADDRESS, REMOTE_IP_ADDRESS
    
    LOCAL_DEVICE = sys.argv[1]
    LOCAL_MAC_ADDRESS = shared.get_local_mac_addres_of_device(LOCAL_DEVICE)
    REMOTE_IP_ADDRESS = IPAddress(str_val=sys.argv[2])
    
    fd = bpf.get_bpf_fg(device=LOCAL_DEVICE)
    
    dhcp_info = shared.request_dhcp_info(fd, LOCAL_MAC_ADDRESS)
    
    LOCAL_IP_ADDRESS = dhcp_info['yiaddr']
    SUBNET_MASK = dhcp_info['subnet_mask']
    
    if SUBNET_MASK.addresses_in_same_subnet(LOCAL_IP_ADDRESS, REMOTE_IP_ADDRESS):
        NEXT_HOOP_IP_ADDRESS = REMOTE_IP_ADDRESS
    else:
        NEXT_HOOP_IP_ADDRESS = dhcp_info['router']

    REMOTE_MAC_ADDRESS = shared.request_adp_mac_addres(fd, LOCAL_MAC_ADDRESS, LOCAL_IP_ADDRESS, NEXT_HOOP_IP_ADDRESS)
    
    for var_name in ('LOCAL_DEVICE', 'LOCAL_MAC_ADDRESS', 'LOCAL_IP_ADDRESS', 'REMOTE_MAC_ADDRESS', 'REMOTE_IP_ADDRESS'):
        print "%-20s %s" % (var_name + ':', globals()[var_name])
    
    ping(fd)
    
    bpf.bpf_dispose(fd)
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print
        sys.exit(0)
