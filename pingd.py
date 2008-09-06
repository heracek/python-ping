#!/usr/bin/env python
import os
import sys
import random

import bpf
import shared
from utils import bin2hex
from wrappers import Ethernet, IPv4, ICMP, ARP
from fields import MACAddres

LOCAL_DEVICE = None
LOCAL_MAC_ADDRESS = MACAddres(colon_hex_str='01:80:c2:00:bb:aa')
PRINT_DEBUG = False

raw_packet = None

def print_debug(what, force=False):
    if PRINT_DEBUG:
        print what
    elif force:
        print what.__str__(parents=True)
        # x = what.raw_val()
        # print repr(x)

def pingd(fd):
    
    icmp_eth = Ethernet(data_dict=dict(
        dmac=None,
        smac=LOCAL_MAC_ADDRESS,
        type=Ethernet.TYPE_IP,
    ))
    
    icmp_ipv4 = IPv4(parent=icmp_eth, data_dict=dict(
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
        daddr=None,
    ))
    
    icmp = ICMP(parent=icmp_ipv4, data_dict=dict(
        type=0,
        code=0,
        checksum=0x0000,
        id=None,
        sequence=None
    ))
    
    arp_eth = Ethernet(data_dict=dict(
        dmac=None,
        smac=LOCAL_MAC_ADDRESS,
        type=Ethernet.TYPE_ARP,
    ))
    
    arp = ARP(parent=arp_eth, data_dict=dict(
        htype=0x0001,
        ptype=0x0800,
        hlen=0x0006,
        plen=0x0004,
        oper=0x0002,
        sha=LOCAL_MAC_ADDRESS,
        spa=LOCAL_IP_ADDRESS,
        tha=None,
        tpa=None,
    ))
    
    for bpf_packet in bpf.packet_reader(fd):
        raw_packet = bpf_packet.data
        
        in_eth = (Ethernet(bpf_packet.data))
                
        if in_eth.dmac == LOCAL_MAC_ADDRESS \
            and in_eth.type == Ethernet.TYPE_IP:
            
            
            in_ip = IPv4(parent=in_eth)
            
            if in_ip.version == 4 \
                and in_ip.protocol == IPv4.PROTOCOL_ICMP \
                and in_ip.daddr == LOCAL_IP_ADDRESS:
                
                in_icmp = ICMP(parent=in_ip)
                
                if in_icmp.type == 8 \
                    and in_icmp.code == 0:
                        print 'Received ICMP ECHO request from %s (%s): id=%s, sequence=%s' % \
                            (in_ip.saddr, in_ip.saddr, in_icmp.id, in_icmp.sequence)
                        
                        icmp.payload = in_icmp.payload
                        icmp.id = in_icmp.id
                        icmp.sequence = in_icmp.sequence
                        
                        icmp_ipv4.daddr = in_ip.saddr
                        icmp_ipv4.identification.val += 1
                        
                        icmp_eth.smac = LOCAL_MAC_ADDRESS
                        icmp_eth.dmac = in_eth.smac
                        
                        icmp.compute_checksum()
                        icmp_ipv4.compute_checksum()
                        
                        out_packet = icmp.raw_val() + icmp.payload
                        
                        #print_debug(icmp, force=True)
                        #print repr(out_packet)
                        
                        os.write(fd, out_packet)
        
        elif in_eth.dmac == MACAddres(colon_hex_str='ff:ff:ff:ff:ff:ff') \
            and in_eth.type == Ethernet.TYPE_ARP:
            
            in_arp = ARP(parent=in_eth)
            
            if in_arp.htype == 0x0001 \
                and in_arp.ptype == 0x0800 \
                and in_arp.hlen == 0x0006 \
                and in_arp.plen == 0x0004 \
                and in_arp.oper == 0x0001 \
                and in_arp.tpa == LOCAL_IP_ADDRESS:
                
                print 'Received ARP request from: %s (%s)' % (in_arp.spa, in_arp.sha)
                
                arp.tha = in_arp.sha
                arp.tpa = in_arp.spa
                arp._parent.dmac = in_arp.sha
                
                os.write(fd, arp.raw_val())

def main():
    if len(sys.argv) != 2:
        if len(sys.argv) == 1:
            sys.argv.extend(['en1'])
            print 'using defaul args:', ' '.join(sys.argv)
        else:
            print 'usage: %s dev' % sys.argv[0]
            print '\tdev ... device'
            sys.exit(1)
    
    
    global LOCAL_DEVICE, LOCAL_MAC_ADDRESS, LOCAL_IP_ADDRESS, \
        REMOTE_MAC_ADDRESS, REMOTE_IP_ADDRESS
    
    LOCAL_DEVICE = sys.argv[1]
    
    if LOCAL_MAC_ADDRESS is None:
        LOCAL_MAC_ADDRESS = shared.get_local_mac_addres_of_device(LOCAL_DEVICE)
    
    fd = bpf.get_bpf_fg(device=LOCAL_DEVICE, promiscuous=False)
    
    dhcp_info = shared.request_dhcp_info(fd, LOCAL_MAC_ADDRESS)
    LOCAL_IP_ADDRESS = dhcp_info['yiaddr']
    
    for var_name in ('LOCAL_DEVICE', 'LOCAL_MAC_ADDRESS', 'LOCAL_IP_ADDRESS'):
        print "%-20s %s" % (var_name + ':', globals()[var_name])
    print
    
    pingd(fd)
    
    bpf.bpf_dispose(fd)
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print
        sys.exit(0)
