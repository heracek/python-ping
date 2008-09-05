import os
import sys
import random
import time

import bpf
from wrappers import Ethernet, IPv4, UDP, DHCP, DHCPOptions, DHCPOption, ARP
from fields import MACAddres, IPAddress

IFCONFIG_MAC_ADDRESS_LINE = '\tether'

def get_local_mac_addres_of_device(dev):
    cmd = 'ifconfig %s' % dev
    try:
        pipe = os.popen(cmd)
    except IOError:
        raise Exception('''Can't get MAC addres.''')
    
    for line in pipe:
        if line.startswith(IFCONFIG_MAC_ADDRESS_LINE):
            return MACAddres(colon_hex_str = line[len(IFCONFIG_MAC_ADDRESS_LINE):])


def request_dhcp_info(fd, local_mac_address, timeout=2.0):
    
    # DISCOVERY
    
    eth = Ethernet(data_dict=dict(
        dmac=MACAddres(colon_hex_str='ff:ff:ff:ff:ff:ff'),
        smac=local_mac_address,
        type=0x0800
    ))
    
    ipv4 = IPv4(parent=eth, data_dict=dict(
        version=4,
        header_length=5,
        type_of_service=0x00,
        total_length=0,
        identification=random.getrandbits(16),
        flags=0x0,
        fragment_offset=0,
        time_to_live=255,
        protocol=0x11,
        header_checksum=0x0000,
        saddr=IPAddress(str_val='0.0.0.0'),
        daddr=IPAddress(str_val='255.255.255.255'),
    ))
    
    udp = UDP(parent=ipv4, data_dict=dict(
        sport=68,
        dport=67,
        length=0,
        checksum=0x0000,
    ))
    
    dhcp = DHCP(parent=udp, data_dict=dict(
        op=0x01,
        htype=0x01,
        hlen=0x06,
        hops=0x00,
        xid=random.getrandbits(32),
        secs=0x0000,
        flags=0x0000,
        ciaddr=IPAddress(str_val='0.0.0.0'),
        yiaddr=IPAddress(str_val='0.0.0.0'),
        siaddr=IPAddress(str_val='0.0.0.0'),
        giaddr=IPAddress(str_val='0.0.0.0'),
        chaddr=local_mac_address,
        _bootp_legacy='\x00' * 202,
        magic_cookie=0x63825363,
        dhcp_options=DHCPOptions([
            DHCPOption(dhcp_options=chr(53) + chr(1) + '\x01'), # dhcp_message_type
            DHCPOption(dhcp_options='\xff'),
            DHCPOption(dhcp_options='\x00' * 19),
        ])
    ))
    
    udp.payload = dhcp.raw_val(parents=False)
    udp.compute_length()
    udp.compute_checksum()
    
    ipv4.payload = udp.raw_val(parents=False) + udp.payload
    ipv4.compute_length()
    ipv4.compute_checksum()
    
    os.write(fd, dhcp.raw_val())
    start_time = time.time()
    
    # OFFER
    
    try:
        while True:
            end_time = time.time()
            
            rest_of_timeout = timeout / 2. - (end_time - start_time)
            if rest_of_timeout <= 0.0:
                raise bpf.BPFTimeout()
            
            packet = bpf.read_packet(fd, timeout=rest_of_timeout)
            
            in_eth = Ethernet(packet.data)
            is_valid_dhcp = False
            if in_eth.dmac == local_mac_address \
                and in_eth.type == 0x0800:
                
                in_ip = IPv4(parent=in_eth)
                
                if in_ip.version == 4 \
                    and in_ip.protocol == IPv4.PROTOCOL_UDP:
                        
                        in_udp = UDP(parent=in_ip)
                        
                        if in_udp.sport == 67 \
                            and in_udp.dport == 68:
                            
                            in_dhcp = DHCP(parent=in_udp)
                            
                            if in_dhcp.op == 0x02 \
                                and in_dhcp.htype == 0x01 \
                                and in_dhcp.xid == dhcp.xid \
                                and in_dhcp.chaddr == local_mac_address \
                                and in_dhcp.magic_cookie == 0x63825363 \
                                and in_dhcp.dhcp_options.get('dhcp_message_type') == '\x02':
                                
                                offer_dict = { 'yiaddr': in_dhcp.yiaddr }
                                for name in ('router', 'domain_name_server', 'subnet_mask'):
                                    offer_dict[name] = in_dhcp.dhcp_options.get(name)[0]
                                
                                is_valid_dhcp = True
            if is_valid_dhcp:
                break
    except bpf.BPFTimeout:
        print 'request_dhcp_info(local_mac_address=%s) timed out!' % local_mac_address
        sys.exit(1)
    
    
    # REQUEST
    
    ipv4.identification.val += 1
    
    dhcp.dhcp_options = DHCPOptions([
        DHCPOption(dhcp_options=chr(53) + chr(1) + '\x03'), # dhcp_message_type
        DHCPOption(dhcp_options=chr(55) + chr(10) + '\x01\x03\x06\x0f\x77\x5f\xfc\x2c\x2e\x2f'), # parameter_request_list
        DHCPOption(dhcp_options=chr(57) + chr(2) + '\x05\xdc'), # maximum_dhcp_message_size
        DHCPOption(dhcp_options=chr(50) + chr(4) + offer_dict['yiaddr'].raw_val()), # requested_ip_address
        DHCPOption(dhcp_options=chr(51) + chr(4) + '\x00\x76\xa7\x00'), # ip_address_lease_time (90 days)
        DHCPOption(dhcp_options='\xff'),
        DHCPOption(dhcp_options='\x00' * 19),
    ])
    
    udp.payload = dhcp.raw_val(parents=False)
    udp.compute_length()
    udp.compute_checksum()
    
    ipv4.payload = udp.raw_val(parents=False) + udp.payload
    ipv4.compute_length()
    ipv4.compute_checksum()
    
    os.write(fd, dhcp.raw_val())
    start_time = time.time()
    
    # ACKNOWLAGE
    
    try:
        while True:
            end_time = time.time()
            
            rest_of_timeout = timeout - (end_time - start_time)
            if rest_of_timeout <= 0.0:
                raise bpf.BPFTimeout()
            
            packet = bpf.read_packet(fd, timeout=rest_of_timeout)
            
            in_eth = Ethernet(packet.data)
            is_valid_dhcp = False
            if in_eth.dmac == local_mac_address \
                and in_eth.type == 0x0800:
                
                in_ip = IPv4(parent=in_eth)
                
                if in_ip.version == 4 \
                    and in_ip.protocol == IPv4.PROTOCOL_UDP:
                        
                        in_udp = UDP(parent=in_ip)
                        
                        if in_udp.sport == 67 \
                            and in_udp.dport == 68:
                            
                            in_dhcp = DHCP(parent=in_udp)
                            
                            if in_dhcp.op == 0x02 \
                                and in_dhcp.htype == 0x01 \
                                and in_dhcp.xid == dhcp.xid \
                                and in_dhcp.chaddr == local_mac_address \
                                and in_dhcp.magic_cookie == 0x63825363 \
                                and in_dhcp.dhcp_options.get('dhcp_message_type') == '\x05':
                                
                                return_dict = { 'yiaddr': in_dhcp.yiaddr }
                                for name in ('router', 'domain_name_server', 'subnet_mask'):
                                    return_dict[name] = in_dhcp.dhcp_options.get(name)[0]
                                
                                is_valid_dhcp = True
            if is_valid_dhcp:
                break
    except bpf.BPFTimeout:
        print 'request_dhcp_info(local_mac_address=%s) timed out!' % local_mac_address
        sys.exit(1)
    
    return return_dict

def request_adp_mac_addres(fd, local_mac_address, local_ip_address, remote_ip_address, timeout=1.0):
    
    eth = Ethernet(data_dict=dict(
        dmac=MACAddres(colon_hex_str='ff:ff:ff:ff:ff:ff'),
        smac=local_mac_address,
        type=Ethernet.TYPE_ARP,
    ))
    
    arp = ARP(parent=eth, data_dict=dict(
        htype=0x0001,
        ptype=0x0800,
        hlen=0x0006,
        plen=0x0004,
        oper=0x0001,
        sha=local_mac_address,
        spa=local_ip_address,
        tha=MACAddres(colon_hex_str='00:00:00:00:00:00'),
        tpa=remote_ip_address,
    ))
    
    os.write(fd, arp.raw_val())
    start_time = time.time()
    
    try:
        while True:
            end_time = time.time()
            
            rest_of_timeout = timeout - (end_time - start_time)
            if rest_of_timeout <= 0.0:
                raise bpf.BPFTimeout()
            
            packet = bpf.read_packet(fd, timeout=rest_of_timeout)
            
            in_eth = Ethernet(raw_data=packet.data)
            
            if in_eth.dmac == local_mac_address \
                and in_eth.type == Ethernet.TYPE_ARP:
                
                in_arp = ARP(parent=in_eth)
                
                if in_arp.htype == 0x0001 \
                    and in_arp.ptype == 0x0800 \
                    and in_arp.hlen == 0x0006 \
                    and in_arp.plen == 0x0004 \
                    and in_arp.oper == 0x0002 \
                    and in_arp.spa == remote_ip_address \
                    and in_arp.tha == local_mac_address \
                    and in_arp.tpa == local_ip_address:
                    
                    return in_arp.sha
            
    except bpf.BPFTimeout:
        print 'request_adp_mac_addres(local_mac_address=%s, local_ip_address=%s, remote_ip_address=%s) timed out!' % (
            local_mac_address, local_ip_address, remote_ip_address)
        sys.exit(1)
    
if __name__ == '__main__':
    LOCAL_DEVICE = 'en1'
    REMOTE_IP_ADDRESS = IPAddress(str_val='192.168.1.1')
    LOCAL_MAC_ADDRESS = get_local_mac_addres_of_device(LOCAL_DEVICE)
    
    fd = bpf.get_bpf_fg(device=LOCAL_DEVICE)
    
    LOCAL_IP_ADDRESS = request_dhcp_info(fd, LOCAL_MAC_ADDRESS)['yiaddr']
    
    print request_adp_mac_addres(fd, LOCAL_MAC_ADDRESS, LOCAL_IP_ADDRESS, REMOTE_IP_ADDRESS)
    
    bpf.bpf_dispose(fd)
    