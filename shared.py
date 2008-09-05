import os
import sys
import random
import time

from wrappers import Ethernet, IPv4, UDP, DHCP, DHCPOptions, DHCPOption
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

def request_ip_address(fd, local_mac_address, timeout=5.0):
    
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
        dhcp_options=DHCPOptions(dhcp_options=[
            DHCPOption(dhcp_options=chr(53) + chr(1) + '\x03'), # dhcp_message_type
            DHCPOption(dhcp_options=chr(55) + chr(10) + '\x01\x03\x06\x0f\x77\x5f\xfc\x2c\x2e\x2f'), # parameter_request_list
            DHCPOption(dhcp_options=chr(57) + chr(2) + '\x05\xdc'), # maximum_dhcp_message_size
            DHCPOption(dhcp_options=chr(61) + chr(7) + '\x01\x00\x19\xe3\x02\xd9\x2b'), # client_identifier
            DHCPOption(dhcp_options=chr(50) + chr(4) + IPAddress(str_val='192.168.1.2').raw_val()), # requested_ip_address
            DHCPOption(dhcp_options=chr(51) + chr(4) + '\x00\x76\xa7\x00'), # ip_address_lease_time (90 days)
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
    
    try:
        while True:
            end_time = time.time()
            packet = bpf.read_packet(fd, timeout=(timeout - (end_time - start_time)))
            
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
                                and in_dhcp.magic_cookie == 0x63825363:
                                
                                print 'ok!'
                                print in_dhcp
                                
            
    except bpf.BPFTimeout:
        print 'request_ip_address(local_mac_address=%s) timed out!' % local_mac_address
        sys.exit(1)
    bpf.bpf_dispose(fd)

if __name__ == '__main__':
    import bpf
    
    LOCAL_DEVICE = 'en1'
    
    LOCAL_MAC_ADDRESS = get_local_mac_addres_of_device(LOCAL_DEVICE)
    fd = bpf.get_bpf_fg(device=LOCAL_DEVICE)
    
    request_ip_address(fd, LOCAL_MAC_ADDRESS)
