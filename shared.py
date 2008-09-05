import os
import random

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

def request_ip_address(fd, local_mac_address):
    
    eth = Ethernet(data_dict=dict(
        dmac=MACAddres(colon_hex_str='ff:ff:ff:ff:ff:ff'),
        smac=local_mac_address,
        type=0x0800
    ))
    
    ipv4 = IPv4(parent=eth, data_dict=dict(
        version=4,
        header_length=5,
        type_of_service=0x00,
        total_length=0, # !!!
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
        length=0, # !!!
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
            DHCPOption(dhcp_options=chr(53) + '\x01\x03'),
            
            DHCPOption(dhcp_options='\xff'),
            DHCPOption(dhcp_options='\x00' * 19),
        ])
    ))
    
    udp.payload = dhcp.raw_val(parents=False)
    print len(udp.payload)
    
    udp.length.val = len(udp.payload)
    udp.compute_checksum()
    print udp.length
    
    ipv4.total_length.val = len(ipv4.raw_val(parents=False)) + len(udp.raw_val(parents=False)) + len(udp.payload)
    ipv4.compute_checksum()
    print ipv4.total_length
    
    print repr(dhcp.raw_val()), len(dhcp.raw_val())
    
    os.write(fd, dhcp.raw_val())

if __name__ == '__main__':
    import bpf
    
    LOCAL_DEVICE = 'en1'
    
    LOCAL_MAC_ADDRESS = get_local_mac_addres_of_device(LOCAL_DEVICE)
    fd = bpf.get_bpf_fg(device=LOCAL_DEVICE)
    
    request_ip_address(fd, LOCAL_MAC_ADDRESS)
