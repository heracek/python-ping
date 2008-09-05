import os
import random

from wrappers import Ethernet, IPv4, UDP, DHCP
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
        length=308,
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
        dhcp_options=IPAddress(str_val='1.2.3.4')
        # dhcp_options=<DHCPOptions
        #     option(t=53 [dhcp_message_type], l=1): 03
        #     option(t=55 [parameter_request_list], l=10): 01 03 06 0f 77 5f fc 2c 2e 2f
        #     option(t=57 [maximum_dhcp_message_size], l=2): 05 dc
        #     option(t=61 [client_identifier], l=7): 01 00 17 f2 f3 55 77
        #     option(t=50 [requested_ip_address], l=4): 192.168.1.4
        #     option(t=51 [ip_address_lease_time], l=4): 00 76 a7 00>
    ))
    
    udp.payload = dhcp.raw_val(parents=False)
    udp.compute_checksum()
    ipv4.compute_checksum()
    
    print repr(dhcp.raw_val()), len(dhcp.raw_val())

#request_ip_address(1, MACAddres(colon_hex_str='00:17:f2:f3:55:77'))