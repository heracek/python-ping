#!/usr/bin/env python
# encoding: utf-8

import unittest

__doc__ = """
###############################################################################
### Field.raw_val()                                                         ###
###############################################################################

#---------------------------------------------------------#
#-- MACAddres.raw_val()                                 --#
#---------------------------------------------------------#

>>> from fields import MACAddres
>>> mac_addr_1 = MACAddres(bin_val='\\x00\\x19\\xe3\\x02\\xd9\\x1b')
>>> mac_addr_1
<MAC addres 00:19:e3:02:d9:1b>

>>> mac_addr_1.raw_val()
'\\x00\\x19\\xe3\\x02\\xd9\\x1b'


>>> mac_addr_2 = MACAddres(colon_hex_str='00:19:e3:02:d9:1b')
>>> mac_addr_2
<MAC addres 00:19:e3:02:d9:1b>

>>> mac_addr_2.raw_val()
'\\x00\\x19\\xe3\\x02\\xd9\\x1b'

#---------------------------------------------------------#
#-- HexIntClass.raw_val()                               --#
#---------------------------------------------------------#

>>> from fields import HexIntClass
>>> hex_int_1 = HexIntClass(0x0806, 4)
>>> str(hex_int_1)
'0x0806'

>>> hex_int_1.raw_val('!H')
'\\x08\\x06'

#---------------------------------------------------------#
#-- Int.raw_val()                                       --#
#---------------------------------------------------------#

>>> from fields import Int
>>> int_1 = Int(0x0806)
>>> str(int_1)
'2054'

>>> int_1.raw_val('!H')
'\\x08\\x06'

>>> int_1 * 2
4108

>>> int_1 << 2
8216

>>> int_1 == 2054
True
>>> int_1 == 123
False

>>> int_2 = Int(123)
>>> int_1 == int_2
False

>>> int_3 = Int(2054)
>>> int_1 == int_3
True

#---------------------------------------------------------#
#-- IPAddress.raw_val()                                 --#
#---------------------------------------------------------#

>>> from fields import IPAddress
>>> ip_addr_1 = IPAddress(3232235778)
>>> print ip_addr_1
192.168.1.2

>>> ip_addr_1.raw_val()
'\\xc0\\xa8\\x01\\x02'

>>> ip_addr_2 = IPAddress(str_val='192.168.1.2')
>>> print ip_addr_2
192.168.1.2

>>> ip_addr_2.raw_val()
'\\xc0\\xa8\\x01\\x02'

###############################################################################
### Wrapper.raw_val()                                                       ###
###############################################################################

#---------------------------------------------------------#
#-- Ethernet.raw_val()                                  --#
#---------------------------------------------------------#

>>> from fields import MACAddres
>>> from wrappers import Ethernet
>>> eth_1 = Ethernet('\\x01\\x80\\xc2\\x00\\x00\\x00\\x00\\x1a\\x92\\x12\\x11\\x1c\\x00\\x1e' + \
'E\\x00\\x00TKW\\xbf\\x10@\\x01\\xab\\xfe\\xc0\\xa8\\x01\\x01\\xc0\\xa8\\x01\\x02\\x00\\x00' + \
'\\x97\\xbd\\xe0+\\x00;h\\x90\\xbdHi\\xff\\r\\x00\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12' \
'\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f !"#$%&\\'()*+,-./01234567')

>>> print eth_1
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>

>>> eth_1.raw_val()
'\\x01\\x80\\xc2\\x00\\x00\\x00\\x00\\x1a\\x92\\x12\\x11\\x1c\\x00\\x1e'

>>> print Ethernet(eth_1.raw_val())
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>


>>> dmac = MACAddres(colon_hex_str='01:80:c2:00:00:00')
>>> smac = MACAddres(colon_hex_str='00:1a:92:12:11:1c') 
>>> eth_2 = Ethernet(data_dict=dict(dmac=dmac, smac=smac, type=0x001e))
>>> print eth_2
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>

>>> eth_2.raw_val()
'\\x01\\x80\\xc2\\x00\\x00\\x00\\x00\\x1a\\x92\\x12\\x11\\x1c\\x00\\x1e'


#---------------------------------------------------------#
#-- IPv4.raw_val()                                      --#
#---------------------------------------------------------#

>>> from fields import IPAddress
>>> from wrappers import IPv4
>>> ipv4_1 = IPv4(eth_1)
>>> print ipv4_1.__str__(parents=True)
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=84
        identification=0x4b57
        flags=0x5
        fragment_offset=7952
        time_to_live=64
        protocol=0x01
        header_checksum=0xabfe
        saddr=192.168.1.1
        daddr=192.168.1.2>

>>> ipv4_1.raw_val()
'\\x01\\x80\\xc2\\x00\\x00\\x00\\x00\\x1a\\x92\\x12\\x11\\x1c\\x00\\x1eE\\x00\\x00TKW\\xbf\\x10@\\x01\\xab\\xfe\\xc0\\xa8\\x01\\x01\\xc0\\xa8\\x01\\x02'

>>> print IPv4(Ethernet(ipv4_1.raw_val())).__str__(parents=True)
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=84
        identification=0x4b57
        flags=0x5
        fragment_offset=7952
        time_to_live=64
        protocol=0x01
        header_checksum=0xabfe
        saddr=192.168.1.1
        daddr=192.168.1.2>


>>> ipv4_2 = IPv4(parent=eth_1, data_dict=dict( \
    version=4, \
    header_length=5, \
    type_of_service=0x00, \
    total_length=84, \
    identification=0x4b57, \
    flags=0x5, \
    fragment_offset=7952, \
    time_to_live=64, \
    protocol=0x01, \
    header_checksum=0xabfe, \
    saddr=IPAddress(str_val='192.168.1.1'), \
    daddr=IPAddress(str_val='192.168.1.2')))

>>> print ipv4_2.__str__(parents=True)
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=84
        identification=0x4b57
        flags=0x5
        fragment_offset=7952
        time_to_live=64
        protocol=0x01
        header_checksum=0xabfe
        saddr=192.168.1.1
        daddr=192.168.1.2>


#---------------------------------------------------------#
#-- ICMP.raw_val()                                      --#
#---------------------------------------------------------#

>>> from wrappers import ICMP
>>> icmp_1 = ICMP(parent=ipv4_1)
>>> print icmp_1.__str__(parents=True)
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=84
        identification=0x4b57
        flags=0x5
        fragment_offset=7952
        time_to_live=64
        protocol=0x01
        header_checksum=0xabfe
        saddr=192.168.1.1
        daddr=192.168.1.2>
        <ICMP 
            type=0
            code=0
            checksum=0x97bd
            id=0xe02b
            sequence=59>
>>> icmp_1.raw_val()
'\\x01\\x80\\xc2\\x00\\x00\\x00\\x00\\x1a\\x92\\x12\\x11\\x1c\\x00\\x1eE\\x00\\x00TKW\\xbf\\x10@\\x01\\xab\\xfe\\xc0\\xa8\\x01\\x01\\xc0\\xa8\\x01\\x02\\x00\\x00\\x97\\xbd\\xe0+\\x00;'
>>> icmp_1.payload
'h\\x90\\xbdHi\\xff\\r\\x00\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f !"#$%&\\'()*+,-./01234567'

>>> print ICMP(parent=IPv4(Ethernet(icmp_1.raw_val()))).__str__(parents=True)
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=84
        identification=0x4b57
        flags=0x5
        fragment_offset=7952
        time_to_live=64
        protocol=0x01
        header_checksum=0xabfe
        saddr=192.168.1.1
        daddr=192.168.1.2>
        <ICMP 
            type=0
            code=0
            checksum=0x97bd
            id=0xe02b
            sequence=59>

>>> icmp_2 = ICMP(parent=ipv4_1, data_dict=dict( \
    type=0, \
    code=0, \
    checksum=0x97bd, \
    id=0xe02b, \
    sequence=59 \
))
>>> print icmp_2.__str__(parents=True)
<Ethernet 
    dmac=01:80:c2:00:00:00
    smac=00:1a:92:12:11:1c
    type=0x001e>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=84
        identification=0x4b57
        flags=0x5
        fragment_offset=7952
        time_to_live=64
        protocol=0x01
        header_checksum=0xabfe
        saddr=192.168.1.1
        daddr=192.168.1.2>
        <ICMP 
            type=0
            code=0
            checksum=0x97bd
            id=0xe02b
            sequence=59>
            

#---------------------------------------------------------#
#-- DHCP.raw_val()                                      --#
#---------------------------------------------------------#

>>> from wrappers import UDP, DHCP
>>> dhcp_raw_packet_4 = '\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\x19\\xe3\\x02\\xd9+\\x08\\x00E\\x00\\x01H3\\xa1\\x00\\x00\\xff\\x11\\x87\\x04\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\x00D\\x00C\\x014\\x80\\x82\\x01\\x01\\x06\\x00O\\xe33\\x9b\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x19\\xe3\\x02\\xd9+\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00c\\x82Sc5\\x01\\x037\\n\\x01\\x03\\x06\\x0fw_\\xfc,./9\\x02\\x05\\xdc=\\x07\\x01\\x00\\x19\\xe3\\x02\\xd9+2\\x04\\xc0\\xa8\\x01\\x023\\x04\\x00v\\xa7\\x00\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
>>> eth_4 = Ethernet(dhcp_raw_packet_4)
>>> ipv4_4 = IPv4(parent=eth_4)
>>> udp_4 = UDP(parent=ipv4_4)
>>> dhcp_4 = DHCP(parent=udp_4)
>>> print dhcp_4.__str__(parents=True)
<Ethernet 
    dmac=ff:ff:ff:ff:ff:ff
    smac=00:19:e3:02:d9:2b
    type=0x0800>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=328
        identification=0x33a1
        flags=0x0
        fragment_offset=0
        time_to_live=255
        protocol=0x11
        header_checksum=0x8704
        saddr=0.0.0.0
        daddr=255.255.255.255>
        <UDP 
            sport=68
            dport=67
            length=308
            checksum=0x8082>
            <DHCP 
                op=0x01
                htype=0x01
                hlen=0x06
                hops=0x00
                xid=0x4fe3339b
                secs=0x0000
                flags=0x0000
                ciaddr=0.0.0.0
                yiaddr=0.0.0.0
                siaddr=0.0.0.0
                giaddr=0.0.0.0
                chaddr=00:19:e3:02:d9:2b
                magic_cookie=0x63825363
                dhcp_options=<DHCPOptions
                    option(t=53 [dhcp_message_type], l=1): 03
                    option(t=55 [parameter_request_list], l=10): 01 03 06 0f 77 5f fc 2c 2e 2f
                    option(t=57 [maximum_dhcp_message_size], l=2): 05 dc
                    option(t=61 [client_identifier], l=7): 01 00 19 e3 02 d9 2b
                    option(t=50 [requested_ip_address], l=4): 192.168.1.2
                    option(t=51 [ip_address_lease_time], l=4): 00 76 a7 00
                    option(t=255 [end], l=0): 
                    option(t=0 [pad], l=18): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00>

>>> dhcp_4.raw_val() == dhcp_raw_packet_4
True

>>> dhcp_4.dhcp_options.get('dhcp_message_type')
'\\x03'
>>> dhcp_4.dhcp_options.get('requested_ip_address')
[<IP address 192.168.1.2>]


>>> from wrappers import DHCPOptions, DHCPOption
>>> eth_5 = Ethernet(data_dict=dict( \
    dmac=MACAddres(colon_hex_str='ff:ff:ff:ff:ff:ff'), \
    smac=MACAddres(colon_hex_str='00:19:e3:02:d9:2b'), \
    type=0x0800 \
))
>>> ipv4_5 = IPv4(parent=eth_5, data_dict=dict( \
    version=4, \
    header_length=5, \
    type_of_service=0x00, \
    total_length=0, \
    identification=0x33a1, \
    flags=0x0, \
    fragment_offset=0, \
    time_to_live=255, \
    protocol=0x11, \
    header_checksum=0x0000, \
    saddr=IPAddress(str_val='0.0.0.0'), \
    daddr=IPAddress(str_val='255.255.255.255'), \
))
>>> udp_5 = UDP(parent=ipv4_5, data_dict=dict( \
    sport=68, \
    dport=67, \
    length=0, \
    checksum=0x0000, \
))
>>> dhcp_5 = DHCP(parent=udp_5, data_dict=dict( \
    op=0x01, \
    htype=0x01, \
    hlen=0x06, \
    hops=0x00, \
    xid=0x4fe3339b, \
    secs=0x0000, \
    flags=0x0000, \
    ciaddr=IPAddress(str_val='0.0.0.0'), \
    yiaddr=IPAddress(str_val='0.0.0.0'), \
    siaddr=IPAddress(str_val='0.0.0.0'), \
    giaddr=IPAddress(str_val='0.0.0.0'), \
    chaddr=MACAddres(colon_hex_str='00:19:e3:02:d9:2b'), \
    _bootp_legacy='\\x00' * 202, \
    magic_cookie=0x63825363, \
    dhcp_options=DHCPOptions(dhcp_options=[ \
        DHCPOption(dhcp_options=chr(53) + chr(1) + '\\x03'), \
        DHCPOption(dhcp_options=chr(55) + chr(10) + '\\x01\\x03\\x06\\x0f\\x77\\x5f\\xfc\\x2c\\x2e\\x2f'), \
        DHCPOption(dhcp_options=chr(57) + chr(2) + '\\x05\\xdc'), \
        DHCPOption(dhcp_options=chr(61) + chr(7) + '\\x01\\x00\\x19\\xe3\\x02\\xd9\\x2b'), \
        DHCPOption(dhcp_options=chr(50) + chr(4) + IPAddress(str_val='192.168.1.2').raw_val()), \
        DHCPOption(dhcp_options=chr(51) + chr(4) + '\\x00\\x76\\xa7\\x00'), \
        DHCPOption(dhcp_options='\\xff'), \
        DHCPOption(dhcp_options='\\x00' * 19), \
    ]) \
))

>>> len(dhcp_5.raw_val()), len(dhcp_raw_packet_4)
(342, 342)

>>> udp_5.payload = dhcp_5.raw_val(parents=False)
>>> udp_5.compute_length()
308
>>> udp_5.length.val, udp_4.length.val
(308, 308)
>>> print hex(udp_5.compute_checksum())
0x8082

>>> ipv4_5.payload = udp_5.raw_val(parents=False) + udp_5.payload
>>> ipv4_5.compute_length()
328
>>> print hex(ipv4_5.compute_checksum())
0x8704

>>> dhcp_5.raw_val() == dhcp_raw_packet_4
True


###############################################################################
### compute_checksum()                                                      ###
###############################################################################

#---------------------------------------------------------#
#-- ICMP.compute_checksum()                             --#
#---------------------------------------------------------#

>>> icmp_2 = ICMP(parent=ipv4_1, data_dict=dict( \
    type=0, \
    code=0, \
    id=0xe02b, \
    sequence=59 \
))
>>> print icmp_2
        <ICMP 
            type=0
            code=0
            checksum=0x0000
            id=0xe02b
            sequence=59>

>>> icmp_2.payload = 'h\\x90\\xbdHi\\xff\\r\\x00\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12' \
'\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f !"#$%&\\'()*+,-./01234567'

>>> print icmp_2.compute_checksum()
0x97bd

>>> print icmp_2
        <ICMP 
            type=0
            code=0
            checksum=0x97bd
            id=0xe02b
            sequence=59>

#---------------------------------------------------------#
#-- ICMP.compute_checksum()                             --#
#---------------------------------------------------------#

>>> ipv4_3 = IPv4(parent=eth_1, data_dict=dict( \
    version=4, \
    header_length=5, \
    type_of_service=0x00, \
    total_length=52, \
    identification=0xe9bb, \
    flags=0x2, \
    fragment_offset=0, \
    time_to_live=51, \
    protocol=0x06, \
    saddr=IPAddress(str_val='62.50.73.12'), \
    daddr=IPAddress(str_val='192.168.1.2') \
))

>>> ipv4_3.raw_val(parents=False)
'E\\x00\\x004\\xe9\\xbb@\\x003\\x06\\x00\\x00>2I\\x0c\\xc0\\xa8\\x01\\x02'
>>> print hex(ipv4_3.compute_checksum())
0x1520
>>> ipv4_3.raw_val(parents=False) # after compute_checksum()
'E\\x00\\x004\\xe9\\xbb@\\x003\\x06\\x15 >2I\\x0c\\xc0\\xa8\\x01\\x02'


#---------------------------------------------------------#
#-- UDP.compute_checksum()                              --#
#---------------------------------------------------------#

>>> from wrappers import UDP
>>> udp_1 = UDP(IPv4(Ethernet('\\x01\\x00^\\x7f\\xff\\xfa\\x00\\x1a\\x92b1L\\x08\\x00E\\x00\\x01\\x8b\\x00\\x00@\\x00\\x04\\x11\\xc3\\xbe\\xc0\\xa8\\x01\\x01\\xef\\xff\\xff\\xfa\\x07l\\x07l\\x01w\\xf8}NOTIFY * HTTP/1.1 \\r\\nHOST: 239.255.255.250:1900\\r\\nCACHE-CONTROL: max-age=30\\r\\nLocation: http://192.168.1.1:5431/dyndev/uuid:001a9262-314c-001a-9262-314c00585400\\r\\nNT: urn:schemas-upnp-org:service:WANPPPConnection:1\\r\\nNTS: ssdp:alive\\r\\nSERVER:LINUX/2.4 UPnP/1.0 BRCM400/1.0\\r\\nUSN: uuid:001a9262-314c-001a-9262-314c02585400::urn:schemas-upnp-org:service:WANPPPConnection:1\\r\\n\\r\\n')))
>>> print udp_1.__str__(parents=True)
<Ethernet 
    dmac=01:00:5e:7f:ff:fa
    smac=00:1a:92:62:31:4c
    type=0x0800>
    <IPv4 
        version=4
        header_length=5
        type_of_service=0x00
        total_length=395
        identification=0x0000
        flags=0x2
        fragment_offset=0
        time_to_live=4
        protocol=0x11
        header_checksum=0xc3be
        saddr=192.168.1.1
        daddr=239.255.255.250>
        <UDP 
            sport=1900
            dport=1900
            length=375
            checksum=0xf87d>

>>> udp_1.checksum.val = 0
>>> print udp_1
        <UDP 
            sport=1900
            dport=1900
            length=375
            checksum=0x0000>

>>> print hex(udp_1.compute_checksum())
0xf87d
>>> print udp_1 # after compute_checksum()
        <UDP 
            sport=1900
            dport=1900
            length=375
            checksum=0xf87d>


"""

def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
