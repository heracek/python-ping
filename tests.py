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
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
    type=0x001e>

>>> eth_1.raw_val()
'\\x01\\x80\\xc2\\x00\\x00\\x00\\x00\\x1a\\x92\\x12\\x11\\x1c\\x00\\x1e'

>>> print Ethernet(eth_1.raw_val())
<Ethernet 
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
    type=0x001e>


>>> smac = MACAddres(colon_hex_str='01:80:c2:00:00:00')
>>> dmac = MACAddres(colon_hex_str='00:1a:92:12:11:1c') 
>>> eth_2 = Ethernet(data_dict=dict(smac=smac, dmac=dmac, type=0x001e))
>>> print eth_2
<Ethernet 
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
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
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
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
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
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
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
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
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
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
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
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
    smac=01:80:c2:00:00:00
    dmac=00:1a:92:12:11:1c
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

>>> str(icmp_2.compute_checksum())
'0x97bd'

>>> print icmp_2
        <ICMP 
            type=0
            code=0
            checksum=0x97bd
            id=0xe02b
            sequence=59>

"""

def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
