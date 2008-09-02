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

"""

def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
