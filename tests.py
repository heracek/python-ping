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




"""

def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
