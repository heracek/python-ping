import os
import struct

from utils import bin2hex

def HexInt(width):
    def CreateHexInt(val):
        return HexIntClass(val, width)
    return CreateHexInt

class HexIntClass(object):
    def __init__(self, val, width):
        self.val = val
        self.width = width
    
    def __str__(self):
        format = '0x%%0%dx' % self.width
        return format % self.val


class MACAddres(object):
    def __init__(self, bin_val=None, colon_hex_str=None, pure_hex_str=None, num_val=None):
        ''' MACAddres constructor:
            
            accepts one of these arguments:
                pure_hex_str = '\x00\x19\xe3\x02\xd9\x2b'
                colon_hex_str = '00:19:e3:02:d9:2b'
                pure_hex_str = '0019e302d92b' or '19e302d92b'
                num_val = 111182797099 or 0x19e302d92b
        '''
        if bin_val:
            pure_hex_str = bin2hex(bin_val, '')
        if colon_hex_str:
            pure_hex_str = ''.join([ch for ch in colon_hex_str if ch.isalnum()])
        if pure_hex_str:
            self.num_val = int(pure_hex_str, 16)
        if num_val:
            self.num_val = num_val
    
    def __repr__(self):
        return '<MAC addres %s>' % self.__str__()
    
    def __str__(self):
        str_repr = "%012x" % self.num_val
        bytes = [str_repr[i:i + 2] for i in xrange(0, len(str_repr), 2)]
        return ':'.join(bytes)

class Wrapper(object):
    def __init__(self, data=None):
        '''
        Processes '_fields_' list and inits object's argumets by vals defined in data.
        '''
        if data:
            data_index = 0
            for field in self._fields_:
                name = field[0]
                unpack_str = field[1]
                _type = field[2]
                size = struct.calcsize(unpack_str)
            
                raw_val = struct.unpack(unpack_str, data[data_index:data_index + size])[0]
                val = _type(raw_val)
            
                self.__setattr__(name, val)
            
                data_index += size
    
    def __str__(self):
        fields_arr = []
        for field in self._fields_:
            name = field[0]
            
            field_str = "%s=%s" % (name, self.__getattribute__(name))
            fields_arr.append(field_str)
        
        return '<%s %s>' % (self.__class__.__name__, ' '.join(fields_arr))
    
class Ethernet(Wrapper):
    
    TYPE_IP = 0x0800
    
    _fields_ = [
        ('source', '6s', MACAddres),
        ('destination', '6s', MACAddres),
        ('type', '!H', HexInt(4))
    ]
    
    def __init__(self, eth_packet=None):
        super(Ethernet, self).__init__(eth_packet)

print Ethernet('\x01\x80\xc2\x00\x00\x00\x00\x1a\x92\x62\x31\x4c\x00\x2e\x42\x42\x03\x00\x00\x00\x00\x00\x80\x00\x00\x1a\x92\x62\x31\x4c\x01\x80\xc2')
