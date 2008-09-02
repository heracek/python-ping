import struct
from utils import bin2hex

class Field(object):
    def raw_val(self):
        raise NotImplementedError('raw_val() not implemented in %s.' % self.__class__.__name__)

def HexInt(width):
    def CreateHexInt(val):
        return HexIntClass(val, width)
    return CreateHexInt

class HexIntClass(Field):
    def __init__(self, val, width):
        self.val = val
        self.width = width
    
    def __str__(self):
        format = '0x%%0%dx' % self.width
        return format % self.val
    
    def __eq__(self, other):
        return self.val == other.val


class MACAddres(Field):
    def __init__(self, bin_val=None, colon_hex_str=None, pure_hex_str=None, num_val=None):
        ''' MACAddres constructor:
            
            accepts one of these arguments:
                bin_val = '\x00\x19\xe3\x02\xd9\x2b'
                colon_hex_str = '00:19:e3:02:d9:2b'
                pure_hex_str = '0019e302d92b' or '19e302d92b'
                num_val = 111182797099 or 0x19e302d92b
        '''
        self.num_val = None
        
        if bin_val:
            pure_hex_str = bin2hex(bin_val, '')
        if colon_hex_str:
            pure_hex_str = ''.join([ch for ch in colon_hex_str if ch.isalnum()])
        if pure_hex_str:
            self.num_val = int(pure_hex_str, 16)
        if num_val:
            self.num_val = num_val
        
        if not self.num_val:
            raise Exception('Missing arguments')
            
    
    def raw_val(self):
        return struct.pack('!H', self.num_val // 2 ** 32) + struct.pack('!L', self.num_val % 2 ** 32)
        
    
    def __repr__(self):
        return '<MAC addres %s>' % self.__str__()
    
    def __str__(self):
        str_repr = "%012x" % self.num_val
        bytes = [str_repr[i:i + 2] for i in xrange(0, len(str_repr), 2)]
        return ':'.join(bytes)

class IPAddress(Field):
    
    def __init__(self, bin_val):
        self.bin_val = bin_val
    
    def __str__(self):
        addr_segments = [str((self.bin_val >> shift) % 256) for shift in (24, 16, 8, 0)]
        return '.'.join(addr_segments)
    
    def raw_val(self):
        return self.bin_val
