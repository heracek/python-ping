import struct
from utils import bin2hex

class Field(object):
    def raw_val(self, struct_fmt=None):
        raise NotImplementedError('raw_val() not implemented in %s.' % self.__class__.__name__)

class Int(Field):
    def __init__(self, val):
        self.val = val
    
    def __str__(self):
        return str(self.val)
    
    def __eq__(self, other):
        if isinstance(other, Int):
            return self.val == other.val
        return self.val == other
    
    def __mul__(self, other):
        return self.val * other
    
    def __lshift__(self, other):
        return self.val << other
    
    def raw_val(self, struct_fmt):
        return struct.pack(struct_fmt, self.val)

def HexInt(width):
    def CreateHexInt(val):
        return HexIntClass(val, width)
    return CreateHexInt

class HexIntClass(Int):
    def __init__(self, val, width):
        self.val = val
        self.width = width
    
    def __str__(self):
        format = '0x%%0%dx' % self.width
        return format % self.val

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
        
        if bin_val is not None:
            pure_hex_str = bin2hex(bin_val, '')
        if colon_hex_str is not None:
            pure_hex_str = ''.join([ch for ch in colon_hex_str if ch.isalnum()])
        if pure_hex_str is not None:
            self.num_val = int(pure_hex_str, 16)
        if num_val is not None:
            self.num_val = num_val
        
        if self.num_val is None:
            raise Exception('Missing arguments')
            
    
    def raw_val(self, struct_fmt=None):
        return struct.pack('!H', self.num_val // 2 ** 32) + struct.pack('!L', self.num_val % 2 ** 32)
        
    
    def __eq__(self, other):
        if isinstance(other, MACAddres):
            return self.num_val == other.num_val
        if isinstance(other, str):
            return str(self) == other
    
    def __repr__(self):
        return '<MAC addres %s>' % self.__str__()
    
    def __str__(self):
        str_repr = "%012x" % self.num_val
        bytes = [str_repr[i:i + 2] for i in xrange(0, len(str_repr), 2)]
        return ':'.join(bytes)

class IPAddress(Field):
    
    def __init__(self, bin_val=None, str_val=None):
        if str_val:
            bin_val = 0
            for v in str_val.split('.'):
                bin_val <<= 8
                bin_val |= int(v)
                
        self.bin_val = bin_val
    
    def __eq__(self, other):
        if isinstance(other, IPAddress):
            return self.bin_val == other.bin_val
        if isinstance(other, str):
            return str(self) == other
    
    def __str__(self):
        addr_segments = [str((self.bin_val >> shift) % 256) for shift in (24, 16, 8, 0)]
        return '.'.join(addr_segments)
    
    def __repr__(self):
        return '<IP address %s>' % self.__str__()
    
    def raw_val(self, struct_fmt=None):
        return struct.pack('!L', self.bin_val)

class IPAddressFromBinStr(IPAddress):
    
    def __init__(self, bin_str):
        bin_val = struct.unpack('!L', bin_str)[0]
        super(IPAddressFromBinStr, self).__init__(bin_val=bin_val)