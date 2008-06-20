import os
import struct

import fields


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
    
    def __str__(self, level=0):
        level_separator = '\t'
        fields_arr = []
        field_separator = '\n' + level_separator * (level + 1)
        
        for field in self._fields_:
            name = field[0]
            
            field_str = "%s=%s" % (name, self.__getattribute__(name))
            fields_arr.append(field_str)
        
        return level_separator * level + '<%s %s>' % (
            self.__class__.__name__,
            field_separator + field_separator.join(fields_arr))
    
class Ethernet(Wrapper):
    
    TYPE_IP = fields.HexIntClass(0x0800, 4)
    TYPE_ARP = fields.HexIntClass(0x0806, 4)
    
    _fields_ = [
        ('smac', '6s', fields.MACAddres),
        ('dmac', '6s', fields.MACAddres),
        ('type', '!H', fields.HexInt(4)),
        ('data', 'B', fields.HexInt(2))
    ]
    
    def __init__(self, eth_packet=None):
        super(Ethernet, self).__init__(eth_packet)
        self.payload = eth_packet[14:]

class IPv4(Wrapper):
    
    _fields_ = [
        ('version__and__header_length', 'B', fields.HexInt(2)),
        ('type_of_service', 'B', fields.HexInt(2)),
        ('total_length', '!H', fields.HexInt(4)),
        ('identification', '!H', fields.HexInt(4)),
        ('flags__and__fragment_offset', '!H', fields.HexInt(4)),
        ('time_to_live', 'B', fields.HexInt(2)),
        ('protocol', 'B', fields.HexInt(2)),
        ('header_checksum', '!H', fields.HexInt(4)),
        ('saddr', '!L', fields.IPAddress),
        ('daddr', '!L', fields.IPAddress),
    ]
    

print Ethernet('\x01\x80\xc2\x00\x00\x00\x00\x1a\x92\x62\x31\x4c\x00\x2e\x42\x42\x03\x00\x00\x00\x00\x00\x80\x00\x00\x1a\x92\x62\x31\x4c\x01\x80\xc2')
