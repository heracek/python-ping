import os
import struct

import fields
import utils

LEVEL_SEPARATOR = ' ' * 4

def _get_field_separator(level):
    return '\n' + LEVEL_SEPARATOR * (level + 1)

class Wrapper(object):
    
    _LEVEL_ = 0
    
    def __init__(self, raw_data=None, parent=None, data_dict=None):
        '''
        Processes '_fields_' list and inits object's argumets by vals defined in raw_data.
        
         * polozky nezarovana na cele byty je mozne take nacist
            * staci zvolit rozsah na cely pocet bytu
            * jmena poli spojit pomoci retezce __and__
            * jako typ predat n-tici dvojic, kde:
                * polozka n-tice odpvida prislusne polozce
                * prvni cast dvojice je pocet bitu
                * druha cast dvojice je typ polozky
            * pr.:
                ('flags__and__fragment_offset', '2s', ( # nacteme 2 byty
                    (3, fields.HexInt(1)),              # 'flags' ma 3 bity a je typu HexInt
                    (13, fields.Int))),                 # 'fragment_offset' je 13-bitovy integer
        '''
        
        self._parent = parent
        
        if data_dict:
            for field in self._fields_:
                name = field[0]
                unpack_str = field[1]
                _type = field[2]
                
                splitted_names = name.split('__and__')
                
                for (i, splitted_name) in enumerate(splitted_names):
                    if 'checksum' in splitted_name and splitted_name not in data_dict:
                        setattr(self, splitted_name, _type(0))
                        continue
                    
                    val = data_dict[splitted_name]
                    
                    if isinstance(val, int):
                        if len(splitted_names) > 1:
                            val = _type[i][1](val)
                        else:
                            val = _type(val)
                    
                    setattr(self, splitted_name, val)
        else:
            if parent and raw_data is None:
                raw_data = parent.payload
        
            if raw_data:
                data_index = 0
                for field in self._fields_:
                    name = field[0]
                    unpack_str = field[1]
                    _type = field[2]
                    size = struct.calcsize(unpack_str)
                    
                    if not name.startswith('_'):
                        raw_val = struct.unpack(unpack_str, raw_data[data_index:data_index + size])[0]
                        splitted_names = name.split('__and__')
                        if len(splitted_names) > 1:
                            start_bit = size * 8
                            for field_name, (num_bits, splitted_type) in zip(splitted_names, _type):
                                shift = start_bit - num_bits
                                splitted_raw_val = (raw_val >> shift) % (1 << num_bits)
                        
                                val = splitted_type(splitted_raw_val)
                                self.__setattr__(field_name, val)
                     
                                start_bit -= num_bits
                        else:                
                            val = _type(raw_val)
                            self.__setattr__(name, val)
            
                    data_index += size
                
                self.payload = raw_data[data_index:]
    
    def __str__(self, level=None, parents=False):
        if level is None:
            level = self._LEVEL_
        
        fields_arr = []
        field_separator = _get_field_separator(level)
        
        for field in self._fields_:
            unsplitted_name = field[0]
            
            if not unsplitted_name.startswith('_'):
                for name in unsplitted_name.split('__and__'):
                    field_str = "%s=%s" % (name, self.__getattribute__(name))
                    fields_arr.append(field_str)
        
        
        out = LEVEL_SEPARATOR * level + '<%s %s>' % (
            self.__class__.__name__,
            field_separator + field_separator.join(fields_arr))
        
        if parents and self._parent:
            out = self._parent.__str__(parents=True) + '\n' + out
        
        return out
    
    def raw_val(self, parents=True):
        raw_vals_list = []
        
        if self._parent and parents:
            raw_vals_list = [self._parent.raw_val()]
        
        for field in self._fields_:
            name, unpack_str, _type = field
            
            splitted_names = name.split('__and__')
            if len(splitted_names) > 1:
                size = struct.calcsize(unpack_str)
                start_bit = size * 8
                val = 0
                
                for field_name, (num_bits, splitted_type) in zip(splitted_names, _type):
                    shift = start_bit - num_bits
                    
                    splitted_raw_val = getattr(self, field_name)
                    val |= (splitted_raw_val << shift)
                    
                    start_bit -= num_bits
                
                val = fields.Int(val)
            else:
                val = getattr(self, name)
            
            if isinstance(val, int):
                val = fields.Int(val)
            
            raw_val = val.raw_val(unpack_str)
            raw_vals_list.append(raw_val)
        
        #print raw_vals_list
        
        return ''.join(raw_vals_list)

class Ethernet(Wrapper):
    
    TYPE_IP = fields.HexIntClass(0x0800, 4)
    TYPE_ARP = fields.HexIntClass(0x0806, 4)
    
    _fields_ = [
        ('smac', '6s', fields.MACAddres),
        ('dmac', '6s', fields.MACAddres),
        ('type', '!H', fields.HexInt(4)),
    ]
    
    _LEVEL_ = 0
    
    def __init__(self, raw_data=None, data_dict=None):
        super(Ethernet, self).__init__(raw_data, data_dict=data_dict)
        if raw_data:
            self.payload = raw_data[14:]

class IPv4(Wrapper):
    
    PROTOCOL_UDP = fields.HexIntClass(0x11, 2)
    PROTOCOL_ICMP = fields.HexIntClass(0x01, 2)
    
    _fields_ = [
        ('version__and__header_length', 'B', (
            (4, fields.Int),
            (4, fields.Int))),
        ('type_of_service', 'B', fields.HexInt(2)),
        ('total_length', '!H', fields.Int),
        ('identification', '!H', fields.HexInt(4)),
        ('flags__and__fragment_offset', '!H', (
            (3, fields.HexInt(1)),
            (13, fields.Int))),
        ('time_to_live', 'B', fields.Int),
        ('protocol', 'B', fields.HexInt(2)),
        ('header_checksum', '!H', fields.HexInt(4)),
        ('saddr', '!L', fields.IPAddress),
        ('daddr', '!L', fields.IPAddress),
    ]
    
    _LEVEL_ = 1
    
    def __init__(self, parent, data_dict=None):
        super(IPv4, self).__init__(parent=parent, data_dict=data_dict)
        self.payload = parent.payload[self.header_length * 4:]
    
    def compute_checksum(self):
        self.header_checksum.val = 0
        
        packet = self.raw_val(parents=False)
        
        self.header_checksum.val = utils.cksum(packet)
        
        return self.header_checksum
    

class UDP(Wrapper):
    
    COMM_DHCP = (
        (68, 67),
        (67, 68),
    )
    
    _fields_ = [
        ('sport', '!H', fields.Int),
        ('dport', '!H', fields.Int),
        ('length', '!H', fields.Int),
        ('checksum', '!H', fields.HexInt(4)),
    ]
    
    _LEVEL_ = 2
    
    def __init__(self, parent):
        super(UDP, self).__init__(parent=parent)
        self.payload = parent.payload[8:]
        self.len = len(self.payload)

class DHCPOption(object):
    def __init__(self, dhcp_options):
        self.option = ord(dhcp_options[0])
        
        if not self.option == 0xff:
            self.len = ord(dhcp_options[1])
            self.value = dhcp_options[2:2 + self.len]
    
    def __str__(self):
        return 'option(t=%i, l=%i): %s' % (
            self.option,
            self.len,
            ' '.join(['%02x' % ord(ch) for ch in self.value]),
        )
    
class DHCPOptions(object):
    def __init__(self, dhcp_options):
        self.options = []
        
        options_index = 0
        while True:
            option = DHCPOption(dhcp_options[options_index:])
            if option.option == 0xff:
                break
            self.options.append(option)
            
            options_index += 2 + option.len
    
    def __str__(self, level=None):
        if level is None:
            level = 4

        fields_arr = []
        field_separator = _get_field_separator(level)
        
        return '<%s%s%s' % (
            self.__class__.__name__,
            field_separator,
            field_separator.join([str(option) for option in self.options]))

class DHCP(Wrapper):
    
    _fields_ = [
        ('op', 'B', fields.HexInt(2)),
        ('htype', 'B', fields.HexInt(2)),
        ('hlen', 'B', fields.HexInt(2)),
        ('hops', 'B', fields.HexInt(2)),
        ('xid', '!L', fields.HexInt(8)),
        ('secs', '!H', fields.HexInt(4)),
        ('flags', '!H', fields.HexInt(4)),
        ('ciaddr', '!L', fields.IPAddress),
        ('yiaddr', '!L', fields.IPAddress),
        ('siaddr', '!L', fields.IPAddress),
        ('giaddr', '!L', fields.IPAddress),
        ('chaddr', '6s', fields.MACAddres),
        ('_bootp_legacy', '202s', None),
        ('magic_cookie', '!L', fields.HexInt(8)),
        ('dhcp_options', '60s', DHCPOptions),
    ]
    
    _LEVEL_ = 3

class ICMP(Wrapper):
    
    _fields_ = [
        ('type', 'B', fields.Int),
        ('code', 'B', fields.Int),
        ('checksum', '!H', fields.HexInt(4)),
        ('id', '!H', fields.HexInt(4)),
        ('sequence', '!H', fields.Int),
    ]
    
    _LEVEL_ = 2
    
    def compute_checksum(self):
        self.checksum = fields.HexIntClass(0, 4)
        packet = self.raw_val(parents=False) + self.payload
        self.checksum.val = utils.cksum(packet)
        
        return self.checksum
