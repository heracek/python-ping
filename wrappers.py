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
                    
                    if type(val) in (int, long):
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
                    
                    #if not name.startswith('_'):
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
                        if _type is None:
                            val = raw_val
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
            
            if type(val) in (int, long):
                val = fields.Int(val)
            
            if _type is None:
                raw_val = val
            else:
                raw_val = val.raw_val(unpack_str)
            raw_vals_list.append(raw_val)
        
        #print raw_vals_list
        
        return ''.join(raw_vals_list)

class Ethernet(Wrapper):
    
    TYPE_IP = fields.HexIntClass(0x0800, 4)
    TYPE_ARP = fields.HexIntClass(0x0806, 4)
    
    _fields_ = [
        ('dmac', '6s', fields.MACAddres),
        ('smac', '6s', fields.MACAddres),
        ('type', '!H', fields.HexInt(4)),
    ]
    
    _LEVEL_ = 0
    
    def __init__(self, raw_data=None, data_dict=None):
        super(Ethernet, self).__init__(raw_data, data_dict=data_dict)
        if raw_data is not None:
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
        if hasattr(parent, 'payload'):
            self.payload = parent.payload[self.header_length * 4:]
    
    def compute_checksum(self):
        self.header_checksum.val = 0
        
        packet = self.raw_val(parents=False)
        
        self.header_checksum.val = utils.cksum(packet)
        
        return self.header_checksum.val
    
    def compute_length(self):
        self.total_length.val = len(self.payload) + self.header_length.val * 4
        return self.total_length.val

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
    
    def __init__(self, parent, data_dict=None):
        super(UDP, self).__init__(parent=parent, data_dict=data_dict)
        if hasattr(parent, 'payload'):
            self.payload = parent.payload[8:]
            self.len = len(self.payload)
    
    def compute_checksum(self):
        self.checksum.val = 0
        
        ipv4_pseudo_header = '%s%s\x00%s%s' % (
            self._parent.saddr.raw_val(),
            self._parent.daddr.raw_val(),
            self._parent.protocol.raw_val('B'),
            fields.Int(self.length.val).raw_val('!H'),
        )
        
        self.checksum.val = utils.cksum(ipv4_pseudo_header + self.raw_val(parents=False) + self.payload)
        
        return self.checksum.val
    
    def compute_length(self):
        self.length.val = len(self.payload) + 8
        return self.length.val

class DHCPOption(object):
    OPTION_NAMES = {
        0 : 'pad',
        1 : 'subnet_mask',
        2 : 'time_offset',
        3 : 'router',
        4 : 'time_server',
        5 : 'name_server',
        6 : 'domain_name_server',
        7 : 'log_server',
        8 : 'cookie_server',
        50 : 'requested_ip_address',
        51 : 'ip_address_lease_time',
        53 : 'dhcp_message_type',
        54 : 'server_identifier',
        55 : 'parameter_request_list',
        57 : 'maximum_dhcp_message_size',
        61 : 'client_identifier',
        255 : 'end',
    }
    
    IP_ADDRESS_OPTIONS = (1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 50, 54)
    
    def __init__(self, dhcp_options):
        self.option = ord(dhcp_options[0])
        self.type = None
        self.value = ''
        self.name = self.OPTION_NAMES.get(self.option, None)
        
        if self.option == 0x00:
            max_i = len(dhcp_options)
            for i in xrange(1, len(dhcp_options)):
                if dhcp_options[i] != '\x00':
                    max_i = i
                    break
            self.value = dhcp_options[1:max_i]
            self.len = max_i
            
        elif self.option == 0xff:
            self.len = 0
        else:
            self.len = ord(dhcp_options[1])
            self.value = dhcp_options[2:2 + self.len]
            
            self.unit_len = self.len
            
            if self.option in self.IP_ADDRESS_OPTIONS:
                self.unit_len = 4
                self.type = fields.IPAddressFromBinStr
                
            
    def __str__(self):
        if self.name:
            name_str = ' [%s]' % self.name
        else:
            name_str = ''
        
        obj_val = self.get_value()
        
        if isinstance(obj_val, list):
            val = ', '.join(map(str, obj_val))
        else:
            val = utils.bin2hex(obj_val)
        
        return 'option(t=%i%s, l=%i): %s' % (
            self.option,
            name_str,
            self.len,
            val,
        )
    
    def get_value(self):
        if self.type:
            return [self.type(self.value[i:i + self.unit_len]) for i in xrange(0, self.len, self.unit_len) ]
        
        return self.value
            
    
    def raw_val(self):
        if self.option in (0x00, 0xff):
            len_str = ''
        else:
            len_str = chr(self.len)
        
        return chr(self.option) + len_str + self.value
        
    
class DHCPOptions(object):
    def __init__(self, dhcp_options):        
        if type(dhcp_options) in (list, tuple):
            self.options = list(dhcp_options)
        else:
            self.options = []
            
            max_options_index = len(dhcp_options)
            options_index = 0
            end_options_on_pad = False
            while options_index < max_options_index:
                if end_options_on_pad and dhcp_options[options_index] == '\x00':
                    option = DHCPOption('\x00')
                    option.value = dhcp_options[options_index + 1:]
                    option.len = len(option.value)
                else:
                    option = DHCPOption(dhcp_options[options_index:])

                if option.option == 0xff:
                    end_options_on_pad = True
                self.options.append(option)
                
                header_len = 2
                if option.option in (0x00, 0xff):
                    header_len = 1
                
                options_index += header_len + option.len
    
    def __str__(self, level=None):
        if level is None:
            level = 4

        fields_arr = []
        field_separator = _get_field_separator(level)
        
        return '<%s%s%s' % (
            self.__class__.__name__,
            field_separator,
            field_separator.join([str(option) for option in self.options]))
    
    def raw_val(self, struct_fmt=None):
        output_list = [option.raw_val() for option in self.options]
        return ''.join(output_list)
    
    def get(self, option_name):
        if not hasattr(DHCPOption, '_REVERSE_OPTION_NAMES'):
            DHCPOption._REVERSE_OPTION_NAMES = \
                dict([(value, key) for (key, value) in DHCPOption.OPTION_NAMES.items()])
        
        option_id = DHCPOption._REVERSE_OPTION_NAMES[option_name]
        
        for option in self.options:
            if option.option == option_id:
                return option.get_value()
                

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
        ('dhcp_options', '0s', str),
    ]
    
    _LEVEL_ = 3
    
    def __init__(self, parent, data_dict=None):
        super(DHCP, self).__init__(parent=parent, data_dict=data_dict)
        if data_dict is None:
            self.dhcp_options = DHCPOptions(self.payload)

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
    
    def len(self):
        return len(self.raw_val(parents=False)) + len(self.payload)

class ARP(Wrapper):
    
    _fields_ = [
        ('htype', '!H', fields.HexInt(4)),
        ('ptype', '!H', fields.HexInt(4)),
        ('hlen', 'B', fields.HexInt(4)),
        ('plen', 'B', fields.HexInt(4)),
        ('oper', '!H', fields.HexInt(4)),
        ('sha', '6s', fields.MACAddres),
        ('spa', '!L', fields.IPAddress),
        ('tha', '6s', fields.MACAddres),
        ('tpa', '!L', fields.IPAddress),
    ]
    
    _LEVEL_ = 1
    