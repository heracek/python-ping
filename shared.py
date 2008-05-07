import os
import socket

IFCONFIG_MAC_ADDRESS_LINE = '\tether'

class MACAddres(object):
    def __init__(self, colon_hex_str=None, pure_hex_str=None, num_val=None):
        ''' MACAddres constructor:
            
            accept one of these arguments:
                colon_hex_str = '00:19:e3:02:d9:2b'
                pure_hex_str = '0019e302d92b' or '19e302d92b'
                num_val = 111182797099 or 0x19e302d92b
        '''
        if colon_hex_str:
            pure_hex_str = ''.join([ch for ch in colon_hex_str if ch.isalnum()])
        if pure_hex_str:
            self.num_val = int(pure_hex_str, 16)
    
    def __repr__(self):
        return '<MAC addres %s>' % self.__str__()
    
    def __str__(self):
        str_repr = "%012x" % self.num_val
        bytes = [str_repr[i:i + 2] for i in xrange(0, len(str_repr), 2)]
        return ':'.join(bytes)
    
    def pack(self):
        pass

class EthernetFrame(object):
    
    TYPE_IP = 0x0800
    
    def __init__(self, dest, src, type, payload):
        self.dest = dest
        self.src = src
        self.type = type
        self.payload = payload
    
    
        

def get_local_mac_addres_of_device(dev):
    cmd = 'ifconfig %s' % dev
    try:
        pipe = os.popen(cmd)
    except IOError:
        raise Exception('''Can't get MAC addres.''')
    
    for line in pipe:
        if line.startswith(IFCONFIG_MAC_ADDRESS_LINE):
            print line
            return MACAddres(colon_hex_str = line[len(IFCONFIG_MAC_ADDRESS_LINE):])

