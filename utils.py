import struct

def bin2hex(bin, separator=' '):
    return separator.join(['%02x' % ord(byte) for byte in bin])

def cksum(packet):
    if len(packet) & 1:
        packet += '\0'

    words = struct.unpack('!%dH' % (len(packet) // 2), packet) 
    sum = 0

    for word in words:
        sum += word & 0xffff
            
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);

    return int((~sum) & 0xffff)