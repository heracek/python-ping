import os
import fcntl
import struct
import select

BPF_FORMAT = "/dev/bpf%d"

def u_int2int(u_int):
    return struct.unpack('i', struct.pack('I', u_int))[0]

BIOCIMMEDIATE = -2147204496
BIOCSETIF = -2145369492
BIOCGBLEN = 1074020966

BPF_ALIGNMENT = 4
BPF_WORDALIGN = lambda x: (((x)+(BPF_ALIGNMENT-1))&~(BPF_ALIGNMENT-1))

class BPFPacket(object):
    def __init__(self, header, data):
        self.header = header
        self.data = data

class BPFTimeout(Exception):
    pass

def read_packet(fd, timeout=None):
    blen = bpf_get_blen(fd)
    
    if timeout is not None:
        iwtd, owtd, ewtd = select.select([fd], [], [], timeout)
        if not iwtd:
            raise BPFTimeout()
            
    buffer = os.read(fd, blen)
    if len(buffer) > 0:
        packet_index = 0
        while packet_index < len(buffer):
            header = get_header(buffer[packet_index:packet_index + 18])
            
            if header.bh_caplen != header.bh_datalen:
                print 'Packet fraction at BPF level. - skipped'
                packet_index += BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen)
                continue
            
            data = buffer[packet_index + header.bh_hdrlen: \
                          packet_index + header.bh_caplen + header.bh_hdrlen]

            return BPFPacket(header, data)
            
            packet_index += BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen)
    
def packet_reader(fd, timeout=None):
    blen = bpf_get_blen(fd)
    while True:
        if timeout is not None:
            iwtd, owtd, ewtd = select.select([fd], [], [], timeout)
            if not iwtd:
                yield BPFTimeout()
                continue
                
        buffer = os.read(fd, blen)
        if len(buffer) > 0:
            packet_index = 0
            while packet_index < len(buffer):
                header = get_header(buffer[packet_index:packet_index + 18])
                
                if header.bh_caplen != header.bh_datalen:
                    print 'Packet fraction at BPF level. - skipped'
                    packet_index += BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen)
                    continue
                
                data = buffer[packet_index + header.bh_hdrlen: \
                              packet_index + header.bh_caplen + header.bh_hdrlen]

                yield BPFPacket(header, data)
                
                packet_index += BPF_WORDALIGN(header.bh_hdrlen + header.bh_caplen)

def get_bpf_fg(device, nonblocking=False):
    fd = bpf_new()
    bpf_set_immediate(fd, 1)
    bpf_setif(fd, device)
    
    if nonblocking:
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK) # nonblocking reading - slows down CPU
    
    return fd

def bpf_new():
    for i in xrange(10):
        bpfdev = BPF_FORMAT % i
        try:
            os.stat(bpfdev)
        except:
            raise Exception('''Can't open BPF.''')
        try:
            fd = os.open(bpfdev, os.O_RDWR, 0)
            return fd
        except:
            pass
    raise Exception('''Can't open any BPF.''')

def bpf_set_immediate(fd, value):
    return fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', value))
        
def bpf_dispose(bpf_fd):
    return os.close(bpf_fd)

def bpf_setif(fd, en_name):
    ifreq = en_name + '\0x0' * (32 - len(en_name));
    return fcntl.ioctl(fd, BIOCSETIF, ifreq)

def bpf_get_blen(fd):
    return struct.unpack('I', fcntl.ioctl(fd, BIOCGBLEN, "    "))[0]

class BPFHeader(object):
    def __init__(self, unpacked):
        self._unpacked = unpacked
        self.tv_sec = unpacked[0]
        self.tv_usec = unpacked[1]
        self.bh_caplen = unpacked[2]
        self.bh_datalen = unpacked[3]
        self.bh_hdrlen = unpacked[4]
    
    def __str__(self):
        return '''<BPFHeader tv_sec=%u tv_usec=%u bh_caplen=%u bh_datalen=%u bh_hdrlen=%u>''' % \
                self._unpacked

def get_header(buffer):
    return BPFHeader(struct.unpack('IIIIH', buffer))

