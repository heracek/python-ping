import os
import fcntl
import struct

BPF_FORMAT = "/dev/bpf%d"

def u_int2int(u_int):
    return struct.unpack('i', struct.pack('I', u_int))[0]

BIOCIMMEDIATE = -2147204496
BIOCSETIF = -2145369492
BIOCGBLEN = 1074020966

BPF_ALIGNMENT = 4
BPF_WORDALIGN = lambda x: (((x)+(BPF_ALIGNMENT-1))&~(BPF_ALIGNMENT-1))

def bpf_new():
    for i in xrange(10):
        bpfdev = BPF_FORMAT % i
        try:
            os.stat(bpfdev)
        except:
            raise Exception('''Can't open BPF.''')
        try:
            fd = os.open(bpfdev, os.O_RDWR, 0)
            print 'Opened BPF:', bpfdev
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
        return '''<BPFHeader tv_sec=%u tv_usec=%u bh_caplen=%u bh_datalen=%u bh_hdrlen=%u>''' % self._unpacked

def get_header(buffer):
    return BPFHeader(struct.unpack('IIIIH', buffer))

