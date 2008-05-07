import os
import fcntl
import struct

BPF_FORMAT = "/dev/bpf%d"

def u_int2int(u_int):
    return struct.unpack('i', struct.pack('I', u_int))[0]

BIOCIMMEDIATE = -2147204496
BIOCSETIF = -2145369492
BIOCGBLEN = 1074020966

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

def get_headder(buffer):
    return struct.unpack('IIIIH', buffer)
