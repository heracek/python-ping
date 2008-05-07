#!/usr/bin/env python
import fcntl
import os
import re
import shared
import struct
import sys

import bpf

LOCAL_DEVICE = None
LOCAL_MAC_ADDRESS = None

def my_listen(fd):
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
    blen = bpf.bpf_get_blen(fd)
    while True:
        buffer = os.read(fd, blen)
        if len(buffer) > 0:
            print bpf.get_headder(buffer[:18])


def main():
    if len(sys.argv) != 3:
        if len(sys.argv) == 1:
            sys.argv.extend(['en1', '192.168.1.1'])
            print 'using defaul args:', ' '.join(sys.argv)
        else:
            print 'usage: %s dev host' % sys.argv[0]
            print '\tdev ... device'
            print '\thost ... ip address of host'
            sys.exit(1)
    
    LOCAL_DEVICE = sys.argv[1]
    LOCAL_MAC_ADDRESS = shared.get_local_mac_addres_of_device(LOCAL_DEVICE)
    print 'LOCAL_MAC_ADDRESS: %s' % LOCAL_MAC_ADDRESS
    
    fd = -1
    try:
        fd = bpf.bpf_new()
        bpf.bpf_set_immediate(fd, 1)
        bpf.bpf_setif(fd, 'en1')
        my_listen(fd)
        bpf.bpf_dispose(fd)
    except Exception, e:
        print e
        print
        bpf.bpf_dispose(fd)

if __name__ == '__main__':
    main()