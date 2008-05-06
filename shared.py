import os

IFCONFIG_MAC_ADDRESS_LINE = '\tether'

def get_local_mac_addres_of_device(dev):
    cmd = 'ifconfig %s' % dev
    try:
        pipe = os.popen(cmd)
    except IOError:
        raise Exception('''Can't get MAC addres.''')
    
    for line in pipe:
        if line.startswith(IFCONFIG_MAC_ADDRESS_LINE):
            return int(''.join([ch for ch in line[len(IFCONFIG_MAC_ADDRESS_LINE):] if ch.isalnum()]), 16)
