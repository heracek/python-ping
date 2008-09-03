
def bin2hex(bin, separator=' '):
    return separator.join(['%02x' % ord(byte) for byte in bin])

