""" Python TLV functions - part of pyGT https://github.com/sybip/pyGT """

from struct import pack, unpack
from binascii import hexlify

try:
    basestring
except NameError:  # Python3 doesn't know basestring
    basestring = str


def tlvRead(data):
    while data:
        try:
            type, length = unpack('BB', data[:2])
            value = unpack('%is' % length, data[2:2+length])[0]
        except:
            print("WW: Invalid TLV: " + hexlify(data).decode())
            break
        yield type, length, value
        data = data[2+length:]


def tlvPack(dtype, data):
    if (type(data) is basestring):
        data = data.encode('utf8')
    return pack('BB', dtype, len(data)) + data
