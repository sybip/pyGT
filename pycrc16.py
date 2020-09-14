# Python implementation of CRC16-XMODEM algo published by Serge Ballesta
# https://stackoverflow.com/questions/25239423/crc-ccitt-16-bit-python-manual-calculation

POLYNOMIAL = 0x1021
PRESET = 0
CRCVERBOSE = 0


def _initial(c):
    crc = 0
    c = c << 8
    for j in range(8):
        if (crc ^ c) & 0x8000:
            crc = (crc << 1) ^ POLYNOMIAL
        else:
            crc = crc << 1
        c = c << 1
    return crc

_tab = [_initial(i) for i in range(256)]


def _update_crc(crc, c):
    cc = 0xff & c

    tmp = (crc >> 8) ^ cc
    crc = (crc << 8) ^ _tab[tmp & 0xff]
    crc = crc & 0xffff
    if CRCVERBOSE:
        print (crc)

    return crc


def crc(str):
    crc = PRESET
    for c in bytearray(str):
        crc = _update_crc(crc, c)
    return crc
