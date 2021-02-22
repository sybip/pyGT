""" Python GTH16 hash - part of pyGT https://github.com/sybip/pyGT """


def gtAlgoH16(str):
    """ Proprietary hash based on the Park-Miller LCG """
    seed = 0xaa
    mult = 48271
    incr = 1
    modulus = (1 << 31) - 1  # 0x7FFFFFFF

    h = 0
    x = seed
    for c in bytearray(str):
        x = (((x + c) * mult + incr) & 0xFFFFFFFF) % modulus
        h = h ^ x

    # Derive 16-bit value from 32-bit hash by XORing its two halves
    r = ((h & 0xFFFF0000) >> 16) ^ (h & 0xFFFF)
    return r
