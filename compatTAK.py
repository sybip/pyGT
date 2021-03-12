""" goTenna TAK plugin objects - part of pyGT https://github.com/sybip/pyGT """

# ATAK-goTenna specific encryption
from base64 import b64decode, b64encode
from struct import pack, unpack
import os

# pip install cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from compatGTA import gtReadGTABlob, gtMakeGTABlobMsg
from pycrc16 import crc
from gtdefs import MSGB_TLV_TEXT

BLOCK_SIZE = 16  # for AES encryption

# PKCS padding macros
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * pack('B', (BLOCK_SIZE - len(s) % BLOCK_SIZE))
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

# Types of objects used by the ATAK-goTenna plugin
GTAK_TYPE_MSG = 0  # goTenna plugin built-in chat facility
GTAK_TYPE_PLI = 1  # Location (PLI)


"""
NOTE: blob CRC is of ciphertext (because in the GTM protocol,
  the message is labeled as "NOT ENCRYPTED" in order to
  bypass native GTM decryption), which makes CRC useless
  for message decryption verification.
"""


def parseClearText(clearText, objType=0):
    """
    ATAK-goTenna encrypted messages don't include any integrity check,
     which makes it difficult to determine whether a decryption operation
     was successful, OR EVEN NECESSARY
    This function attempts to validate a (presumed) cleartext message by
     parsing it via expected known patterns or strings in the text.

    There are two types of cleartext objects seen in the wild:
     - location (PLI) packets are 9-element semicolon separated values
     - chat messages formatted as "CALLSIGN: message"

    We try to support both.
    """

    PLIKEYS = ['uuid', 'type', 'callsign', 'how', 'lat', 'lon',
               'hae', 'team', 'update']

    res = {}
    res['objType'] = objType

    if (objType == GTAK_TYPE_PLI):
        values = clearText.split(b';')
        if (len(values)) >= 9:
            for i in range(len(values)):
                res[PLIKEYS[i]] = values[i].decode('utf8')
            return res

    elif (objType == GTAK_TYPE_MSG):
        divpos = clearText.find(b': ')
        if divpos > 0:
            res['callsign'] = clearText[:divpos].decode('utf8')
            res['message'] = clearText[divpos+2:].decode('utf8')
            return res

    return False


def aesDecrypt(cipherGram, aesKey):
    """ Decrypt an AES encrypted TAK payload """
    iv = cipherGram[:16]
    cipherText = cipherGram[16:]
    cipher = Cipher(algorithms.AES(aesKey), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()

    try:
        clearText = decryptor.update(cipherText) + decryptor.finalize()
    except:
        return False

    return unpad(clearText)


def aesEncrypt(clearText, aesKey):
    """ Encrypt a TAK payload using AES """
    clearText = pad(clearText)
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(aesKey), modes.CBC(iv), default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(clearText) + encryptor.finalize()
    return iv + ct


def gtReadTAKBlob(blob, keys={}):
    """
    Break down a TAK message blob into its elements
    (optionally attempt decryption using multiple keys, if provided)
    """

    """
    ATAK-GTM appears to use two types of message envelopes:
    - SDK messages - unstructured payload + CRC16 (used for PLI)
    - GTA "TEXT" messages, body inside the type 4 TLV (used for chat)

    To discern between the two, we look at the first 4 bytes of the blob:
      if 01013003, treat it as GTA (01-01-30, 03-xx-xxxx... you get it)
    """

    # check CRC first and stop if incorrect
    wantCRC = unpack('!H', blob[-2:])[0]
    haveCRC = crc(blob[:-2])

    if wantCRC != haveCRC:
        print("CRC failed, want=%04x, have=%04x" % (wantCRC, haveCRC))
        return False

    # Object type can be PLI or MSG
    objType = GTAK_TYPE_PLI

    if blob[:4] == b'\x01\x01\x30\x03':
        # Envelope type is GTA -> object must be a chat message
        m = gtReadGTABlob(blob)
        if m and (MSGB_TLV_TEXT in m):
            payLoadRaw = m[MSGB_TLV_TEXT]
            objType = GTAK_TYPE_MSG
        else:
            return False  # could not parse
    else:
        # Envelope type is SDK -> object is probably a PLI
        payLoadRaw = blob[:-2]

    # Attempt parsing as cleartext
    msgData = parseClearText(payLoadRaw, objType)
    if msgData:
        print("Cleartext message received")
        msgData['crypt'] = False
        return(msgData)

    # Cleartext parsing failed

    # Assume encrypted and try decrypting with our keys
    #   encrypted chat message objects are b64 encoded
    if objType == GTAK_TYPE_MSG:
        try:
            payLoadRaw = b64decode(payLoadRaw)
        except:
            return False

    # Due to the block cipher nature of AES, an encrypted payload must be
    #   a multiple of BLOCK_SIZE - if it's not, bail out early
    if (len(payLoadRaw) < 2*BLOCK_SIZE) or (len(payLoadRaw) % BLOCK_SIZE):
        print("Invalid length for decryption: %d" % len(payLoadRaw))
        return False

    for a in keys:
        # Attempt decryption, should succeed even if incorrect key
        payLoadClear = aesDecrypt(payLoadRaw, keys[a])

        # Validate result by parsing it
        msgData = parseClearText(payLoadClear, objType)
        if msgData:
            msgData['crypt'] = True
            msgData['keyID'] = a
            return(msgData)

    return False


def gtMakeTAKBlobPLI(uuid, type, callsign, how, lat, lon, hae,
                     team, update, aesKey=False):
    """
    Assemble an ATAK plugin compatible PLI blob
      (suitable for feeding to gtMakeAPIMsg() )
    With optional AES encryption, if a key is provided
    """
    body = (b'%s;%s;%s;%s;%.06f;%.06f;%.03f;%s;%d' %
            (uuid, type, callsign, how, lat, lon, hae, team, update))
    # Apply optional encryption
    if aesKey:
        body = aesEncrypt(body, aesKey)

    return body + pack("!H", crc(body))


def gtMakeTAKBlobMsg(callsign, text, aesKey=False):
    """
    Assemble an ATAK plugin compatible chat message blob
      (suitable for feeding to gtMakeAPIMsg() )
    With optional AES encryption, if a key is provided
    """
    body = (callsign + b': ' + text)[:230]
    # Apply optional encryption (and base64 encoding only for chats)
    if aesKey:
        body = b64encode(aesEncrypt(body, aesKey))
    return gtMakeGTABlobMsg(body, 'A')


if __name__ == '__main__':

    # Generate 3 keys, one good and two bad
    aesKeys = {
        'alice': os.urandom(16),
        'bob': os.urandom(16),
        'charlie': os.urandom(16),
    }

    # test make and read chat object
    print(gtReadTAKBlob(gtMakeTAKBlobMsg(b'WORLD', b'Hello to you too',
          aesKeys['bob']), aesKeys))

    # test make and read PLI object
    print(gtReadTAKBlob(gtMakeTAKBlobPLI(b'0123-4567-89ab-cdef',
          b'a-f-G-U-C', b'SYBIP', b'm-g',
          51.9489, 4.0535, 1000, b'Red', 60, aesKeys['bob']), aesKeys))
