""" goTenna App objects - part of pyGT https://github.com/sybip/pyGT """

from struct import pack, unpack
from pyTLV import tlvPack, tlvRead
from pycrc16 import crc
from gtdefs import *  # noqa: F403

# Message content types - GTA specific
GTA_CONTENT_TEXT = 0
GTA_CONTENT_TEXT_LCTN = 1  # Text message with location attached
GTA_CONTENT_LCTN_RES = 2   # Location response
GTA_CONTENT_LCTN_REQ = 3   # Location request
GTA_CONTENT_TEXT_LREQ = 4  # Text message with location request
GTA_CONTENT_GROUP_KEY = 5  # Group setup information: GID, KEY and members
GTA_CONTENT_PING = 7       # Ping request
GTA_CONTENT_PUBK_REQ = 14
GTA_CONTENT_PUBK_RES = 15


def gtMakeGTABlobMsg(bodyTXT, fromTXT='API'):
    """
    Assemble a GTA compatible message blob
    (suitable for feeding to gtMakeAPIMsg() )
    """
    blob = (tlvPack(MSGB_TLV_TYPE, "%d" % GTA_CONTENT_TEXT) +
            tlvPack(MSGB_TLV_NICK, fromTXT) +
            tlvPack(MSGB_TLV_TEXT, bodyTXT))
    # append CRC and return
    return blob + pack("!H", crc(blob))


def gtReadGTABlob(blob):
    """
    Break down a GTA message blob into its elements
    """

    msg = {}
    # there's a CRC16 field at the end of the content blob;
    #   check this first and stop if incorrect
    wantCRC = unpack('!H', blob[-2:])[0]
    haveCRC = crc(blob[:-2])

    if wantCRC != haveCRC:
        print("CRC failed, want=%04x, have=%04x" % (wantCRC, haveCRC))
        return False

    for type, length, value in tlvRead(blob[:-2]):
        msg[type] = value

    return msg
