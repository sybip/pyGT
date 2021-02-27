""" goTenna radio objects - part of pyGT https://github.com/sybip/pyGT """
""" WARNING: not to be confused with gtapiobj.py (API objects) """

from struct import pack, unpack
from binascii import hexlify, unhexlify
from datetime import datetime
import time

from pyTLV import tlvPack
from pygth16 import gtAlgoH16
from gtdefs import *  # noqa: F403


def gtMakeAirMsg(msgBlob, msgClass, msgAppID, fromGID, destGID=0, destTag=0,
                 meshTTL=3, seqNo0=0, seqNo1=0, crypt=0):
    """
    Assemble a GTM radio compatible message PDU (NO top-level TLVs)
      (for gtm-lab command !tx)
    """

    # 1) Message destination element
    msgDest = pack('!BH', msgClass, msgAppID)
    if msgClass in (MSG_CLASS_P2P, MSG_CLASS_GROUP):
        # Destination address only in addressed messages
        msgDest += unhexlify('%012x%02x' % (destGID, destTag))

    # 2) Message header element (sender GID, timestamp and seq numbers)
    msgHead = pack('!BQLHB', crypt, fromGID, int(time.time()), seqNo0, seqNo1)
    msgHeadTLV = tlvPack(MESG_TLV_HEAD, msgHead)

    # 3) Assemble the PDU: Dest, 0x04, Data (Head + Blob), Mesh TTL
    msgFullPDU = msgDest
    if msgClass in (MSG_CLASS_P2P, MSG_CLASS_GROUP):
        # Element 0x04 only in addressed messages
        msgFullPDU += b'\xff\x00\x00'
    msgFullPDU += msgHeadTLV + msgBlob

    return msgFullPDU


def gtReadAirMsg(msgPDU, verbose=1):
    """
    Parse a GTM radio message PDU (NO top-level TLVs)
      (via gtm-lab RX_MSG)
    """
    msg = {}
    headPos = 3   # if DEST element is short

    (msg['classID'], msg['appID']) = unpack("!BH", msgPDU[:3])

    if msg['classID'] in (MSG_CLASS_P2P, MSG_CLASS_GROUP):
        # Non-broadcast messages have a destination address:
        #   extract 6-byte destGID and 1-byte dest tag
        # (there's no unpack template for 48-bit numbers, so we
        #  unpack AppID+GID as a 64-bit number and mask out AppID)
        msg['destGID'] = unpack('!Q', msgPDU[1:9])[0] & 0xffffffffffff
        msg['destTag'] = bytearray(msgPDU)[9]
        msg['tlv_04'] = msgPDU[10:13]
        headPos = 13  # long DEST element

    (tFB, t10) = unpack('BB', msgPDU[headPos:headPos+2])
    if (tFB != MESG_TLV_HEAD) or (t10 != 0x10):
        print("HEAD element not in expected position")
        return False

    (msg['cryptFlag'], msg['fromGID'], msg['tstamp'], msg['seqNo0'],
        msg['seqNo1']) = unpack('!BQLHB', msgPDU[headPos+2:headPos+18])

    msg['hashID'] = gtAlgoH16(msgPDU[headPos+2:headPos+18])

    msg['msgBlob'] = msgPDU[headPos+18:]

    if verbose:
        print("[MSGD]   CLASSID: %02x (%s)" %
              (msg['classID'], MSG_CLASS_NAME[msg['classID']]))
        print("[MSGD]   APPID  : %04x" % msg['appID'])

        if 'destGID' in msg:
            print("[MSGD]   DESTGID: %012x" % msg['destGID'])
            print("[MSGD]   DESTTAG: %02x" % msg['destTag'])

        print("[MSGH]   ENCRYPT: %01x" % msg['cryptFlag'])
        print("[MSGH]   FROMGID: %012x" % msg['fromGID'])
        print("[MSGH]   DTSTAMP: " + "%08x (%s)" % (msg['tstamp'],
              datetime.fromtimestamp(msg['tstamp']).
              strftime("%Y-%m-%d %H:%M:%S")))
        print("[MSGH]   SEQNO_0: %04x" % msg['seqNo0'])
        print("[MSGH]   SEQNO_1: %02x" % msg['seqNo1'])

    return msg
