""" goTenna API objects - part of pyGT https://github.com/sybip/pyGT """

from struct import pack, unpack
from binascii import hexlify, unhexlify
from datetime import datetime
import time

from pyTLV import tlvPack, tlvRead
from pygth16 import gtAlgoH16
from gtdefs import *  # noqa: F403


def gtMakeAPIMsg(msgBlob, msgClass, msgAppID, fromGID, destGID=0, destTag=0,
                 meshTTL=3, seqNo0=0, seqNo1=0, crypt=0):
    """
    Assemble a GTM API compatible message PDU (WITH top-level TLVs)
      (for API command 03 - OP_SENDMSG)
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
    msgFullPDU = tlvPack(MESG_TLV_DEST, msgDest)
    if msgClass in (MSG_CLASS_P2P, MSG_CLASS_GROUP):
        # Element 0x04 only in addressed messages
        msgFullPDU += tlvPack(0x04, b'\xff\x00\x00')
    msgFullPDU += tlvPack(MESG_TLV_DATA, msgHeadTLV + msgBlob)
    msgFullPDU += tlvPack(MESG_TLV_TTL,  pack('B', meshTTL))

    return msgFullPDU


def gtReadAPIMsg(msgPDU, verbose=1):
    """
    Parse a GTM API message PDU (WITH top-level TLVs)
      (via API command 06 - OP_READMSG)
    """
    msg = {}

    # Message PDU is a TLV structure
    for type, length, value in tlvRead(msgPDU):
        if verbose:
            print("[MESG] TYPE %02x: " % type + hexlify(value).decode())

        if type == MESG_TLV_DEST:        # Destination element
            (msg['classID'], msg['appID']) = unpack("!BH", value[:3])

            if msg['classID'] not in (0x02, 0x03):
                # Non-broadcast messages have a destination address:
                #   extract 6-byte destGID and 1-byte dest tag
                # (there's no unpack template for 48-bit numbers, so we
                #  unpack AppID+GID as a 64-bit number and mask out AppID)
                msg['destGID'] = unpack('!Q', value[1:9])[0] & 0xffffffffffff
                msg['destTag'] = bytearray(value)[9]

            if verbose:
                print("[MSGD]   CLASSID: %02x (%s)" %
                      (msg['classID'], MSG_CLASS_NAME[msg['classID']]))
                print("[MSGD]   APPID  : %04x" % msg['appID'])

                if 'destGID' in msg:
                    print("[MSGD]   DESTGID: %012x" % msg['destGID'])
                    print("[MSGD]   DESTTAG: %02x" % msg['destTag'])

        elif type == MESG_TLV_DATA:      # Main (DATA) element
            if (length < 16):
                print("WW: Length %02x invalid for DATA TLV" % length)
                continue

            stype, slength, = unpack('BB', value[:2])

            # This is really the HEAD (0xFB) element, its format is strict
            #   so we'll just parse it as a fixed struct
            if (stype != 0xfb):  # Expecting first byte to be FB
                print("WW: Don't know how to parse: " +
                      hexlify(value).decode())
                continue

            if (slength != 0x10):
                print("WW: Length %02x invalid for FB TLV" % slength)

            (msg['cryptFlag'], msg['fromGID'], msg['tstamp'],
                msg['seqNo0'], msg['seqNo1']) = unpack('!BQLHB', value[2:18])

            msg['hashID'] = gtAlgoH16(value[2:18])

            if verbose:
                print("[MSGH]   ENCRYPT: %01x" % msg['cryptFlag'])
                print("[MSGH]   FROMGID: %012x" % msg['fromGID'])
                print("[MSGH]   DTSTAMP: " + "%08x (%s)" % (msg['tstamp'],
                      datetime.fromtimestamp(msg['tstamp']).
                      strftime("%Y-%m-%d %H:%M:%S")))
                print("[MSGH]   SEQNO_0: %04x" % msg['seqNo0'])
                print("[MSGH]   SEQNO_1: %02x" % msg['seqNo1'])

            # skip the HEAD element
            value = value[18:]

            # message content is here
            msg['msgBlob'] = value       # as received

        elif type == MESG_TLV_0x04:      # Unknown TLV 4
            msg['tlv_04'] = value

        elif type == MESG_TLV_DLR:       # Delivery ACK
            (msg['ackStatus'], msg['ackMsgID'],) = unpack('!BH', value)
            if verbose:
                print("  Delivery ACK: status 0x%02x for message ID 0x%04x" %
                      (msg['ackStatus'], msg['ackMsgID']))

        elif type == MESG_TLV_HOPS:      # Number of hops
            (msg['meshHops'], msg['dChRSSI'],) = unpack('BB', value)
            if verbose:
                print("  Received via %d hops, dChRSSI=0x%02x" %
                      (msg['meshHops'], msg['dChRSSI']))

    return msg
