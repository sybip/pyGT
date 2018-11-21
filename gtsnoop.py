#!/usr/bin/python

""" gtsnoop.py
Parse a btsnoop log (from bluez hcidump or Android HCI snoop)
  to extract and analyze goTenna protocol packets
"""

import sys
from binascii import hexlify
from struct import unpack
from pycrc16 import crc
import gtdevice

# Dump protocol packets
debugPDUS = False

# Make dump parsing (even more) verbose
debugDUMP = False

# Reassembly buffer, global to keep it simple (FIXME REFACTOR)
buf = ""

# Opcodes known to contain/return NON-TLV data
nonTLVops = [0x04, ]


def opDissect(opCode, data):
    """
    Analyze a goTenna packet payload and display its elements
    """

    # Most payloads are TLV formatted (which ones?)

    if len(data) < 3:
        # Data too short to contain TLVs
        return

    if opCode in nonTLVops:
        # No TLVs expected
        return

    # try TLV parsing
    while data:
        try:
            type, length = unpack('BB', data[:2])
            value = unpack('%is' % length, data[2:2+length])[0]
        except:
            # Fail gracefully
            print "  -> INVALID_TLV: " + hexlify(data)
            break
        print "  -> TYPE_%02x_%02x: " % (opCode, type) + hexlify(value)
        data = data[2+length:]


def pduDissect(pdu):
    """
    Analyze a goTenna protocol packet and display its elements
    """
    (opCode, seqNo) = unpack('BB', pdu[0:2])

    if (opCode < 0x40):
        # is a command (ME->GT)
        print "ME:CMD(%02x): %02x    " % (seqNo, opCode) + hexlify(pdu[2:])
        print "  " + gtdevice.GT_OP_NAME[opCode]
        if len(pdu) > 2:
            print "  DATA: " + hexlify(pdu[2:])
        if len(pdu) >= 5:
            opDissect(opCode, pdu[2:])
        # Visual delimiter
        print "-" * 70

    else:
        # is a response (GT->ME)
        resCode = opCode & 0xc0
        opCode = opCode & 0x3f
        print ("GT:RES(%02x): %02x|%02x " % (seqNo, opCode, resCode) +
               hexlify(pdu[2:]))
        print ("  " + gtdevice.GT_OP_NAME[opCode] + " " +
               ("OK" if resCode == 0x40 else "FAILED"))
        if len(pdu) > 2:
            print "  DATA: " + hexlify(pdu[2:])
        if len(pdu) > 5:
            opDissect(opCode, pdu[2:])
        # Visual delimiter
        print "=" * 70


def bt_receive(raw=""):
        """
        Receives and assembles data packets
        """
        # FIXME! REFACTOR
        # This is a nearly identical copy of gtdevice.receive

        global buf

        if len(raw) > 1:  # Avoid the case when a single-byte tail is rcved
            head = unpack('>H', raw[0:2])[0]
        else:
            head = 0

        if (head == gtdevice.GT_STX):
            if (len(buf) > 0):
                print "WARN: previous unsynced data was lost"
            buf = raw[2:]
        else:
            buf = buf + raw

        tail = unpack('>H', buf[-2:])[0]

        if (tail == gtdevice.GT_ETX):
            # strip ETX, PDU is ready to process
            buf = buf[:-2]

            # extract sequence number
            #seq = unpack('B', buf[1:2])[0]

            # unescape 0x10
            buf = buf.replace(b'\x10\x10', '\x10')

            # extract and verify crc
            wantcrc = unpack('!H', buf[-2:])[0]
            havecrc = crc(buf[:-2])
            if wantcrc != havecrc:
                print ("ERROR: CRC failed, want=%04x, have=%04x" %
                       (wantcrc, havecrc))
                print "for string=" + hexlify(buf[:-2])
                return False

            # Debug dump
            if debugPDUS:
                # FIXME! CHEATING + HARDCODED
                print "Rx PDU: " + "1002" + hexlify(buf) + "1003"

            # DON'T post the PDU in the numbered box for collection
            # Instead, pass it to PDU dissector
            pduDissect(buf[:-2])
            buf = ""


def parseBTSnoop(filename):
    """
    Parse btsnoop_hci.log binary data

    This function is based on https://github.com/robotika/jessica
      (Copyright (c) 2013 robotika.cz | MIT License)

    "Snoop Version 2 Packet Capture File Format"
      from http://tools.ietf.org/html/rfc1761
    """

    f = open(filename, "rb")
    assert f.read(8) == "btsnoop\0"
    version, datalinkType = unpack(">II", f.read(8))
    assert version == 1, version
    assert datalinkType == 0x3EA, datalinkType

    i = 0
    startTime = None

    print "goTenna Bluetooth protocol analyzer\n"

    while True:
        header = f.read(24)  # is the header size
        if len(header) < 24:
            break
        origLen, incLen, flags, drops, time64 = unpack(">IIIIq", header)
        assert origLen == incLen, (origLen, incLen)
        assert drops == 0, drops
        assert flags in [0, 1, 2, 3], (i, flags)

        if startTime is None:
            startTime = time64

        data = f.read(origLen)

        if ((len(data) != origLen) or        # Short read?
            (flags not in [0, 1]) or
            (data[0] != '\x02') or           # Only keep type TYPE_ACL (2)
            (ord(data[9]) not in [0x52, 0x1d, ])):
                # include 0x1b above to also capture MWI notifs
                continue

        if len(data) < 12:
            continue

        totalLen, dataLen, CID, cmd, handle = unpack(
            '<HHHBH', data[3:12])

        # Sanity check on length fields etc
        if dataLen == totalLen-4 == len(data)-9:
            if debugDUMP:
                t = ((time64-startTime)/1000)/1000.
                print ("IN  " if flags == 1 else "OUT ") + "%.03f" % t
                print hexlify(data[0x0c:])
            bt_receive(data[0x0c:])

        i += 1

    print "Total packets: ", i
    return i


def main(filename):
    """
    Parse a btsnoop log
    """
    parseBTSnoop(filename)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        sys.exit(-1)
