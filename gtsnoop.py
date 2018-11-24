#!/usr/bin/python

""" gtsnoop.py
Parse a btsnoop log (from bluez hcidump or Android HCI snoop)
  to extract and analyze goTenna protocol packets
"""

import sys
from binascii import hexlify
from struct import unpack
from pycrc16 import crc
from gtdefs import *  # constants, lists and definitions
from gtdevice import gtBtReAsm

# Dump protocol packets
debugPDUS = False

# Make dump parsing (even more) verbose
debugDUMP = False

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

        if (opCode in [OP_SENDMSG, OP_READMSG, ]):
            # Show TLV names if known
            try:
                print "  -> %s: " % MSG_TLV_NAME[type] + hexlify(value)
            except KeyError:
                print "  -> TYPE_%02x_%02x: " % (opCode, type) + hexlify(value)
        else:
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
        try:
            print "  " + GT_OP_NAME[opCode]
        except KeyError:
            print "  OP_UNKNOWN"
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
        try:
            print ("  " + GT_OP_NAME[opCode] + " " +
                   ("OK" if resCode == GT_OP_SUCCESS else "FAILED"))
        except KeyError:
            print ("  OP_UNKNOWN " +
                   ("OK" if resCode == GT_OP_SUCCESS else "FAILED"))
        if len(pdu) > 2:
            print "  DATA: " + hexlify(pdu[2:])
        if len(pdu) > 5:
            opDissect(opCode, pdu[2:])
        # Visual delimiter
        print "=" * 70


def parseBTSnoop(filename):
    """
    Parse btsnoop_hci.log binary data

    This function is based on https://github.com/robotika/jessica
      (Copyright (c) 2013 robotika.cz | MIT License)

    "Snoop Version 2 Packet Capture File Format"
      from http://tools.ietf.org/html/rfc1761
    """

    try:
        f = open(filename, "rb")
    except:
        print "Unable to open file: %s" % filename
        return

    assert f.read(8) == "btsnoop\0"
    version, datalinkType = unpack(">II", f.read(8))
    assert version == 1, version
    assert datalinkType == 0x3EA, datalinkType

    i = 0
    startTime = None

    # Bluetooth frame reassembly
    frag = gtBtReAsm()

    # Pass packet to pduDissect when complete
    frag.packetHandler=pduDissect

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

            # send frame to packet reassembly routine
            frag.receiveFrame(data[0x0c:])

        i += 1

    print "Total packets: ", i
    return i


def giveHelp():
    print "\ngoTenna Bluetooth API protocol analyzer"
    print "\nUsage: %s filename\n" % sys.argv[0]


def main():
    if len(sys.argv) >= 2:
        parseBTSnoop(sys.argv[1])
    else:
        giveHelp()
        sys.exit(-1)


if __name__ == "__main__":
    main()
