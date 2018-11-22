"""An open source driver for goTenna Mesh devices over Bluetooth LE"""

from binascii import hexlify
from struct import pack, unpack
from bluepy.btle import Peripheral, ADDR_TYPE_RANDOM, DefaultDelegate
from pycrc16 import crc

from gtdefs import *  # constants, lists and definitions

# Dump GATT operations
debugGATT = False

# Dump protocol packets
debugPDUS = False

# Dump command/result
debugCMDS = False


class goTennaDev(Peripheral, DefaultDelegate):
    """
    GoTenna device operations
    """
    def __init__(self, addr):
        Peripheral.__init__(self, addr, addrType=ADDR_TYPE_RANDOM)

        self.hndSt = 0
        self.hndTx = 0
        self.hndRx = 0
        self.seq = 0      # protocol sequence, 1-byte rolling
        self.buf = ""     # temporary buffer for received packet reassembly
        self.res = {}     # numbered boxes for response strings
        self.mwi = 0      # message waiting indication
        self.withDelegate(self)  # handle notifications ourselves

    def initialize(self):
        # List characteristics, search for the three handles
        if debugGATT:
            print "Enumerating characteristics:"
        for s in self.getCharacteristics():
            if debugGATT:
                print ("  %04x-%04x (%02x): %s" %
                       (s.handle, s.valHandle, s.properties, s.uuid))
            if s.uuid == GT_UUID_ST:
                self.hndSt = s.valHandle
            elif s.uuid == GT_UUID_TX:
                self.hndTx = s.valHandle
            elif s.uuid == GT_UUID_RX:
                self.hndRx = s.valHandle

        if debugGATT:
            print ("HANDLES: hndSt=%x, hndTx=%x, hndRx=%x" %
                   (self.hndSt, self.hndTx, self.hndRx))

        # Any handles missing, bail out
        if self.hndSt == 0 or self.hndTx == 0 or self.hndRx == 0:
            print "ERROR: Could not locate all handles"
            return False

        # Activate indication handles
        try:
            if debugGATT:
                print "write: 0x%04x 0200" % (self.hndRx+1)
            self.writeCharacteristic(self.hndRx+1, "\x02\x00", True)
        except:
            print "ERROR: hndRx activation failed"
            return False
        # clear notifications
        self.waitForNotifications(.5)

        try:
            if debugGATT:
                print "write: 0x%04x 0100 " % (self.hndSt+1)
            self.writeCharacteristic(self.hndSt+1, "\x01\x00", True)
        except:
            print "ERROR: hndSt activation failed"
            return False
        # clear notifications
        self.waitForNotifications(.5)
        return True

    def execute(self, opcode, data=""):
        """
        Takes an opcode and data PDU on input, executes them on gotenna,
        returns a result code and data PDU or False on failure
        """

        # Increment sequence index, skip reserved byte 0x10
        self.seq = (self.seq + 1) & 0xff
        if self.seq == 0x10:
            self.seq = 0x11

        if debugCMDS:
            print "CMD: %02x " % opcode + hexlify(data)

        txpdu = pack("BB", opcode & 0xff, self.seq) + data

        # Calculate crc pre-escaping
        send_crc = crc(txpdu)

        # \x10 characters must be escaped as \x10 \x10
        txpdu = txpdu.replace(b'\x10', '\x10\x10')

        # Add STX, CRC and ETX
        txpdu = (pack("!H", GT_BLE_STX) + txpdu +
                 pack("!HH", send_crc, GT_BLE_ETX))

        if debugPDUS:
            print "Tx PDU: " + hexlify(txpdu)

        # Fragmentation happens here
        sendpos = 0
        while sendpos < len(txpdu):
            if debugGATT:
                print "Xmit data: " + hexlify(txpdu[sendpos:sendpos+20])
            try:
                self.writeCharacteristic(self.hndTx,
                                         txpdu[sendpos:sendpos+20],
                                         False)
            except:
                print "WARN: Xmit Data Failed"
                return False
            sendpos = sendpos+20

            while self.waitForNotifications(1.0):
                pass

        # check numbered box for a response
        try:
            data = self.res[self.seq]
        except KeyError:
            # No data, return empty
            return False

        # delete numbered box
        del self.res[self.seq]

        # XOR with opcode to normalize result code
        code = opcode ^ unpack('B', data[0:1])[0]
        data = data[2:]

        if debugCMDS:
            print "RES: %02x " % code + hexlify(data)

        # return in an array - result code and data PDU
        return (code, data)

    def receive(self, raw=""):
        """
        Receives and assembles data packets from notification handler
        """

        if len(raw) > 1:  # Avoid the case when a single-byte tail is rcved
            head = unpack('>H', raw[0:2])[0]
        else:
            head = 0

        if (head == GT_BLE_STX):
            if (len(self.buf) > 0):
                print "WARN: previous unsynced data was lost"
            self.buf = raw[2:]
        else:
            self.buf = self.buf + raw

        tail = unpack('>H', self.buf[-2:])[0]

        if (tail == GT_BLE_ETX):
            # strip ETX, PDU is ready to process
            self.buf = self.buf[:-2]

            # extract sequence number
            seq = unpack('B', self.buf[1:2])[0]

            # unescape 0x10
            self.buf = self.buf.replace(b'\x10\x10', '\x10')

            # extract and verify crc
            wantcrc = unpack('!H', self.buf[-2:])[0]
            havecrc = crc(self.buf[:-2])
            if wantcrc != havecrc:
                print ("ERROR: CRC failed, want=%04x, have=%04x" %
                       (wantcrc, havecrc))
                print "for string=" + hexlify(self.buf[:-2])
                return False

            # Debug dump
            if debugPDUS:
                # FIXME! CHEATING + HARDCODED
                print "Rx PDU: " + "1002" + hexlify(self.buf) + "1003"

            # post the PDU in the numbered box for collection
            self.res[seq] = self.buf[:-2]
            self.buf = ""

    def mwiChange(self):
        # called on new message waiting indication
        print "MWI has been raised"

    def handleNotification(self, hnd, data):
        """
        Notification handler, called from BT stack
        """
        if hnd == self.hndSt:
            if debugGATT:
                print "Rcvd status: " + hexlify(data)
            (want_mwi,) = unpack('B', data)
            if self.mwi != want_mwi:
                self.mwi = want_mwi
                self.mwiChange()

        elif hnd == self.hndRx:
            if debugGATT:
                print "Rcvd data: " + hexlify(data)
            self.receive(data)
        else:
            print "WARN: Rcvd via unknown hnd %x: " % hnd + hexlify(data)
