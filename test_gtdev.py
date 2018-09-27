#!/usr/bin/python
import binascii
import sys
import select
import gtdevice

# Dump GATT operations
gtdevice.debugGATT = False

# Dump protocol packets
gtdevice.debugPDUS = False

# Dump command/result
gtdevice.debugCMDS = False

print('Manual test for gtdevice library')

cliHelpText = "Syntax: " + sys.argv[0] + " MAC_ADDR"

if (len(sys.argv) < 2):
    print cliHelpText
    sys.exit()

if (len(sys.argv[1]) < 17):
    print cliHelpText
    sys.exit()

# Pick up MAC address from command line
MAC = sys.argv[1]

# Open Bluetooth connection
print('Connecting to ' + MAC + '...')
try:
    gotenna = gtdevice.goTennaDev(MAC)
except:
    print 'Connection FAILED, exiting'
    sys.exit()

print('CONNECTED')

# Initialize device communication
print('Initializing...')
if not gotenna.initialize():
    print "Initialization failed"
    sys.exit()

print "READY. Press Enter to continue"

opCode = None
opData = None

while True:
    # read lines in non-blocking mode
    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:

        l = sys.stdin.readline()

        if l:
            l = l.rstrip()
        else:
            print "End of input, will exit."
            break

        # Read numeric opcode first
        if opCode is None:
            try:
                opCode = int(l, 0)
            except:
                print "Enter a numeric opcode, 0 - %d, or Ctrl-D to quit:" % gtdevice.OPCODE_MAX
                opCode = None
                continue

            if opCode > gtdevice.OPCODE_MAX:
                print "Opcode %d out of range. Enter to continue" % opCode
                opCode = None
                continue

            print "Got opcode 0x%02x (%s)" % (opCode, gtdevice.GT_OP_NAME[opCode])
            print "Enter optional args in valid HEX, or empty if none:"
            continue

        else:
            # Reading optional HEX arguments
            try:
                opData = binascii.unhexlify(l)
            except:
                print "Invalid HEX value. Press Enter to continue."
                opCode = None
                opData = ""
                continue

            result = gotenna.execute(opCode, opData)
            if (result):
                print ('ALL OK' if result[0] == 0x40 else 'FAILED')
                print "Result: " + binascii.hexlify(result[1])
            else:
                print "ERROR: command not executed"

            opCode = None
            print "Press Enter to continue."

    try:
        gotenna.waitForNotifications(0.1)
    except:
        print "ERROR: Exception in main loop, exiting"
        break

print "DISCONNECTING"
gotenna.disconnect()
del gotenna

print "Goodbye"
