
""" Constants, lists and definitions for pyGT driver
    Warning: ALLCAPS SPOKEN HERE

    Contains several sets of definitions, grouped under headings:
    1) Bluetooth protocol level
    2) Bluetooth API level
    3a) API object level (non-message)
    3b) Message envelope level
    4) Message content level
"""

#
# 1) Bluetooth protocol level
#

# start and end of protocol messages
GT_BLE_STX = 0x1002
GT_BLE_ETX = 0x1003

# gotenna UUIDs
GT_UUID_ST = "12762b18-df5e-11e6-bf01-fe55135034f3"
GT_UUID_TX = "1276b20a-df5e-11e6-bf01-fe55135034f3"
GT_UUID_RX = "1276b20b-df5e-11e6-bf01-fe55135034f3"


#
# 2) Bluetooth API level - commands, opcodes and result codes
#

# Known goTenna opcodes (from traffic analysis, CLI fuzzing etc)
OP_FLASH   = 0x00    # Blink the light 3 times to help locate
OP_SET_GID = 0x01    # Set GID on device
OP_SET_PUB = 0x02    # Upload public key (don't know why)
OP_SENDMSG = 0x03    # Send a message (shout, direct, key exch etc)
OP_SYSINFO = 0x04    # Get system info (serial, version, battery etc)
OP_READMSG = 0x06    # Read the first message in receive queue
OP_NEXTMSG = 0x07    # Delete the first message from queue
OP_RST_GID = 0x0b    # Reset GID
OP_DEL_GID = 0x0d    # Delete GID?
OP_SET_APP = 0x10    # Set App ID
OP_SET_GEO = 0x21    # Set geopolitical region (1=US)
OP_GET_GEO = 0x22    # Get geopolitical region

# Max opcode ID
GT_OPCODE_MAX = 0x2c

GT_OP_SUCCESS = 0x40

# Translating opcodes to human-readable names
GT_OP_NAME = {
    OP_FLASH: "OP_FLASH",
    OP_SET_GID: "OP_SET_GID",
    OP_SET_PUB: "OP_SET_PUB",
    OP_SENDMSG: "OP_SENDMSG",
    OP_SYSINFO: "OP_SYSINFO",
    0x05: "OP_RSVD_05",
    OP_READMSG: "OP_READMSG",
    OP_NEXTMSG: "OP_NEXTMSG",
    0x08: "OP_RSVD_08",
    0x09: "OP_RSVD_09",
    0x0a: "OP_RSVD_0A",
    OP_RST_GID: "OP_RST_GID",
    0x0c: "OP_RSVD_0C",
    OP_DEL_GID: "OP_DEL_GID",
    0x0e: "OP_RSVD_0E",
    0x0f: "OP_RSVD_0F",
    0x10: "OP_SET_APP",
    0x11: "OP_RSVD_11",
    0x12: "OP_RSVD_12",
    0x13: "OP_RSVD_13",
    0x14: "OP_RSVD_14",
    0x15: "OP_BLE_BER",
    0x16: "OP_RSVD_16",
    0x17: "OP_RSVD_17",
    0x18: "OP_RSVD_18",
    0x19: "OP_RSVD_19",
    0x1a: "OP_RSVD_1A",
    0x1b: "OP_RSVD_1B",
    0x1c: "OP_RSVD_1C",
    0x1d: "OP_RSVD_1D",
    0x1e: "OP_RSVD_1E",
    0x1f: "OP_RSVD_1F",
    0x20: "OP_BLE_RST",
    OP_SET_GEO: "OP_SET_GEO",
    OP_GET_GEO: "OP_GET_GEO",
    0x23: "OP_RSVD_23",
    0x24: "OP_RSVD_24",
    0x25: "OP_GETPROP",
    0x26: "OP_GET_FLT",
    0x27: "OP_GET_DDI",
    0x28: "OP_RSVD_28",
    0x29: "OP_MORSE",
    0x2a: "OP_SCAN_CH",
    0x2b: "OP_TESTBER",
    0x2c: "OP_RSVD_2C",
}


#
# 3a) API object level (non-message) - some data object defs go in here
#


#
# 3b) Message envelope level - main message object components, which
#     are processed and sometimes syntax-enforced by the goTenna device
# Most of these are REQUIRED EVEN FOR NON-INTEROP APPLICATIONS
#

# Message class IDs
MSG_CLASS_P2P   = 0     # Regular peer-to-peer message
                        #  (contains sender and destination GIDs)
MSG_CLASS_GROUP = 1     # Group message
                        #  (sender GID, dest is group GID + extra byte)
MSG_CLASS_SHOUT = 2     # Shout message
                        #  (sender GID only, TTL=1, rcvd by all in range)
MSG_CLASS_EMERG = 3     # Emergency message
                        #  (sender GID only, like shout but with a TTL)

# Translating class IDs to human names
MSG_CLASS_NAME = {
    MSG_CLASS_P2P:   "P2P",
    MSG_CLASS_GROUP: "GROUP",
    MSG_CLASS_SHOUT: "SHOUT",
    MSG_CLASS_EMERG: "EMERG",
}

# Envelope-level TLVs in message objects
#  (R) = present in rcvd msgs (air-to-app), (T) in sent msgs (app-to-air)
# MANDATORY TLVs for app-generated msgs are DEST, DATA and TTL
MESG_TLV_0x04 = 0x04    # (R,T) Undoc, required in some cases
MESG_TLV_DATA = 0x05    # (R,T) Main section: sender, body, payloads
MESG_TLV_DEST = 0x06    # (R,T) Message class and dest (GID or all)
MESG_TLV_HOPS = 0x20    # (R) Rx'd msg hops count (set by device from MXRX)
MESG_TLV_DLR  = 0x21    # (R) Delivery report (created by device)
MESG_TLV_TTL  = 0x22    # (T) Message TTL (set by sender app)
MESG_TLV_MXRX = 0x23    # (air only) Mesh metadata RX (stripped by device)
MESG_TLV_MXTX = 0x24    # (air only) Mesh metadata TX (appended by device)

# Reverse translation
MSG_TLV_NAME = {
    MESG_TLV_0x04: "X_04",
    MESG_TLV_DATA: "DATA",
    MESG_TLV_DEST: "DEST",
    MESG_TLV_HOPS: "HOPS",
    MESG_TLV_DLR:  "DLR ",
    MESG_TLV_TTL:  "TTL ",
    MESG_TLV_MXRX: "MXRX",
    MESG_TLV_MXTX: "MXTX",
}


#
# 4) Message content level - specific to goTenna app and not processed
#     on the goTenna device
# FOR INTEROP PURPOSES ONLY - NOT A REQUIREMENT FOR NEW APPLICATIONS
#
