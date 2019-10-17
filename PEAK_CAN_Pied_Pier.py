# !/usr/bin/env python3
# 
#  PEAK_CAN_Pied_Piper.py
#
#  ~~~~~~~~~~~~
#
#  Receiving Packages from Peak CAN Adapters and forwarding them to 
#  a Pipe to be recorded and analyzed by WireShark
#
#  ~~~~~~~~~~~~
#
#  ------------------------------------------------------------------
#  Author : Niels Göran Blume
#  Last change: 2019-05-31 Blume
#  ------------------------------------------------------------------
#
#  Copyright (C) 2019  embeX GmbH, Freiburg im Breisgau
#  more Info at http://embex.de
#
#  Links:
#  https://www.peak-system.com/forum/viewtopic.php?f=41&t=3253&p=9725&hilit=python#p9725
#  https://www.peak-system.com/forum/viewtopic.php?f=41&t=2817
#  https://wiki.wireshark.org/CaptureSetup/Pipes
#  https://wiki.wireshark.org/Development/LibpcapFileFormat
#  https://www.tcpdump.org/linktypes.html
#  https://github.com/wireshark/wireshark/blob/master/wiretap/wtap.h
#  https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-socketcan.c
#  https://fossies.org/diffs/wireshark/2.6.7_vs_3.0.0/epan/dissectors/packet-socketcan.h-diff.html
#  
#  ------------------------------------------------------------------
#  Maior Code REUSE AND INSPIRATION 
#  from Pinoccio/tool-serial-pcap (https://github.com/Pinoccio/tool-serial-pcap/blob/master/serial-pcap)
#  THANKS !!!
#  ------------------------------------------------------------------

# Imports
#
from include.PCANBasic import *        ## PCAN-Basic library import

import win32pipe, win32file
import time
import subprocess
from time import sleep
import struct

from ctypes import *
from string import *
import platform

import argparse
import threading

CANHandle = {'PCAN_DNGBUS1':PCAN_DNGBUS1, 'PCAN_PCCBUS1':PCAN_PCCBUS1, 'PCAN_PCCBUS2':PCAN_PCCBUS2, 'PCAN_ISABUS1':PCAN_ISABUS1, 
            'PCAN_ISABUS2':PCAN_ISABUS2, 'PCAN_ISABUS3':PCAN_ISABUS3, 'PCAN_ISABUS4':PCAN_ISABUS4, 'PCAN_ISABUS5':PCAN_ISABUS5,
            'PCAN_ISABUS6':PCAN_ISABUS6, 'PCAN_ISABUS7':PCAN_ISABUS7, 'PCAN_ISABUS8':PCAN_ISABUS8, 'PCAN_PCIBUS1':PCAN_PCIBUS1,
            'PCAN_PCIBUS2':PCAN_PCIBUS2, 'PCAN_PCIBUS3':PCAN_PCIBUS3, 'PCAN_PCIBUS4':PCAN_PCIBUS4, 'PCAN_PCIBUS5':PCAN_PCIBUS5,
            'PCAN_PCIBUS6':PCAN_PCIBUS6, 'PCAN_PCIBUS7':PCAN_PCIBUS7, 'PCAN_PCIBUS8':PCAN_PCIBUS8, 'PCAN_PCIBUS9':PCAN_PCIBUS9,
            'PCAN_PCIBUS10':PCAN_PCIBUS10, 'PCAN_PCIBUS11':PCAN_PCIBUS11, 'PCAN_PCIBUS12':PCAN_PCIBUS12, 'PCAN_PCIBUS13':PCAN_PCIBUS13,
            'PCAN_PCIBUS14':PCAN_PCIBUS14, 'PCAN_PCIBUS15':PCAN_PCIBUS15, 'PCAN_PCIBUS16':PCAN_PCIBUS16, 'PCAN_USBBUS1':PCAN_USBBUS1,
            'PCAN_USBBUS2':PCAN_USBBUS2, 'PCAN_USBBUS3':PCAN_USBBUS3, 'PCAN_USBBUS4':PCAN_USBBUS4, 'PCAN_USBBUS5':PCAN_USBBUS5,
            'PCAN_USBBUS6':PCAN_USBBUS6, 'PCAN_USBBUS7':PCAN_USBBUS7, 'PCAN_USBBUS8':PCAN_USBBUS8, 'PCAN_USBBUS9':PCAN_USBBUS9,
            'PCAN_USBBUS10':PCAN_USBBUS10, 'PCAN_USBBUS11':PCAN_USBBUS11, 'PCAN_USBBUS12':PCAN_USBBUS12, 'PCAN_USBBUS13':PCAN_USBBUS13,
            'PCAN_USBBUS14':PCAN_USBBUS14, 'PCAN_USBBUS15':PCAN_USBBUS15, 'PCAN_USBBUS16':PCAN_USBBUS16, 'PCAN_LANBUS1':PCAN_LANBUS1,
            'PCAN_LANBUS2':PCAN_LANBUS2, 'PCAN_LANBUS3':PCAN_LANBUS3, 'PCAN_LANBUS4':PCAN_LANBUS4, 'PCAN_LANBUS5':PCAN_LANBUS5,
            'PCAN_LANBUS6':PCAN_LANBUS6, 'PCAN_LANBUS7':PCAN_LANBUS7, 'PCAN_LANBUS8':PCAN_LANBUS8, 'PCAN_LANBUS9':PCAN_LANBUS9,
            'PCAN_LANBUS10':PCAN_LANBUS10, 'PCAN_LANBUS11':PCAN_LANBUS11, 'PCAN_LANBUS12':PCAN_LANBUS12, 'PCAN_LANBUS13':PCAN_LANBUS13,
            'PCAN_LANBUS14':PCAN_LANBUS14, 'PCAN_LANBUS15':PCAN_LANBUS15, 'PCAN_LANBUS16':PCAN_LANBUS16}

CANBaudrates = {'PCAN_BAUD_1M':PCAN_BAUD_1M, 'PCAN_BAUD_800K':PCAN_BAUD_800K, 'PCAN_BAUD_500K':PCAN_BAUD_500K, 'PCAN_BAUD_250K':PCAN_BAUD_250K,
                'PCAN_BAUD_125K':PCAN_BAUD_125K, 'PCAN_BAUD_100K':PCAN_BAUD_100K, 'PCAN_BAUD_95K':PCAN_BAUD_95K, 'PCAN_BAUD_83K':PCAN_BAUD_83K,
                'PCAN_BAUD_50K':PCAN_BAUD_50K, 'PCAN_BAUD_47K':PCAN_BAUD_47K, 'PCAN_BAUD_33K':PCAN_BAUD_33K, 'PCAN_BAUD_20K':PCAN_BAUD_20K,
                'PCAN_BAUD_10K':PCAN_BAUD_10K, 'PCAN_BAUD_5K':PCAN_BAUD_5K}

###*****************************************************************
### Timer class
###*****************************************************************
class TimerRepeater(object):

    """
    A simple timer implementation that repeats itself
    """

    # Constructor
    #
    def __init__(self, name, interval, target, isUi, args=[], kwargs={}):
        """
        Creates a timer.

        Parameters:
            name        name of the thread
            interval    interval in second between execution of target
            target      function that is called every 'interval' seconds
            args        non keyword-argument list for target function
            kwargs      keyword-argument list for target function
        """
        # define thread and stopping thread event
        self._name = name
        self._thread = None
        self._event = None
        self._isUi = isUi
        # initialize target and its arguments
        self._target = target
        self._args = args
        self._kwargs = kwargs
        # initialize timer
        self._interval = interval
        self._bStarted = False

    # Runs the thread that emulates the timer
    #
    def _run(self):
        """
        Runs the thread that emulates the timer.

        Returns:
            None
        """
        while not self._event.wait(self._interval):
            self._target(*self._args, **self._kwargs)

    # Starts the timer
    #
    def start(self):
        """
        Starts the timer

        Returns:
            None
        """
        # avoid multiple start calls
        if (self._thread == None):
            self._event = threading.Event()
            self._thread = threading.Thread(None, self._run, self._name)
            self._thread.start()

    # Stops the timer
    #
    def stop(self):
        """
        Stops the timer

        Returns:
            None
        """
        if (self._thread != None):
            self._event.set()
            self._thread = None

def tmrRead_Tick():
    # Checks if in the receive-queue are currently messages for read
    # 
    ReadMessages()

def ReadMessages():
    stsResult = PCAN_ERROR_OK

    # We read at least one time the queue looking for messages.
    # If a message is found, we look again trying to find more.
    # If the queue is empty or an error occurr, we get out from
    # the dowhile statement.
    #
    while (not (stsResult & PCAN_ERROR_QRCVEMPTY)):
        stsResult = ReadMessage()
        if stsResult == PCAN_ERROR_ILLOPERATION:
            break

## Function for reading CAN messages on normal CAN devices
##
def ReadMessage():
    # We execute the "Read" function of the PCANBasic
    #
    result = objPCAN.Read(handle)

    if result[0] == PCAN_ERROR_OK:
        # We show the received message
        # 

        # Split the arguments: 
        # [0] TPCANMsg
        # [1] TPCANTimestamp
        #
        theMsg = result[1]
        itsTimeStamp = result[2]

        newTimestamp = (0x100000000 * 1000 * itsTimeStamp.millis_overflow + 1000 * itsTimeStamp.millis + itsTimeStamp.micros)
        data_str = '0x'
        for i in range(8 if (theMsg.LEN > 8) else theMsg.LEN):
            data_str += '{:02x}'.format(theMsg.DATA[i]) + " "
        if (options.verbose):
            print(newTimestamp, "-", '0x{:02x}'.format(theMsg.ID), "-", '0x{:02x}'.format(theMsg.LEN), "-", data_str, "-", '0x{:02x}'.format(theMsg.MSGTYPE))

        # SocketCAN - Header
        socketcan_header = (theMsg.ID).to_bytes(4, byteorder='big')
        # eX-ToDo
        # add additional infos in first 3 bits (acc. SocketCAN)
        # bit 0: extended flag
        # bit 1: Remote Transfer Request flag
        # bit 2: Error Message flag
        # Example: 0x00 00 05 c2
        # 0000 0000 0000 0000 0000 0101 1100 0010:
        # Bit 0: Extended = False (0)
        # Bit 1: RTR = False (0)
        # Bit 2: Error Message = False (0)
        # ...
        # unused
        # ...
        # Bei Standard IDs:
        # Bit 21 bis Bit 31: 11-bit CAN ID = 0x5C2 (101 1100 0010)
        # 
        # Bei Extended IDs:
        # Bit 3 bis Bit 31: 29-bit CAN ID = 0x24A (‭0 0000 0000 0000 0000 0010 0100 1010)‬

        # SocketCAN - Length / Number of data bytes
        socketcan_length = theMsg.LEN.to_bytes(4, byteorder='little')
        # eX-ToDo
        # Example: 0x08 00 00 00
        # 0000 1000 0000 0000 0000 0000 0000 0000:
        # Bit 0 bis Bit 7: Data Length = 8 Bytes (0x08 = 0000 1000)
        # Bit 8 bis Bit 31: Reserved (not cleared what it is used for)

        # SocketCAN - CAN data (max. 8 bytes)
        # socketcan_data = data_raw
        socketcan_data = bytes(theMsg.DATA)
        # print(socketcan_data.hex())

        # SocketCAN - Complete Frame
        # Combine elements into "complete" SocketCAN frame
        socketcan_frame = socketcan_header + socketcan_length + socketcan_data
        socketcan_frame_length = len(socketcan_frame)
        # print (socketcan_frame.hex())

        # Send received message to pipe
        # 
        packet_header = struct.pack("=IIII",
            newTimestamp // 1000000,        # timestamp seconds
            (newTimestamp - (newTimestamp // 1000000) * 1000000 ),  # timestamp microseconds
            socketcan_frame_length,        # number of octets of packet saved in file
            socketcan_frame_length,        # actual length of packet
        )
        win32file.WriteFile(CAN_pipe, packet_header)
        # Header is immediately followed by corresponding packet data = theMsg
        win32file.WriteFile(CAN_pipe, socketcan_frame)

    return result[0]

# MAIN MAIN MAIN
# 

# "Global" objects
# 

# PEAK CAN objects and variabels
# 
objPCAN = PCANBasic()
handle = CANHandle['PCAN_USBBUS1']
baudrate = CANBaudrates['PCAN_BAUD_500K']

# Initialize timer for checking receive queue regularly
# every 0.05 s; call function "tmrRead_Tick",  not started YET (use Start fct for that)
# 
tmrRead = TimerRepeater("tmrRead", 0.05, tmrRead_Tick, False)

# create the named pipe \\.\pipe\PEAK_CAN
# 
CAN_pipe = win32pipe.CreateNamedPipe(
    r'\\.\pipe\PEAK_CAN',
    win32pipe.PIPE_ACCESS_OUTBOUND,
    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
    1, 65536, 65536,
    300,
    None)


# Parse CMD line arguments
# 
parser = argparse.ArgumentParser(description='Receives CAN messages from PEAK CAN Adapter and forwards them to pipe to be read and analyzed in WireShark')
parser.add_argument('-p', '--handle', default='PCAN_USBBUS1', help='The TPCanHandle to read from')
parser.add_argument('-b', '--baudrate', default='PCAN_BAUD_500K', help='The TPCanBaudrate of the bus')
parser.add_argument('-ext', '--extended', action='store_true', help='Use extended CAN IDs on the bus')
parser.add_argument('-v', '--verbose', action='store_true', help='Activate extended debug logging to console')
options = parser.parse_args()

# open Wireshark, configure pipe interface and start capture (not mandatory, you can also do this manually)
# 
wireshark_cmd=['C:\Program Files\Wireshark\Wireshark.exe', r'-i\\.\pipe\PEAK_CAN','-k']
proc=subprocess.Popen(wireshark_cmd)

# Connect to pipe
# 
win32pipe.ConnectNamedPipe(CAN_pipe, None)

# Send header to pipe
# 
data = struct.pack("=IHHiIII",
        0xa1b2c3d4,   # magic number
        2,            # major version number
        4,            # minor version number
        0,            # GMT to local correction
        0,            # accuracy of timestamps
        65535,        # max length of captured packets, in octets
        227,          # data link type (DLT)   //  227 = SocketCAN
    )
win32file.WriteFile(CAN_pipe, data)

# Initialize CAN interface
# 
handle = CANHandle[options.handle]
baudrate = CANBaudrates[options.baudrate]
print("CAN-Interface Configuration: TPCANHandle: ", options.handle, "- TPCANBaudrate: ", options.baudrate)

result = objPCAN.Initialize( handle, baudrate)
# result = objPCAN.Initialize(PCAN_USBBUS1, PCAN_BAUD_500K)
if result != PCAN_ERROR_OK:
    # An error occurred, get a text describing the error and show it
    result = objPCAN.GetErrorText(result)
    print(result[1])
else:
    print("CAN-Interface was succesfully initialized")

# Start timer for reading messages
# 
tmrRead.start()

input("Press [ENTER] to exit\n") 

# Stop timer for reading messages
# 
tmrRead.stop()

# Uninitialize CAN interface
# 
result = objPCAN.Uninitialize( handle )
if result != PCAN_ERROR_OK:
    # An error occurred, get a text describing the error and show it
    #
    result = objPCAN.GetErrorText(result)
    print(result[1])
else:
    print("CAN-Interface was succesfully un-initialized")

# Disconnect from named pipe
# 
win32pipe.DisconnectNamedPipe(CAN_pipe)
