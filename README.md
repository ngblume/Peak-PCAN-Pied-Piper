# Python_CAN_Pied_Piper
Using the PEAK CAN adapter with Wireshark for CANopen logging

Use a PEAK USB CAN adapter to record CAN  messages and forward them via pipes to WireShark (via SocketCAN), which then decodes the CAN messages. CANopen decoding can be added via second-level di-sectors

## Usage

### Silent ###

python PEAK_CAN_Pied_Piper.py -p PCAN_USBBUS2 -b PCAN_BAUD_250K

### Verbose ###

python PEAK_CAN_Pied_Piper.py -p PCAN_USBBUS2 -b PCAN_BAUD_250K -v

## Open Issues

1. Use python-can as HAL
