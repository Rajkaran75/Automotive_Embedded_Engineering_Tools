"""Open a CAN bus: virtual (testing), SocketCAN (Linux), or SLCAN (Windows)."""

import can


def open_bus(interface="virtual", channel="truckdiag", bitrate=250000):
    """interface:
      'virtual'   - in-process virtual bus for the simulator (any OS)
      'socketcan' - real hardware on Linux (channel e.g. 'can0';
                    bring up first with:
                    sudo ip link set can0 up type can bitrate 250000)
      'slcan'     - real hardware over a serial port, e.g. Windows
                    (channel e.g. 'COM3'; adapter must speak SLCAN)"""
    if interface == "virtual":
        return can.interface.Bus(channel=channel, interface="virtual",
                                 receive_own_messages=True)
    if interface == "slcan":
        return can.interface.Bus(channel=channel, interface="slcan",
                                 bitrate=bitrate)
    return can.interface.Bus(channel=channel, interface="socketcan",
                             bitrate=bitrate)
