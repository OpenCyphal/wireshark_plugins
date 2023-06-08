# wireshark_plugins

A place to hold WireShark Filters for Cyphal Headers. These filters are based on the specification from https://opencyphal.org/specification/Cyphal_Specification.pdf.

| PROTOCOL | Status |
|----------|--------|
| Cyphal/UDP | working |
| Cyphal/CAN | - |
| Cyphal/serial | - |

Serial debugging with Wireshark may be possible with some tools which redirect the serial port over a named pipe.

The older wireshark plugin which uses SocketCAN for UAVCAN should be possible to port over to Cyphal.

## Installation

Copy the `*.lua` to your WireShark Plugins directory (consult the docs to find where).

You may have to give your root password to install or `sudo cp`.

## Development

To add features to the protocol plugin, simply copy, reload (`Cmd+Shift+L` on Mac, `Ctrl+Shift+L` elsewhere), and test.

Happy Decoding!
