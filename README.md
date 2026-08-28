# wireshark_plugins

A place to hold WireShark Filters for Cyphal. These filters are based on the specification from https://opencyphal.org/specification.

| PROTOCOL | Status |
|----------|--------|
| Cyphal/UDP | working |
| Cyphal/CAN | working |
| Cyphal/serial | - |

Serial debugging with Wireshark may be possible with some tools which redirect the serial port over a named pipe.

The older Wireshark plugin which uses SocketCAN for UAVCAN/CAN is implemented in C in Wireshark itself.

`cyphal_1v1.lua` is the current Cyphal/CAN and Cyphal/UDP dissector. It implements the Cyphal v1.1 session protocol, retains Cyphal/CAN v1.0 transport support, and leaves application payloads opaque.

`cyphal_1v0_can.lua` and `cyphal_1v0_udp.lua` are the original Cyphal v1.0-only plugins.

## Installation

Copy the desired `.lua` to your WireShark Plugins directory. The location of the Lua plugin directory can be found via Help → About → Folders:

<img width="675" alt="image" src="https://github.com/OpenCyphal/wireshark_plugins/assets/3298404/7bde8f6d-8c1d-41f7-81d8-f6769ef456ae">

You may have to give your root password to install or `sudo cp`. The v1.1 dissector requires Wireshark 4.6 or newer with Lua 5.4; do not load it together with the old CAN dissector.

## How to Use

### Cyphal v1.1

`cyphal_1v1.lua` normally recognizes extended Cyphal automatically. It can also be selected using "Decode As".

BPF capture filter: `udp`; display filter: `cyphal11`.

### Cyphal/UDP v1.0

The following BPF expression can be used to filter Cyphal/UDP traffic only (useful if the network traffic is high):

```
udp and dst net 239.0.0.0 mask 255.0.0.0 and dst port 9382
```

The Cyphal/UDP filter will automatically detect messages. The Cyphal/CAN v1.0 filter however will not and will need to be added to the "Decode As" list.

### Cyphal/CAN v1.0

Right-click on the CANFD messages stream and select "Decode As". Remove the initial entry from the list and add a new entry which sets the first column to "CAN next level dissector", and the "current" column to "CYPHALCAN".

Once added the message stream in the top of Wireshark will continue to say "CANFD" but the detail window will have all the decoded parts of the Cyphal/CAN header, payload (for Heartbeat and GetInfo) and the footer.

## Development

To add features to the protocol plugin, simply copy, reload (`Cmd+Shift+L` on Mac, `Ctrl+Shift+L` elsewhere), and test.

The headless v1.1 test suite generates captures with the pinned Cy submodule and requires TShark 4.6 or newer. Initialize submodules after a non-recursive clone with `git submodule update --init --recursive`:

```sh
tests/run.sh
```

Happy Decoding!
