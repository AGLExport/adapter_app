# virtio-loopback adapter repository

This repository includes the beta version of the "virtio_loopback_adapter" application which is part of the Virtio Loopback Design presented in this [document](https://git.virtualopensystems.com/virtio-loopback/docs/-/blob/master/design_docs). This work carried on by Virtual Open Systems in the [Automotive Grade Linux](https://www.automotivegradelinux.org) community.

As described in the design document, the adapter is only a part of a more complex architecture. If you want to see the implementation and build the other components, refer to the [virtio-loopback docs repository](https://git.virtualopensystems.com/virtio-loopback/docs/-/tree/beta-release).

## Build the virtio-loopback adapter

In order to build this project the next commands need to be used:
- `make` for x86
- `make ARCH=arm64` for arm64

**NOTE**: You can also use the parameter "DEBUG=1" in order to enable the debug messages.

Example building the adapter with all the available parameters:
`make ARCH=arm64 DEBUG=1`
