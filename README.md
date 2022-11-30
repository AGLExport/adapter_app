# virtio-loopback adapter repository

This repository includes a alpha version of the "virtio_loopback_adapter" application which is part of the Virtio Loopback Design presented in this [document](https://git.virtualopensystems.com/virtio-loopback/docs/-/blob/master/design_docs).

As described in the design document, the adapter is only a part of a more complex architecture. If you want to see the implementation and build the other componets, refer to the [virtio-loopback docs repository](https://git.virtualopensystems.com/virtio-loopback/docs/-/tree/alpha-release).

## Build the virtio-loopback adapter

In order to build this project the next commands need to be used:
- `make` for x86
- `make ARCH=arm64` for arm64

**NOTE**: You can also use the parameter "DEBUG=1" in order to enable the debug messages and "VHOST_USER_RNG=1" which tells to the adapter to use an external entropy source. An external entropy source in our case is a rng-user-space drivers which communicates with the adapter via the "vhost-user" protocol. If the option "VHOST_USER_RNG" is not specified into the "make" command, then the adapter will use its internal mechanism and produce its own random numbers (this case is used only for testing purposes).

Exaple building the adapter with all the available parameters:
`make ARCH=arm64 VHOST_USER_RNG=1 DEBUG=1`

## Current status
This repository contains the current results of the activity carried on by Virtual Open Systems in the [Automotive Grade Linux](https://www.automotivegradelinux.org) community. Both code and documentation included in this release are under active development, and are intended to be used to familiarize with the concept of virtio-loopback and to give developers the opportunity to test it.
