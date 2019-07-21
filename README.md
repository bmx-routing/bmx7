![alt text](https://github.com/bmx-routing/bmx7/blob/a2a361eb994879371d13551a65496ed779ca0c44/doc/images/bmx7.png "BMX7 Logo")

BMX7 is a mesh routing protocol for Linux based operating systems.
The academic paper with more theoretical details can be found [here](http://dsg.ac.upc.edu/node/843).

## Content

*   [Installation](#installation)
    *   [Installing in OpenWRT](#installing-in-openwrt)
    *   [Packages](#Packages)
*   [FAQ](#faq)
*   [Usage](doc/Usage.md)
*   [Concepts](doc/Concepts.md)
    *   [Autoconfiguration](doc/Usage.md#address-auto-and-manual-configuration)
    *   [Unicast Host Network Announcements (UHNA)](doc/Usage.md#unicast-host-network-announcements-uhna)
*   [Tunnel Announcements](doc/Tunneling.md)
*   [BMX7 Plugins](doc/Plugins.md)
*   [Debugging](doc/Debugging.md)


  [github]: https://github.com/bmx-routing/bmx7

## Installation ##

### Requirements ###

The following tools and libraries are needed to obtain, compile, and install bmx7:
* git (debian package: git-core)
* gcc
* make
* build-essential
* libjson-c-dev zlib1g-dev libiw-dev
* libmbedtls-dev ( or mbedtls-2.4.0 from https://tls.mbed.org/download/mbedtls-2.4.0-gpl.tgz)

Optional for static configuration:
* uci-0.7.5 from http://downloads.openwrt.org/sources/uci-0.7.5.tar.gz

The following Linux-kernel modules are needed (depending on used bmx7 features)
* ipv6
* tunnel6
* ip6_tunnel

The mbed TLS or PolarSSL crypto library is needed for cryptographic operations:
Most tested with debian or mbedtls-2.4.0:
```
wget https://tls.mbed.org/download/mbedtls-2.4.0-gpl.tgz
tar xzvf mbedtls-2.4.0-gpl.tgz
cd mbedtls-2.4.0
make
sudo make install
# compile bmx7 with: make EXTRA_CFLAGS="-DCRYPTLIB=MBEDTLS_2_4_0"
```

### Downloading

Latest development sources are available from bmx7 git repository:

```
git clone https://github.com/bmx-routing/bmx7.git
cd bmx7
```

### Compile and Install

To only compile the main bmx7 daemon (no bmx7 plugins):
```
make EXTRA_CFLAGS="-DCRYPTLIB=MBEDTLS_2_4_0"
sudo make install
```

## Installing in OpenWRT

BMX7 is currently in the official OpenWRT-routing feed, so to install it from a existing system you can use opkg:
```
opkg install bmx7 bmx7-uci-config
```

If you are compiling your own OpenWRT, you can add the routing feed (already enabled by default) which can be found here: https://github.com/openwrt-routing/packages

Then run "make menuconfig" and select the bmx7 package in Networking -> Routing and redirection

It is recommended to select also, at least, the uci plugin (bmx7-uci-config)

You can select "luci-app-bmx7" to have a nice web interface for manage and monitorize the routing daemon.

Finally type "make" to build the image.

## Packages
Available packages exist for the following distributions:
- Arch Linux package(AUR): https://aur.archlinux.org/packages/bmx7/
- Debian Linux package(deb): **Coming soon**

## FAQ
1. How does BMX7 work and on which OSI layer?
- BMX7 is a routing protocol that operates on layer 3 of the OSI layer; it
    extends the concept of **receiver-driven routing**  and the principles of
    DSDV routing. The routing update of BMX7 (in contrast to traditional DSDV)
    contains a single and verifiable heartbeat value which unambiguously
    identifies a particular node of the network and a specific version of this
    nodes' self-defined description and routing-update version.

2. The goal of BMX7/SEMTOR?
- The goal of BMX7 is to provide secure mechanisms to ensure that
	non-trusted nodes in an open network are effectively prevented from
	disrupting the routing between trusted nodes.
- It's achieved by enforcing the exclusion of a given set of identified faulty nodes.

3. Differences with bmx6
- TBD

4. Similar Software
- AODV,
- Babel,
- BMX6,
- OLSR,
- batman-adv
