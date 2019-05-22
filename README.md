# BMX7

Bmx7 is a mesh routing protocol for Linux based operating systems.
The following intro provides kind of tutorial to get started.

## Content

*   [Installation](#installation)
    *   [Installing in OpenWRT](#installing-in-openwrt)
*   [Usage (hello mesh)](#usage-hello-mesh)
*   [Concepts](#concepts)
*   [Autoconfiguration](#address-auto-and-manual-configuration)
*   [Unicast Host Network Announcements (UHNA)](#unicast-host-network-announcements-uhna)
*   [Tunnel Announcements](#tunnel-announcements)
*   [Bmx7 Plugins](#bmx7-plugins)
    *   [Config Plugin](#config-plugin)
    *   [Json Plugin](#json-plugin)
    *   [SMS Plugin](#sms-plugin)
    *   [Table plugin](#table-plugin)


Note: This document is written using Markdown syntax. Modifications should be
synced via README.md file in bmx7 repositories at [github][github].
Nice syntax examples are [here][syntax].

  [bmx7]: http://bmx6.net
  [github]: https://github.com/bmx-routing/bmx7
  [syntax]: http://daringfireball.net/projects/markdown/syntax.text


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
<pre>
wget https://tls.mbed.org/download/mbedtls-2.4.0-gpl.tgz
tar xzvf mbedtls-2.4.0-gpl.tgz
cd mbedtls-2.4.0
make
sudo make install
# compile bmx7 with: make EXTRA_CFLAGS="-DCRYPTLIB=MBEDTLS_2_4_0"
</pre>


### Downloading

Latest development sources are available from bmx7 git repository:

<pre>
git clone https://github.com/bmx-routing/bmx7.git
cd bmx7
</pre>

### Compile and Install

To only compile the main bmx7 daemon (no bmx7 plugins):
<pre>
make EXTRA_CFLAGS="-DCRYPTLIB=MBEDTLS_2_4_0"
sudo make install 
</pre>




## Installing in OpenWRT

Bmx7 is currently in the official OpenWRT-routing feed, so to install it from a existing system you can use opkg:
<pre>
opkg install bmx7 bmx7-uci-config
</pre>

If you are compiling your own OpenWRT, you can add the routing feed (already enabled by default) which can be found here: https://github.com/openwrt-routing/packages

Then run "make menuconfig" and select the bmx7 package in Networking -> Routing and redirection

It is recommended to select also, at least, the uci plugin (bmx7-uci-config)

You can select "luci-app-bmx7" to have a nice web interface for manage and monitorize the routing daemon.

Finally type "make" to build the image.

