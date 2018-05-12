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

## Usage (hello mesh)

### Starting

In the most simple configuration, the only required parameter are the interfaces names that should be used for meshing.
The following example starts bmx7 on interface wlan0:
<pre>
root@mlc1001:~# bmx7 dev=eth1
</pre>

However, to let this simple command work as expected also check the following basic requirements:

* `bmx7` must be executed in root context (with super user permissions). If you are not already root, prepend all commands with sudo (eg: `sudo bmx7 dev=eth1` ).

* No IP address needs to be configured. By default bmx7 assumes IPv6
  and autoconfigures a [ULA](https://en.wikipedia.org/wiki/Unique_local_address)-based IPv6
  address for each interface based on the MAC address of the
  device. The only pre-requisite is that the interfaces must be in the
  `up` state, E.G.: `ip link set wlan0 up`. 

  If you are using a wireless interface, the interface settings must
  have been configured using `iwconfig` or `iw` to communicate with bmx7
  daemons running on other nodes. This is a typical configuration for
  a wireless mesh setup: <pre>iwconfig wlan0 mode ad-hoc ap 02:ca:ff:ee:ba:be channel 11 essid my-mesh-network</pre>

* Bmx7 (by default) works in daemon mode, thus sends itself to
  background and gives back a prompt. To let it run in foreground
  specify a debug level with the startup command like:
  <pre> bmx7 debug=0 dev=eth1 </pre>
  Of course, you may need to kill a previously
  started bmx7 daemon beforehand (`killall bmx7`)

If everything went fine bmx7 is running now, searches for neighboring
bmx7 daemons via the configured interface (link), and coordinates with
them to learn about existence-of and routes-to all other bmx7 nodes in
the network.


### Monitoring bmx7 ###

To access debug and status information of a running bmx7 daemon, a
second bmx7 process can be launched in client mode (with the
`--connect` or `-c` parameter) to connect to the main bmx7 daemon and
retrieve the desired information.

In the following, a few example will be discussed. Continuous debug levels with different verbosity and scope are accessible with the `--debug` or `-d` parameter.

* Debug level 0 only reports critical events
* Debug level 3 reports relevant changes and
* Debug level 4 reports everything.
* Debug level 12 dump in and outgoing protocol traffic

For example, `bmx7 -cd3` runs a bmx7 client process at debug level 3,
connected to the main daemon and logs the output to stdout until
terminated with `ctrl-c`.

Status, network, and statistic information are also accessible via
their own parameters:

* `parameters`
* `status`
* `interfaces`
* `links`
* `originators`
* `descriptions`, plus optional sub-parameters for filtering
* `tunnels` (only with bmx7_tun.so plugin)
* `traffic=DEV` where DEV:=`all`, `eth1`, etc.


<pre>
root@mlc1001:~# bmx7 -c show=status
STATUS:
shortId  name    nodeKey cv revision primaryIp                              tun6Address         tun4Address  uptime     cpu txQ  nbs rts nodes
01662D16 mlc1001 RSA2048 21 0abee1e  fd70:166:2d16:1ff6:253f:d0bc:1558:d89a 2013:0:0:1001::1/64 10.20.1.1/24 0:00:11:43 0.1 4/50 2   9   10/10
</pre>

As can be seen, the status reveals:
* shortId: the short form of the node's [Global ID](wiki#global-id)
* name: the hostname of the node
* nodeKey: the key type and strength of its public RSA key
* cv: compatibility version
* revision: the git revision of the used source code
* primaryIP: its primary cryptographically generated IPv6 address
* uptime: the time since when it is running
* cpu: its current cpu consumption (0.1%)
* nbs: the number of neighbors perceived by this node
* rts: the number of routes to other nodes
* nodes: the total number of known and fully resolved nodes (including itself)

These desired types can be combined. Also the above given example shows kind of shortcut.
The long argument would be:
`bmx7 connect show=status`. A more informative case using the long form would be:

<pre>
root@mlc1001:~# bmx7 -c parameters show=status show=interfaces show=links show=originators show=tunnels
PARAMETERS:
 plugin                 bmx7_config.so       (0)
 plugin                 bmx7_sms.so          (0)
 plugin                 bmx7_tun.so          (0)
 plugin                 bmx7_topology.so     (0)
 plugin                 bmx7_table.so        (0)
 dev                    eth1                 (0)
 dev                    eth2                 (0)
 unicastHna             2013:0:0:1001::/64   (0)
 tunDev                 default              (0)
    /tun4Address        10.20.1.1/24         (0)
    /tun6Address        2013:0:0:1001::1/64  (0)
 tunOut                 ip6                  (0)
    /network            2013::/16            (0)
 tunOut                 ip4                  (0)
    /network            10.20.0.0/16         (0)
STATUS:
shortId  name    nodeKey cv revision primaryIp                              tun6Address         tun4Address  uptime     cpu txQ  nbs rts nodes
01662D16 mlc1001 RSA2048 21 e2bd709  fd70:166:2d16:1ff6:253f:d0bc:1558:d89a 2013:0:0:1001::1/64 10.20.1.1/24 0:00:03:34 0.2 0/50 2   9   10/10
INTERFACES:
dev  state linkKey    linkKeys          type     channel rateMax idx localIp                     rts helloSqn rxBpP   txBpP
eth1 UP    DH2048M112 RSA896,DH2048M112 ethernet 0       1000M   1   fe80::a2cd:efff:fe10:101/64 9   39457    382/2.6 217/1.3
eth2 UP    DH2048M112 RSA896,DH2048M112 ethernet 0       1000M   2   fe80::a2cd:efff:fe10:102/64 0   9120     0/0.0   136/1.3
LINKS:
shortId  name    linkKey    linkKeys          nbLocalIp                dev  rts rq  tq  rxRate txRate wTxRate mcs sgi chw wSnr
2ECE1A4E mlc1000 DH2048M112 RSA896,DH2048M112 fe80::a2cd:efff:fe10:1   eth1 1   100 100 1000M  1000M  -1      0   0   20  0
AAD9C0F5 mlc1002 DH2048M112 RSA896,DH2048M112 fe80::a2cd:efff:fe10:201 eth1 8   100 100 1000M  1000M  -1      0   0   20  0
ORIGINATORS:
shortId  name    as S s T t descSqn lastDesc descSize cv revision primaryIp                               dev  nbShortId nbName  metric hops ogmSqn lastRef
2ECE1A4E mlc1000 nA A A A A 612     212      733+784  21 e2bd709  fd70:2ece:1a4e:fa8e:fb9d:3b70:33e3:da00 eth1 2ECE1A4E  mlc1000 999M   1    36     0       
01662D16 mlc1001 nQ A A A A 612     213      733+784  21 e2bd709  fd70:166:2d16:1ff6:253f:d0bc:1558:d89a  ---  ---       ---     257G   0    36     0       
AAD9C0F5 mlc1002 nA A A A A 612     212      733+784  21 e2bd709  fd70:aad9:c0f5:8c20:a082:a462:a859:210d eth1 AAD9C0F5  mlc1002 999M   1    36     0       
DD57B855 mlc1003 pA A A A A 612     203      733+784  21 e2bd709  fd70:dd57:b855:3cdf:b057:10cc:2a93:c19  eth1 AAD9C0F5  mlc1002 706M   2    36     1       
369C6293 mlc1004 pA A A A A 612     200      733+784  21 e2bd709  fd70:369c:6293:4199:c156:3bb8:2c6a:e3aa eth1 AAD9C0F5  mlc1002 576M   3    36     1       
0BE5272C mlc1005 pA A A A A 612     200      733+784  21 e2bd709  fd70:be5:272c:703e:822a:e0c5:5d6c:587d  eth1 AAD9C0F5  mlc1002 495M   4    36     1       
DDC8E9EF mlc1006 pA A A A A 612     193      733+784  21 e2bd709  fd70:ddc8:e9ef:4ff0:385e:b034:6fd0:b5f  eth1 AAD9C0F5  mlc1002 443M   5    36     0       
6F59035D mlc1007 pA A A A A 612     188      733+784  21 e2bd709  fd70:6f59:35d:ae9b:1d55:3066:b3f9:74c7  eth1 AAD9C0F5  mlc1002 403M   6    36     0       
BF335A96 mlc1008 pA A A A A 612     178      733+784  21 e2bd709  fd70:bf33:5a96:889d:eedd:767b:6ca9:42fb eth1 AAD9C0F5  mlc1002 373M   7    36     0       
1191C909 mlc1009 pA A A A A 612     184      733+784  21 e2bd709  fd70:1191:c909:1e4e:4c9c:4d4a:33eb:b09b eth1 AAD9C0F5  mlc1002 349M   8    35     6       
</pre>

Only if relevant information exists for a requested type is available
is will be shown.  In this example no tunnels are configured locally
nor are any tunnels offered by other nodes, so no tunnel information
is shown.

The `loop` argument can be prepended to the connect argument to
continuously show the requested information.  Many of the long
arguments are available via a short notation, like `l` for `loop`, `c`
for `connect`, `s` for `show`, `d` for `debug`.  And there is another
shortcut summarizing my current favorite information types via debug
level 8 The following commands do the same as above: `bmx7 -lc status
interfaces links originators tunnels` or simply `bmx7 -lcd8`.

Description of selected section columns:

PARAMETERS section:

This section shows all configured parameters.
The value in braces indicates the default value for the given parameter or 0 if no default value exists.

INTERFACES section:

* dev: Interface name
* state and type: Whether the interface is UP or DOWN and its assumed link-layer type.
* rateMax: assumed maximum transmit rates for this interface.
* llocalIp: IPv6 link-local address (used as source address for all outgoing protocol data).
* rts: nuber of routes to other nodes via this interface
* rxBpP: received protocol data in Bytes per Packet per second via this interface
* txBpP: transmitted protocol data in Bytes per Packet per second via this interface

LINKS section:

* shortId and name of link neighbor
* linkKey and linkKeys show currently active and supported signature schemes for link verification
* nbLocalIp: Neighbors IPv6 link-local address
* dev: Interface via which this link is detected
* rts: Nuber of active routes to other nodes via this link
* rq: Measured receive rate in percent for the link.
* tq: Measured transmit rate in percent for the link.
* rxRate: Calculated receive rate in bps for the link.
* txRate: Calculated transmit rate in bps for the link.
* ...: More wireless channel statistics (if available)


ORIGINATORS section:

* shortId and name of node (originator)
* lastDesc: Seconds since the last description update was received
* primaryIp: The primary IP of that node.
* viaDev: Outgoing interface of the best route towards this node.
* metric: Calculated end to end path metric to this node
* lastRef: Seconds since this node was referenced by any neighboring node


Quick summary of provided info:

* Node mlc1001 uses two wired interface (eth1 and eth2) which is up and actively used for meshing.
* Node mlc1001 got aware of 2 neighbors and 10 nodes (originators) including itself.
* The link qualities (rx and tx rate) to its neighbors are perfect (100%)
* Routes to nodes mlc1000 and mlc1002 are via interface eth1 and directly to the neighbor's link-local address with a metric of 999M (nearly maximum tx/rx rate of the configured interface)
* Route to node mlc1003 is setup via interface eth1 and via the link-local address of neighbor mlc1002 (at least two hops to the destination node).

The following links of the total network topology can be guessed from this information (further links may exist):
<pre>
mlc1000 --- mlc1001 --- mlc1002 --- mlc1003 --- ... --- mlc1009
</pre>

### Simple Ping Test ###

This could be verified using traceroute6 towards the primary IP of the other nodes.

To mlc1000's primary IP fd66:66:66:0:a2cd:efff:fe10:1 shows one hop:

<pre>
root@mlc1001:~# traceroute6 -n -q 1 fd66:66:66:0:a2cd:efff:fe10:1
traceroute to fd66:66:66:0:a2cd:efff:fe10:1 (fd66:66:66:0:a2cd:efff:fe10:1), 30 hops max, 80 byte packets
 1  fd66:66:66:0:a2cd:efff:fe10:1  0.324 ms
</pre>

To mlc1002's primary IP fd66:66:66:0:a2cd:efff:fe10:201 shows one hop:

<pre>
root@mlc1001:~# traceroute6 -n -q 1 fd66:66:66:0:a2cd:efff:fe10:201
traceroute to fd66:66:66:0:a2cd:efff:fe10:201 (fd66:66:66:0:a2cd:efff:fe10:201), 30 hops max, 80 byte packets
 1  fd66:66:66:0:a2cd:efff:fe10:201  0.302 ms
</pre>

To mlc1003's primary IP fd66:66:66:0:a2cd:efff:fe10:301 shows two hops:

<pre>
root@mlc1001:~# traceroute6 -n -q 1 fd66:66:66:0:a2cd:efff:fe10:301
traceroute to fd66:66:66:0:a2cd:efff:fe10:301 (fd66:66:66:0:a2cd:efff:fe10:301), 30 hops max, 80 byte packets
 1  fd66:66:66:0:a2cd:efff:fe10:201  0.313 ms
 2  fd66:66:66:0:a2cd:efff:fe10:301  0.429 ms
</pre>

### Dynamic Reconfiguration ###

Most bmx7 parameters can be applied not only at startup, but also dynamically to an already running main daemon, using the `--connect` command.
For example interfaces can be added, removed, or specified with more details:
The following example removes interface eth1 and adds eth2 with a max rate of 100 Mbits (overwriting the default assumption of 1000Mbits for ethernet interfaces).

<pre>
bmx7 -c dev=-eth1 dev=eth2 /rateMax=100000
bmx7 -cd8
</pre>

Checking new status of interfaces, links, and originator:

<pre>
root@mlc1001:~# bmx7 -cd8
</pre>

It can be seen that:

* Interface eth1 has been replaced by eth2 with a lower rate.
* The old links (via eth1) are removed and a single new link via eth2 to mlc1000 has been detected
* All routes are now going via eth2


## Concepts ##

### Global ID ###

Each bmx7 node creates during its initialization (booting) a global ID
for itself.  This ID is created based on the public key which is also
created during the first launch of bmx7 and stored permanently in
/etc/bmx/rsa.der.

### Descriptions ###

Instead of propagating individual routing updates for each announced
network and interface address, each bmx7 daemon summarizes this and
other node-specific attributes into a node-specific description. A
specific description is propagated only once to all other
nodes. Subsequent routing updates are referencing to the corresponding
description with it's hash.  If a node is reconfigured, for example
because its interfaces change or a new network shall be announced,
than also the node's description changes.  Other nodes are becoming
aware of the changed attributes of a reconfigured node by receiving a
corresponding description update.  Subsequent references to this node
will use the hash of the new description.

Because the description is designed very generic it can be easily used
to piggyback other non-routing specific data. For example the bmx7-sms
plugin is taking advantage of this option by adding arbitrary short
messages data to the node's description.

### Blocked Nodes ###

Nodes may be blocked by other nodes.  When a node is blocked no
routing updates (OGMs) of the blocked node are propagated by the
blocking node.  The decision for blocking another node is done locally
based on the detection of more than one node announcing the same
unique resource.  This happens if two nodes are declaring themselves
as the owner of a unique resource. Then one of those two nodes
(usually the latter) is blocked to avoid the propagation of
conflicting allocations (and ambiguous forwarding state). Duplicate
address usage is the most common reason for such events which happens
if two nodes are using (and announcing) the same primary IPs.



## Address auto and manual configuration ##

By default bmx7 autoconfigures all configred interface by combining a default prefix (fd70::/16) with
the SHA224 hash of each nodes' public rsa key.



## Unicast Host Network Announcements (UHNA) ###

A Host Network Announcements (HNA) describes the advertisement of IP addresses and networks by a node to other nodes in the mesh.
Typically (but not with BMX7), several nodes can announce the same or overlapping HNAs at the same time.
Announced networks do overlap if they are equal or one being a subset of another (eg. 10.1.1.0/24 is a subset and overlapped by 10.1.0.0/16).
Packets with a destination address matching an announced networks will be routed toward any node that originated a corresponding HNA.
Therefore these HNA types may also be called anycast HNA.

In bmx7, HNAs have an unicast nature (UHNAs) because each network can only be announced once and announced networks MUST NOT overlap (See also Wiki).
This way it can be ensured that the destination of an UHNA routed packet is exactly known.

In a sense the origination and propagation (by intermediate nodes) of UHNA announcements can be thought of a promise that guarantees:
  1. All packets with a destination address matching an announced UHNA network will be routed exactly to the node (with the global ID) that originated the UHNA and
  2. each node on the forwarding path towards the originator of the UHNA is supporting this promise.

By default, Bmx7 only announces primary addresses via UHNAs.
The cryptographic address configuration ensures that interface addresses are unique.

Using UHNAs for the announcements of networks requires a strict coordination to ensure that no network is announced twice.

Technically, multiple UHNAs, each wrapped into a single message, are aggregated into a UHNA frame and attached to the description of a node.
Only IPv6 UHNAs can be announced.

The announcement of UHNAs can be configured with the `--unicastHna` or `-u` parameter followed by a network specification in ip/prefixlen notation.
By default all interface addresses are announced via UHNAs. However, this can be disabled by setting the `--dev` subparameter `/announce` or `/a` to 0.

The following example reconfigures an already running bmx7 daemon to UHNA announce the network fd00:ffff:ffff:ffff::/64 and fd01:ffff:ffff::/48.
By omitting the `--connect / -c` parameter, the same could be configured as startup parameter for bmx7.

<pre>
bmx7 -c u=fd00:ffff:ffff:ffff::/64 u=fd01:ffff:ffff::/48
</pre>

An already active announcement can be removed by preceeding the network with the `-` char:
<pre>
bmx7 -c u=-fd00:ffff:ffff:ffff::/64
</pre>

Before bmx7 accepts a dynamically configured UHNA announcement it checks if this UHNA is not overlapping with an already existing UHNA announcement form another node.
If this is the case the configuration will fail.
To check if a chain of dynamic commands would be accepted by a bmx7 daemon without actually applying it, the `--test` command may follow the `--connect` command.






## Tunnel Announcements ##

Tunnel announcements offer an alternative mechanism to propagate routes.
IPv6 and IPv4 networks can be announced.
In contrast to UHNAs, using tunnel announcements, the same or overlapping networks can be announced from different nodes. Tunnel announcements are an offer from the originating node to other nodes. Other nodes can take the offer or not. For example several nodes in a network may offer to share their DSL connection by doing a default-route (0.0.0.0/0 or ::/0) tunnel announcement.
Other nodes looking for a route to the internet (a default route) can choose between the multiple offers by establishing a tunnel to one specific of the offering nodes.
Therefore an unidirectional (onw-way) tunnel is established from the searching to the offering node.
At the searching node, the remote (outer) tunnel address is configured with an UHNA address (usually the primary address) of the offering node.
The networks advertised with the tunnel announcements are configured at the client side as routes via (into) the unidirectional tunnel.

This way, each node can make an individual choice between networks offered via tunnel announcements.
The automatic selection can be specified via a policy description that considers parameters such as advertised bandwidth, path metric, trust in specific GW nodes, hysteresis, ... .
Since an UHNA address is used as the outer (remote) tunnel address, the client end of the tunnel can be sure that all packets routed into the tunnel will indeed end up at the intended GW node (see Wiki).

Technically, multiple tunnel announcements, each wrapped into a single tun4/6in6-net message, are aggregated into a tun4/6in6-net frame and attached to the description of a node.

Tunnel announcements are also used for redistributing routes from other routing protocols (see Wiki) into a bmx7 zone.
Therefore, each announcements message is decorated with a route-type field indicating the routing protocol that exported the route for being redistributed.


### Tunnel requirements  ###

The following Linux-kernel modules are needed for tunnel-based overlay networking:
* ipv6
* tunnel6
* ip6_tunnel

### Tunnel Configuration and Debugging ###
In general, a specific tunnel configuration is described from two perspectives:

* Gateway (GW) nodes or just GWs are offering GW services to networks via the advertizement of tunnel announcements and the provisioning of tunnel-end-points.

* GW-client nodes (or just GW-clients) that are searching for GWs with tunnel endpoints and routing services to networks.

A node can (and usually is) operating in both modes (as GW and as GW-client).
But regarding a specific network each node is operating either in GW mode (thus, offering GW-services to that network) or in GW-client mode (thus, searching and using GW-services to that network)!

A quick and simple tunnel configuration example is given here.
Further details and options are described in the next Sections.
The full set of available options for configuring tunnels is given via the build-in --help and --verboseHelp commands

* First make your own tunnel addresses known and reachable for other nodes, eg:
`bmx7 -c tunDev=Default /tun4Address=10.254.10.123/32 /tun6Address=2012:1234:5678:123::1/64`

* Second, configure the automatic establishment of outgoing tunnels to other nodes by searching and selecting any kind of announcement:
`bmx7 -c tunOut=v4Default /network=0.0.0.0/0 tunOut=v6Default /network=::/0`

* Optionally, check the currently offered tunnel announcements of other GW nodes and the selected tunnel routes by this node with:
`bmx7 -c show=tunnels`


#### Tunnel Device Configuration ####

Operation in GW and/or GW-client mode implies the configuration of a bmx7 tunnel device and the IPv4 and/or IPv6 addresses that shall be used for tunnel traffic.
The selection of these addresses should be coordinated with:
* the mesh community because conflicting tunnel address usage will cause problems for the conflicting nodes
* GW administrators because (depending on the GW connection to other networks) only specific addresses may be routable and considered to be originated from the bmx7 cloud.

The command
<pre>
bmx7 -c tunDev=Default /tun4Address=10.254.10.123/32 /tun6Address=2012:1234:5678:123::1/64
</pre>
dynamically
* configures a linux ip4/6in6 tunnel device called bmxDefault (check it with command: ip link show).
* assignes the address `10.254.10.123` and `2012:1234:5678:123::1` to the tunnel interface and uses them for outgoing tunnel traffic.
* enables GW-mode for the specified networks: Makes a tunnel announcement so that other nodes can select it for tunneling packets to this node.

Now other nodes can send tunneled packets to this node via the unidirectional tunnel end point offered by this node.

But for bidirectional tunnel communication with any another node also a backwards tunnel is needed (an unidirectional tunnel from this node to the other node).

The automatic selection and establishment of tunnels to other nodes is achieved with the GW-client mode as described in more derail in the next Section.

#### Gateway-Client Nodes ####

The configuration of GW clients can be simple but also, depending on the preferences for a GW-selection policy, very complex.
Through the configuration of the mandatory tunDev and it's addresses (see above), each GW client node is also a GW node to its own (usually small) tunnel address space.

In the following simple example a GW-client node is searching for any other kind of offered IPv4 and v6 tunnels:
<pre>
bmx7 -c tunOut=v4Default /network=0.0.0.0/0 tunOut=v6Default /network=::/0
</pre>

With the above configured tunnel selection policy, tunnels are selected in the following order:
  1. prefix-length of announced tunnels (networks that are more specific than others).
  2. the resulting tunnelMetric (combination of the advertised bandwidth, path metric in the bmx7 cloud, and locally specified preferences like hysteresis or bonus)

The disadvantage of this simple config is that other nodes can easily redirect your tunnel selections
to specific networks by announcing more precise tunnel networks (larger prefix length).
To prevent this, the selection policy can be split into several and more precise search directives.

Imagine the following address assignment policy for IPv4 tunnel addresses in a mesh cloud (the general
idea can be straight translated to IPv6).

* Nodes in the mesh cloud announce their private and local address ranges with a prefix length of 24 and somewhere in the range of 10.254.0.0/16.

* Announcements of this type should always be preferred, even if any of the following announced types has a better end-to-end metric or more precise announcement.
<pre>
    bmx7 -c tunOut=v4Nodes /network=10.254.0.0/16 /minPrefixLen=24 /maxPrefixLen=24 /ipmetric=2001
</pre>

* Some BGP GW nodes are connected to other mesh clouds/areas of the same overall community network. These clouds are operating in a different IPv4 range (than 10.254.0.0/16) but always somewhere in the range of 10.0.0.0/8. Route announcements of this type should be preferred over the announcement of a default route.
<pre>
    bmx7 -c tunOut=v4Clouds /network=10.0.0.0/8 /maxPrefixLen=16 /bgp=1
</pre>

* Some DSL GW nodes are offering to share their DSL line and are announcing a default route (0.0.0.0/0).

* Further, to mitigate the effects of GW switching between GWs having a similar end-to-end metric a GW switch should only happen if the other GW is at least 30% better.
<pre>
    bmx7 -c tunOut=v4Default /network=0.0.0.0/0 /maxPrefixLen=0 /hysteresis=30 # refine the above configured v4 tunnel search
</pre>

* In case my node is directly connected to a DSL gateway and gets a automatically (dhcp) configured default route in the main routing table (use: ip route show table main ). then this route 
should be preferred and should NOT clash with default tunnel routes configured by bmx7.
* Therefore move all bmx7 tunnel routes to 0.0.0.0/0 into a separate routing table with lower lookup prioriy (check with: ip rule show; ip route show table 150)
<pre>
    bmx7 -c tunOut=v4Default /network=0.0.0.0/0 /maxPrefixLen=0 /hysteresis=30 /tableRule=50000/150 # again refine the above default search
</pre>

* The default route announcements from two well known GWs (with hostname pepe and paula) should be strictly preferred over unknown GWs.
* So, if available, move them to new table (with lower priority than main and higher priority than used for the backup tunnel rule configured above)
<pre>
    bmx7 -c tunOut=v4DefaultPepe  /network=0.0.0.0/0 /maxPrefixLen=0 /gwName=pepe  /hysteresis=30 /tableRule=40000/140
    bmx7 -c tunOut=v4DefaultPaula /network=0.0.0.0/0 /maxPrefixLen=0 /gwName=paula /hysteresis=30 /tableRule=40000/140
</pre>

* Finally, GW Paula turned out to be more stable. Therefore I want to prefer GW Paula over Pepe:
<pre>
    bmx7 -c tunOut=v4DefaultPaula /network=0.0.0.0/0 /maxPrefixLen=0 /gwName=paula /hysteresis=30 /bonus=100
</pre>

#### Gateway Nodes ####

The advertisement of a tunnel endpoint to a network can be configured with the --tunIn=<arbitrary name> and /network=<network> argument and an optional bandwidth specification (given as bits per second) using the /bandwidth or /b sub parameter.
Announcement can be removed by preceeding the name argument with a '-' char.
The following command dynamically configures the advertisement of the following routes:

* An IPv4 default route 0.0.0.0/0 with a bandwidth of 32 Mbps.
* A more specific route to 10.10.0.0/16 with a bandwidth of 10 Mbps (eg: a local v4 Network).
* An IPv6 route to the [RFC 4291] designated `2000::/3` global unicast address space with a bandwidth of 16 Mbps.
* A more specific route to the `2012:1234::/32` IPv6 space at 10 Mbps (eg: a local v6 Network).
<pre>
bmx7 -c tunIn=def4Offer /n=0.0.0.0/0 /b=32000000  tunIn=local4 /n=10.10.0.0/16 /b=10000000  tunIn=def6Offer /n=2000::/3 /b=16000000  tunIn=local6 /n=2012:1234::/32 /b=10000000
</pre>

#### Tunnel Status Information ####

Tunnel status information can be accessed with the `--tunnels or --show=tunnels` parameters.



## Bmx7 Plugins ##

### Compile and Install ###

To compile and install bmx7 daemon and all bmx7 plugins simply do:
<pre>
make build_all EXTRA_CFLAGS="-DTRAFFIC_DUMP -DCRYPTLIB=MBEDTLS_2_4_0"
sudo make install_all
</pre>

However. specific requirements may need to be fulfilled for some plugins in order to compile correctly.
These requirements are described in the corresponding plugin section.

### Config Plugin ###

#### Requirements ####

uci libs are needed for the bmx7-config plugin.
To install try (old version):
<pre>
wget http://downloads.openwrt.org/sources/uci-0.7.5.tar.gz
tar xzvf uci-0.7.5.tar.gz
cd uci-0.7.5
make clean all install WOPTS="-pedantic -Wall"
sudo make install
</pre>


#### Compile and Install ####
<pre>
make -C lib/bmx7_uci_config/
sudo make -C lib/bmx7_uci_config/ install
</pre>

#### Usage ####

### Json Plugin ###

#### Requirements ####

json-c for bmx_json plugin (debian package: libjson-c-dev)

json-c developer libs are needed!
For further reading check: http://json.org/ or https://github.com/jehiah/json-c


To install manually (only if NOT installed via debian or other package management system):
<pre>
wget http://ftp.de.debian.org/debian/pool/main/j/json-c/json-c_0.10.orig.tar.gz
tar xzvf json-c_0.10.orig.tar.gz
cd json-c..
./configure ; make ; make install; ldconfig
</pre>

#### Compile and Install ####

To compile and install only the bmx7 json plugins:
<pre>
make -C lib/bmx7_json/
sudo make -C lib/bmx7_json/ install
</pre>

#### Usage ####

### SMS Plugin ###

This plug-in uses routing packets to transmit any information from one node to the
whole network. The good point is that propagation works even if there is no continuous data-
path. Even though the WiFi network is under bad conditions (because the Wireless noise,
distance between nodes, etc...), the data will be propagated. The current implementation, by default, sets a maximum size limit of several KBytes for each file.

The API of the sms plug-in is very simple. It simply clones the content of one or more files
given by one node to all other nodes. All other nodes can do the same. Once started, each
node will have two directories:/var/run/bmx7/sms/rcvdSms and /var/run/bmx7/sms/sendSms. Files
put into the sendSms folder will be cloned to all other nodes inside rcvdSms folder.
Wireless-mesh distros are using this feature for several things such as positioning Map information or a chat in web interface.

### Table plugin ###

This plug-in can be used to automatically announce routes from specific routing tables.
For example to dynamically announce (redistribute) routes from another routing protocol.

#### Usage ####

To use the bmx7 table plugin it must be loaded during bmx7 daemon startup with the plugin=bmx7_table.so argument.
Alternatively a plugin section can be defined in the bmx7 config file like this:
<pre>
config 'plugin'
        option 'plugin' 'bmx7_table.so'
</pre>

Once the plugin is successfully loaded, the new parameters for redistributing routes from specific tables are enabled.

A full documentation of the table-related parameters is available via the --help and --verboseHelp /r=1 option.

#### Configuring route redistribution ####

Redistribution of routes is configurable with the `--redistTable` parameter.
Similar to the `--tunIn parameter, --redistTable` must be given with an arbitrary name for referencing to a specific redistribution directive and further sub-criterias.

Mandatary sub-criterias are /table and at least one route of the available types ( /kernel, /boot, /static )
Typical further but optional sub parameters are: /network, /minPrefixLen, /maxPrefixLen, /aggregatePrefixLen, /bandwidth
The following example automatically and dynamically announces (and removes announcements of) routes as they appear/disappear in routing table 100 and that match the criterias of:
* being a sub network of 192.168.0.0/16
* have a prefix length >= 24
* are configured as type kernel or boot
  (manually configured routes via the ip command will appear by default as type boot,
  eg: `ip r add 192.168.254.2/31 via 10.0.0.1 table 100`

If routes matching these criterias exist, then:
* They are announced with a bandwidth of 1Mbit
* Subsequent routes are aggregated down to a minimum prefix length of 24
<pre>
 bmx7 -c \
 redistTable            otherProtocol        \
    /network            192.168.0.0/16       \
    /table              100                  \
    /aggregatePrefixLen 24                   \
    /minPrefixLen       24                   \
    /kernel             1                    \
    /boot               1                    \
    /bandwidth          1000000
</pre>

