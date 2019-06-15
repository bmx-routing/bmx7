# Usage

## Contents
   * [Intro](#intro)
   * [Monitoring bmx7](#monitoring-bmx7)
   * [Simple Ping Test](#simple-ping-test)
   * [Dynamic Reconfiguration](#dynamic-reconfiguration)
   * [Address Auto & Manual Configuration](#address-auto-and-manual-configuration)
   * [UHNAs](#unicast-host-network-announcements)

## Starting

In the most simple configuration, the only required parameter are the interfaces names that should be used for meshing.
The following example starts bmx7 on interface wlan0:
```
root@mlc1001:~# bmx7 dev=eth1
```

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
  a wireless mesh setup: ```iwconfig wlan0 mode ad-hoc ap 02:ca:ff:ee:ba:be channel 11 essid my-mesh-network```

* Bmx7 (by default) works in daemon mode, thus sends itself to
  background and gives back a prompt. To let it run in foreground
  specify a debug level with the startup command like:
  ``` bmx7 debug=0 dev=eth1 ```
  Of course, you may need to kill a previously
  started bmx7 daemon beforehand (`killall bmx7`)

If everything went fine bmx7 is running now, searches for neighboring
bmx7 daemons via the configured interface (link), and coordinates with
them to learn about existence-of and routes-to all other bmx7 nodes in
the network.


## Monitoring bmx7

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


```
root@mlc1001:~# bmx7 -c show=status
STATUS:
shortId  name    nodeKey cv revision primaryIp                              tun6Address         tun4Address  uptime     cpu txQ  nbs rts nodes
01662D16 mlc1001 RSA2048 21 0abee1e  fd70:166:2d16:1ff6:253f:d0bc:1558:d89a 2013:0:0:1001::1/64 10.20.1.1/24 0:00:11:43 0.1 4/50 2   9   10/10
```

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

```
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
```

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
```
mlc1000 --- mlc1001 --- mlc1002 --- mlc1003 --- ... --- mlc1009
```

## Simple Ping Test

This could be verified using traceroute6 towards the primary IP of the other nodes.

To mlc1000's primary IP fd66:66:66:0:a2cd:efff:fe10:1 shows one hop:

```
root@mlc1001:~# traceroute6 -n -q 1 fd66:66:66:0:a2cd:efff:fe10:1
traceroute to fd66:66:66:0:a2cd:efff:fe10:1 (fd66:66:66:0:a2cd:efff:fe10:1), 30 hops max, 80 byte packets
 1  fd66:66:66:0:a2cd:efff:fe10:1  0.324 ms
```

To mlc1002's primary IP fd66:66:66:0:a2cd:efff:fe10:201 shows one hop:

```
root@mlc1001:~# traceroute6 -n -q 1 fd66:66:66:0:a2cd:efff:fe10:201
traceroute to fd66:66:66:0:a2cd:efff:fe10:201 (fd66:66:66:0:a2cd:efff:fe10:201), 30 hops max, 80 byte packets
 1  fd66:66:66:0:a2cd:efff:fe10:201  0.302 ms
```

To mlc1003's primary IP fd66:66:66:0:a2cd:efff:fe10:301 shows two hops:

```
root@mlc1001:~# traceroute6 -n -q 1 fd66:66:66:0:a2cd:efff:fe10:301
traceroute to fd66:66:66:0:a2cd:efff:fe10:301 (fd66:66:66:0:a2cd:efff:fe10:301), 30 hops max, 80 byte packets
 1  fd66:66:66:0:a2cd:efff:fe10:201  0.313 ms
 2  fd66:66:66:0:a2cd:efff:fe10:301  0.429 ms
```

## Dynamic Reconfiguration

Most bmx7 parameters can be applied not only at startup, but also dynamically to an already running main daemon, using the `--connect` command.
For example interfaces can be added, removed, or specified with more details:
The following example removes interface eth1 and adds eth2 with a max rate of 100 Mbits (overwriting the default assumption of 1000Mbits for ethernet interfaces).

```
bmx7 -c dev=-eth1 dev=eth2 /rateMax=100000
bmx7 -cd8
```

Checking new status of interfaces, links, and originator:

```
root@mlc1001:~# bmx7 -cd8
```

It can be seen that:

* Interface eth1 has been replaced by eth2 with a lower rate.
* The old links (via eth1) are removed and a single new link via eth2 to mlc1000 has been detected
* All routes are now going via eth2


## Address auto and manual configuration

By default bmx7 autoconfigures all configred interface by combining a default prefix (fd70::/16) with
the SHA224 hash of each nodes' public rsa key.



## Unicast Host Network Announcements

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

```
bmx7 -c u=fd00:ffff:ffff:ffff::/64 u=fd01:ffff:ffff::/48
```

An already active announcement can be removed by preceeding the network with the `-` char:
```
bmx7 -c u=-fd00:ffff:ffff:ffff::/64
```

Before bmx7 accepts a dynamically configured UHNA announcement it checks if this UHNA is not overlapping with an already existing UHNA announcement form another node.
If this is the case the configuration will fail.
To check if a chain of dynamic commands would be accepted by a bmx7 daemon without actually applying it, the `--test` command may follow the `--connect` command.





