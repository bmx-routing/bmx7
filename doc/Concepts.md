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

