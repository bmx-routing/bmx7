# Tunnel Announcements #
Tunnel announcements offer an alternative mechanism to propagate routes.  
IPv6 and IPv4 networks can be announced.  

## Content
*   [Overview](#overview)
    *   [Requirements](#requirements)
*   [Configuration and Debugging](#configuration-and-debugging)
    *   [Device Configuration](#device-configuration)
    *   [Gateway Nodes](#gateway-nodes)
    *   [Route Redistribution](#route-redistribution)

## Overview


In contrast to UHNAs, using Tunnel Announcements, the same or overlapping networks can be announced from different nodes. 
  - Tunnel announcements are an offer from the originating node to other nodes. 
  - Other nodes can take the offer or not. 
  - For example, several nodes in a network may offer to share their DSL connection by doing a default-route   
    (0.0.0.0/0 or ::/0) tunnel announcement.  

Other nodes looking for a route to the internet (a default route) can choose between the multiple offers by establishing a tunnel to one specific of the offering nodes.  

Therefore, an unidirectional (one-way) tunnel is established from the searching to the offering node.  

At the searching node, the remote (outer) tunnel address is configured with an UHNA address (usually the primary address) of the offering node.  

The networks advertised with the tunnel announcements are configured at the client side as routes via (into) the unidirectional tunnel.

This way, each node can make an individual choice between networks offered via tunnel announcements.
The automatic selection can be specified via a policy description that considers parameters such as advertised bandwidth, path metric, trust in specific GW nodes, hysteresis, ... .  

Since an UHNA address is used as the outer (remote) tunnel address, the client end of the tunnel can be sure that all packets routed into the tunnel will indeed end up at the intended GW node (see Wiki).

Technically, multiple tunnel announcements, each wrapped into a single tun4/6in6-net message, are aggregated into a tun4/6in6-net frame and attached to the description of a node.

Tunnel announcements are also used for redistributing routes from other routing protocols (see Wiki) into a bmx7 zone.  

Therefore, each announcements message is decorated with a route-type field indicating the routing protocol that exported the route for being redistributed.


### Requirements 

The following Linux-kernel modules are needed for tunnel-based overlay networking:
* ipv6
* tunnel6
* ip6_tunnel

## Configuration and Debugging
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

* Tunnel status information can be accessed with the `--tunnels or --show=tunnels` parameters.


### Device Configuration

Operation in GW and/or GW-client mode implies the configuration of a bmx7 tunnel device and the IPv4 and/or IPv6 addresses that shall be used for tunnel traffic.
The selection of these addresses should be coordinated with:
* the mesh community because conflicting tunnel address usage will cause problems for the conflicting nodes
* GW administrators because (depending on the GW connection to other networks) only specific addresses may be routable and considered to be originated from the bmx7 cloud.

The command
```
bmx7 -c tunDev=Default /tun4Address=10.254.10.123/32 /tun6Address=2012:1234:5678:123::1/64
```
dynamically
* configures a linux ip4/6in6 tunnel device called bmxDefault (check it with command: ip link show).
* assignes the address `10.254.10.123` and `2012:1234:5678:123::1` to the tunnel interface and uses them for outgoing tunnel traffic.
* enables GW-mode for the specified networks: Makes a tunnel announcement so that other nodes can select it for tunneling packets to this node.

Now other nodes can send tunneled packets to this node via the unidirectional tunnel end point offered by this node.

But for bidirectional tunnel communication with any another node also a backwards tunnel is needed (an unidirectional tunnel from this node to the other node).

The automatic selection and establishment of tunnels to other nodes is achieved with the GW-client mode as described in more derail in the next Section.

## Gateway-Client Nodes

The configuration of GW clients can be simple but also, depending on the preferences for a GW-selection policy, very complex.
Through the configuration of the mandatory tunDev and it's addresses (see above), each GW client node is also a GW node to its own (usually small) tunnel address space.

In the following simple example a GW-client node is searching for any other kind of offered IPv4 and v6 tunnels:
```
bmx7 -c tunOut=v4Default /network=0.0.0.0/0 tunOut=v6Default /network=::/0
```

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
```
    bmx7 -c tunOut=v4Nodes /network=10.254.0.0/16 /minPrefixLen=24 /maxPrefixLen=24 /ipmetric=2001
```

* Some BGP GW nodes are connected to other mesh clouds/areas of the same overall community network. These clouds are operating in a different IPv4 range (than 10.254.0.0/16) but always somewhere in the range of 10.0.0.0/8. Route announcements of this type should be preferred over the announcement of a default route.
```
    bmx7 -c tunOut=v4Clouds /network=10.0.0.0/8 /maxPrefixLen=16 /bgp=1
```

* Some DSL GW nodes are offering to share their DSL line and are announcing a default route (0.0.0.0/0).

* Further, to mitigate the effects of GW switching between GWs having a similar end-to-end metric a GW switch should only happen if the other GW is at least 30% better.
```
    bmx7 -c tunOut=v4Default /network=0.0.0.0/0 /maxPrefixLen=0 /hysteresis=30 # refine the above configured v4 tunnel search
```

* In case my node is directly connected to a DSL gateway and gets a automatically (dhcp) configured default route in the main routing table (use: ip route show table main ). then this route 
should be preferred and should NOT clash with default tunnel routes configured by bmx7.
* Therefore move all bmx7 tunnel routes to 0.0.0.0/0 into a separate routing table with lower lookup prioriy (check with: ip rule show; ip route show table 150)
```
    bmx7 -c tunOut=v4Default /network=0.0.0.0/0 /maxPrefixLen=0 /hysteresis=30 /tableRule=50000/150 # again refine the above default search
```

* The default route announcements from two well known GWs (with hostname pepe and paula) should be strictly preferred over unknown GWs.
* So, if available, move them to new table (with lower priority than main and higher priority than used for the backup tunnel rule configured above)
```
    bmx7 -c tunOut=v4DefaultPepe  /network=0.0.0.0/0 /maxPrefixLen=0 /gwName=pepe  /hysteresis=30 /tableRule=40000/140
    bmx7 -c tunOut=v4DefaultPaula /network=0.0.0.0/0 /maxPrefixLen=0 /gwName=paula /hysteresis=30 /tableRule=40000/140
```

* Finally, GW Paula turned out to be more stable. Therefore I want to prefer GW Paula over Pepe:
```
    bmx7 -c tunOut=v4DefaultPaula /network=0.0.0.0/0 /maxPrefixLen=0 /gwName=paula /hysteresis=30 /bonus=100
```

### Gateway Nodes

The advertisement of a tunnel endpoint to a network can be configured with the --tunIn=<arbitrary name> and /network=<network> argument and an optional bandwidth specification (given as bits per second) using the /bandwidth or /b sub parameter.
Announcement can be removed by preceeding the name argument with a '-' char.
The following command dynamically configures the advertisement of the following routes:

* An IPv4 default route 0.0.0.0/0 with a bandwidth of 32 Mbps.
* A more specific route to 10.10.0.0/16 with a bandwidth of 10 Mbps (eg: a local v4 Network).
* An IPv6 route to the [RFC 4291] designated `2000::/3` global unicast address space with a bandwidth of 16 Mbps.
* A more specific route to the `2012:1234::/32` IPv6 space at 10 Mbps (eg: a local v6 Network).
```
bmx7 -c tunIn=def4Offer /n=0.0.0.0/0 /b=32000000  tunIn=local4 /n=10.10.0.0/16 /b=10000000  tunIn=def6Offer /n=2000::/3 /b=16000000  tunIn=local6 /n=2012:1234::/32 /b=10000000
```

### Route Redistribution

Redistribution of routes is configurable with the `--redistTable` parameter.
Similar to the `--tunIn parameter, --redistTable` must be given with an arbitrary name for referencing to a specific redistribution directive and further sub-criterias.

Mandatory sub-criterias are /table and at least one route of the available types ( /kernel, /boot, /static )
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
```
 bmx7 -c \
 redistTable            otherProtocol        \
    /network            192.168.0.0/16       \
    /table              100                  \
    /aggregatePrefixLen 24                   \
    /minPrefixLen       24                   \
    /kernel             1                    \
    /boot               1                    \
    /bandwidth          1000000
```

