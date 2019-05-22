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


