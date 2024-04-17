# WiregGuard Secure Tunneling Plugin

## Setup
- Follow the [the official WireGuard installation documentation](https://www.wireguard.com/install/) for your target OS to add the iproute2 type wireguard interface capabilities
- Compile with the directive:
``` bash
make -C lib/bmx7_wg_tun/ install
```
(Might need sudo priviledges)
- Launch BMX7 with the command
```bash
bmx7 --plugin bmx7_wg_tun.so 
```
- Monitor your instance with 
```bash
bmx7 -c wg_status
```

## Developer Documentation

- The approach follows the BMX7 style for a plugin integrated as a shared library in the BMX7 ecosystem.
- For WireGuard capabilities, the [embeddable_wg library](https://github.com/WireGuard/WireGuard/tree/master/contrib/examples/embeddable-wg-library) has been chosen to make functionalities native and reduce overhead over the other potential approach of wrapping userland calls.
- The current approach uses a single wg device that can take many peers
- Also, the current approach adds every BMX7-WG neighbor found as a peer (autoconfiguration).
- The description fields of WG_TUN as seen are piggybagged into every BMX7 description and contain all the info needed for our device to be used as a peer by another device
- The crypto address of a WG Device is a combination of **fd77** which has been chosen as a unique identifier and the **first 14 bytes of the SHA224 hash of the node** same as the standard crypto addresses of bmx7 (starting with fd70::).


### Testing
There are two options when it comes to testing:
- Either use [Mesh Linux Containers](https://github.com/axn/mlc),
- Or setup two Linux (most preferably Debian) machines and compile/run bmx7 with wg_tun plugin.

** Current work is still under development and considered WIP **

