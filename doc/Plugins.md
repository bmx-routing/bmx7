## Intro 
BMX7 offers plugins which are used for the distribution of small files, settings up tunnels or offer stats of the network structure.

- To enable them run the bmx7 daemon like:
```
bmx7 --plugin=bmx7_{wanted-plugin}.so dev={yourDev}
```

- Available Plugins are:
	- dnsupdate
	- iwinfo
	- json
	- sms
	- table 
	- topology
	- tun 
	- uci-config

## Contents
*   [BMX7 Plugins](../src/lib)
    *   [Config Plugin](#config-plugin)
    *   [Json Plugin](#json-plugin)
    *   [SMS Plugin](#sms-plugin)
    *   [Table plugin](#table-plugin)

## Config Plugin

### Requirements

uci libs are needed for the bmx7-config plugin.
To install try (old version):
```
wget http://downloads.openwrt.org/sources/uci-0.7.5.tar.gz
tar xzvf uci-0.7.5.tar.gz
cd uci-0.7.5
make clean all install WOPTS="-pedantic -Wall"
sudo make install
```

### Compile and Install
```
make -C lib/bmx7_uci_config/
sudo make -C lib/bmx7_uci_config/ install
```

## Json Plugin

### Requirements

json-c for bmx_json plugin (debian package: libjson-c-dev)

json-c developer libs are needed!
For further reading check: http://json.org/ or https://github.com/jehiah/json-c

To install manually (only if NOT installed via debian or other package management system):
```
wget http://ftp.de.debian.org/debian/pool/main/j/json-c/json-c_0.10.orig.tar.gz
tar xzvf json-c_0.10.orig.tar.gz
cd json-c..
./configure ; make ; make install; ldconfig
```

### Compile and Install

To compile and install only the bmx7 json plugins:
```
make -C lib/bmx7_json/
sudo make -C lib/bmx7_json/ install
```

## SMS Plugin

This plug-in uses routing packets to transmit any information from one node to the
whole network. The good point is that propagation works even if there is no continuous data-
path. Even though the WiFi network is under bad conditions (because the Wireless noise,
distance between nodes, etc...), the data will be propagated. The current implementation, by default, sets a maximum size limit of several KBytes for each file.

The API of the sms plug-in is very simple. It simply clones the content of one or more files given by one node to all other nodes. All other nodes can do the same. Once started, each node will have two directories: `/var/run/bmx7/sms/rcvdSms` and `/var/run/bmx7/sms/sendSms`.

Files are cloned from the sendSms folder on the current node to the rcvdSmS folder on all other nodes with the syncSms option using the following steps

* Place (or link) files you want to send in `/var/run/bmx7/sms/sendSms`
* Use the `syncSms` option in BMX7 to send the file: `bmx7 -c syncSms="filename placed in the sendSms folder"`

Wireless-mesh distros are using this feature for several things such as positioning Map information or a chat in web interface.

## Table plugin

This plug-in can be used to automatically announce routes from specific routing tables.
For example to dynamically announce (redistribute) routes from another routing protocol.

### Usage

To use the bmx7 table plugin it must be loaded during bmx7 daemon startup with the plugin=bmx7_table.so argument.
Alternatively a plugin section can be defined in the bmx7 config file like this:
```
config 'plugin'
        option 'plugin' 'bmx7_table.so'
```

Once the plugin is successfully loaded, the new parameters for redistributing routes from specific tables are enabled.

A full documentation of the table-related parameters is available via the --help and --verboseHelp /r=1 option.

### Configuring route redistribution 

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
