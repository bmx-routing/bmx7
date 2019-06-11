# Installation
```
sudo apt-get install libjson0 libjson0-dev
```
or download sources from: wget http://ftp.de.debian.org/debian/pool/main/j/json-c/json-c_0.9.orig.tar.gz

```
tar xzvf json-c_0.9.orig.tar.gz
cd json-c..
./configure ; make ; make install; ldconfig
```

- For quick introduction into JSON syntax see: http://www.json.org/


- The bmx7_json.so plugin is primarily meant to provide status information of a running BMX7 daemon in a JSON formatted syntax.  

__Depending on durability of the type of available information it is generated proactively or reactively.__


#### Non-durable information:

The following status information is created reactively by calling one of the following commands:
--json-status
--json-interfaces
--json-links
--json-originators

Detailed examples are given below.


#### Durable information:
The following information is created proactively as soon as it becomes available.
The information is stored in various files and directories in the json subdirectory in the bmx7 runtime-dir.
By default the bmx7 runtime-dir is set to /var/run/bmx7
The plugin maintains the following files in the json subdirectory of the bmx7 runtime-dir.

options  
     This FILE provides a detailed description of all available bmx7 configuration options and its 
     attributes (like default/min/max values, help, syntax).
parameters 
     This FILE provides a detailed summary of the daemons current configuration
descriptions 
     This DIRECTORY holds one file for each currently active node in the network, 
     describing the attributes (like IP addresses, hostname, IDs,...) of each node respectively.

Detailed examples are given below.


#### Non-durable information (detailed examples):
```
mlc115:~# bmx7 -c json-status
{ "status": { "version": "BMX6-0.1-alpha", "compatibility": 14, "codeVersion": 5, "globalId": "mlc115.5B1116F69452328AAFE0", "primaryIp": "fd02::a0cd:ef00:7301:0:1", "uptime": "0:00:00:39", "cpu": "0.1", "nodes": 15 } }

mlc115:~# bmx7 -c json-interfaces
{ "interfaces": [
                  { "devName": "eth1.12", "state": "UP", "type": "ethernet", "rateMin": "1000M", "rateMax": "1000M", "llocalIp": "fe80::a2cd:efff:fe00:7301\/64", "globalIp": "fd02::a0cd:ef00:7301:0:1\/96", "multicastIp": "ff02::2", "primary": 1 },
                  { "devName": "eth2.12", "state": "UP", "type": "ethernet", "rateMin": "1000M", "rateMax": "1000M", "llocalIp": "fe80::a2cd:efff:fe00:7302\/64", "globalIp": "fd02::a0cd:ef00:7302:0:1\/96", "multicastIp": "ff02::2", "primary": 0 }
                ]
}

mlc115:~# bmx7 -c json-links
{ "links": [
             { "globalId": "mlc116.65A370182BEFDF5E702E", "llocalIp": "fe80::a2cd:efff:fe00:7401", "viaDev": "eth1.12", "rxRate": 100, "txRate": 100, "routes": 4, "wantsOgms": 1 },
             { "globalId": "mlc125.3681CBE838DBFD492E32", "llocalIp": "fe80::a2cd:efff:fe00:7d01", "viaDev": "eth1.12", "rxRate": 100, "txRate": 100, "routes": 1, "wantsOgms": 1 },
             { "globalId": "mlc114.D5A250E3A8DA07E65CE5", "llocalIp": "fe80::a2cd:efff:fe00:7201", "viaDev": "eth1.12", "rxRate": 100, "txRate": 100, "routes": 8, "wantsOgms": 1 },
             { "globalId": "mlc105.560B8EABCF091C3FB9CA", "llocalIp": "fe80::a2cd:efff:fe00:6901", "viaDev": "eth1.12", "rxRate": 100, "txRate": 100, "routes": 2, "wantsOgms": 1 }
           ]
}


mlc115:~# bmx7 -c json-originators
{ "originators": [
                   { "globalId": "mlc103.173A43BE22C3F14D077C", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:6701:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:7201", "viaDev": "eth1.12", "metric": "576M", "lastDesc": 108, "lastRef": 3 },
                   { "globalId": "mlc104.0EC109E295B0C13145D5", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:6801:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:7201", "viaDev": "eth1.12", "metric": "709M", "lastDesc": 108, "lastRef": 3 },
                   { "globalId": "mlc105.560B8EABCF091C3FB9CA", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:6901:0:1", "routes": 1, "viaIp": "fe80::a2cd:efff:fe00:6901", "viaDev": "eth1.12", "metric": "999M", "lastDesc": 108, "lastRef": 0 },
                   { "globalId": "mlc106.7AFB3B48A90D813DB92E", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:6a01:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:6901", "viaDev": "eth1.12", "metric": "709M", "lastDesc": 107, "lastRef": 2 },
                   { "globalId": "mlc107.86ABA478A4DCC6368F0C", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:6b01:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:6901", "viaDev": "eth1.12", "metric": "576M", "lastDesc": 108, "lastRef": 2 },
                   { "globalId": "mlc113.38B890A127F937D3B53F", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7101:0:1", "routes": 1, "viaIp": "fe80::a2cd:efff:fe00:7201", "viaDev": "eth1.12", "metric": "709M", "lastDesc": 106, "lastRef": 1 },
                   { "globalId": "mlc114.D5A250E3A8DA07E65CE5", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7201:0:1", "routes": 1, "viaIp": "fe80::a2cd:efff:fe00:7201", "viaDev": "eth1.12", "metric": "999M", "lastDesc": 111, "lastRef": 0 },
                   { "globalId": "mlc115.5B1116F69452328AAFE0", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7301:0:1", "routes": 0, "viaIp": "::", "viaDev": "", "metric": "128G", "lastDesc": 112, "lastRef": 0 },
                   { "globalId": "mlc116.65A370182BEFDF5E702E", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7401:0:1", "routes": 1, "viaIp": "fe80::a2cd:efff:fe00:7401", "viaDev": "eth1.12", "metric": "999M", "lastDesc": 111, "lastRef": 0 },
                   { "globalId": "mlc117.CD73F593835D43750AC4", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7501:0:1", "routes": 1, "viaIp": "fe80::a2cd:efff:fe00:7401", "viaDev": "eth1.12", "metric": "709M", "lastDesc": 106, "lastRef": 1 },
                   { "globalId": "mlc123.9B3317729F5EFBF44C6D", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7b01:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:7201", "viaDev": "eth1.12", "metric": "576M", "lastDesc": 109, "lastRef": 5 },
                   { "globalId": "mlc124.B5BDD2917537982A4CC0", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7c01:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:7201", "viaDev": "eth1.12", "metric": "709M", "lastDesc": 109, "lastRef": 0 },
                   { "globalId": "mlc125.3681CBE838DBFD492E32", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7d01:0:1", "routes": 1, "viaIp": "fe80::a2cd:efff:fe00:7d01", "viaDev": "eth1.12", "metric": "999M", "lastDesc": 109, "lastRef": 0 },
                   { "globalId": "mlc126.A57873C9302DD4923281", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7e01:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:7401", "viaDev": "eth1.12", "metric": "709M", "lastDesc": 110, "lastRef": 4 },
                   { "globalId": "mlc127.F48C1A9DE327156645D7", "blocked": 0, "primaryIp": "fd02::a0cd:ef00:7f01:0:1", "routes": 2, "viaIp": "fe80::a2cd:efff:fe00:7401", "viaDev": "eth1.12", "metric": "576M", "lastDesc": 109, "lastRef": 4 },
                 ]
}
```

#### Durable information (detailed examples):
```
mlc115:~# ls -l /var/run/bmx7/json/
total 20
drwxr-xr-x 2 root root  4096 May 23 05:53 descriptions
-rw-r--r-- 1 root root 10208 May 22 18:31 options
-rw-r--r-- 1 root root   426 May 22 18:33 parameters
```
```
mlc115:~# cat /var/run/bmx7/json/options
{ "OPTIONS": [
               { "name": "help", "help": "summarize help" },
               { "name": "verboseHelp", "help": "show help" },
               { "name": "extraHelp", "help": "summarize advanced and experimental options" },
               { "name": "verboseExtraHelp", "help": "show advanced and experimental options" },
               { "name": "test", "help": "test remaining args and provide feedback about projected success (without applying them)" },
               { "name": "noFork", "min": 0, "max": 12, "def": -1, "syntax": "<VAL>", "help": "print debug information instead of forking to background\n" },
               { "name": "debug", "min": 0, "max": 12, "def": -1, "syntax": "<VAL>", "help": "show debug information:\n\t 0  : system\n\t 3  : changes\n\t 4  : verbose changes (depends on -DNO_DEBUG_ALL)\n\t 5  : profiling (depends on -DNO_DEBUG_MALLOC -DNO_MEMORY_USAGE -DPROFILE_DATA)\n\t 8  : details\n\t11  : testing       12  : traffic dump" },
               { "name": "configFile", "def": "\/etc\/config\/bmx7", "syntax": "<FILE>", "help": "use non-default config file. If defined, this must be the first given option.\n\tuse --configFile=0 or -f0 to disable" },
               { "name": "configReload", "help": "dynamically reload config file" },
               { "name": "runtimeDir", "def": "\/var\/run\/bmx7", "syntax": "<DIRECTORY>", "help": "set runtime DIR of pid, sock, ... - default: \/var\/run\/bmx7 (must be defined before --connect)." },
               { "name": "plugin", "syntax": "<FILE>", "help": "load plugin. <FILE> must be in LD_LIBRARY_PATH or BMX6_LIB_PATH\n\tpath (e.g. --plugin bmx7_howto_plugin.so )\n" },
               { "name": "loop_mode", "help": "put client daemon in loop mode to periodically refresh debug information" },
               { "name": "loop_interval", "min": 100, "max": 10000, "def": 1000, "syntax": "<VAL>", "help": "periodicity in ms with which client daemon in loop-mode refreshes debug information" },
               { "name": "connect", "help": "set client mode. Connect and forward remaining args to main routing daemon" },
               { "name": "ipVersion", "min": 4, "max": 6, "def": 4, "syntax": "<VAL>", "help": "select ip protocol Version 4 or 6", "CHILD_OPTIONS": [ { "name": "policyRouting", "min": 0, "max": 1, "def": 1, "syntax": "<VAL>", "help": "disable policy routing (throw and priority rules)" },
               { "name": "throwRules", "min": 0, "max": 1, "def": 1, "syntax": "<VAL>", "help": "disable\/enable default throw rules" },
               { "name": "prioRules", "min": 0, "max": 1, "def": 1, "syntax": "<VAL>", "help": "disable\/enable default priority rules" },
               { "name": "preference", "min": 3, "max": 32765, "def": 6000, "syntax": "<VAL>", "help": "specify iprout2 rule preference offset" },
               { "name": "table", "min": 0, "max": 32000, "def": 60, "syntax": "<VAL>", "help": "specify iprout2 table offset" } ] },
               { "name": "lo_rule", "min": 0, "max": 1, "def": 1, "syntax": "<VAL>", "help": "disable\/enable autoconfiguration of lo rule" },
               { "name": "parameters", "help": "show configured parameters" },
               { "name": "dbg_mute_timeout", "min": 0, "max": 10000000, "def": 100000, "syntax": "<VAL>", "help": "set timeout in ms for muting frequent messages" },
               { "name": "quit" },
               { "name": "globalPrefix", "syntax": "<NETADDR>\/<PREFIX-LENGTH>", "help": "specify global prefix for interfaces" },
               { "name": "llocalPrefix", "syntax": "<NETADDR>\/<PREFIX-LENGTH>", "help": "specify link-local prefix for interfaces" },
               { "name": "dev", "syntax": "<interface-name>", "help": "add or change interface device or its configuration", "CHILD_OPTIONS": [ { "name": "announce", "min": 0, "max": 1, "def": 1, "syntax": "<VAL>", "help": "disable\/enable announcement of interface IP" },
               { "name": "linklayer", "min": 0, "max": 2, "def": 0, "syntax": "<VAL>", "help": "manually set device type for linklayer specific optimization (1=lan, 2=wlan)" },
               { "name": "globalPrefix", "syntax": "<VAL>", "help": "specify global prefix for interface" },
               { "name": "llocalPrefix", "syntax": "<VAL>", "help": "specify global prefix for interface" },
               { "name": "rateMax", "syntax": "<VAL>", "help": "set maximum bandwidth as bits\/sec of dev" },
               { "name": "rateMax", "syntax": "<VAL>", "help": "set maximum bandwidth as bits\/sec of dev" } ] },
               { "name": "pedanticCleanup", "min": 0, "max": 1, "def": 0, "syntax": "<VAL>", "help": "disable\/enable pedantic cleanup of system configuration (like ip_forward,..) \n\tat program termination. Its generally safer to keep this disabled to not mess up \n\twith other routing protocols" },
               { "name": "version", "help": "show version" },
               { "name": "status", "help": "show status\n" },
               { "name": "interfaces", "help": "show interfaces\n" },
               { "name": "links", "help": "show links\n" },
               { "name": "originators", "help": "show originators\n" },
               { "name": "ttl", "min": 1, "max": 63, "def": 50, "syntax": "<VAL>", "help": "set time-to-live (TTL) for OGMs" },
               { "name": "txInterval", "min": 35, "max": 10000, "def": 500, "syntax": "<VAL>", "help": "set aggregation interval (SHOULD be smaller than the half of your and others OGM interval)" },
               { "name": "ogmInterval", "min": 200, "max": 60000, "def": 5000, "syntax": "<VAL>", "help": "set interval in ms with which new originator message (OGM) are send" },
               { "name": "purgeTimeout", "min": 70000, "max": 864000000, "def": 100000, "syntax": "<VAL>", "help": "timeout in ms for purging stale originators" },
               { "name": "linkPurgeTimeout", "min": 20000, "max": 864000000, "def": 100000, "syntax": "<VAL>", "help": "timeout in ms for purging stale originators" },
               { "name": "dadTimeout", "min": 100, "max": 360000000, "def": 20000, "syntax": "<VAL>", "help": "duplicate address (DAD) detection timout in ms" },
               { "name": "flush_all", "help": "purge all neighbors and routes on the fly" },
               { "name": "dropAllFrames", "min": 0, "max": 1, "def": 0, "syntax": "<VAL>", "help": "drop all received frames (but process packet header)" },
               { "name": "dropAllPackets", "min": 0, "max": 1, "def": 0, "syntax": "<VAL>", "help": "drop all received packets" },
               { "name": "configShow", "help": "show current config as it could be saved to configFile" },
               { "name": "udpDataSize", "min": 128, "max": 1400, "def": 512, "syntax": "<VAL>", "help": "set preferred udp-data size for send packets" },
               { "name": "ogmAdvSends", "min": 0, "max": 30, "def": 10, "syntax": "<VAL>", "help": "set maximum resend attempts for ogm aggregations" },
               { "name": "descUnsolicitedSends", "min": 0, "max": 1, "def": 1, "syntax": "<VAL>", "help": "send unsolicited description advertisements after receiving a new one" },
               { "name": "descReqSends", "min": 1, "max": 100, "def": 10, "syntax": "<VAL>", "help": "set tx iterations for description requests" },
               { "name": "descShaReqSends", "min": 1, "max": 100, "def": 10, "syntax": "<VAL>", "help": "set tx iterations for description-hash requests" },
               { "name": "descAdvSends", "min": 1, "max": 20, "def": 1, "syntax": "<VAL>", "help": "set tx iterations for descriptions" },
               { "name": "descShaAdvSends", "min": 1, "max": 100, "def": 1, "syntax": "<VAL>", "help": "set tx iterations for description hashes" },
               { "name": "ogmAckSends", "min": 0, "max": 4, "def": 1, "syntax": "<VAL>", "help": "set tx iterations for ogm acknowledgements" },
               { "name": "descriptions", "help": "show node descriptions\n", "CHILD_OPTIONS": [ { "name": "type", "min": 0, "max": 255, "def": 255, "syntax": "<TYPE>", "help": "show description extension(s) of given type (0..253=type 254=none 255=all) \n" },
               { "name": "name", "syntax": "<NAME>", "help": "only show description of nodes with given name" },
               { "name": "relevance", "syntax": "<VAL>", "help": "only show description with given relevance" } ] },
               { "name": "metricAlgo", "min": 0, "max": 16, "def": 16, "syntax": "<VAL>", "help": "set metric algo for routing towards myself:\n        0:HopCount  1:MP (M=1 \/R=0 \/T=1 \/t=1 <=> TQ) 2:EP  4:MB  8:EB (M=8 \/R=1 \/r=1 \/T=1 \/t=1 <=> ETT)  16:VB", "CHILD_OPTIONS": [ { "name": "rxExpNumerator", "min": 0, "max": 3, "def": 1, "syntax": "<VAL>", "help": " " },
               { "name": "rxExpDivisor", "min": 1, "max": 2, "def": 2, "syntax": "<VAL>", "help": " " },
               { "name": "txExpNumerator", "min": 0, "max": 3, "def": 1, "syntax": "<VAL>", "help": " " },
               { "name": "txExpDivisor", "min": 1, "max": 2, "def": 1, "syntax": "<VAL>", "help": " " } ] },
               { "name": "pathMetricMin", "min": 33, "max": 2147483647, "def": 33, "syntax": "<VAL>", "help": " " },
               { "name": "pathWindow", "min": 1, "max": 250, "def": 5, "syntax": "<VAL>", "help": "set path window size (PWS) for end2end path-quality calculation (path metric)" },
               { "name": "pathLounge", "min": 0, "max": 10, "def": 1, "syntax": "<VAL>", "help": "set default PLS buffer size to artificially delay my OGM processing for ordered path-quality calulation" },
               { "name": "pathRegression", "min": 1, "max": 255, "def": 1, "syntax": "<VAL>", "help": "set (slow) path regression " },
               { "name": "hopPenalty", "min": 0, "max": 255, "def": 0, "syntax": "<VAL>", "help": "penalize non-first rcvd OGMs in 1\/255 (each hop will substract metric*(VALUE\/255) from current path-metric)" },
               { "name": "linkWindow", "min": 1, "max": 128, "def": 48, "syntax": "<VAL>", "help": "set link window size (LWS) for link-quality calculation (link metric)" },
               { "name": "newRouterDismissal", "min": 0, "max": 200, "def": 99, "syntax": "<VAL>", "help": "dismiss new routers according to specified percentage" },
               { "name": "hna", "syntax": "<NETADDR>\/<PREFIX-LENGTH>", "help": "specify host-network announcement (HNA) for defined ip range" },
               { "name": "niitSource", "syntax": "<ADDRESS>", "help": "specify niit4to6 source IP address (IP MUST be assigned to niit4to6 interface!)" },
               { "name": "trafficRegressionExponent", "min": 0, "max": 20, "def": 4, "syntax": "<VAL>", "help": "set regression exponent for traffic-dump statistics " },
               { "name": "traffic", "syntax": "<DEV>", "help": "show traffic statistics for given device name, summary, or all\n" },
               { "name": "jsonSubdir", "def": "json", "syntax": "<DIRECTORY>", "help": "set json subdirectory withing runtime_dir (currently only default value allowed)" },
               { "name": "json_status", "help": "show status in json format\n" },
               { "name": "json_interfaces", "help": "show interfaces in json format\n" },
               { "name": "json_links", "help": "show links in json format\n" },
               { "name": "json_originators", "help": "show originators in json format\n" }
             ]
}
```

```
mlc115:~# cat /var/run/bmx7/json/parameters
{ "OPTIONS": [
               { "name": "plugin", "INSTANCES": [ { "value": "bmx7_json.so" } ] },
               { "name": "ipVersion", "INSTANCES": [ { "value": "6", "CHILD_INSTANCES": [ { "name": "throwRules", "value": "0" } ] } ] },
               { "name": "globalPrefix", "INSTANCES": [ { "value": "fd02::\/48" } ] },
               { "name": "dev", "INSTANCES": [ { "value": "eth1.12" }, { "value": "eth2.12", "CHILD_INSTANCES": [ { "name": "announce", "value": "1" } ] } ] }
             ]
}
```

```
mlc115:~# ls -l /var/run/bmx7/json/descriptions/
total 120
-rw-r--r-- 1 root root 699 May 23 05:53 mlc100.A69036A0031A0C66AD20
-rw-r--r-- 1 root root 700 May 23 05:53 mlc101.2377050DB5C5ADC9BDD7
-rw-r--r-- 1 root root 700 May 23 05:53 mlc102.F0CA8B3D8E8ACB296710
-rw-r--r-- 1 root root 700 May 23 05:53 mlc103.173A43BE22C3F14D077C
-rw-r--r-- 1 root root 700 May 23 05:53 mlc104.0EC109E295B0C13145D5
-rw-r--r-- 1 root root 700 May 23 05:53 mlc105.560B8EABCF091C3FB9CA
-rw-r--r-- 1 root root 700 May 23 05:53 mlc106.7AFB3B48A90D813DB92E
-rw-r--r-- 1 root root 700 May 23 05:53 mlc107.86ABA478A4DCC6368F0C
-rw-r--r-- 1 root root 700 May 23 05:53 mlc108.9372015E17AD0E9FABDE
-rw-r--r-- 1 root root 699 May 23 05:53 mlc109.43B2B84EE01CAF1F835A
-rw-r--r-- 1 root root 699 May 23 05:53 mlc110.E9C32AA8FDB9CDEB9B0D
-rw-r--r-- 1 root root 700 May 23 05:53 mlc111.F7DBED76B8080336AF28
-rw-r--r-- 1 root root 700 May 23 05:53 mlc112.7EF3A9613E7782BF272C
-rw-r--r-- 1 root root 700 May 23 05:53 mlc113.38B890A127F937D3B53F
-rw-r--r-- 1 root root 700 May 23 05:53 mlc114.D5A250E3A8DA07E65CE5
-rw-r--r-- 1 root root 698 May 22 18:31 mlc115.5B1116F69452328AAFE0
-rw-r--r-- 1 root root 700 May 23 05:53 mlc116.65A370182BEFDF5E702E
-rw-r--r-- 1 root root 700 May 23 05:53 mlc117.CD73F593835D43750AC4
-rw-r--r-- 1 root root 700 May 23 05:53 mlc118.5E790F311908AAA5D9CB
-rw-r--r-- 1 root root 700 May 23 05:53 mlc119.766B445192E7F6830A45
-rw-r--r-- 1 root root 700 May 23 05:53 mlc120.9AECE8321C7E46360418
-rw-r--r-- 1 root root 699 May 23 05:53 mlc121.B783CB1210C71DCBB2A6
-rw-r--r-- 1 root root 700 May 23 05:53 mlc122.45676E40FC722A671F50
-rw-r--r-- 1 root root 700 May 23 05:53 mlc123.9B3317729F5EFBF44C6D
-rw-r--r-- 1 root root 700 May 23 05:53 mlc124.B5BDD2917537982A4CC0
-rw-r--r-- 1 root root 700 May 23 05:53 mlc125.3681CBE838DBFD492E32
-rw-r--r-- 1 root root 700 May 23 05:53 mlc126.A57873C9302DD4923281
-rw-r--r-- 1 root root 700 May 23 05:53 mlc127.F48C1A9DE327156645D7
-rw-r--r-- 1 root root 699 May 23 05:53 mlc128.F56930DD303568C52227
-rw-r--r-- 1 root root 700 May 23 05:53 mlc129.4DBCAFF8C41B4EB0C226
```

```
mlc115:~# cat /var/run/bmx7/json/descriptions/mlc100.A69036A0031A0C66AD20
{ "descSha": "54B06B8E430500D1D7B52314DC723036C47B7CD4", "blocked": 0,
      "DESC_ADV": { "transmitterIid4x": 56, "globalId": "mlc100.A69036A0031A0C66AD20", "codeVersion": 5, "capabilities": "0", "descSqn": 2760, "ogmSqnMin": 65159, "ogmSqnRange": 7362, "txInterval": 500,
                    "extensions": [ { "METRIC_EXTENSION": { "fmetric_u16_min": "1", "metricAlgo": 16, "flags": "0", "txExpDivisor": 1, "txExpNumerator": 1, "rxExpDivisor": 2, "rxExpNumerator": 1, "pathWindow": 5, "pathLounge": 1, "pathRegression": 1, "hopPenalty": 0 } },
                                    { "HNA6_EXTENSION": [ { "prefixlen": 128, "address": "fd02::a0cd:ef00:6401:0:1", "metric": 0 }, { "prefixlen": 128, "address": "fd02::a0cd:ef00:6402:0:1", "metric": 0 } ] }
                                  ]
                  }
}
```


```
mlc115:~# cat /var/run/bmx7/json/descriptions/mlc115.5B1116F69452328AAFE0
{ "descSha": "BEC91A2124FAA2B74E3D23DC6C2B0B58D3534412", "blocked": 0,
      "DESC_ADV": { "transmitterIid4x": 1, "globalId": "mlc115.5B1116F69452328AAFE0", "codeVersion": 5, "capabilities": "0", "descSqn": 48583, "ogmSqnMin": 2870, "ogmSqnRange": 7649, "txInterval": 500,
                    "extensions": [ { "METRIC_EXTENSION": { "fmetric_u16_min": "1", "metricAlgo": 16, "flags": "0", "txExpDivisor": 1, "txExpNumerator": 1, "rxExpDivisor": 2, "rxExpNumerator": 1, "pathWindow": 5, "pathLounge": 1, "pathRegression": 1, "hopPenalty": 0 } },
                                    { "HNA6_EXTENSION": [ { "prefixlen": 128, "address": "fd02::a0cd:ef00:7301:0:1", "metric": 0 }, { "prefixlen": 128, "address": "fd02::a0cd:ef00:7302:0:1", "metric": 0 } ] }
                                  ]
                  }
}
```
