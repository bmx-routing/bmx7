/*
 * Copyright (c) 2010  Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */


/*
 * The functions for manipulating kernel network configuration
 * [eg: ip(), iptunnel(), ipaddr(), rtnl_talk() ]
 * were inspired by iproute2 code from Alexey Kuznetsov
 */

#ifndef IFA_F_DADFAILED
#define IFA_F_DADFAILED		0x08
#endif

#ifndef	INFINITY_LIFE_TIME
#define INFINITY_LIFE_TIME      0xFFFFFFFFU
#endif

//from  linux/wireless.h
#ifndef SIOCGIWNAME
#define SIOCGIWNAME    0x8B01          /* get name == wireless protocol */
#endif

#ifndef SIOCGIWFREQ
#define SIOCGIWFREQ     0x8B05          /* get channel/frequency (Hz) */
#endif

// from <linux/rtnetlink.h>:
#define RTMGRP_IPV4_RULE	0x80
#define RTMGRP_IPV6_IFINFO	0x800
#define RTMGRP_IPV6_PREFIX	0x20000

#define RTNL_RCV_MAX 16640

#define ARG_NETLINK_BUFFSZ "netlinkBuffSize"
#define MIN_NETLINK_BUFFSZ (66560/8)
#define MAX_NETLINK_BUFFSZ (16*266240)
#define DEF_NETLINK_BUFFSZ (4*266240) // 266240 // 133120 // less causes lost messages !!?? otherwise too small for 2K+ routes and heavy CPU load

extern int32_t netlinkBuffSize;


extern uint32_t udpRxBytesMean, udpRxPacketsMean, udpTxBytesMean, udpTxPacketsMean;

enum {
	FRA_UNSPEC,
	FRA_DST, /* destination address */
	FRA_SRC, /* source address */
	FRA_IIFNAME, /* interface name */
#define FRA_IFNAME	FRA_IIFNAME
	FRA_GOTO, /* target to jump to (FR_ACT_GOTO) */
	FRA_UNUSED2,
	FRA_PRIORITY, /* priority/preference */
	FRA_UNUSED3,
	FRA_UNUSED4,
	FRA_UNUSED5,
	FRA_FWMARK, /* mark */
	FRA_FLOW, /* flow/class id */
	FRA_UNUSED6,
	FRA_UNUSED7,
	FRA_UNUSED8,
	FRA_TABLE, /* Extended table id */
	FRA_FWMASK, /* mask for netfilter mark */
	FRA_OIFNAME,
	__FRA_MAX
};

#define FRA_MAX (__FRA_MAX - 1)


struct ifname {
	char str[IFNAMSIZ];
};

typedef struct ifname IFNAME_T;

#define ARG_DEVSTAT_REGRESSION "devStatRegression"
#define MIN_DEVSTAT_REGRESSION 1
#define MAX_DEVSTAT_REGRESSION 100
#define DEF_DEVSTAT_REGRESSION 10
#define HLP_DEVSTAT_REGRESSION "arithmetic-mean regression for interface traffic-statistics"

extern int32_t devStatRegression;

#define DEF_DEVSTAT_PERIOD 1000
#define DEVSTAT_PRECISION 10000

#define ARG_LLOCAL_PREFIX "llocalPrefix"
#define HLP_LLOCAL_PREFIX "specify link-local prefix for interfaces"

#define ARG_GLOBAL_PREFIX "globalPrefix"
#define HLP_GLOBAL_PREFIX "specify global prefix for interfaces"


#define DEF_AUTO_IP6ID_PREFIX  "fd70::/16"
#define ARG_AUTO_IP6ID_PREFIX  "ipAutoPrefix"
#define HLP_AUTO_IP6ID_PREFIX  "Autoconfigure IPv6 addresses (MUST be something/16)"
#define DEF_AUTO_IP6ID_MASK    16

#define DEF_AUTO_TUNID_OCT_POS ( (DEF_AUTO_IP6ID_MASK / 8) - ((uint8_t)(!((DEF_AUTO_IP6ID_MASK % 8)))) )
#define MIN_AUTO_TUNID_OCT     0x1
#define MAX_AUTO_TUNID_OCT     0xF // limited by 8-bit tun6Id range and (65 - DEF_AUTO_REMOTE_MASK) bit size

#define ARG_INTERFACES "interfaces"


#define ARG_DEV  		"dev"
#define HLP_DEV                 "add or change interface device or its configuration"

#define ARG_DEV_LLOCAL_PREFIX   "llocalPrefix"
#define HLP_DEV_LLOCAL_PREFIX   "specify link-local prefix for interface"


#define DEV_LO "lo"
#define DEV_UNKNOWN "unknown"

#define ARG_DEV_LL		"linklayer"
#define DEF_DEV_LL              0
#define MIN_DEV_LL              0
#define TYP_DEV_LL_LO		0
#define TYP_DEV_LL_LAN		1
#define TYP_DEV_LL_WIFI		2
#define MAX_DEV_LL              2
#define HLP_DEV_LL              "manually set device type for linklayer specific optimization (1=lan, 2=wlan)"

#define ARG_DEV_CHANNEL		  "channel"
#define MIN_DEV_CHANNEL           0
#define TYP_DEV_CHANNEL_EXCLUSIVE 0
#define TYP_DEV_CHANNEL_SHARED    255
#define MAX_DEV_CHANNEL           255
#define DEF_DEV_CHANNEL           255
#define HLP_DEV_CHANNEL           "set channel of interface 0) exclusive access such as wired lans, 1-254) for wireless, 255 for unknown"

#define ARG_DEV_BITRATE_MAX       "rateMax"
#define MIN_DEV_BITRATE_MAX          6000000
#define DEF_DEV_BITRATE_MAX         56000000
#define DEF_DEV_BITRATE_MAX_WIFI    56000000
#define DEF_DEV_BITRATE_MAX_LAN   1000000000
#define MAX_DEV_BITRATE_MAX      UMETRIC_MAX
#define HLP_DEV_BITRATE_MAX       "set maximum bandwidth as bits/sec of dev"



#define ARG_IP "ipVersion"
#define DEF_IP_VERSION "6"
#define DEF_IP_FAMILY AF_INET6

#define ARG_IP_POLICY_ROUTING "policyRouting"
#define DEF_IP_POLICY_ROUTING 1

#define ARG_IP_THROW_RULES "throwRules"
#define DEF_IP_THROW_RULES 0

#define ARG_IP_PRIO_RULES "prioRules"
#define DEF_IP_PRIO_RULES 1


#define RT_PRIO_MAX    -1
//#define RT_PRIO_HOSTS  -1
#define RT_PRIO_HNA   -1
#define RT_PRIO_TUNS   -2
#define RT_PRIO_MIN    -2


//#define ARG_IP_RULE_HOST "tablePrefHosts"
//#define MIN_IP_RULE_HOST 3
//#define MAX_IP_RULE_HOST 32766
//#define DEF_IP_RULE_HOST 6000 // avoid conflicts with bmxd and others

#define ARG_IP_RULE_HNA "tablePrefHnas"
#define MIN_IP_RULE_HNA 3
#define MAX_IP_RULE_HNA 32767
#define DEF_IP_RULE_HNA 70 // avoid conflicts with bmxd and others

#define ARG_IP_RULE_TUN "tablePrefTuns"
#define MIN_IP_RULE_TUN 3
#define MAX_IP_RULE_TUN U16_MAX //64000
#define DEF_IP_RULE_TUN 32767

#define BMX_TABLE_MAX   -1
//#define BMX_TABLE_HOSTS -1
#define BMX_TABLE_HNA  -1
#define BMX_TABLE_TUN  -2
#define BMX_TABLE_MIN   -2

//#define ARG_IP_TABLE_HOST "tableHosts"
//#define DEF_IP_TABLE_HOST 60 //avoid conflicts with bmxd and others
//#define MIN_IP_TABLE_HOST 0
//#define MAX_IP_TABLE_HOST 32000

#define MIN_IP_TABLE 1
#define MAX_IP_TABLE 254

#define ARG_IP_TABLE_HNA "tableHnas"
#define DEF_IP_TABLE_HNA 70 //avoid conflicts with bmxd and others
#define MIN_IP_TABLE_HNA MIN_IP_TABLE
#define MAX_IP_TABLE_HNA MAX_IP_TABLE

#define DEF_IP_TABLE_LOCAL 255
#define DEF_IP_TABLE_MAIN 254
#define DEF_IP_TABLE_DEFAULT 253

#define ARG_IP_TABLE_TUN "tableTuns"
#define DEF_IP_TABLE_TUN 254 //61 //avoid conflicts with bmxd and others
#define MIN_IP_TABLE_TUN MIN_IP_TABLE
#define MAX_IP_TABLE_TUN MAX_IP_TABLE


#define ARG_BASE_PORT "basePort"
#define DEF_BASE_PORT 6270
#define MIN_BASE_PORT 1025
#define MAX_BASE_PORT 60000
extern int32_t base_port;


#define SYSCTL_IP6_FORWARD 1
#define SYSCTL_IP4_RP_FILTER 2
#define SYSCTL_IP4_FORWARD 1
#define SYSCTL_IP4_SEND_REDIRECT 0
#define SYSCTL_IP4_ACCEPT_LOCAL 1

#define DEF_TUN_OUT_PERSIST 1

#define ARG_EXPORT_DISTANCE "exportDistance"
#define TYP_EXPORT_DISTANCE_INFINITE 256
#define MIN_EXPORT_DISTANCE 0
#define MAX_EXPORT_DISTANCE TYP_EXPORT_DISTANCE_INFINITE
#define DEF_EXPORT_DISTANCE TYP_EXPORT_DISTANCE_INFINITE








//#define IPV6_MC_ALL_ROUTERS "FF02::2"

//#define IPV6_LINK_LOCAL_UNICAST_U32 0xFE800000
//#define IPV6_MULTICAST_U32 0xFF000000





extern struct net_key autoconf_prefix_cfg;
extern IPX_T my_primary_ip;

#define AF_CFG AF_INET6
#define ZERO_NETCFG_KEY ZERO_NET6_KEY

extern const IP6_T   IP6_ALLROUTERS_MC_ADDR;

extern const IP6_T   IP6_LINKLOCAL_UC_PREF;
extern const uint8_t IP6_LINKLOCAL_UC_PLEN;

extern const IP6_T   IP6_MC_PREF;
extern const uint8_t IP6_MC_PLEN;


extern int dev_lo_idx;



extern int32_t ip_prio_hna_cfg;
extern int32_t ip_table_hna_cfg;
extern int32_t ip_table_tun_cfg;
extern int32_t ip_prio_rules_cfg;
extern int32_t ip_throw_rules_cfg;
extern int32_t ip_policy_rt_cfg;
extern int32_t policy_routing;
#define POLICY_RT_UNSET -1
#define POLICY_RT_DISABLED 0
#define POLICY_RT_ENABLED 1

extern struct avl_tree if_link_tree;

extern struct avl_tree dev_ip_tree;
extern struct avl_tree dev_name_tree;

//extern struct avl_tree iptrack_tree;


//extern int32_t prio_rules;
//extern int32_t throw_rules;

//extern IDM_T dev_soft_conf_changed; // temporary enabled to trigger changed interface configuration

#define IFCONFIG_PATH_PROCNET_DEV		"/proc/net/dev"

struct user_net_device_stats {
	unsigned long long rx_packets; /* total packets received       */
	unsigned long long tx_packets; /* total packets transmitted    */
	//	unsigned long long rx_bytes; /* total bytes received         */
	//	unsigned long long tx_bytes; /* total bytes transmitted      */
	//	unsigned long rx_errors; /* bad packets received         */
	//	unsigned long tx_errors; /* packet transmit problems     */
	//	unsigned long rx_dropped; /* no space in linux buffers    */
	//	unsigned long tx_dropped; /* no space available in linux  */
	//	unsigned long rx_multicast; /* multicast packets received   */
	//	unsigned long rx_compressed;
	//	unsigned long tx_compressed;
	//	unsigned long collisions;

	/* detailed rx_errors: */
	//	unsigned long rx_length_errors;
	//	unsigned long rx_over_errors; /* receiver ring buff overflow  */
	//	unsigned long rx_crc_errors; /* recved pkt with crc error    */
	//	unsigned long rx_frame_errors; /* recv'd frame alignment error */
	//	unsigned long rx_fifo_errors; /* recv'r fifo overrun          */
	//	unsigned long rx_missed_errors; /* receiver missed packet     */
	/* detailed tx_errors */
	//	unsigned long tx_aborted_errors;
	//	unsigned long tx_carrier_errors;
	//	unsigned long tx_fifo_errors;
	//	unsigned long tx_heartbeat_errors;
	//	unsigned long tx_window_errors;
};



struct nlh_req {
	struct nlmsghdr nlh;
};

struct iplink_req {
	struct nlmsghdr	nlh;
	struct ifinfomsg ifi;
};


struct ip_req {
	struct nlmsghdr nlh;
	struct rtgenmsg rtg;
};

#define RT_REQ_BUFFSIZE 256

struct rtmsg_req {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buff[RT_REQ_BUFFSIZE];
};

struct ifamsg_req {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
        char buf[RT_REQ_BUFFSIZE];
};


struct rtnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	__u32			seq;
	uint8_t                 busy;
};


/*

#define SIOCGETTUNNEL   (SIOCDEVPRIVATE + 0)
#define SIOCADDTUNNEL   (SIOCDEVPRIVATE + 1)
#define SIOCDELTUNNEL   (SIOCDEVPRIVATE + 2)

// don't add encapsulation limit if one isn't present in inner packet
#define IP6_TNL_F_IGN_ENCAP_LIMIT 0x1
// copy the traffic class field from the inner packet
#define IP6_TNL_F_USE_ORIG_TCLASS 0x2
// copy the flowlabel from the inner packet
#define IP6_TNL_F_USE_ORIG_FLOWLABEL 0x4
// being used for Mobile IPv6
#define IP6_TNL_F_MIP6_DEV 0x8
// copy DSCP from the outer packet
#define IP6_TNL_F_RCV_DSCP_COPY 0x10

#define IPV6_DEFAULT_TNL_ENCAP_LIMIT 4

 */

#define DEFAULT_TNL_HOP_LIMIT	(64)



struct if_link_node {
	uint16_t        update_sqn;
	uint16_t        changed;
	int             index;
	int		type;
	int		alen;
	unsigned	flags;

	ADDR_T          addr;
	IFNAME_T        name;

	struct avl_tree if_addr_tree;

	struct nlmsghdr  nlmsghdr[];
};

struct if_addr_node {
	struct if_link_node *iln;
	struct dev_node     *dev;
	struct rtattr       *rta_tb[IFA_MAX + 1];
	
	IPX_T                ip_addr;
	IPX_T                ip_mcast;

	uint16_t             update_sqn;
	uint16_t             changed;
	struct ifaddrmsg     ifa;
	IFNAME_T             label;
        
	struct nlmsghdr      nlmsghdr[];
};



struct dev_node {

	struct if_link_node *if_link;
	struct if_addr_node *if_llocal_addr;  // non-zero but might be global for ipv4 or loopback interfaces
	struct if_addr_node *if_global_addr;  // might be zero for non-primary interfaces
	int32_t tx_task_items;
	
	int8_t hard_conf_changed;
	int8_t soft_conf_changed;
        struct net_key autoIP6Configured;
        int autoIP6IfIndex;
	uint8_t active;
	uint8_t activate_again;
	uint8_t activate_cancelled;

	uint32_t udpTxPacketsCurr;
	uint32_t udpTxPacketsMean;
	uint32_t udpRxPacketsCurr;
	uint32_t udpRxPacketsMean;
	uint32_t udpTxBytesCurr;
	uint32_t udpTxBytesMean;
	uint32_t udpRxBytesCurr;
	uint32_t udpRxBytesMean;


	IFNAME_T name_phy_cfg;  //key for dev_name_tree
	IFNAME_T label_cfg;

        LinkNode dummyLink;

	DevKey llipKey;
	MAC_T mac;


	char ip_llocal_str[IPX_STR_LEN];
	char ip_global_str[IPX_STR_LEN];

	struct sockaddr_storage llocal_unicast_addr;
	struct sockaddr_storage tx_netwbrc_addr;

	int32_t unicast_sock;
	int32_t rx_mcast_sock;
	int32_t rx_fullbrc_sock;

	HELLO_SQN_T link_hello_sqn;

	uint8_t strictSignatures;

	int8_t linklayer_conf;
	int8_t linklayer;

	int16_t channel_conf;
	int16_t channel;

	UMETRIC_T umetric_max_conf;
//	UMETRIC_T umetric_max_configured;
	UMETRIC_T umetric_max;

	void(*upd_link_capacity) (LinkNode *link, struct ctrl_node *cn);


        struct net_key llocal_prefix_conf_;

//	IPX_T global_prefix_conf;
//	int16_t global_prefix_length_conf;
//
//	IPX_T llocal_prefix_conf;
//	int16_t llocal_prefix_length_conf;

	//size of plugin data is defined during intialization and depends on registered PLUGIN_DATA_DEV hooks
	void *plugin_data[];
};

#define TYP_TUN_PROTO_ALL 256

#define ARG_TUN_PROTO_SEARCH "proto"
#define MIN_TUN_PROTO_SEARCH 0 // unspecified
#define MAX_TUN_PROTO_SEARCH TYP_TUN_PROTO_ALL
#define DEF_TUN_PROTO_SEARCH TYP_TUN_PROTO_ALL
#define HLP_TUN_PROTO_SEARCH "filter for routes of given iproute2 protocol type (255 matches all protocols)"

#define ARG_TUN_PROTO_SET "setProto"
#define MIN_TUN_PROTO_SET 0 // unspecified
#define MAX_TUN_PROTO_SET (TYP_TUN_PROTO_ALL-1)
#define DEF_TUN_PROTO_SET 0
#define HLP_TUN_PROTO_SET "set iproute2 protocol type for configured tunnel routes"

#define ARG_TUN_PROTO_ADV "advProto"
#define MIN_TUN_PROTO_ADV 0 // unspecified
#define MAX_TUN_PROTO_ADV (TYP_TUN_PROTO_ALL-1)
#define DEF_TUN_PROTO_ADV 0
#define HLP_TUN_PROTO_ADV "advertise tunnel routes as given protocol type"


//iproute() commands:
#define	IP_NOP             00

#define IP_LINK_DEL        01

#define IP_LINK_GET        03
#define IP_ADDR_GET        04
#define IP_ROUTE_GET       05


#define IP_ADDRESS_SET     11

#define IP_RULES           20
#define IP_RULE_FLUSH      21
#define IP_RULE_DEFAULT    22 //basic rules to interfaces, host, and networks routing tables
#define IP_RULE_TEST       23
#define	IP_RULE_MAX        24

#define IP_ROUTES          30
#define IP_ROUTE_FLUSH_ALL 31
#define IP_ROUTE_FLUSH     32
#define IP_THROW_MY_HNA    33
#define IP_THROW_MY_NET    34
#define IP_THROW_MY_TUNS   35
#define IP_ROUTE_HOST      36
#define IP_ROUTE_HNA       37
#define IP_ROUTE_TUNS      38
#define	IP_ROUTE_MAX       (IP_ROUTE_TUNS + TYP_TUN_PROTO_ALL)




struct route_export {
        uint32_t exportDistance;
        uint8_t exportOnly;
	uint8_t ipexport;
};


struct track_key {
	struct net_key net;
	//IFNAME_T iif;
	uint32_t prio;
	uint32_t table;
	uint32_t metric;
	uint16_t cmd_type;
} __attribute__((packed));

struct track_node {
        struct track_key k;
        uint32_t items;
	int16_t cmd;
	uint32_t tmp;
	struct route_export rt_exp;
	uint32_t oif_idx;
	IPX_T via;
	IPX_T src;
};


struct rtnl_get_node {
        struct list_node list;
	uint16_t nlmsg_type;
        uint32_t rtm_table;
        uint32_t rta_type;
        struct net_key net;
};


//usefult IP tools:



// core:

int rtnl_rcv(int fd, uint32_t pid, uint32_t seq, uint16_t cmd, uint8_t quiet, void (*func) (struct nlmsghdr *nh, void *data), void *data);
uint32_t nl_mgrp(uint32_t group);
int register_netlink_event_hook(uint32_t nlgroups, int buffsize, void (*cb_fd_handler) (int32_t fd));
int unregister_netlink_event_hook(int rtevent_sk, void (*cb_fd_handler) (int32_t fd));

uint32_t get_if_index(IFNAME_T *name);
IDM_T kernel_set_flags(char *name, int fd, int get_req, int set_req, uint16_t up_flags, uint16_t down_flags);
IDM_T kernel_set_addr(IDM_T del, uint32_t if_index, uint8_t family, IPX_T *ip, uint8_t prefixlen, IDM_T deprecated);

IDM_T kernel_link_del(char *name);

IDM_T kernel_dev_exists(char *name);
int32_t kernel_tun_add(char *name, uint8_t proto, IPX_T *local, IPX_T *remote);
IDM_T kernel_tun_del(char *name);

void kernel_dev_tun_del( char *name, int32_t fd );
int32_t kernel_dev_tun_add( char *name, int32_t *fdp, IDM_T accept_local_ipv4 );

uint32_t kernel_get_mtu(char *name);
int32_t kernel_get_ifidx( char *name );
IDM_T kernel_set_mtu(char *name, uint16_t mtu);
IDM_T kernel_get_route(uint8_t quiet, uint8_t family, uint16_t type, uint32_t table, void (*func) (struct nlmsghdr *nh, void *data));

// from net-tools: ifconfig.c and lib/interface.c
IDM_T kernel_get_ifstats(struct user_net_device_stats *stats, char *target);

struct sockaddr_storage set_sockaddr_storage(uint8_t af, IPX_T *ipx, int32_t port);
void set_ipexport( void (*func) (int8_t del, const struct net_key *dst, uint32_t oif_idx, IPX_T *via, uint32_t metric, uint8_t distance) );

IDM_T iproute(uint16_t cmd, int8_t del, uint8_t quiet, const struct net_key *dst, int32_t table_macro, int32_t prio_macro,
        int oif_idx, IPX_T *via, IPX_T *src, uint32_t metric, struct route_export *rte);

void ip_flush_routes(uint8_t family, int32_t table_macro);
void ip_flush_rules(uint8_t family, int32_t table_macro);

IDM_T check_proc_sys_net(char *file, int32_t desired);

void sysctl_config(struct dev_node *dev_node);


int8_t track_rule_and_proceed(uint32_t network, int16_t mask, uint32_t prio, int16_t rt_table, char* iif,
                                      int16_t rule_type, int8_t del, int8_t cmd);

IDM_T is_ip_local(IPX_T *ip);


void init_ip(void);

void cleanup_ip(void);

