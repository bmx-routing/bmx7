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

// from <linux/rtnetlink.h>:
#define RTMGRP_IPV4_RULE	0x80
#define RTMGRP_IPV6_IFINFO	0x800
#define RTMGRP_IPV6_PREFIX	0x20000








struct ifname {
	char str[IFNAMSIZ];
};

typedef struct ifname IFNAME_T;


#define ARG_LLOCAL_PREFIX "llocalPrefix"
#define HLP_LLOCAL_PREFIX "specify link-local prefix for interfaces"

#define ARG_GLOBAL_PREFIX "globalPrefix"
#define HLP_GLOBAL_PREFIX "specify global prefix for interfaces"


#define DEF_AUTO_MASK_DISABLED   0  // DO NOT CHANGE THIS

#define DEF_AUTO_IP6_PREFIX      "fd66:66:66::/56"
#define DEF_AUTO_IP6_MASK        56 // DO NOT CHANGE THIS
#define ARG_AUTO_IP6_PREFIX      "ipAutoPrefix"
#define HLP_AUTO_IP6_PREFIX      "Autoconfigure IPv6 addresses (MUST be something/56 to enable or ::/0 to disable)"
#define DEF_AUTO_IP6_BYTE6       0x00
#define DEF_AUTO_IP6_DEVMASK     64

#define MAX_TUN_REMOTE_IPS       255 // limited by 8-bit tun6Id range and (65 - DEF_AUTO_REMOTE_MASK) bit size
#define DEF_TUN_REMOTE_BYTE6     0xFF

#define ARG_INTERFACES "interfaces"


#define ARG_DEV  		"dev"
#define HLP_DEV                 "add or change interface device or its configuration"

#define ARG_DEV_GLOBAL_PREFIX   "globalPrefix"
#define HLP_DEV_GLOBAL_PREFIX   "specify global prefix for interface"

#define ARG_DEV_LLOCAL_PREFIX   "llocalPrefix"
#define HLP_DEV_LLOCAL_PREFIX   "specify link-local prefix for interface"


#define ARG_DEV_ANNOUNCE        "announce"
#define DEF_DEV_ANNOUNCE        YES
#define HLP_DEV_ANNOUNCE        "disable/enable announcement of interface IP"

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
#define DEF_DEV_CHANNEL           0
#define MIN_DEV_CHANNEL           0
#define TYP_DEV_CHANNEL_SHARED    0
#define TYP_DEV_CHANNEL_WLAN001	  1
#define TYP_DEV_CHANNEL_WLAN150	  150
#define TYP_DEV_CHANNEL_EXCLUSIVE 255
#define MAX_DEV_CHANNEL           255

#define ARG_DEV_BITRATE_MAX       "rateMax"
#define DEF_DEV_BITRATE_MAX         56000000
#define DEF_DEV_BITRATE_MAX_LAN   1000000000
#define DEF_DEV_BITRATE_MAX_WIFI    56000000
#define HLP_DEV_BITRATE_MAX       "set maximum bandwidth as bits/sec of dev"

#define ARG_DEV_BITRATE_MIN       "rateMin"
#define DEF_DEV_BITRATE_MIN          6000000
#define DEF_DEV_BITRATE_MIN_LAN   1000000000
#define DEF_DEV_BITRATE_MIN_WIFI     6000000
#define HLP_DEV_BITRATE_MIN       "set minimum bandwidth as bits/sec of dev"



#define ARG_IP "ipVersion"
#define DEF_IP_VERSION "6"
#define DEF_IP_FAMILY AF_INET6

#define ARG_IP_POLICY_ROUTING "policyRouting"
#define DEF_IP_POLICY_ROUTING 1

#define ARG_IP_THROW_RULES "throwRules"
#define DEF_IP_THROW_RULES 0

#define ARG_IP_PRIO_RULES "prioRules"
#define DEF_IP_PRIO_RULES 1


#define DEF_LO_RULE 1

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
#define MAX_IP_RULE_HNA 32766
#define DEF_IP_RULE_HNA 60 // avoid conflicts with bmxd and others

#define ARG_IP_RULE_TUN "tablePrefTuns"
#define MIN_IP_RULE_TUN 3
#define MAX_IP_RULE_TUN U16_MAX //64000
#define DEF_IP_RULE_TUN 32766

#define RT_TABLE_MAX   -1
//#define RT_TABLE_HOSTS -1
#define RT_TABLE_HNA  -1
#define RT_TABLE_TUN  -2
#define RT_TABLE_MIN   -2

//#define ARG_IP_TABLE_HOST "tableHosts"
//#define DEF_IP_TABLE_HOST 60 //avoid conflicts with bmxd and others
//#define MIN_IP_TABLE_HOST 0
//#define MAX_IP_TABLE_HOST 32000

#define MIN_IP_TABLE 1
#define MAX_IP_TABLE 254

#define ARG_IP_TABLE_HNA "tableHnas"
#define DEF_IP_TABLE_HNA 60 //avoid conflicts with bmxd and others
#define MIN_IP_TABLE_HNA MIN_IP_TABLE
#define MAX_IP_TABLE_HNA MAX_IP_TABLE

#define DEF_IP_TABLE_LOCAL 255
#define DEF_IP_TABLE_MAIN 254
#define DEF_IP_TABLE_DEFAULT 253

#define ARG_IP_TABLE_TUN "tableTuns"
#define DEF_IP_TABLE_TUN 254 //61 //avoid conflicts with bmxd and others
#define MIN_IP_TABLE_TUN MIN_IP_TABLE
#define MAX_IP_TABLE_TUN MAX_IP_TABLE


//extern int32_t base_port;
#define ARG_BASE_PORT "basePort"
#define DEF_BASE_PORT 6240
#define MIN_BASE_PORT 1025
#define MAX_BASE_PORT 60000



#define ARG_PEDANTIC_CLEANUP "pedanticCleanup"
#define DEF_PEDANTIC_CLEANUP  NO




#define B64_SIZE 64

#define IP6NET_STR_LEN (INET6_ADDRSTRLEN+4)  // eg ::1/128
#define IPXNET_STR_LEN IP6NET_STR_LEN

#define IP4_MAX_PREFIXLEN 32
#define IP6_MAX_PREFIXLEN 128


#define IP2S_ARRAY_LEN 10


//#define IPV6_MC_ALL_ROUTERS "FF02::2"

//#define IPV6_LINK_LOCAL_UNICAST_U32 0xFE800000
//#define IPV6_MULTICAST_U32 0xFF000000

extern const IPX_T  ZERO_IP;
extern const MAC_T  ZERO_MAC;
extern const ADDR_T ZERO_ADDR;

extern const struct link_dev_key ZERO_LINK_KEY;

#define ZERO_NET_KEY_INIT {.af = 0}
extern const struct net_key ZERO_NET_KEY;

#define ZERO_NET4_KEY_INIT {.af = AF_INET}
extern const struct net_key ZERO_NET4_KEY;
#define ZERO_NET6_KEY_INIT {.af = AF_INET6}
extern const struct net_key ZERO_NET6_KEY;


extern struct net_key autoconf_prefix_cfg;
extern struct tun_in_node default_tun_in;

#ifdef NO_ASSERTIONS
extern uint8_t __af_cfg;
#define AF_CFG __af_cfg
extern struct net_key __ZERO_NETCFG_KEY;
#define ZERO_NETCFG_KEY __ZERO_NETCFG_KEY
#else
uint8_t _af_cfg(const char *func);
#define AF_CFG _af_cfg(__FUNCTION__)
struct net_key _ZERO_NETCFG_KEY(const char *func);
#define ZERO_NETCFG_KEY _ZERO_NETCFG_KEY(__FUNCTION__)
#endif

extern const IP6_T   IP6_ALLROUTERS_MC_ADDR;
extern const IP6_T   IP6_LOOPBACK_ADDR;

extern const IP6_T   IP6_LINKLOCAL_UC_PREF;
extern const uint8_t IP6_LINKLOCAL_UC_PLEN;

extern const IP6_T   IP6_MC_PREF;
extern const uint8_t IP6_MC_PLEN;


extern int dev_lo_idx;

extern struct dev_node *primary_dev;
extern struct dev_node *primary_phy;
extern IDM_T niit_enabled;


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
};

#define IPV6_DEFAULT_TNL_ENCAP_LIMIT 4
#define DEFAULT_TNL_HOP_LIMIT	(64)

#define SIOCGETTUNNEL   (SIOCDEVPRIVATE + 0)
#define SIOCADDTUNNEL   (SIOCDEVPRIVATE + 1)
#define SIOCDELTUNNEL   (SIOCDEVPRIVATE + 2)

/* don't add encapsulation limit if one isn't present in inner packet */
#define IP6_TNL_F_IGN_ENCAP_LIMIT 0x1
/* copy the traffic class field from the inner packet */
#define IP6_TNL_F_USE_ORIG_TCLASS 0x2
/* copy the flowlabel from the inner packet */
#define IP6_TNL_F_USE_ORIG_FLOWLABEL 0x4
/* being used for Mobile IPv6 */
#define IP6_TNL_F_MIP6_DEV 0x8
/* copy DSCP from the outer packet */
#define IP6_TNL_F_RCV_DSCP_COPY 0x10


struct ip6_tnl_parm {
        char name[IFNAMSIZ]; /* name of tunnel device */
        int link; /* ifindex of underlying L2 interface */
        __u8 proto; /* tunnel protocol */
        __u8 encap_limit; /* encapsulation limit for tunnel */
        __u8 hop_limit; /* hop limit for tunnel */
        __be32 flowinfo; /* traffic class and flowlabel for tunnel */
        __u32 flags; /* tunnel flags */
        struct in6_addr laddr; /* local tunnel end-point address */
        struct in6_addr raddr; /* remote tunnel end-point address */
};



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



struct tx_link_node {
	struct list_head tx_tasks_list[FRAME_TYPE_ARRSZ]; // scheduled frames and messages
};



struct dev_node {

	struct if_link_node *if_link;
	struct if_addr_node *if_llocal_addr;  // non-zero but might be global for ipv4 or loopback interfaces
	struct if_addr_node *if_global_addr;  // might be zero for non-primary interfaces
	void (* tx_task) (void *);

	int8_t hard_conf_changed;
	int8_t soft_conf_changed;
        struct net_key autoIP6Configured;
        int autoIP6IfIndex;
	uint8_t active;
	uint8_t activate_again;
	uint8_t activate_cancelled;
	uint16_t lndevs_tmp;

//	DEVADV_IDX_T dev_adv_idx; //TODO: Remove (use llip_key.idx instead)
	int16_t dev_adv_msg;

	IFNAME_T name_phy_cfg;  //key for dev_name_tree
	IFNAME_T label_cfg;

	struct link_dev_node dummy_lndev;

	struct dev_ip_key llip_key;
//	IPX_T llocal_ip_key; //TODO: Remove (use llip_key.ip instead)
	MAC_T mac;


	char ip_llocal_str[IPX_STR_LEN];
	char ip_global_str[IPX_STR_LEN];
	char ip_brc_str[IPX_STR_LEN];

	int32_t ip4_rp_filter_orig;
	int32_t ip4_send_redirects_orig;

	struct sockaddr_storage llocal_unicast_addr;
	struct sockaddr_storage tx_netwbrc_addr;

	int32_t unicast_sock;
	int32_t rx_mcast_sock;
	int32_t rx_fullbrc_sock;

	HELLO_SQN_T link_hello_sqn;

	struct list_head tx_task_lists[FRAME_TYPE_ARRSZ]; // scheduled frames and messages
	struct avl_tree tx_task_interval_tree;

	int8_t announce;

	int8_t linklayer_conf;
	int8_t linklayer;

	int16_t channel_conf;
	int16_t channel;

	UMETRIC_T umetric_min_conf;
//	UMETRIC_T umetric_min_configured;
	UMETRIC_T umetric_min;

	UMETRIC_T umetric_max_conf;
//	UMETRIC_T umetric_max_configured;
	UMETRIC_T umetric_max;

        struct net_key global_prefix_conf_;
        struct net_key llocal_prefix_conf_;

//	IPX_T global_prefix_conf;
//	int16_t global_prefix_length_conf;
//
//	IPX_T llocal_prefix_conf;
//	int16_t llocal_prefix_length_conf;

	//size of plugin data is defined during intialization and depends on registered PLUGIN_DATA_DEV hooks
	void *plugin_data[];
};

/* BMX6 route types. */
#define BMX6_ROUTE_UNSPEC     0
#define BMX6_ROUTE_REDIRECT   1
#define BMX6_ROUTE_KERNEL     2
#define BMX6_ROUTE_BOOT	      3
#define BMX6_ROUTE_STATIC     4

#define BMX6_ROUTE_GATED      8	/* Apparently, GateD */
#define BMX6_ROUTE_RA	      9	/* RDISC/ND router advertisements */
#define BMX6_ROUTE_MRT	      10	/* Merit MRT */
#define BMX6_ROUTE_ZEBRA      11	/* Zebra */
#define BMX6_ROUTE_BIRD	      12	/* BIRD */
#define BMX6_ROUTE_DNROUTED   13	/* DECnet routing daemon */
#define BMX6_ROUTE_XORP	      14	/* XORP */
#define BMX6_ROUTE_NTK	      15	/* Netsukuku */
#define BMX6_ROUTE_DHCP	      16      /* DHCP client */

#define BMX6_ROUTE_SYSTEM     18
#define BMX6_ROUTE_CONNECT    19
#define BMX6_ROUTE_RIP        20
#define BMX6_ROUTE_RIPNG      21
#define BMX6_ROUTE_OSPF       22
#define BMX6_ROUTE_OSPF6      23
#define BMX6_ROUTE_ISIS       24
#define BMX6_ROUTE_BGP        25
#define BMX6_ROUTE_BABEL      26
#define BMX6_ROUTE_HSLS       27
#define BMX6_ROUTE_OLSR       28
#define BMX6_ROUTE_BMX6       29
#define BMX6_ROUTE_BATMAN     30
#define BMX6_ROUTE_MAX        31

#define ARG_ROUTE_UNSPEC      "unspecified"
#define ARG_ROUTE_REDIRECT    "redirect"
#define ARG_ROUTE_KERNEL      "kernel"
#define ARG_ROUTE_BOOT	      "boot"
#define ARG_ROUTE_STATIC      "static"

#define ARG_ROUTE_GATED       "gated"
#define ARG_ROUTE_RA	      "ra"
#define ARG_ROUTE_MRT	      "mrt"
#define ARG_ROUTE_ZEBRA       "zebra"
#define ARG_ROUTE_BIRD	      "bird"
#define ARG_ROUTE_DNROUTED    "decnet"
#define ARG_ROUTE_XORP	      "xorp"
#define ARG_ROUTE_NTK	      "netsukuku"
#define ARG_ROUTE_DHCP	      "dhcp"

#define ARG_ROUTE_SYSTEM      "system"
#define ARG_ROUTE_CONNECT     "connect"
#define ARG_ROUTE_RIP         "rip"
#define ARG_ROUTE_RIPNG       "ripng"
#define ARG_ROUTE_OSPF        "ospf"
#define ARG_ROUTE_OSPF6       "ospf6"
#define ARG_ROUTE_ISIS        "isis"
#define ARG_ROUTE_BGP         "bgp"
#define ARG_ROUTE_BABEL       "babel"
#define ARG_ROUTE_HSLS        "hsls"
#define ARG_ROUTE_OLSR        "olsr"
#define ARG_ROUTE_BMX6        "bmx6"
#define ARG_ROUTE_BATMAN      "batman"

#define HLP_TUN_OUT_TYPE "match only enabled type(s)"

struct sys_route_dict {
        char* sys2Name;
	char  sys2Char;
	uint8_t sys2bmx;
	uint8_t bmx2sys;

};

#define set_rt_dict( S, T, C, N, B ) do { \
        S[ T ].sys2Name = N; \
        S[ T ].sys2Char = C; \
	S[ T ].sys2bmx  = B; \
	S[ B ].bmx2sys  = T; \
} while (0)


extern struct sys_route_dict bmx6_rt_dict[BMX6_ROUTE_MAX];


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
#define	IP_ROUTE_MAX       (IP_ROUTE_TUNS + BMX6_ROUTE_MAX)




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
	uint8_t cmd_type;
} __attribute__((packed));

struct track_node {
        struct track_key k;
        uint32_t items;
	int8_t cmd;
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


char *family2Str(uint8_t family);


char *ipXAsStr(int family, const IPX_T *addr);
char *ipFAsStr(const IPX_T *addr);
char *ip4AsStr( IP4_T addr );
void  ipXToStr(int family, const IPX_T *addr, char *str);
void ipFToStr(const IPX_T *addr, char *str);
char *netAsStr(const struct net_key *net);


#define ipXto4( ipx ) ((ipx).s6_addr32[3])
IPX_T ip4ToX(IP4_T ip4);

char* macAsStr(const MAC_T* mac);

#define ip6AsStr( addr_ptr ) ipXAsStr( AF_INET6, addr_ptr)

struct net_key * setNet(struct net_key *netp, uint8_t family, uint8_t prefixlen, IPX_T *ip);


IDM_T is_mac_equal(const MAC_T *a, const MAC_T *b);

IDM_T is_ip_equal(const IPX_T *a, const IPX_T *b);
IDM_T is_ip_set(const IPX_T *ip);

IDM_T is_ip_valid( const IPX_T *ip, const uint8_t family );
IDM_T is_ip_local(IPX_T *ip);

IDM_T ip_netmask_validate(IPX_T *ipX, uint8_t mask, uint8_t family, uint8_t force);

IDM_T is_ip_net_equal(const IPX_T *netA, const IPX_T *netB, const uint8_t plen, const uint8_t family);



// core:

IDM_T rtnl_rcv( int fd, uint32_t pid, uint32_t seq, uint8_t cmd, uint8_t quiet, void (*func) (struct nlmsghdr *nh, void *data) ,void *data);

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
IDM_T kernel_get_route(uint8_t quiet, uint8_t family, uint32_t table, void (*func) (struct nlmsghdr *nh, void *data) );

struct sockaddr_storage set_sockaddr_storage(uint8_t af, IPX_T *ipx, int32_t port);
void set_ipexport( void (*func) (int8_t del, const struct net_key *dst, uint32_t oif_idx, IPX_T *via, uint32_t metric, uint8_t distance) );

IDM_T iproute(uint8_t cmd, int8_t del, uint8_t quiet, const struct net_key *dst, int32_t table_macro, int32_t prio_macro,
        int oif_idx, IPX_T *via, IPX_T *src, uint32_t metric, struct route_export *rte);

void ip_flush_routes(uint8_t family, int32_t table_macro);
void ip_flush_rules(uint8_t family, int32_t table_macro);

struct net_key bmx6AutoEUI64Ip6(ADDR_T mac, struct net_key *prefix);

IDM_T check_proc_sys_net(char *file, int32_t desired, int32_t *backup);

void sysctl_config(struct dev_node *dev_node);


int8_t track_rule_and_proceed(uint32_t network, int16_t mask, uint32_t prio, int16_t rt_table, char* iif,
                                      int16_t rule_type, int8_t del, int8_t cmd);



void init_ip(void);

void cleanup_ip(void);

