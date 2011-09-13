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

#define ARG_INTERFACES "interfaces"


#define ARG_DEV  		"dev"
#define HLP_DEV                 "add or change interface device or its configuration"

#define ARG_DEV_GLOBAL_PREFIX   "globalPrefix"
#define HLP_DEV_GLOBAL_PREFIX   "specify global prefix for interface"

#define ARG_DEV_LLOCAL_PREFIX   "llocalPrefix"
#define HLP_DEV_LLOCAL_PREFIX   "specify link-local prefix for interface"

//#define ARG_DEV_TTL		"ttl"
//#define HLP_DEV_TTL             "set TTL of generated OGMs"
//#define ARG_DEV_CLONE		"clone"

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

#define DEF_IP_POLICY_ROUTING 1
#define ARG_IP_POLICY_ROUTING "policyRouting"

#define ARG_IP_THROW_RULES "throwRules"
#define DEF_IP_THROW_RULES 0

#define ARG_IP_PRIO_RULES "prioRules"
#define DEF_IP_PRIO_RULES 1


#define DEF_LO_RULE 1

#define RT_PRIO_MAX    -1
#define RT_PRIO_HOSTS  -1
#define RT_PRIO_NETS   -2
#define RT_PRIO_TUNS   -3
#define RT_PRIO_MIN    -3

#define ARG_IP_RULE_OFFSET "preference"
#define MIN_IP_RULE_OFFSET 3
#define MAX_IP_RULE_OFFSET 32765
#define DEF_IP_RULE_OFFSET 6000 // avoid conflicts with bmxd and others



#define RT_TABLE_MAX   -1
#define RT_TABLE_HOSTS -1
#define RT_TABLE_NETS  -2
#define RT_TABLE_TUNS  -3
#define RT_TABLE_MIN   -3

#define ARG_IP_TABLE_OFFSET "table"
#define DEF_IP_TABLE_OFFSET 60 //avoid conflicts with bmxd and others
#define MIN_IP_TABLE_OFFSET 0
#define MAX_IP_TABLE_OFFSET 32000




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

#define LINK_INFO 0
#define ADDR_INFO 1

// IPv4 versus IPv6 array-position identifier
#define BMX_AFINET4 0
#define BMX_AFINET6 1
#define ORT_MAX 1


//#define IPV6_MC_ALL_ROUTERS "FF02::2"

//#define IPV6_LINK_LOCAL_UNICAST_U32 0xFE800000
//#define IPV6_MULTICAST_U32 0xFF000000

extern const IPX_T ZERO_IP;
extern const MAC_T ZERO_MAC;
extern const struct link_dev_key ZERO_LINK_KEY;

extern const IP6_T   IP6_ALLROUTERS_MC_ADDR;
extern const IP6_T   IP6_LOOPBACK_ADDR;

extern const IP6_T   IP6_LINKLOCAL_UC_PREF;
extern const uint8_t IP6_LINKLOCAL_UC_PLEN
;

extern const IP6_T   IP6_MC_PREF;
extern const uint8_t IP6_MC_PLEN;

struct ort_data {
        uint8_t family;
        uint8_t max_prefixlen;

};

extern const struct ort_data ort_dat[ORT_MAX + 1];

#define AFINET2BMX( fam ) ( ((fam) == AF_INET) ? BMX_AFINET4 : BMX_AFINET6 )


extern struct dev_node *primary_dev_cfg;
extern IDM_T niit_enabled;

extern int32_t ip_throw_rules_cfg;
extern int32_t ip_policy_rt_cfg;
extern int32_t policy_routing;
#define POLICY_RT_UNSET -1
#define POLICY_RT_DISABLED 0
#define POLICY_RT_ENABLED 1

extern struct avl_tree if_link_tree;

extern struct avl_tree dev_ip_tree;
extern struct avl_tree dev_name_tree;


//extern int32_t prio_rules;
//extern int32_t throw_rules;

//extern IDM_T dev_soft_conf_changed; // temporary enabled to trigger changed interface configuration



struct ip_req {
	struct nlmsghdr nlmsghdr;
	struct rtgenmsg rtgenmsg;
};

struct rtmsg_req {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buff[ 256 ];
};

struct rtnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
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
	uint8_t active;
	uint8_t activate_again;
	uint16_t lndevs_tmp;

	DEVADV_IDX_T dev_adv_idx;
	int16_t dev_adv_msg;

	IFNAME_T name_phy_cfg;  //key for dev_name_tree
	IFNAME_T label_cfg;

	struct link_dev_node dummy_lndev;

	IPX_T llocal_ip_key; // copy of dev->if_llocal_addr->ip_addr;
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

	IPX_T global_prefix_conf;
	int16_t global_prefix_length_conf;

	IPX_T llocal_prefix_conf;
	int16_t llocal_prefix_length_conf;

	//size of plugin data is defined during intialization and depends on registered PLUGIN_DATA_DEV hooks
	void *plugin_data[];
};


struct track_key {
	IPX_T net;
	IFNAME_T iif;
	int8_t prio_macro;
	int8_t table_macro;
	uint8_t family;
	uint8_t mask;
	uint32_t metric;
	uint8_t cmd_type;
};

struct track_node {
        struct track_key k;
        uint32_t items;
	int8_t cmd;
};


//ip() commands:
enum {
	IP_NOP,
	IP_RULES,
	IP_RULE_FLUSH,
	IP_RULE_DEFAULT,    //basic rules to interfaces, host, and networks routing tables
	IP_RULE_TEST,
	IP_RULE_MAX,
	IP_ROUTES,
	IP_ROUTE_FLUSH_ALL,
	IP_ROUTE_FLUSH,
	IP_THROW_MY_HNA,
	IP_THROW_MY_NET,
	IP_ROUTE_HOST,
	IP_ROUTE_HNA,
	IP_ROUTE_TUNS,
	IP_ROUTE_MAX
};


//usefult IP tools:


char *family2Str(uint8_t family);


char *ipXAsStr(int family, const IPX_T *addr);
char *ipFAsStr(const IPX_T *addr);
char *ip4AsStr( IP4_T addr );
void  ipXToStr(int family, const IPX_T *addr, char *str);
void ipFToStr(const IPX_T *addr, char *str);

#define ipXto4( ipx ) ((ipx).s6_addr32[3])
void ip4ToX(IPX_T *ipx, IP4_T ip4);

char* macAsStr(const MAC_T* mac);

#define ip6AsStr( addr_ptr ) ipXAsStr( AF_INET6, addr_ptr)

IDM_T is_mac_equal(const MAC_T *a, const MAC_T *b);

IDM_T is_ip_equal(const IPX_T *a, const IPX_T *b);
IDM_T is_ip_set(const IPX_T *ip);

IDM_T is_ip_valid( const IPX_T *ip, const uint8_t family );
IDM_T is_ip_local(IPX_T *ip);

IDM_T ip_netmask_validate(IPX_T *ipX, uint8_t mask, uint8_t family, uint8_t force);

IDM_T is_ip_net_equal(const IPX_T *netA, const IPX_T *netB, const uint8_t plen, const uint8_t family);



// core:

IDM_T iptunnel(IDM_T del, char *name, uint8_t proto, IPX_T *local, IPX_T *remote);

uint8_t _af_cfg(const char *func);

#define af_cfg() _af_cfg(__FUNCTION__)

IDM_T ip(uint8_t family, uint8_t cmd, int8_t del, uint8_t quiet, const IPX_T *NET, uint8_t nmask,
        int8_t table_macro, int8_t prio_macro, IFNAME_T *iifname, int oif_idx, IPX_T *via, IPX_T *src, uint32_t metric);

//static IDM_T kernel_if_config(void);

void sysctl_config(struct dev_node *dev_node);

//static void dev_check(IDM_T ip_config_changed);
//static void dev_check2(void);


int8_t track_rule_and_proceed(uint32_t network, int16_t mask, uint32_t prio, int16_t rt_table, char* iif,
                                      int16_t rule_type, int8_t del, int8_t cmd);


IDM_T track_route(IPX_T *dst, int16_t mask, uint32_t metric, int16_t table, int16_t rta_t, int8_t del, int8_t track_t);



void init_ip(void);

void cleanup_ip(void);

