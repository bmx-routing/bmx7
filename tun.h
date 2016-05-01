/*
 * Copyright (c) 2012-2013  Axel Neumann
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


//extern struct net_key tun4_address;
//extern struct net_key tun6_address;


#define ARG_TUN_NAME_PREFIX "tunDevName"
#define MAX_TUN_NAME_PREFIX_LEN 5
//#define DEF_TUN_NAME_PREFIX see hna.h: DEF_TUN_NAME_PREFIX
#define DEF_TUN_NAME_TYPE_IN "In_"
#define DEF_TUN_NAME_TYPE_OUT "Out_"
#define DEF_TUN_NAME_TYPE_CATCH4 "C4"
#define DEF_TUN_NAME_TYPE_CATCH6 "C6"

#define ARG_TUN_OUT_TIMEOUT "tunOutTimeout"
#define MIN_TUN_OUT_TO 0
#define MAX_TUN_OUT_TO REGISTER_TASK_TIMEOUT_MAX
#define DEF_TUN_OUT_TO 60000

#define MIN_TUN_PROACTIVE_ROUTES 0
#define MAX_TUN_PROACTIVE_ROUTES 1
#define DEF_TUN_PROACTIVE_ROUTES 1
#define ARG_TUN_PROACTIVE_ROUTES "proactiveTunRoutes"
#define HLP_TUN_PROACTIVE_ROUTES "proactively configure all tunnel routes via dedicated tunnels"


#define TDN_STATE_CATCHALL 1
#define TDN_STATE_DEDICATED 0
#define TDN_STATE_CURRENT -1


#define ARG_TUN_DEV  "tunDev"
#define ARG_TUN_DEV_ADDR4 "tun4Address"
#define HLP_TUN_DEV_ADDR4  "specify default IPv4 tunnel address and announced range"
#define ARG_TUN_DEV_ADDR6 "tun6Address"
#define HLP_TUN_DEV_ADDR6  "specify default IPv6 tunnel address and announced range"


#define ARG_TUN_DEV_REMOTE "remote"

#define ARG_TUN_DEV_INGRESS4 "ingress4Prefix"
#define ARG_TUN_DEV_INGRESS6 "ingress6Prefix"

#define ARG_TUN_DEV_SRC4_TYPE "src4Type"
#define ARG_TUN_DEV_SRC4_MIN "src4PrefixMin"

#define ARG_TUN_DEV_SRC6_TYPE "src6Type"
#define ARG_TUN_DEV_SRC6_MIN "src6PrefixMin"



#define ARG_TUN_IN "tunIn"

#define HLP_TUN_IN_DEV "to be used incoming tunnel interface name"

#define ARG_TUN_IN_NET "network"
#define ARG_TUN_IN_BW  "bandwidth"
#define MIN_TUN_IN_BW  UMETRIC_FM8_MIN
#define MAX_TUN_IN_BW  UMETRIC_MAX
#define DEF_TUN_IN_BW  1000
#define HLP_TUN_IN_BW  "bandwidth to network as bits/sec  default: 1000  range: [36 ... 128849018880]"

#define ARG_TUN_OUT          "tunOut"
#define ARG_TUN_OUT_NET      "network"
#define ARG_TUN_OUT_SRCRT    "srcNet"
#define ARG_TUN_OUT_TYPE     "srcType"
#define ARG_TUN_OUT_PREFIX   "srcRangeMin"

#define ARG_TUN_OUT_IPMETRIC "ipMetric"
#define DEF_TUN_OUT_IPMETRIC DEF_IP_METRIC
#define MAX_TUN_OUT_IPMETRIC INT32_MAX
#define MIN_TUN_OUT_IPMETRIC 0

#define ARG_TUN_OUT_GWNAME "gwName"
#define ARG_TUN_OUT_PKID     "gwId"

#define ARG_TUN_OUT_TRULE "tableRule"
#define DEF_TUN_OUT_TABLE DEF_IP_TABLE_TUN
#define MIN_TUN_OUT_TABLE MIN_IP_TABLE_TUN
#define MAX_TUN_OUT_TABLE MAX_IP_TABLE_TUN
#define DEF_TUN_OUT_RULE DEF_IP_RULE_TUN
#define MIN_TUN_OUT_RULE MIN_IP_RULE_TUN
#define MAX_TUN_OUT_RULE MAX_IP_RULE_TUN
#define DEF_TUN_OUT_TRULE "32767/254"
#define FORM_TUN_OUT_TRULE "<PREF>/<TABLE>"

#define MIN_TUN_OUT_PREFIX 0
#define MAX_TUN_OUT_PREFIX 129
#define TYP_TUN_OUT_PREFIX_NET 129 //assumes prefix from ARG_TUN_OUT_NET

#define ARG_TUN_OUT_PREFIX_MIN "minPrefixLen"
#define DEF_TUN_OUT_PREFIX_MIN TYP_TUN_OUT_PREFIX_NET

#define ARG_TUN_OUT_PREFIX_MAX "maxPrefixLen"
#define DEF_TUN_OUT_PREFIX_MAX 128

#define ARG_TUN_OUT_OVLP_ALLOW "allowOverlappingPrefix"
#define DEF_TUN_OUT_OVLP_ALLOW 1
#define ARG_TUN_OUT_OVLP_BREAK "breakOverlappingPrefix"
#define DEF_TUN_OUT_OVLP_BREAK 1
#define MIN_TUN_OUT_OVLP 0
#define MAX_TUN_OUT_OVLP 1

#define ARG_TUN_OUT_HYSTERESIS "hysteresis"
#define DEF_TUN_OUT_HYSTERESIS 20
#define MIN_TUN_OUT_HYSTERESIS 0
#define MAX_TUN_OUT_HYSTERESIS XMIN(100000, (UMETRIC_MULTIPLY_MAX - 100))

#define ARG_TUN_OUT_RATING "rating"
#define DEF_TUN_OUT_RATING 100
#define MIN_TUN_OUT_RATING 0
#define MAX_TUN_OUT_RATING XMIN(INT32_MAX, (UMETRIC_MULTIPLY_MAX - MAX_TUN_OUT_HYSTERESIS))

#define ARG_TUN_OUT_MIN_BW "minBandwidth"
#define MIN_TUN_OUT_MIN_BW UMETRIC_FM8_MIN
#define MAX_TUN_OUT_MIN_BW UMETRIC_MAX
#define DEF_TUN_OUT_MIN_BW DEF_TUN_IN_BW

#define ARG_TUN_OUT_MTU "tunMtu"
#define DEF_TUN_OUT_MTU 0
//#define DEF_TUN_OUT_MTU 1460
#define MIN_TUN_OUT_MTU 1280
#define MAX_TUN_OUT_MTU 65535


#define ARG_EXPORT_ONLY   "exportOnly"
#define DEF_EXPORT_ONLY   0
#define MIN_EXPORT_ONLY   0
#define MAX_EXPORT_ONLY   1


struct dsc_msg_tun6 {
	IP6_T localIp;
} __attribute__((packed));


#define DESCRIPTION_MSG_TUN6_ADV_FORMAT { \
{FIELD_TYPE_IPX6,     -1, 128, 1, FIELD_RELEVANCE_HIGH, "localIp" },  \
FIELD_FORMAT_END }

struct dsc_msg_tun4in6ingress {
	uint8_t tun6Id;
	//        uint8_t srcType;
	//        uint8_t srcPrefixMin;
	uint8_t ingressPrefixLen;
	IP4_T ingressPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN4IN6_INGRESS_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "ingressPrefixLen" },  \
{FIELD_TYPE_IP4,      -1,  32, 0, FIELD_RELEVANCE_HIGH, "ingressPrefix" },  \
FIELD_FORMAT_END }

struct dsc_msg_tun6in6ingress {
	uint8_t tun6Id;
	//        uint8_t srcType;
	//        uint8_t srcPrefixMin;
	uint8_t ingressPrefixLen;
	IP6_T ingressPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN6IN6_INGRESS_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "ingressPrefixLen" },  \
{FIELD_TYPE_IPX6,     -1, 128, 0, FIELD_RELEVANCE_HIGH, "ingressPrefix" },  \
FIELD_FORMAT_END }



#define TUN_SRC_TYPE_MIN           0x00
#define TUN_SRC_TYPE_UNDEF         0x00
#define TUN_SRC_TYPE_STATIC        0x01
#define TUN_SRC_TYPE_AUTO          0x02
#define TUN_SRC_TYPE_AHCP          0x03
#define TUN_SRC_TYPE_MAX           0x03

struct dsc_msg_tun4in6src {
	uint8_t tun6Id;
	uint8_t srcType;
	uint8_t srcPrefixMin;
	uint8_t srcPrefixLen;
	IP4_T srcPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN4IN6_SRC_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "srcType" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "srcPrefixMin" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "srcPrefixLen" },  \
{FIELD_TYPE_IP4,      -1,  32, 0, FIELD_RELEVANCE_HIGH, "srcPrefix" },  \
FIELD_FORMAT_END }

struct dsc_msg_tun6in6src {
	uint8_t tun6Id;
	uint8_t srcType;
	uint8_t srcPrefixMin;
	uint8_t srcPrefixLen;
	IP6_T srcPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN6IN6_SRC_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "srcType" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "srcPrefixMin" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "srcPrefixLen" },  \
{FIELD_TYPE_IPX6,     -1, 128, 0, FIELD_RELEVANCE_HIGH, "srcPrefix" },  \
FIELD_FORMAT_END }

struct dsc_msg_tun4in6net {
	uint8_t tun6Id;
	uint8_t proto_type;
	FMETRIC_U8_T bandwidth;
	uint8_t networkLen;
	IP4_T network;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN4IN6_NET_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "rtype" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 0, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "networkLen" },  \
{FIELD_TYPE_IP4,      -1,  32, 0, FIELD_RELEVANCE_HIGH, "network" },  \
FIELD_FORMAT_END }

struct dsc_msg_tun6in6net {
	uint8_t tun6Id;
	uint8_t proto_type;
	FMETRIC_U8_T bandwidth;
	uint8_t networkLen;
	IP6_T network;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN6IN6_NET_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "rtype" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 0, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
{FIELD_TYPE_UINT,     -1,   8, 0, FIELD_RELEVANCE_HIGH, "networkLen" },  \
{FIELD_TYPE_IPX6,     -1, 128, 0, FIELD_RELEVANCE_HIGH, "network" },  \
FIELD_FORMAT_END }

struct tunXin6_net_adv_node {
	uint8_t af; //family
	uint8_t more;
	struct dsc_msg_tun6in6net adv;

	//	struct list_node list;
	//	uint8_t bmx7_route_type;
	//	FMETRIC_U8_T bandwidth;
	//	struct net_key net;
	char *tunInDev;
};

/*
// requirements:
// - lightweight possibilty for gw to check client ID and request authenticity (no other client send it)
//   -> include: ClientPubSHA, reqSignature
// - lightweight possibilty for gw to check gw authenticity request (meant for this gw)
//   -> include: GwPubSHA
// - let client request tunnel endpoints
// - lightweight possibilty for gw to check request against non-replication (ogm-sqn)
//   -> include: descSqn and recent ogmSqn
// - lightweight possibilty for gw to check request shared-key integritiy (if includes a shared key)
//   -> include: gwPubKey encrypted shared-key, maybe also tunnel endpoints and src networks
// optional:
// - let client request tunneled src networks (routes via tunnel from gw to client)
//   -> explicit routes or refHash
struct dedicated_msg_tun6_req {
	SHA1_T clientRoutesRefSha;
} __attribute__((packed));

struct dedicated_hdr_tun6_req {
//  SHA1_T     clientPubSha; // from packet header
    SHA1_T     gwPubSha;
    IP6_T      gwTun6Ip;
    IP6_T      clientTun6Ip;
    DESC_SQN_T clientDescSqn;
    OGM_SQN_T  clientOgmSqn;
    RSA1024_T  encTunKey;
    RSA1024_T  clientSign;
} __attribute__((packed));
 */




struct tunXin6_net_adv_list_node {
	struct list_node list;
	struct tunXin6_net_adv_node **adv_list;
};


extern struct list_head tunXin6_net_adv_list_list;

struct tun_bit_key_nodes {
	struct tun_search_node *tsn;
	struct tun_net_node *tnn;
} __attribute__((packed));

struct tun_bit_key {
	uint32_t beIpRule;
	uint32_t beIpMetric;
	struct net_key invRouteKey;
	UMETRIC_T beInvTunBitMetric;
	struct tun_bit_key_nodes keyNodes;
} __attribute__((packed));

struct tun_bit_node {
	struct tun_bit_key tunBitKey;

	//uint8_t active; //REMOVE
	struct tun_dev_node *active_tdn;

	uint32_t ipTable;
	IDM_T possible;
};



#define NETWORK_NAME_LEN 32

//struct tun_search_key {
//        struct net_key netKey;
//        char netName[NETWORK_NAME_LEN];
//};

struct tun_search_node {
	//        struct tun_search_key tunSearchKey;
	char nameKey[NETWORK_NAME_LEN];
	uint64_t bmx7RouteBits;
	int16_t routeSearchProto;
	int16_t routeSetProto;
	uint16_t exportDistance;
	uint8_t exportOnly;
	struct net_key net;
	uint8_t netPrefixMin;
	uint8_t netPrefixMax;
	uint8_t allowLargerPrefixRoutesWithWorseTunMetric;
	uint8_t breakSmallerPrefixRoutesWithBetterTunMetric;

	uint32_t hysteresis;
	uint32_t rating;
	UMETRIC_T minBW;
	uint32_t ipmetric;
	uint32_t iptable;
	uint32_t iprule;

	GLOBAL_ID_T global_id;
	char gwName[MAX_HOSTNAME_LEN];
	struct net_key srcRtNet;
	//	IFNAME_T tunName;

	uint8_t srcType;
	uint8_t srcPrefixMin;

	//        uint8_t shown;

	struct avl_tree tun_bit_tree;

	//        struct tun_net_node *act_tnn; //REMOVE
	//        struct tun_net_node *best_tnn;//REMOVE
	//        UMETRIC_T best_tnn_metric;    //REMOVE

};

struct tun_net_key {
	uint8_t bmx7RouteType;
	uint8_t bmx7RouteType__REMOVE;
	struct net_key netKey;
	struct tun_out_node *ton;
} __attribute__((packed));

struct tun_net_node {
	struct tun_net_key tunNetKey;

	uint32_t eval_counter;
	uint32_t tlv_new_counter;

	FMETRIC_U8_T bandwidth;

	UMETRIC_T e2eMetric;

	struct avl_tree tun_bit_tree;
};

struct tun_out_key {
	struct orig_node *on;
	int16_t tun6Id;
} __attribute__((packed));

struct tun_out_node {
	// the advertised part (by description_msg_tun6_adv):
	IP6_T localIp; // key for tunnel_in_tree
	IP6_T remoteIp; // the primary IP of the remote tunnel end

	// the advertised part (by description_msg_src6in6_adv):
	struct net_key ingressPrefix[2];

	uint8_t srcType[2];
	uint8_t srcPrefixMin[2];


	//the status:
	struct tun_out_key tunOutKey; // key for tunnel_out_tree

	//struct tun_dev_node *tdnUP[2]; //0:ipv6, 1:ipv4 //REMOVE
	struct tun_dev_node *tdnDedicated[2]; //0:ipv6, 1:ipv4
	struct tun_dev_node *tdnCatchAll[2]; //0:ipv6, 1:ipv4

	//TIME_SEC_T tdnLastUsed_ts;

	struct avl_tree tun_net_tree;
};

struct tun_catch_key {
	uint8_t afKey; //only set if registered in tun_catch_tree
	struct tun_in_node *tin;
} __attribute__((packed));

struct tun_dev_node {
	IFNAME_T nameKey;
	struct tun_catch_key tunCatchKey;
	int32_t tunCatch_fd;

	int32_t ifIdx;
	uint16_t curr_mtu; // DEF_TUN_OUT_MTU == orig_mtu
	uint16_t orig_mtu;

	struct user_net_device_stats stats;
	IDM_T stats_captured;

	struct avl_tree tun_bit_tree[2];
};


