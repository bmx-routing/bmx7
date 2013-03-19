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


#define ARG_UHNA "unicastHna"



#define HNA6_PREFIXLEN_MIN 32
#define HNA4_PREFIXLEN_MIN 8

//#define ARG_UHNA_NETWORK     "network"
//
//#define	MIN_UHNA_PREFIXLEN   1
//#define	MAX_UHNA_PREFIXLEN   32
//#define ARG_UHNA_PREFIXLEN   "prefixlen"

#define MIN_IP_METRIC      0
#define MAX_IP_METRIC      U32_MAX
#define DEF_IP_METRIC      1024
#define ARG_IP_METRIC      "ipMetric"

#define ARG_TUN6_ADDRESS  "tun6Address"
#define HLP_TUN6_ADDRESS  "specify default IPv6 tunnel address and announced range"

#define ARG_TUN4_ADDRESS  "tun4Address"
#define HLP_TUN4_ADDRESS  "specify default IPv4 tunnel address and announced range"

//#define DEF_NIIT_PREFIX   { { { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0 } } }
//#define DEF_NIIT_4TO6_DEV "niit4to6"
//#define DEF_NIIT_6TO4_DEV "niit6to4"

#define TLV_OP_CUSTOM_HNA_MIN       (TLV_OP_CUSTOM_MIN + 0)
#define TLV_OP_CUSTOM_TUN6_GET_SHA  (TLV_OP_CUSTOM_MIN + 0)
#define TLV_OP_CUSTOM_HNA_ROUTE_ADD (TLV_OP_CUSTOM_MIN + 1)
#define TLV_OP_CUSTOM_HNA_ROUTE_DEL (TLV_OP_CUSTOM_MIN + 2)
#define TLV_OP_CUSTOM_HNA_MAX       (TLV_OP_CUSTOM_MIN + 2)

#define TLV_OP_CUSTOM_NIIT4TO6_ADD  (TLV_OP_CUSTOM_HNA_MAX + 1)
#define TLV_OP_CUSTOM_NIIT4TO6_DEL  (TLV_OP_CUSTOM_HNA_MAX + 2)
#define TLV_OP_CUSTOM_NIIT6TO4_ADD  (TLV_OP_CUSTOM_HNA_MAX + 3)
#define TLV_OP_CUSTOM_NIIT6TO4_DEL  (TLV_OP_CUSTOM_HNA_MAX + 4)

extern IDM_T (*hna_configure_niit4to6) (IDM_T del, struct net_key *key);
extern IDM_T (*hna_configure_niit6to4) (IDM_T del, struct net_key *key);

#define ARG_TUNS "tunnels"

#define ARG_TUN_NAME_PREFIX "tunDevName"
#define MAX_TUN_NAME_PREFIX_LEN 7
#define DEF_TUN_NAME_PREFIX "bmx6"




#define ARG_TUN_ADV  "tunIn"
#define ARG_TUN_ADV_REMOTE "remote"

#define ARG_TUN_ADV_INGRESS4 "ingressPrefix4"
#define ARG_TUN_ADV_INGRESS6 "ingressPrefix6"

#define ARG_TUN_ADV_SRC4_TYPE "srcType4"
#define ARG_TUN_ADV_SRC4_MIN "srcPrefix4Min"

#define ARG_TUN_ADV_SRC6_TYPE "srcType6"
#define ARG_TUN_ADV_SRC6_MIN "srcPrefix6Min"



#define ARG_TUN_IN_NET "tunInNet"
#define ARG_TUN_IN_NET_DEV ARG_TUN_ADV
#define ARG_TUN_IN_NET_BW "bandwidth"
#define MIN_TUN_IN_NET_BW UMETRIC_FM8_MIN
#define MAX_TUN_IN_NET_BW UMETRIC_MAX
#define DEF_TUN_IN_NET_BW UMETRIC_FM8_MIN

#define ARG_TUN_OUT          "tunOut"
#define ARG_TUN_OUT_NET      "network"
#define ARG_TUN_OUT_IP       "address"
#define ARG_TUN_OUT_TYPE     "srcType"
#define ARG_TUN_OUT_PREFIX   "srcRangeMin"
#define ARG_TUN_OUT_IPMETRIC "ipMetric"
#define MAX_TUN_OUT_IPMETRIC INT32_MAX
#define ARG_TUN_OUT_HOSTNAME "gwName"
#define ARG_TUN_OUT_PKID     "gwId"

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
#define MAX_TUN_OUT_HYSTERESIS MIN(100000, (UMETRIC_MULTIPLY_MAX - 100))

#define ARG_TUN_OUT_BONUS "bonus"
#define DEF_TUN_OUT_BONUS 0
#define MIN_TUN_OUT_BONUS 0
#define MAX_TUN_OUT_BONUS MIN(INT32_MAX, (UMETRIC_MULTIPLY_MAX - MAX_TUN_OUT_HYSTERESIS))

#define ARG_TUN_OUT_MTU "tunMtu"
#define DEF_TUN_OUT_MTU 0
//#define DEF_TUN_OUT_MTU 1460
#define MIN_TUN_OUT_MTU 1280
#define MAX_TUN_OUT_MTU 65535

#define ARG_EXPORT_DISTANCE "exportDistance"
#define TYP_EXPORT_DISTANCE_INFINITE 256
#define MIN_EXPORT_DISTANCE 0
#define MAX_EXPORT_DISTANCE TYP_EXPORT_DISTANCE_INFINITE
#define DEF_EXPORT_DISTANCE TYP_EXPORT_DISTANCE_INFINITE

#define ARG_EXPORT_ONLY   "exportOnly"
#define DEF_EXPORT_ONLY   0
#define MIN_EXPORT_ONLY   0
#define MAX_EXPORT_ONLY   1



#define  DESC_MSG_HNA_FLAG_NO_ROUTE 0x01

struct hna_node {
	struct net_key key;
	struct orig_node *on;
        uint8_t flags;
};

struct description_msg_hna4 {
	uint8_t prefixlen;
	uint8_t flags;
	IP4_T    ip4;
} __attribute__((packed));

#define DESCRIPTION_MSG_HNA4_FORMAT { \
{FIELD_TYPE_UINT, -1,  8, 1, FIELD_RELEVANCE_HIGH, "prefixlen"}, \
{FIELD_TYPE_UINT, -1,  8, 1, FIELD_RELEVANCE_LOW,  "reserved"},  \
{FIELD_TYPE_IP4,  -1, 32, 1, FIELD_RELEVANCE_HIGH, "address" },  \
FIELD_FORMAT_END }

struct description_msg_hna6 {
	uint8_t prefixlen;
	uint8_t flags;
	IP6_T    ip6;
} __attribute__((packed));

#define DESCRIPTION_MSG_HNA6_FORMAT { \
{FIELD_TYPE_UINT, -1,   8, 1, FIELD_RELEVANCE_HIGH, "prefixlen"}, \
{FIELD_TYPE_UINT, -1,   8, 1, FIELD_RELEVANCE_LOW,  "reserved"},  \
{FIELD_TYPE_IPX6, -1, 128, 1, FIELD_RELEVANCE_HIGH, "address" },  \
FIELD_FORMAT_END }





struct description_msg_tun6_adv {
        IP6_T localIp;
} __attribute__((packed));


#define DESCRIPTION_MSG_TUN6_ADV_FORMAT { \
{FIELD_TYPE_IPX6,     -1, 128, 1, FIELD_RELEVANCE_HIGH, "localIp" },  \
FIELD_FORMAT_END }



struct description_msg_tun4in6_ingress_adv {
        uint8_t tun6Id;
//        uint8_t srcType;
//        uint8_t srcPrefixMin;
        uint8_t ingressPrefixLen;
        IP4_T   ingressPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN4IN6_INGRESS_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "ingressPrefixLen" },  \
{FIELD_TYPE_IP4,      -1,  32, 1, FIELD_RELEVANCE_HIGH, "ingressPrefix" },  \
FIELD_FORMAT_END }

struct description_msg_tun6in6_ingress_adv {
        uint8_t tun6Id;
//        uint8_t srcType;
//        uint8_t srcPrefixMin;
        uint8_t ingressPrefixLen;
        IP6_T   ingressPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN6IN6_INGRESS_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "ingressPrefixLen" },  \
{FIELD_TYPE_IPX6,     -1, 128, 1, FIELD_RELEVANCE_HIGH, "ingressPrefix" },  \
FIELD_FORMAT_END }



#define TUN_SRC_TYPE_MIN           0x00
#define TUN_SRC_TYPE_UNDEF         0x00
#define TUN_SRC_TYPE_STATIC        0x01
#define TUN_SRC_TYPE_AUTO          0x02
#define TUN_SRC_TYPE_AHCP          0x03
#define TUN_SRC_TYPE_MAX           0x03

struct description_msg_tun4in6_src_adv {
        uint8_t tun6Id;
        uint8_t srcType;
        uint8_t srcPrefixMin;
        uint8_t srcPrefixLen;
        IP4_T   srcPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN4IN6_SRC_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "srcType" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "srcPrefixMin" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "srcPrefixLen" },  \
{FIELD_TYPE_IP4,      -1,  32, 1, FIELD_RELEVANCE_HIGH, "srcPrefix" },  \
FIELD_FORMAT_END }

struct description_msg_tun6in6_src_adv {
        uint8_t tun6Id;
        uint8_t srcType;
        uint8_t srcPrefixMin;
        uint8_t srcPrefixLen;
        IP6_T   srcPrefix;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN6IN6_SRC_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "srcType" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "srcPrefixMin" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "srcPrefixLen" },  \
{FIELD_TYPE_IPX6,     -1, 128, 1, FIELD_RELEVANCE_HIGH, "srcPrefix" },  \
FIELD_FORMAT_END }




struct description_msg_tun4in6_net_adv {
        uint8_t tun6Id;
        uint8_t bmx6_route_type;
        FMETRIC_U8_T bandwidth;
        uint8_t networkLen;
        IP4_T network;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN4IN6_NET_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "rtype" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 1, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "networklen" },  \
{FIELD_TYPE_IP4,      -1,  32, 1, FIELD_RELEVANCE_HIGH, "network" },  \
FIELD_FORMAT_END }

struct description_msg_tun6in6_net_adv {
        uint8_t tun6Id;
        uint8_t bmx6_route_type;
        FMETRIC_U8_T bandwidth;
        uint8_t networkLen;
        IP6_T network;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN6IN6_NET_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "rtype" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 1, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "networklen" },  \
{FIELD_TYPE_IPX6,     -1, 128, 1, FIELD_RELEVANCE_HIGH, "network" },  \
FIELD_FORMAT_END }


struct tunXin6_net_adv_node {
	struct list_node list;
        uint8_t bmx6_route_type;
        FMETRIC_U8_T bandwidth;
        struct net_key net;
};



struct tunXin6_net_adv_list_node {
	struct list_node list;
        struct list_head *adv_list; //LIST_SIMPEL()
};


extern struct list_head tunXin6_net_adv_list_list;

struct tun_bit_key_nodes {

        struct tun_search_node *tsn;
        struct tun_net_node *tnn;
};

struct tun_bit_key {

        uint32_t beIpMetric;
        UMETRIC_T beInvTunBitMetric;
        struct net_key invNetKey;
        struct tun_bit_key_nodes keyNodes;
};

struct tun_bit_node {

        struct tun_bit_key tunBitKey;

        uint8_t active;
};



#define NETWORK_NAME_LEN 32

//struct tun_search_key {
//        struct net_key netKey;
//        char netName[NETWORK_NAME_LEN];
//};

struct tun_search_node {

//        struct tun_search_key tunSearchKey;
        char nameKey[NETWORK_NAME_LEN];
	uint32_t bmx6RouteBits;
	uint16_t exportDistance;
	uint8_t exportOnly;
        struct net_key net;
        uint8_t netPrefixMin;
        uint8_t netPrefixMax;
        uint8_t allowOverlappingLargerPrefixes;
        uint8_t breakOverlappingSmallerPrefixes;
        
        uint32_t hysteresis;
        uint32_t bonus;
        uint32_t ipmetric;

        GLOBAL_ID_T global_id;
        struct net_key srcPrefix;

        uint8_t srcType;
        uint8_t srcPrefixMin;

//        uint8_t shown;

        struct avl_tree tun_bit_tree;

//        struct tun_net_node *act_tnn; //REMOVE
//        struct tun_net_node *best_tnn;//REMOVE
//        UMETRIC_T best_tnn_metric;    //REMOVE

};

struct tun_net_key {
        uint8_t bmx6RouteType;
        struct net_key netKey;
        struct tun_out_node *tun;
};

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
};


struct tun_out_node {

        // the advertised part (by description_msg_tun6_adv):
        IP6_T localIp;          // key for tunnel_in_tree
        IP6_T remoteIp;         // the primary IP of the remote tunnel end

        // the advertised part (by description_msg_src6in6_adv):
        struct net_key ingress4Prefix;
        struct net_key ingress6Prefix;

        uint8_t src4Type;
        uint8_t src4PrefixMin;

        uint8_t src6Type;
        uint8_t src6PrefixMin;

        //the status:
        struct tun_out_key tunOutKey; // key for tunnel_out_tree
        IFNAME_T name;
        uint8_t name_auto;
        uint32_t upIfIdx;
	uint16_t curr_mtu; // DEF_TUN_OUT_MTU == orig_mtu
	uint16_t orig_mtu;

        IPX_T src4Ip;
        IPX_T src6Ip;

        struct avl_tree tun_net_tree;
};


struct tun_in_node {

        IFNAME_T nameKey;    // key for tunnel_in_tree
        uint8_t name_auto;
        uint8_t remote_manual;

        // the advertised part (by description_msg_tun6_adv):
        IP6_T remote;

        // the advertised part (by description_msg_src6in6_adv):
        struct net_key ingress4Prefix;
        struct net_key ingress6Prefix;


        uint8_t src4Type;
        uint8_t src4PrefixMin;

        uint8_t src6Type;
        uint8_t src6PrefixMin;

        //the status:
        int16_t tun6Id;
        uint32_t upIfIdx;
};

char* bmx6RouteBits2String(uint32_t bmx6_route_bits);

void set_tunXin6_net_adv_list(uint8_t del, struct list_head *adv_list);

struct hna_node * find_overlapping_hna( IPX_T *ipX, uint8_t prefixlen, struct orig_node *except );
