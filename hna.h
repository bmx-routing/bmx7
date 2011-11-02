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


#define ARG_UHNA "hna"

#define HNA6_PREFIXLEN_MIN 32
#define HNA4_PREFIXLEN_MIN 8

//#define ARG_UHNA_NETWORK     "network"
//
//#define	MIN_UHNA_PREFIXLEN   1
//#define	MAX_UHNA_PREFIXLEN   32
//#define ARG_UHNA_PREFIXLEN   "prefixlen"

#define MIN_IP_METRIC      0
#define MAX_IP_METRIC      U32_MAX
#define DEF_IP_METRIC      0
#define ARG_IP_METRIC      "ipMetric"

#define ARG_TUN6_ADDRESS  "tun6Address"
#define HLP_TUN6_ADDRESS  "specify default IPv6 tunnel address and announced range"

#define ARG_TUN4_ADDRESS  "tun4Address"
#define HLP_TUN4_ADDRESS  "specify default IPv4 tunnel address and announced range (IP SHOULD be assigned to niit4to6 interface!)"

#define DEF_NIIT_PREFIX   { { { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0 } } }
#define DEF_NIIT_4TO6_DEV "niit4to6"
#define DEF_NIIT_6TO4_DEV "niit6to4"

#define TLV_OP_CUSTOM_NIIT4TO6_ADD  (TLV_OP_CUSTOM_MIN + 0)
#define TLV_OP_CUSTOM_NIIT4TO6_DEL  (TLV_OP_CUSTOM_MIN + 1)
#define TLV_OP_CUSTOM_NIIT6TO4_ADD  (TLV_OP_CUSTOM_MIN + 2)
#define TLV_OP_CUSTOM_NIIT6TO4_DEL  (TLV_OP_CUSTOM_MIN + 3)
#define TLV_OP_CUSTOM_HNA_ROUTE_ADD (TLV_OP_CUSTOM_MIN + 4)
#define TLV_OP_CUSTOM_HNA_ROUTE_DEL (TLV_OP_CUSTOM_MIN + 5)


#define ARG_TUNS "tunnels"

#define ARG_TUN_NAME_PREFIX "tunDevName"
#define MAX_TUN_NAME_PREFIX_LEN 7
#define DEF_TUN_NAME_PREFIX "bmx6"




#define ARG_TUN_ADV  "tunInRemote"
#define ARG_TUN_ADV_NAME "dev"

#define ARG_TUN_ADV_INGRESS4 "ingressPrefix4"
#define ARG_TUN_ADV_INGRESS6 "ingressPrefix6"

#define ARG_TUN_ADV_SRC4_TYPE "srcType4"
#define ARG_TUN_ADV_SRC4_MIN "srcPrefix4Min"

#define ARG_TUN_ADV_SRC6_TYPE "srcType6"
#define ARG_TUN_ADV_SRC6_MIN "srcPrefix6Min"



#define ARG_TUN_NET "tunInNet"
#define ARG_TUN_NET_LOCAL ARG_TUN_ADV
#define ARG_TUN_NET_BW "bandwidth"

#define ARG_TUN_SEARCH_NAME       "tunOut"
#define ARG_TUN_SEARCH_NETWORK    "network"
#define ARG_TUN_SEARCH_IP         "address"
#define ARG_TUN_SEARCH_TYPE       "srcType"
#define ARG_TUN_SEARCH_PREFIX_MIN  "srcRangeMin"
#define ARG_TUN_SEARCH_IPMETRIC   "ipMetric"
#define MAX_TUN_SEARCH_IPMETRIC   INT32_MAX
#define ARG_TUN_SEARCH_HOSTNAME   "gwName"
#define ARG_TUN_SEARCH_PKID       "gwId"


struct net_key {
	uint8_t prefixlen;
	IPX_T net;
};

struct hna_node {
	struct net_key key;
	struct orig_node *on;
};

struct description_msg_hna4 {
	uint8_t prefixlen;
	uint8_t reserved;
	IP4_T    ip4;
} __attribute__((packed));

#define DESCRIPTION_MSG_HNA4_FORMAT { \
{FIELD_TYPE_UINT, -1,  8, 1, FIELD_RELEVANCE_HIGH, "prefixlen"}, \
{FIELD_TYPE_UINT, -1,  8, 1, FIELD_RELEVANCE_LOW,  "reserved"},  \
{FIELD_TYPE_IP4,  -1, 32, 1, FIELD_RELEVANCE_HIGH, "address" },  \
FIELD_FORMAT_END }

struct description_msg_hna6 {
	uint8_t prefixlen;
	uint8_t reserved;
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
        uint8_t reserved;
        FMETRIC_U8_T bandwidth;
        uint8_t networkLen;
        IP4_T network;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN4IN6_NET_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_LOW,  "reserved" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 1, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "networklen" },  \
{FIELD_TYPE_IP4,      -1,  32, 1, FIELD_RELEVANCE_HIGH, "network" },  \
FIELD_FORMAT_END }

struct description_msg_tun6in6_net_adv {
        uint8_t tun6Id;
        uint8_t reserved;
        FMETRIC_U8_T bandwidth;
        uint8_t networkLen;
        IP6_T network;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN6IN6_NET_ADV_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_MEDI, "tun6Id" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_LOW,  "reserved" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 1, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "networklen" },  \
{FIELD_TYPE_IPX6,     -1, 128, 1, FIELD_RELEVANCE_HIGH, "network" },  \
FIELD_FORMAT_END }





#define NETWORK_NAME_LEN 32

struct tun_search_key {

//        uint32_t ipmetric;
        uint8_t family;
        struct net_key network;
        char netName[NETWORK_NAME_LEN];
};

struct tun_search_node {

        struct tun_search_key key;
        
        uint32_t ipmetric;
//        uint8_t family;
//        struct net_key network;
//        char netName[NETWORK_NAME_LEN];

        uint8_t networkMin;
        GLOBAL_ID_T global_id;
        struct net_key srcPrefix;

        uint8_t srcType;
        uint8_t srcPrefixMin;
        
        struct tun_net_node *tun_net;
        uint8_t shown;
};

struct tun_net_key {
        struct net_key network;
        struct tunnel_node_out *tun;
};

struct tun_net_node {

        struct tun_net_key key;
        
        uint8_t family;
        FMETRIC_U8_T bandwidth;

        UMETRIC_T e2eMetric;

        struct avl_tree tun_search_tree;
};

struct tun_adv_key {
        struct orig_node *on;
        int16_t tun6Id;
};


struct tunnel_node_out {

        // the advertised part (by description_msg_tun6_adv):
        IP6_T localIp;          // key for tunnel_in_tree

        // the advertised part (by description_msg_src6in6_adv):
        struct net_key ingress4Prefix;
        struct net_key ingress6Prefix;

        uint8_t src4Type;
        uint8_t src4PrefixMin;

        uint8_t src6Type;
        uint8_t src6PrefixMin;

        //the status:
        struct tun_adv_key key; // key for tunnel_out_tree
        IFNAME_T name;
        uint8_t name_auto;
        uint32_t upIfIdx;

        IPX_T src4Ip;
        IPX_T src6Ip;

        struct avl_tree tun_net_tree;
};


struct tunnel_node_in {

        // the advertised part (by description_msg_tun6_adv):
        IP6_T remoteIp;          // key for tunnel_in_tree

        // the advertised part (by description_msg_src6in6_adv):
        struct net_key ingress4Prefix;
        struct net_key ingress6Prefix;

        uint8_t src4Type;
        uint8_t src4PrefixMin;

        uint8_t src6Type;
        uint8_t src6PrefixMin;

        //the status:
        int16_t tun6Id;
        IFNAME_T name;
        uint8_t name_auto;
        uint32_t upIfIdx;
};

