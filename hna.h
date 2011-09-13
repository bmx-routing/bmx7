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

#define ARG_UHNA_NETWORK     "network"

#define	MIN_UHNA_PREFIXLEN   1
#define	MAX_UHNA_PREFIXLEN   32
#define ARG_UHNA_PREFIXLEN   "prefixlen"

#define MIN_IP_METRIC      0
#define MAX_IP_METRIC      U32_MAX
#define DEF_IP_METRIC      0
#define ARG_IP_METRIC      "ipMetric"

#define ARG_NIIT          "niitSource"
#define HLP_NIIT          "specify niit4to6 source IP address (IP MUST be assigned to niit4to6 interface!)"
#define DEF_NIIT_PREFIX   { { { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0,0,0 } } }
#define DEF_NIIT_4TO6_DEV "niit4to6"
#define DEF_NIIT_6TO4_DEV "niit6to4"

#define TLV_OP_CUSTOM_NIIT4TO6_ADD  (TLV_OP_CUSTOM_MIN + 0)
#define TLV_OP_CUSTOM_NIIT4TO6_DEL  (TLV_OP_CUSTOM_MIN + 1)
#define TLV_OP_CUSTOM_NIIT6TO4_ADD  (TLV_OP_CUSTOM_MIN + 2)
#define TLV_OP_CUSTOM_NIIT6TO4_DEL  (TLV_OP_CUSTOM_MIN + 3)
#define TLV_OP_CUSTOM_HNA_ROUTE_ADD (TLV_OP_CUSTOM_MIN + 4)
#define TLV_OP_CUSTOM_HNA_ROUTE_DEL (TLV_OP_CUSTOM_MIN + 5)



#define ARG_TUN_NAME_PREFIX "tunnelName"
#define MAX_TUN_NAME_PREFIX_LEN 7
#define DEF_TUN_NAME_PREFIX "bmx6"

#define ARG_TUN_SRC  "tunnelSource"
#define ARG_TUN_SRC_NAME "dev"
#define ARG_TUNS "tunnels"

#define ARG_TUN_ADV "tunnelAdv"
#define ARG_TUN_ADV_SRC "tunnelSrc"
#define ARG_TUN_ADV_BW "bandwidth"

#define ARG_TUN_SEARCH "tunnelSearch"
#define ARG_TUN_SEARCH_NETWORK "network"
#define ARG_TUN_SEARCH_IPMETRIC "ipmetric"
#define MAX_TUN_SEARCH_IPMETRIC INT32_MAX
#define ARG_TUN_SEARCH_HOSTNAME "hostname"
#define ARG_TUN_SEARCH_PKID "pkid"


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




struct description_msg_tun_adv {
        IP6_T srcTunIp;
        IPX_T network;
        uint8_t prefixlen;
        FMETRIC_U8_T bandwidth;
} __attribute__((packed));

#define DESCRIPTION_MSG_TUN_ADV_FORMAT { \
{FIELD_TYPE_IPX,      -1, 128, 1, FIELD_RELEVANCE_HIGH, "srcTunIp" },  \
{FIELD_TYPE_IPX,      -1, 128, 1, FIELD_RELEVANCE_HIGH, "network" },  \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "prefixlen" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 1, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
FIELD_FORMAT_END }


struct tun_adv_node {
        struct orig_node *on;

        IP6_T srcTunIp;
        IPX_T network;
        uint8_t prefixlen;
        FMETRIC_U8_T bandwidth;
        UMETRIC_T e2e_path;

        struct avl_tree tun_search_tree;
        struct tunnel_node *tun_out;

};


#define NETWORK_NAME_LEN 32

struct tun_search_node {
        char netName[NETWORK_NAME_LEN];
        IPX_T net;
        uint8_t prefixlen;
        uint8_t family;
        uint32_t ipmetric;
        GLOBAL_ID_T global_id;

        struct tun_adv_node *tun_adv;
};


struct tunnel_node {
        IP6_T srcTunIp;
        IFNAME_T name;
        uint8_t name_auto;
        uint8_t up;

        struct avl_tree tun_adv_tree;

//        struct orig_node *on;
};




#define TUNNEL_NODE_FORMAT { \
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6,          tunnel_node, srcTunIp,     1, FIELD_RELEVANCE_HIGH), \
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,   tunnel_node, name,         1, FIELD_RELEVANCE_HIGH), \
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,          tunnel_node, name_auto,    1, FIELD_RELEVANCE_MEDI), \
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,          tunnel_node, up,           1, FIELD_RELEVANCE_HIGH), \
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_BINARY, tunnel_node, tun_adv_tree, 1, FIELD_RELEVANCE_LOW), \
        FIELD_FORMAT_END }


