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


#define TLV_OP_CUSTOM_HNA_MIN       (TLV_OP_CUSTOM_MIN + 0)
#define TLV_OP_CUSTOM_TUN6_GET_SHA  (TLV_OP_CUSTOM_MIN + 0)
#define TLV_OP_CUSTOM_HNA_ROUTE_ADD (TLV_OP_CUSTOM_MIN + 1)
#define TLV_OP_CUSTOM_HNA_ROUTE_DEL (TLV_OP_CUSTOM_MIN + 2)
#define TLV_OP_CUSTOM_HNA_MAX       (TLV_OP_CUSTOM_MIN + 2)



struct hna_node {
	struct net_key key;
	struct orig_node *on;
        uint8_t flags;
};

struct dsc_msg_hna6 {
	uint8_t prefixlen;
	uint8_t flags;
	IP6_T    ip6;
} __attribute__((packed));

#define DESCRIPTION_MSG_HNA6_FORMAT { \
{FIELD_TYPE_UINT, -1,   8, 1, FIELD_RELEVANCE_HIGH, "prefixLen"}, \
{FIELD_TYPE_UINT, -1,   8, 1, FIELD_RELEVANCE_LOW,  "flags"},  \
{FIELD_TYPE_IPX6, -1, 128, 1, FIELD_RELEVANCE_HIGH, "address" },  \
FIELD_FORMAT_END }




struct hna_node * find_overlapping_hna( IPX_T *ipX, uint8_t prefixlen, struct orig_node *except );

struct plugin *hna_get_plugin(void);


//finally some tunnel stuff that is needed by other modules:

extern struct avl_tree tun_in_tree;
extern IFNAME_T tun_name_prefix;

#define DEF_TUN_NAME_PREFIX "X7"

#define ARG_TUNS "tunnels"
#define  DESC_MSG_HNA_FLAG_NO_ROUTE 0x01

struct tun_in_node {
	IFNAME_T nameKey; // key for tunnel_in_tree
	uint8_t name_auto;
	uint8_t remote_manual;

	// the advertised part (by description_msg_tun6_adv):
	IP6_T remote;
	struct net_key tunAddr46[2];


	// the advertised part (by description_msg_src6in6_adv):
	struct net_key ingressPrefix46[2];

	uint8_t srcType46[2];
	uint8_t srcPrefixMin46[2];
	uint8_t advProto;

	//the status:
	int16_t tun6Id;
	int32_t upIfIdx;

	struct avl_tree tun_dev_tree;
};

extern void (*set_tunXin6_net_adv_list) (uint8_t, void**);
