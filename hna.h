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

#define MIN_UHNA_METRIC      0
#define MAX_UHNA_METRIC      U32_MAX
#define DEF_UHNA_METRIC      0
#define ARG_UHNA_METRIC      "metric"

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

#define ARG_TUN_NAME_PREFIX "tunnelNamePrefix"
#define MAX_TUN_NAME_PREFIX_LEN 7
#define DEF_TUN_NAME_PREFIX "bmx6"


#define ARG_IN_TUN  "inTunnel"
#define ARG_IN_TUNS "inTunnels"

#define ARG_OUT_TUN "outTunnel"
#define ARG_OUT_TUNS "outTunnels"

#define ARG_TUN_NAME "name"
#define ARG_TUN_TYPE "type"
#define DEF_TUN_TYPE 0
#define MIN_TUN_TYPE 0
#define MAX_TUN_TYPE 0
#define TUN_TYPE_ANY 0
#define TUN_TYPE_IP6IP6 1
#define TUN_TYPE_IP4IP6 2
#define TUN_TYPE_GRE 3


#define ARG_GWIN "gateway"
#define ARG_GWIN_TUN "tun"
#define ARG_GWIN_BW "bandwidth"



struct uhna_key {
	uint8_t family;
	uint8_t prefixlen;
	IPX_T glip;
	uint32_t metric_nl;
};

struct uhna_node {
	struct uhna_key key;
	struct orig_node *on;
};

struct description_msg_hna4 {
	uint8_t prefixlen;
	uint8_t reserved;
	IP4_T    ip4;
	uint32_t metric;
} __attribute__((packed));

#define DESCRIPTION_MSG_HNA4_FORMAT { \
{FIELD_TYPE_UINT, -1,  8, 1, FIELD_RELEVANCE_HIGH, "prefixlen"}, \
{FIELD_TYPE_UINT, -1,  8, 1, FIELD_RELEVANCE_LOW,  "reserved"},  \
{FIELD_TYPE_IP4,  -1, 32, 1, FIELD_RELEVANCE_HIGH, "address" },  \
{FIELD_TYPE_UINT, -1, 32, 0, FIELD_RELEVANCE_HIGH, "metric" },   \
FIELD_FORMAT_END }

struct description_msg_hna6 {
	uint8_t prefixlen;
	uint8_t reserved;
	IP6_T    ip6;
	uint32_t metric;
} __attribute__((packed));

#define DESCRIPTION_MSG_HNA6_FORMAT { \
{FIELD_TYPE_UINT, -1,   8, 1, FIELD_RELEVANCE_HIGH, "prefixlen"}, \
{FIELD_TYPE_UINT, -1,   8, 1, FIELD_RELEVANCE_LOW,  "reserved"},  \
{FIELD_TYPE_IPX6, -1, 128, 1, FIELD_RELEVANCE_HIGH, "address" },  \
{FIELD_TYPE_UINT, -1,  32, 0, FIELD_RELEVANCE_HIGH, "metric" },   \
FIELD_FORMAT_END }




struct gw_key {
	uint8_t prefixlen;
	IPX_T dst;
        IPX_T src;
};

struct gw_node {
	struct gw_key key;
	struct orig_node *on;
        UMETRIC_T bw;

};

struct description_msg_gw {
        uint8_t prefixlen;
        FMETRIC_U8_T bandwidth;
        IP6_T hna;
        IP6_T src;
} __attribute__((packed));

#define DESCRIPTION_MSG_GW_FORMAT { \
{FIELD_TYPE_UINT,     -1,   8, 1, FIELD_RELEVANCE_HIGH, "prefixlen" },  \
{FIELD_TYPE_FMETRIC8, -1,   8, 1, FIELD_RELEVANCE_HIGH, "bandwidth" },  \
{FIELD_TYPE_IPX,      -1, 128, 1, FIELD_RELEVANCE_HIGH, "hna" },  \
{FIELD_TYPE_IPX,      -1, 128, 1, FIELD_RELEVANCE_HIGH, "src" },  \
FIELD_FORMAT_END }



/*
//
//struct description_msg_tunnel {
//        IP6_T dst;
//        IP6_T src;
//        uint8_t type;
//} __attribute__((packed));
//
//#define DESCRIPTION_MSG_TUNNEL_FORMAT { \
//{FIELD_TYPE_IPX6, -1, 128, 1, FIELD_RELEVANCE_HIGH, "src" },  \
//{FIELD_TYPE_IPX6, -1, 128, 1, FIELD_RELEVANCE_HIGH, "dst" },  \
//{FIELD_TYPE_UINT, -1,   8, 1, FIELD_RELEVANCE_HIGH, "type" },  \
//FIELD_FORMAT_END }
*/

struct tun_node {
        IFNAME_T name;
        uint8_t name_auto;
        uint8_t up;
        IP6_T src;
        IP6_T dst;
};


#define TUNNEL_NODE_FORMAT { \
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR, tun_node, name,        1, FIELD_RELEVANCE_HIGH), \
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,        tun_node, name_auto,   1, FIELD_RELEVANCE_MEDI), \
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,        tun_node, up,          1, FIELD_RELEVANCE_HIGH), \
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6,        tun_node, src,         1, FIELD_RELEVANCE_HIGH), \
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6,        tun_node, dst,         1, FIELD_RELEVANCE_HIGH), \
        FIELD_FORMAT_END }


struct orig_tuns {
        uint16_t msgs;
        struct tun_node tun[];
};
