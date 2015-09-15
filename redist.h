/*
 * Copyright (c) 2013  Axel Neumann
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
#define ARG_EXPORT           "export"

#define ARG_EXPORT_UHNA      "unicastHna"
#define DEF_EXPORT_UHNA      0

#define ARG_EXPORT_RTYPE_BMX "bmx6"
#define DEF_EXPORT_RTYPE_BMX 1

#define ARG_EXPORT_ONLY   "exportOnly"
#define DEF_EXPORT_ONLY   0
#define MIN_EXPORT_ONLY   0
#define MAX_EXPORT_ONLY   1
*/



#define ARG_REDIST_NET    "network"
#define HLP_REDIST_NET    "network permit filter (optional)"

#define ARG_REDIST_BW     "bandwidth"
#define HLP_REDIST_BW     "bandwidth to network as bits/sec  default: 1000  range: [36 ... 128849018880]"

#define ARG_REDIST_METRIC "metric"
#define DEF_REDIST_METRIC 0
#define MIN_REDIST_METRIC 0
#define MAX_REDIST_METRIC INT32_MAX

#define ARG_REDIST_DISTANCE "distance"
#define DEF_REDIST_DISTANCE 0
#define MIN_REDIST_DISTANCE 0
#define MAX_REDIST_DISTANCE UINT8_MAX

#define MIN_REDIST_PREFIX 0
#define MAX_REDIST_PREFIX 129
#define TYP_REDIST_PREFIX_NET 129 //assumes prefix from ARG_TUN_OUT_NET

#define ARG_REDIST_PREFIX_MIN "minPrefixLen"
#define HLP_REDIST_PREFIX_MIN "minumum prefix len (129 = network prefix len)"
#define DEF_REDIST_PREFIX_MIN TYP_REDIST_PREFIX_NET

#define ARG_REDIST_PREFIX_MAX "maxPrefixLen"
#define HLP_REDIST_PREFIX_MAX "maximum prefix len (129 = network prefix len)"
#define DEF_REDIST_PREFIX_MAX 128

#define ARG_REDIST_TABLE  "table"
#define DEF_REDIST_TABLE  0
#define MIN_REDIST_TABLE  0
#define MAX_REDIST_TABLE  MAX_IP_TABLE
#define HLP_REDIST_TABLE "table to be searched for to-be redistributed routes (mandatory)"

#define ARG_REDIST_AGGREGATE "aggregatePrefixLen"
#define HLP_REDIST_AGGREGATE "minimum prefix len to aggregate redistributions"
#define MIN_REDIST_AGGREGATE 0
#define MAX_REDIST_AGGREGATE 128
#define DEF_REDIST_AGGREGATE 0

//#define MIN_REDIST_RTYPE_ENABLED 0
//#define MAX_REDIST_RTYPE_ENABLED 1
//#define DEF_REDIST_RTYPE_ENABLED 0


#define ARG_REDIST_HYSTERESIS "hysteresis"
#define DEF_REDIST_HYSTERESIS 20
#define MIN_REDIST_HYSTERESIS 0
#define MAX_REDIST_HYSTERESIS XMIN(100000, (UMETRIC_MULTIPLY_MAX - 100))

#define NETWORK_NAME_LEN 32





struct redist_out_key {
        IFNAME_T tunInDev;
	uint8_t proto_type;
        FMETRIC_U8_T bandwidth;
        struct net_key net;
        uint8_t must_be_one; // to find_next route_type and bandwidth if net is zero
} __attribute__((packed));

struct redist_out_node {
        struct redist_out_key k;
        uint8_t minAggregatePrefixLen;
        uint8_t old;
        uint8_t new;
};

struct redist_in_key {
        struct net_key net;
        IPX_T via;
	uint32_t table;
        uint32_t ifindex;
        uint8_t proto_type;
} __attribute__((packed));

struct redist_in_node {
	struct redist_in_key k;

	int16_t cnt;
	uint8_t flags;
	uint8_t message;
	uint8_t old;
	uint8_t distance;
	uint32_t metric;
	TIME_T stamp;
	struct redistr_opt_node *roptn;
};

struct redistr_opt_node {
        char nameKey[NETWORK_NAME_LEN];
        struct net_key net;
        uint32_t hysteresis;
	uint32_t table;
	uint16_t searchProto;
	uint16_t advProto;
	uint8_t netPrefixMin;
        uint8_t netPrefixMax;
        uint8_t minAggregatePrefixLen;
        FMETRIC_U8_T bandwidth;
	char *tunInDev;
};

void redist_dbg(int8_t dbgl, int8_t dbgt, const char *func, struct redist_in_node *zrn, char* misc1, char* misc2);
void update_tunXin6_net_adv_list(struct avl_tree *redist_out_tree, struct tunXin6_net_adv_node **tunXin6_net_adv_list);
IDM_T redistribute_routes(struct avl_tree *redist_out_tree, struct avl_tree *zroute_tree, struct avl_tree *redist_opt_tree);

int32_t opt_redist(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn, struct avl_tree *redist_opt_tree, uint8_t *changed);
struct redistr_opt_node *matching_redist_opt(struct redist_in_node *rin, struct avl_tree *redist_opt_tree);