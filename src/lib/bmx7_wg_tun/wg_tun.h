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

/* HARRY TODO
extern struct net_key tun4_address;
extern struct net_key tun6_address;
*/

#include "wireguard.h"

/* Set default names */
#define ARG_WG_TUN_NAME_PREFIX "wg_dev"
#define MAX_WG_TUN_NAME_PREFIX_LEN 5

#define DEF_WG_TUN_NAME_TYPE_IN "In_"
#define DEF_WG_TUN_NAME_TYPE_OUT "Out_"
#define DEF_WG_TUN_NAME_TYPE_CATCH4 "C4"
#define DEF_WG_TUN_NAME_TYPE_CATCH6 "C6"

#define ARG_WG_TUN_OUT_TIMEOUT "tunOutTimeout"
#define MIN_WG_TUN_OUT_TO 0
#define MAX_WG_TUN_OUT_TO REGISTER_TASK_TIMEOUT_MAX
#define DEF_WG_TUN_OUT_TO 60000

/* TODO Harry: Read on Proactive Routing and renable them if needed
#define MIN_WG_TUN_PROACTIVE_ROUTES 0
#define MAX_WG_TUN_PROACTIVE_ROUTES 1
#define DEF_WG_TUN_PROACTIVE_ROUTES 1
#define ARG_WG_TUN_PROACTIVE_ROUTES "proactiveTunRoutes"
#define HLP_WG_TUN_PROACTIVE_ROUTES "Proactively configure all tunnel routes via dedicated tunnels"
*/

#define TDN_STATE_CATCHALL 1
#define TDN_STATE_DEDICATED 0
#define TDN_STATE_CURRENT -1

#define ARG_WG_TUN_DEV  "wgDev"
#define ARG_TUN_DEV_ADDR4 "tun4Address"
#define HLP_TUN_DEV_ADDR4 "specify default IPv4 tunnel address and announced range"
#define ARG_TUN_DEV_ADDR6 "tun6Address"
#define HLP_TUN_DEV_ADDR6 "specify default IPv6 tunnel address and announced range"

#define ARG_WG_TUN_DEV_REMOTE "remote"

#define ARG_TUN_IN "tunIn"

//#define HLP_TUN_IN_DEV "Incoming tunnel interface name to be used"

#define ARG_WG_TUN_IN_NET "network"
#define ARG_WG_TUN_IN_BW  "bandwidth"
#define MIN_TUN_IN_BW  UMETRIC_FM8_MIN
#define MAX_TUN_IN_BW  UMETRIC_MAX
#define DEF_TUN_IN_BW  1000
#define HLP_TUN_IN_BW  "bandwidth to network as bits/sec  default: 1000  range: [36 ... 128849018880]"

#define ARG_TUN_OUT          "tunOut"
#define ARG_TUN_OUT_NET      "network"
#define ARG_TUN_OUT_SRCRT    "srcNet"
#define ARG_TUN_OUT_TYPE     "srcType"
#define ARG_TUN_OUT_PREFIX   "srcRangeMin"


struct dsc_msg_wg_tun {
	wg_key public_key;
};

#define DESCRIPTION_MSG_WG_TUN_ADV_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 32*8, 0, FIELD_RELEVANCE_HIGH, "public_key" }, \
FIELD_FORMAT_END }


//extern struct bmx_list_head tunXin6_net_adv_list_list;


#define NETWORK_NAME_LEN 32


/* Tunnel Network Node
struct tun_net_node {
	struct tun_net_key tunNetKey;

	uint32_t eval_counter;
	uint32_t tlv_new_counter;

	FMETRIC_U8_T bandwidth;

	UMETRIC_T e2eMetric;

	struct avl_tree tun_bit_tree;
};
*/

/* Remap wg_device as wg_tun_dev_node */
//typedef wg_device wg_tun_dev_node;

/* TODO: Merge the above two
struct wg_tun_dev_node {
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
*/
