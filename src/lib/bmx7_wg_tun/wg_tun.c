#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/types.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <endian.h>

#include <sys/ioctl.h>
//#include <net/if.h>

//#include <linux/if_tun.h> /* TUNSETPERSIST, ... */
//#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <fcntl.h>        /* open(), O_RDWR */
#include <linux/ip.h>
#include <netinet/ip6.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "ip.h"
#include "plugin.h"
#include "prof.h"
#include "hna.h"
#include "tun.h"
#include "tools.h"
#include "iptools.h"
#include "schedule.h"
#include "allocate.h"

#include "wireguard.h"
#include "wg_tun.h"

#define CODE_CATEGORY_NAME "wg_tun"

// configured tun_out names searches
// static AVL_TREE(tun_search_tree, struct tun_search_node, nameKey);

// identified matching bits (peaces) of tun_search and tun_net trees
// static AVL_TREE(tun_bit_tree, struct tun_bit_node, tunBitKey);

// rcvd tun_out network advs
// static AVL_TREE(tun_net_tree, struct tun_net_node, tunNetKey);

// rcvd tun_out advs
// static AVL_TREE(tun_out_tree, struct tun_out_node, tunOutKey);

// active tun_out tunnels
// static AVL_TREE(tun_catch_tree, struct tun_dev_node, tunCatchKey);

// HARRY TODO: What this EXACTLY does?
// LIST_SIMPEL(tunXin6_net_adv_list_list, struct tunXin6_net_adv_list_node, list, list);

static const struct tun_net_key ZERO_TUN_NET_KEY = { .ton = NULL };

/* HARRY TODO: Is this useful?
static struct net_key tun4_address = ZERO_NET_KEY_INIT;
char* tun4_dev = NULL;
static struct net_key tun6_address = ZERO_NET_KEY_INIT;
char* tun6_dev = NULL;
*/

static int32_t tun_out_delay = DEF_TUN_OUT_DELAY;
static int32_t tun_out_mtu = DEF_TUN_OUT_MTU;
static int32_t tun_dedicated_to = DEF_TUN_OUT_TO;
static int32_t tun_proactive_routes = DEF_TUN_PROACTIVE_ROUTES;
static int32_t tun_real_src = DEF_TUN_REAL_SRC;


STATIC_FUNC
int create_dsc_tlv_wg_tun(struct tx_frame_iterator *it)
{
	/* STUB */
	return 0;
}

STATIC_FUNC
int process_dsc_tlv_wg_tun(struct rx_frame_iterator *it)
{
	/* STUB */
	return 0;
}

STATIC_FUNC
IDM_T configure_wg_tunnel_in(uint8_t del, struct tun_in_node *tin, int16_t tun6Id)
{

/*
	// Possible del values: DEL | ADD
	assertion(-501523, IMPLIES(!del, is_ip_set(&tin->remote)));
	assertion(-501341, IMPLIES(!del, (is_ip_set(&my_primary_ip))));
	assertion(-501311, IMPLIES(tin->upIfIdx, tin->nameKey.str[0]));
	assertion(-501342, IMPLIES(tin->upIfIdx, del));
	assertion(-501368, IMPLIES(del, ((tin->tun6Id >= 0) == (tin->upIfIdx > 0))));
	assertion(-501369, IMPLIES(!del, ((tun6Id >= 0) && (tin->upIfIdx == 0))));

	// If del == DEL
	if (del && tin->upIfIdx) {

		// Reset tin values
		IDM_T result = kernel_tun_del(tin->nameKey.str);
		assertion(-501451, (result == SUCCESS));

		tin->upIfIdx = 0;
		tin->tun6Id = -1;

		// Update Description
		my_description_changed = YES;

	// If del == ADD
	} else if (!del && !tin->upIfIdx) {

		// Add new tin values
		IPX_T *local = &my_primary_ip;
		IPX_T remoteIp = (tun_real_src >= TYP_TUN_REAL_SRC_ANY) ?  ZERO_IP : tin->remote;

		if (!is_ip_set(&tin->remote) || is_ip_local(&tin->remote) ||
			(tin->ingressPrefix46[0].mask && find_overlapping_hna(&tin->ingressPrefix46[0].ip, tin->ingressPrefix46[0].mask, NULL))) {

			dbgf_sys(DBGT_WARN, "FAILED creating tun remoteIp=%s", ip6AsStr(&tin->remote));
			return FAILURE;
		}

		assertion(-501312, (strlen(tin->nameKey.str)));

		if ((tin->upIfIdx = kernel_tun_add(tin->nameKey.str, IPPROTO_IP, local, &remoteIp)) > 0) {

			tin->tun6Id = tun6Id;

			if (tin->tunAddr46[1].mask)
				kernel_set_addr(ADD, tin->upIfIdx, AF_INET, &tin->tunAddr46[1].ip, 32, NO);

			if (tin->tunAddr46[0].mask)
				kernel_set_addr(ADD, tin->upIfIdx, AF_INET6, &tin->tunAddr46[0].ip, 128, NO);

			my_description_changed = YES;
		}
	}

	return(XOR(del, tin->upIfIdx)) ? SUCCESS : FAILURE;
*/
	return FAILURE;
}

STATIC_FUNC
void reconfigure_wg_tun_ins(void)
{
/*
	struct avl_node *an;
	struct tun_in_node *tin;

	// Loop and reset tun_in_tree values
	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));) {
		configure_wg_tunnel_in(DEL, tin, -1);
	}

	//  Reconfigure wg_tun_in_tree
	int16_t iterator = 0;
	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));) {

		if (!tin->remote_manual) {
			tin->remote = my_primary_ip;
			tin->remote.s6_addr[DEF_AUTO_TUNID_OCT_POS] += (iterator + MIN_AUTO_TUNID_OCT);
		}

		configure_wg_tunnel_in(ADD, tin, iterator++);

		assertion(-502040, ((iterator + MIN_AUTO_TUNID_OCT) <= MAX_AUTO_TUNID_OCT));
		assertion(-501237, (tin->upIfIdx && tin->tun6Id >= 0));
	}
*/
}


STATIC_FUNC
void purge_wg_tunCatchTree(void)
{
/*
 *	struct tun_dev_node *tdnUP;
	while ((tdnUP = avl_first_item(&tun_catch_tree))) {
		assertion(-501543, (!tdnUP->tun_bit_tree[0].items && !tdnUP->tun_bit_tree[1].items));
		avl_remove(&tun_catch_tree, &tdnUP->tunCatchKey, -300546);
		avl_remove(&tdnUP->tunCatchKey.tin->tun_dev_tree, &tdnUP->nameKey, -300559);
		kernel_dev_tun_del(tdnUP->nameKey.str, tdnUP->tunCatch_fd);
		debugFree(tdnUP, -300547);

	}
*/

}

struct wg_tun_out_status {
	/* Values for wg_tunOut -- peers */
	char* wg_tunOut;

	GLOBAL_ID_T *id;
	GLOBAL_ID_T *longId;

	char *gwName;
	int16_t proto;

	char src[IPX_PREFIX_STR_LEN];
	char net[IPX_PREFIX_STR_LEN];

	//uint32_t min;
	//uint32_t max;
	//uint32_t aOLP;
	//uint32_t bOSP;
	//uint32_t hyst;
	//uint32_t rating;

	//UMETRIC_T *minBw;

	uint32_t pref;
	uint32_t table;
	uint32_t ipMtc;

	/* Renamed these variables
	 * HARRY TODO: Apply across source */
	char *wg_tunIn;
	char *wg_tunName;

	int16_t setProto;

	/* HARRY TODO */
	char wg_tunRoute[IPX_PREFIX_STR_LEN];

	GLOBAL_ID_T *remoteId;
	GLOBAL_ID_T *remoteLongId;
	char* remoteName;

	/* Harry TODO */
	uint32_t wg_tunId;

	int16_t advProto;
	char advNet[IPX_PREFIX_STR_LEN];
	char srcIngress[IPX_PREFIX_STR_LEN];

	wg_key public_key;

	IPX_T *localTunIp;
	IPX_T *remoteTunIp;
};

/* HARRY TODO: Add desc */
static const struct field_format wg_tun_out_status_format[] = {

        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_BINARY,     wg_tun_out_status, public_key, 1, FIELD_RELEVANCE_HIGH),
/* Harry TODO
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunOut,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  tun_out_status, id,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, longId,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, gwName,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, src,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, proto,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, net,         1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, min,         1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, max,         1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, aOLP,        1, FIELD_RELEVANCE_LOW),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, bOSP,        1, FIELD_RELEVANCE_LOW),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, hyst,        1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, rating,      1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, minBw,       1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, pref,        1, FIELD_RELEVANCE_MEDI),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, table,       1, FIELD_RELEVANCE_MEDI),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, ipMtc,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, wg_tunIn,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, wg_tunName,  1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, setProto,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, wg_tunRoute, 1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  tun_out_status, remoteId,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, remoteLongId,1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, remoteName,  1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, wg_tunId,    1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, advProto,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, advNet,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, srcIngress,  1, FIELD_RELEVANCE_MEDI),
//    FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, advBwVal,    1, FIELD_RELEVANCE_LOW),
//    FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, advBw,       1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, pathMtc,     1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, tunMtcVal,   1, FIELD_RELEVANCE_LOW),
//        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, tunMtc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, localTunIp,  1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, remoteTunIp, 1, FIELD_RELEVANCE_LOW),
//      FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, up,          1, FIELD_RELEVANCE_HIGH),
*/
		FIELD_FORMAT_END
};

static int32_t wg_tun_out_status_creator(struct status_handl *handl, void *data)
{
/*
 *	struct tun_net_node *tnn;
	struct tun_search_node *tsn;
	struct avl_node *an;

	int32_t status_size = tun_bit_tree.items * sizeof(struct tun_out_status);

	for (an = NULL; (tnn = avl_iterate_item(&tun_net_tree, &an));)
		status_size += (tnn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));

	for (an = NULL; (tsn = avl_iterate_item(&tun_search_tree, &an));)
		status_size += (tsn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));

	// Declaration of status
	struct tun_out_status *status = (struct tun_out_status *) (handl->data = debugRealloc(handl->data, status_size, -300428));
	memset(status, 0, status_size);

	struct avl_tree * t[] = { &tun_search_tree, &tun_bit_tree, &tun_net_tree };

	//
	uint8_t avl_iterator;
	for (avl_iterator = 0; avl_iterator < 3; a++) {

		void *p;
		for (an = NULL; (p = avl_iterate_item(t[avl_iterator], &an));) {

			struct tun_bit_node *tbn = (t[a] == &tun_bit_tree) ? p : NULL;
			struct tun_net_node *tnn = (t[a] == &tun_net_tree) ? p : (tbn ? tbn->tunBitKey.keyNodes.tnn : NULL);
			struct tun_search_node *tsn = (t[a] == &tun_search_tree) ? p : (tbn ? tbn->tunBitKey.keyNodes.tsn : NULL);

			if (!tbn && tsn && tsn->tun_bit_tree.items)
				continue;

			if (!tbn && tnn && tnn->tun_bit_tree.items)
				continue;

			if (tsn) {

				status->tunOut = tsn->nameKey;
				status->id = &tsn->global_id;
				status->longId = &tsn->global_id;
				status->gwName = strlen(tsn->gwName) ? tsn->gwName : DBG_NIL;
				status->proto = tsn->routeSearchProto;
				status->setProto = tsn->routeSetProto;
				strcpy(status->net, netAsStr(&(tsn->net)));
				strcpy(status->src, tsn->srcRtNet.mask ? netAsStr(&(tsn->srcRtNet)) : DBG_NIL);
				status->min = tsn->netPrefixMin == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMin;
				status->max = tsn->netPrefixMax == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMax;
				status->aOLP = tsn->allowLargerPrefixRoutesWithWorseTunMetric;
				status->bOSP = tsn->breakSmallerPrefixRoutesWithBetterTunMetric;
				status->hyst = tsn->hysteresis;
				status->rating = tsn->rating;
				status->minBw = tsn->minBW ? &tsn->minBW : NULL;
				status->table = tsn->iptable;
				status->pref = tsn->iprule;
				status->ipMtc = tsn->ipmetric;
			} else {
				status->tunOut = DBG_NIL;
				status->gwName = DBG_NIL;
				status->proto = -1;
				status->setProto = -1;
				strcpy(status->net, DBG_NIL);
				strcpy(status->src, DBG_NIL);
			}

			if (tbn) {
				struct net_key tunRoute = tbn->tunBitKey.invRouteKey;
				tunRoute.mask = tbn ? (128 - tunRoute.mask) : 0;
				strcpy(status->tunRoute, netAsStr(&tunRoute));

				status->tunName = (tbn->active_tdn ? tbn->active_tdn->nameKey.str : DBG_NIL);
				status->tunIn = (tbn->active_tdn ? tbn->active_tdn->tunCatchKey.tin->nameKey.str : DBG_NIL);
				status->tunMtcVal = UMETRIC_MAX - ntoh64(tbn->tunBitKey.beInvTunBitMetric);
				status->tunMtc = status->tunMtcVal ? &status->tunMtcVal : NULL;

			} else {
				strcpy(status->tunRoute, DBG_NIL);
				status->tunName = DBG_NIL;
				status->tunIn = DBG_NIL;
			}

			if (tnn) {
				struct tun_out_node *tun = tnn->tunNetKey.ton;

				assertion(-501391, (tun));

				status->remoteName = strlen(tun->tunOutKey.on->k.hostname) ? tun->tunOutKey.on->k.hostname : DBG_NIL;
				status->remoteId = &tun->tunOutKey.on->k.nodeId;
				status->localTunIp = &tun->localIp;
				status->remoteTunIp = &tun->remoteIp;
				status->tunId = tun->tunOutKey.tun6Id;
				status->advProto = tnn->tunNetKey.bmx7RouteType;
				strcpy(status->advNet, netAsStr(&tnn->tunNetKey.netKey));
				strcpy(status->srcIngress, netAsStr(&tun->ingressPrefix[(tnn->tunNetKey.netKey.af == AF_INET)]));
				status->advBwVal = fmetric_u8_to_umetric(tnn->bandwidth);
				status->advBw = status->advBwVal ? &status->advBwVal : NULL;
				status->pathMtc = tun->tunOutKey.on->neighPath.link ? &tun->tunOutKey.on->neighPath.um : NULL;
			} else {
				strcpy(status->advNet, DBG_NIL);
				strcpy(status->srcIngress, DBG_NIL);
			}

			status++;
		}
	}

	assertion(-501322, (handl->data + status_size == (uint8_t*) status));
*/
//	return status_size;
	return 0;
}

static struct opt_type wg_tun_options[] = {

	/* Here lies an analysis of all the possible tunnel plugin options
	 * one can access them through 'bmx7 --plugin=bmx7_tun.so -H'
	 */

/* Tunnel Plugin Options
	// ord parent long_name | shrt Attributes | *ival | min | max | default | *func, *syntax, | *help
	{ODI,0,ARG_TUN_NAME_PREFIX, 0, 8, 1, A_PS1,A_ADM,A_INI,A_CFA,A_ANY, 0, 0, 0, 0, DEF_TUN_NAME_PREFIX, opt_tun_name_prefix, ARG_NAME_FORM, "specify first letters of local tunnel-interface names"},
    	{ODI,0,ARG_TUN_PROACTIVE_ROUTES,0, 9, 1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &tun_proactive_routes,MIN_TUN_PROACTIVE_ROUTES,MAX_TUN_PROACTIVE_ROUTES,DEF_TUN_PROACTIVE_ROUTES, 0, 0, ARG_VALUE_FORM, HLP_TUN_PROACTIVE_ROUTES},
	{ODI,0,ARG_TUN_OUT_TIMEOUT, 0, 9, 2, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_TO, MAX_TUN_OUT_TO, DEF_TUN_OUT_TO, 0, opt_tun_state_dedicated_to, ARG_VALUE_FORM, "timeout for reactive (dedicated) outgoing tunnels"},
	{ODI,0,ARG_TUN_OUT_MTU, 0, 9, 2, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_MTU, MAX_TUN_OUT_MTU, DEF_TUN_OUT_MTU, 0, opt_tun_out_mtu, ARG_VALUE_FORM, "MTU of outgoing tunnels"},
	{ODI,0,ARG_TUN_OUT_DELAY, 0, 9, 2, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &tun_out_delay, MIN_TUN_OUT_DELAY,MAX_TUN_OUT_DELAY,DEF_TUN_OUT_DELAY, 0, 0, ARG_VALUE_FORM, "Delay catched tunnel packets for given us before rescheduling (avoid dmesg warning ip6_tunnel: X7Out_.. xmit: Local address not yet configured!)"},

	{ODI,0,ARG_TUN_REAL_SRC, 0, 9, 1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &tun_real_src, MIN_TUN_REAL_SRC, MAX_TUN_REAL_SRC, DEF_TUN_REAL_SRC, 0, opt_tun_real_src, ARG_VALUE_FORM, "1: Accept any src address for incoming outer ip6 tunnel header. 2: Use primary address as src address for outgoing outer ip6 tunnel header"},

    //order must be after ARG_HOSTNAME (which initializes self via init_self(), called from opt_hostname):
	{ODI,0,ARG_TUN_DEV, 0, 9, 2, A_PM1N, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in_dev, ARG_NAME_FORM, "Define incoming IPIP tunnel interface name (prefix is " ARG_TUN_NAME_PREFIX "=" DEF_TUN_NAME_PREFIX ") and sub criteria!\n"
	"        eg: " ARG_TUN_DEV "=Default (resulting interface name would be: " DEF_TUN_NAME_PREFIX "Default )\n"
	"        WARNING: This creates a general ipip tunnel device allowing to tunnel arbitrary IP packets to this node!\n"
	"        Use firewall rules to filter deprecated packets!"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_ADDR4, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in_dev, ARG_ADDR_FORM, HLP_TUN_DEV_ADDR4},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_ADDR6, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in_dev, ARG_ADDR_FORM, HLP_TUN_DEV_ADDR6},

// If user has chosen the -h option
#ifndef LESS_OPTIONS
	{ODI,ARG_TUN_DEV, ARG_TUN_DEV_REMOTE, 0,9,1, A_CS1,A_ADM,A_DYI,A_CFA,A_ANY, 0, 0, 0, 0, 0, opt_tun_in_dev, ARG_IP_FORM, "Remote dummy IP of tunnel interface"},
	{ODI,ARG_TUN_DEV, ARG_TUN_DEV_INGRESS4, 0,9,1, A_CS1,A_ADM,A_DYI,A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in_dev, ARG_NETW_FORM,"IPv4 source prefix (ingress filter)"},
	{ODI,ARG_TUN_DEV, ARG_TUN_DEV_INGRESS6, 0,9,1, A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0, 0, 0, 0, 0, opt_tun_in_dev, ARG_NETW_FORM,"IPv6 source prefix (ingress filter)"},
	{ODI,ARG_TUN_DEV, ARG_TUN_DEV_SRC4_TYPE, 0,9,0, A_CS1,A_ADM,A_DYI,A_CFA,A_ANY, 0, TUN_SRC_TYPE_MIN, TUN_SRC_TYPE_MAX, TUN_SRC_TYPE_UNDEF, 0, opt_tun_in_dev, ARG_VALUE_FORM, "IPv4 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_DEV, ARG_TUN_DEV_SRC4_MIN, 0,9,0, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 32, 0, 0, opt_tun_in_dev, ARG_VALUE_FORM, "IPv4 source prefix len usable for address auto configuration (0 = NO autoconfig)"},
	{ODI,ARG_TUN_DEV, ARG_TUN_DEV_SRC6_TYPE, 0,9,0, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, TUN_SRC_TYPE_MIN, TUN_SRC_TYPE_MAX, TUN_SRC_TYPE_UNDEF, 0, opt_tun_in_dev, ARG_VALUE_FORM, "IPv6 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_DEV, ARG_TUN_DEV_SRC6_MIN, 0,9,0, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 128, 0, 0, opt_tun_in_dev, ARG_VALUE_FORM, "IPv6 source prefix len usable for address auto configuration (0 = NO autoconfig)"},
	{ODI,ARG_TUN_DEV, ARG_TUN_PROTO_ADV, 0,9,2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_PROTO_ADV, MAX_TUN_PROTO_ADV, DEF_TUN_PROTO_ADV, 0, opt_tun_in_dev, ARG_VALUE_FORM, HLP_TUN_PROTO_ADV},

#endif
    {ODI, 0, ARG_TUN_IN, 0,9,2, A_PM1N, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in, ARG_NAME_FORM, "Arbitrary but UNIQUE name for tunnel network to be announced with given sub criterias"},
	{ODI, ARG_TUN_IN, ARG_TUN_IN_NET, 'n', 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in, ARG_ADDR_FORM, "Network to be offered via incoming tunnel | MANDATORY"},
	{ODI, ARG_TUN_IN, ARG_TUN_IN_BW, 'b', 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in, ARG_VALUE_FORM, HLP_TUN_IN_BW},
	{ODI, ARG_TUN_IN, ARG_TUN_DEV, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in, ARG_NAME_FORM, HLP_TUN_IN_DEV},
	{ODI, ARG_TUN_IN, ARG_TUN_PROTO_ADV, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_PROTO_ADV, MAX_TUN_PROTO_ADV, DEF_TUN_PROTO_ADV, 0, opt_tun_in, ARG_VALUE_FORM, HLP_TUN_PROTO_ADV},

	{ODI, 0, ARG_TUN_OUT, 0, 9, 2, A_PM1N, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NAME_FORM, "Arbitrary but UNIQUE name for network which should be reached via tunnel depending on sub criterias"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_NET, 'n', 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NETW_FORM, "Network to be searched via outgoing tunnel | MANDATORY"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_SRCRT, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NETW_FORM, "Additional source-address range to-be routed via Tunnel"},
	{ODI, ARG_TUN_OUT, ARG_TUN_PROTO_SEARCH, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_PROTO_SEARCH, MAX_TUN_PROTO_SEARCH, DEF_TUN_PROTO_SEARCH, 0, opt_tun_search, ARG_VALUE_FORM, HLP_TUN_PROTO_SEARCH},
	{ODI, ARG_TUN_OUT, ARG_TUN_PROTO_SET, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_PROTO_SET, MAX_TUN_PROTO_SET, DEF_TUN_PROTO_SET, 0, opt_tun_search, ARG_VALUE_FORM, HLP_TUN_PROTO_SET},
#ifndef LESS_OPTIONS
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_TYPE, 0, 9, 0, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, TUN_SRC_TYPE_MIN, TUN_SRC_TYPE_MAX, TUN_SRC_TYPE_UNDEF, 0, opt_tun_search, ARG_VALUE_FORM, "Tunnel IP allocation mechanism (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
#endif
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_GWNAME, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NAME_FORM, "Hostname of remote Tunnel endpoint"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_PREFIX_MIN, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_PREFIX, MAX_TUN_OUT_PREFIX, DEF_TUN_OUT_PREFIX_MIN, 0, opt_tun_search, ARG_VALUE_FORM, "Minimum prefix length for accepting Advertised tunnel network, 129 = network prefix length"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_PREFIX_MAX, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_PREFIX, MAX_TUN_OUT_PREFIX, DEF_TUN_OUT_PREFIX_MAX, 0, opt_tun_search, ARG_VALUE_FORM, "Maximum prefix length for accepting Advertised Tunnel network, 129 = network prefix len"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_OVLP_ALLOW, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0 ,MIN_TUN_OUT_OVLP, MAX_TUN_OUT_OVLP, DEF_TUN_OUT_OVLP_ALLOW, 0, opt_tun_search, ARG_VALUE_FORM, "Allow overlapping other tunRoutes with worse tunMetric but larger prefix length"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_OVLP_BREAK, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_OVLP, MAX_TUN_OUT_OVLP, DEF_TUN_OUT_OVLP_BREAK, 0, opt_tun_search, ARG_VALUE_FORM, "Let this tunRoute break other tunRoutes with better tunMetric but smaller prefix length"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_PKID, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_SHA2_FORM,  "PKID of remote Tunnel endpoint"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_HYSTERESIS, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_HYSTERESIS, MAX_TUN_OUT_HYSTERESIS, DEF_TUN_OUT_HYSTERESIS, 0, opt_tun_search, ARG_VALUE_FORM, "Specify in percent how much the metric to an alternative GW must be better than to curr GW"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_RATING, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_RATING, MAX_TUN_OUT_RATING, DEF_TUN_OUT_RATING, 0, opt_tun_search, ARG_VALUE_FORM, "Specify in percent a metric rating for GWs matching this tunOut spec when compared with other tunOut specs for same network"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_MIN_BW, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_VALUE_FORM, "MIN bandwidth as bits/sec beyond which GW's advertised bandwidth is ignored  default: 100000  range: [36 ... 128849018880]"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_IPMETRIC, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_OUT_IPMETRIC, MAX_TUN_OUT_IPMETRIC, DEF_TUN_OUT_IPMETRIC, 0, opt_tun_search, ARG_VALUE_FORM, "IP metric for local routing table entries"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_TRULE, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, DEF_TUN_OUT_TRULE, opt_tun_search, FORM_TUN_OUT_TRULE, "IP rules table and preference to maintain matching tunnels"},
	// {ODI, ARG_TUN_OUT, ARG_EXPORT_ONLY, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_EXPORT_ONLY, MAX_EXPORT_ONLY, DEF_EXPORT_ONLY, 0, opt_tun_search, ARG_VALUE_FORM, "DO NOT add route to bmx7 tunnel table!  Requires quagga plugin!"},
	// {ODI, ARG_TUN_OUT, ARG_EXPORT_DISTANCE, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_EXPORT_DISTANCE, MAX_EXPORT_DISTANCE, DEF_EXPORT_DISTANCE, 0, opt_tun_search, ARG_VALUE_FORM, "export distance to network (256 == no export). Requires quagga plugin!"},

	{ODI, 0, ARG_TUNS, 0, 9, 2, A_PS0, A_USR, A_DYN, A_ARG, A_ANY, 0, 0, 0, 0, 0, opt_status, 0, "Show announced and used Tunnels and related networks"}
*/

/* DECLARE AND DECOMMENT
	{ODI,0,ARG_WG_TUN_NAME_PREFIX, 0, 8, 1, A_PS1, A_ADM, A_INI, A_CFA, A_ANY, 0, 0, 0, 0, DEF_TUN_NAME_PREFIX, opt_wg_tun_name_prefix, ARG_NAME_FORM, "Specify first letter of the local wg tunnel interface names"},
	{ODI,0,ARG_WG_TUN_DEV, 0, 9, 2, A_PMIN, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_wg_tun_in_dev, ARG_NAME_FORM, "Define the WG interface name. This creates the wg interface"}
		{ODI,ARG_WG_TUN_DEV,ARG_TUN_DEV_ADDR4, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_wg_tun_in_dev, ARG_ADDR_FORM, HLP_TUN_DEV_ADDR4},
		{ODI,ARG_WG_TUN_DEV,ARG_TUN_DEV_ADDR6, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_wg_tun_in_dev, ARG_ADDR_FORM, HLP_TUN_DEV_ADDR6},

    {ODI, 0, ARG_WG_TUN_IN, 0,9,2, A_PM1N, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_wg_tun_in, ARG_NAME_FORM, "Arbitrary but UNIQUE name for tunnel network to be announced with given sub criterias"},
	{ODI, ARG_TUN_IN, ARG_TUN_IN_NET, 'n', 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_wg_tun_in, ARG_ADDR_FORM, "Network to be offered via incoming tunnel | MANDATORY"},
	// {ODI, ARG_TUN_IN, ARG_TUN_IN_BW, 'b', 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_in, ARG_VALUE_FORM, HLP_TUN_IN_BW},
	{ODI, ARG_TUN_IN, ARG_TUN_DEV, 0, 9, 1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_wg_tun_in, ARG_NAME_FORM, HLP_TUN_IN_DEV},
	// {ODI, ARG_TUN_IN, ARG_TUN_PROTO_ADV, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_PROTO_ADV, MAX_TUN_PROTO_ADV, DEF_TUN_PROTO_ADV, 0, opt_tun_in, ARG_VALUE_FORM, HLP_TUN_PROTO_ADV},

	{ODI, 0, ARG_TUN_OUT, 0, 9, 2, A_PM1N, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NAME_FORM, "Arbitrary but UNIQUE name for network which should be reached via tunnel depending on sub criterias"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_NET, 'n', 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NETW_FORM, "Network to be searched via outgoing tunnel | MANDATORY"},
	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_SRCRT, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NETW_FORM, "Additional source-address range to-be routed via Tunnel"},
	{ODI, ARG_TUN_OUT, ARG_TUN_PROTO_SEARCH, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_PROTO_SEARCH, MAX_TUN_PROTO_SEARCH, DEF_TUN_PROTO_SEARCH, 0, opt_tun_search, ARG_VALUE_FORM, HLP_TUN_PROTO_SEARCH},
	{ODI, ARG_TUN_OUT, ARG_TUN_PROTO_SET, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, MIN_TUN_PROTO_SET, MAX_TUN_PROTO_SET, DEF_TUN_PROTO_SET, 0, opt_tun_search, ARG_VALUE_FORM, HLP_TUN_PROTO_SET},

	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_TYPE, 0, 9, 0, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, TUN_SRC_TYPE_MIN, TUN_SRC_TYPE_MAX, TUN_SRC_TYPE_UNDEF, 0, opt_tun_search, ARG_VALUE_FORM, "Tunnel IP allocation mechanism (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},

	{ODI, ARG_TUN_OUT, ARG_TUN_OUT_GWNAME, 0, 9, 2, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, 0, 0, 0, 0, 0, opt_tun_search, ARG_NAME_FORM, "Hostname of remote Tunnel endpoint"},
*/
};

STATIC_FUNC
void wg_tun_dev_event_hook(int32_t cb_id, void* unused)
{
	/*
	struct tun_in_node *tun;
	struct avl_node *an = NULL;
	while ((tun = avl_iterate_item(&tun_in_tree, &an))) {

		if (tun->upIfIdx && is_ip_local(&tun->remote)) {
			dbgf_sys(DBGT_WARN, "ERROR: %s=%s remote=%s already used!!!",
				ARG_TUN_DEV, tun->nameKey.str, ip6AsStr(&tun->remote));
			my_description_changed = YES;
		}
	}

	static IP6_T prev_primary_ip;

	if (memcmp(&prev_primary_ip, &my_primary_ip, sizeof(IP6_T))) {

		prev_primary_ip = my_primary_ip;

		reconfigure_wg_tun_ins();
	}
	*/
}


STATIC_FUNC
void wg_tun_cleanup(void)
{
	/* Harry TODO */
	// task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 1));

	// purge_wg_tunCatchTree();

	/* The famous wtin variable */

/*
	struct tun_in_node *tin;
	while ((tin = avl_remove_first_item(&tun_in_tree, -123456))) {
		configure_wg_tunnel_in(DEL, tin, -1);
		debugFree(tin, -123457);
	}
*/
}

STATIC_FUNC
int32_t wg_tun_init(void)
{
	/* Initialize tunnel */
	//assertion(-501335, is_zero((void*) &ZERO_TUN_NET_KEY, sizeof(ZERO_TUN_NET_KEY)));
	//assertion(-501327, tun_search_net_tree.key_size == sizeof (struct tun_search_key));
	//assertion(-501328, tun_search_tree.key_size == NETWORK_NAME_LEN);


//	static const struct field_format wg_tun_format[] = DESCRIPTION_MSG_WG_TUN_FORMAT;
	static const struct field_format wg_tun_adv_format[] = DESCRIPTION_MSG_WG_TUN_ADV_FORMAT;


	/* Message handler declared in msg.h */
	struct frame_handl tlv_handl;
	memset(&tlv_handl, 0, sizeof(tlv_handl));

	/* Register a handler for  DSC_WG_TUN */
	tlv_handl.name = "DSC_WG_TUN";
	tlv_handl.min_msg_size= sizeof(struct dsc_msg_wg_tun);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.tx_frame_handler = create_dsc_tlv_wg_tun;
	tlv_handl.rx_msg_handler = process_dsc_tlv_wg_tun;
	tlv_handl.msg_format = wg_tun_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_WG_TUN, &tlv_handl);

	register_options_array(wg_tun_options, sizeof(wg_tun_options), CODE_CATEGORY_NAME);

	/* TODO HARRY */
	register_status_handl(sizeof(struct wg_tun_out_status), 1, wg_tun_out_status_format, ARG_TUNS, wg_tun_out_status_creator);

	/* WG Tunnel Plugin initialized properly */
	return SUCCESS;
}

/* Register Plugin and initialize */
struct plugin* get_plugin(void)
{
	static struct plugin wg_tun_plugin;

	memset(&wg_tun_plugin, 0, sizeof(struct plugin));

	/* Assign Attributes */
	wg_tun_plugin.plugin_name = CODE_CATEGORY_NAME;
	wg_tun_plugin.plugin_size = sizeof(struct plugin);

	/* Init */
	wg_tun_plugin.cb_init = wg_tun_init;

	/* Cleanup */
	wg_tun_plugin.cb_cleanup = wg_tun_cleanup;

	/* Register call back handler
	 * HARRY TODO
	 */
	wg_tun_plugin.cb_plugin_handler[PLUGIN_CB_SYS_DEV_EVENT] = wg_tun_dev_event_hook;

	return &wg_tun_plugin;
}

/* TODO: Place them around
int wg_CnC()
{
	wg_peer new_peer = {
		.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS
	};

	wg_device new_device = {
		.name = "wgtest0",
		.listen_port = 1234,
		.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
		.first_peer = &new_peer,
		.last_peer = &new_peer
	};

	// TODO PLACE THEM AROUND
	wg_key temp_private_key;
	wg_generate_private_key(temp_private_key);
	wg_generate_public_key(new_peer.public_key, temp_private_key);
	wg_generate_private_key(new_device.private_key);


	if (wg_add_device(new_device.name) < 0) {
		perror("Unable to add device");
		exit(1);
	}

	if (wg_set_device(&new_device) < 0) {
		perror("Unable to set device");
		exit(1);
	}

	list_devices();

	if (wg_del_device(new_device.name) < 0) {
		perror("Unable to delete device");
		exit(1);
	}

	return 0;
}
*/
