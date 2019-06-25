#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/types.h>


/* CLEAR UNNEEDED */
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

static int32_t wg_tun_out_delay = DEF_WG_TUN_OUT_DELAY;
static int32_t wg_tun_out_mtu = DEF_WG_TUN_OUT_MTU;
static int32_t wg_tun_dedicated_to = DEF_WG_TUN_OUT_TO;
static int32_t wg_tun_proactive_routes = DEF_WG_TUN_PROACTIVE_ROUTES;
static int32_t wg_tun_real_src = DEF_WG_TUN_REAL_SRC;

STATIC_FUNC
void purge_wg_tunCatchTree(void)
{
	struct tun_dev_node *tdnUP;
	while ((tdnUP = avl_first_item(&tun_catch_tree))) {
		assertion(-501543, (!tdnUP->tun_bit_tree[0].items && !tdnUP->tun_bit_tree[1].items));
		avl_remove(&tun_catch_tree, &tdnUP->tunCatchKey, -300546);
		avl_remove(&tdnUP->tunCatchKey.tin->tun_dev_tree, &tdnUP->nameKey, -300559);
		kernel_dev_tun_del(tdnUP->nameKey.str, tdnUP->tunCatch_fd);
		debugFree(tdnUP, -300547);
	}
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

	uint32_t min;
	uint32_t max;
	uint32_t aOLP;
	uint32_t bOSP;
	uint32_t hyst;
	uint32_t rating;

	UMETRIC_T *minBw;

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

	UMETRIC_T advBwVal;
	UMETRIC_T *advBw;
	UMETRIC_T *pathMtc;
	UMETRIC_T tunMtcVal;
	UMETRIC_T *tunMtc;

	IPX_T *localTunIp;
	IPX_T *remoteTunIp;
};

/* HARRY TODO: Add desc */
static const struct field_format wg_tun_out_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, wg_tunOut,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  tun_out_status, id,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, longId,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, gwName,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, src,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, proto,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, net,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, min,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, max,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, aOLP,        1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, bOSP,        1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, hyst,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, rating,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, minBw,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, pref,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, table,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, ipMtc,       1, FIELD_RELEVANCE_MEDI),
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
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, advBwVal,    1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, advBw,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, pathMtc,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, tunMtcVal,   1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, tunMtc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, localTunIp,  1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, remoteTunIp, 1, FIELD_RELEVANCE_LOW),
//      FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, up,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t wg_tun_out_status_creator(struct status_handl *handl, void *data)
{
	struct tun_net_node *tnn;
	struct tun_search_node *tsn;
	struct avl_node *an;

	int32_t status_size = tun_bit_tree.items * sizeof(struct tun_out_status);

	for (an = NULL; (tnn = avl_iterate_item(&tun_net_tree, &an));)
		status_size += (tnn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));

	for (an = NULL; (tsn = avl_iterate_item(&tun_search_tree, &an));)
		status_size += (tsn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));

	struct tun_out_status *status = (struct tun_out_status *) (handl->data = debugRealloc(handl->data, status_size, -300428));
	memset(status, 0, status_size);

	struct avl_tree * t[] = { &tun_search_tree, &tun_bit_tree, &tun_net_tree };
	uint8_t a;
	for (a = 0; a < 3; a++) {
		void *p;
		for (an = NULL; (p = avl_iterate_item(t[a], &an));) {

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

	return status_size;
}

STATIC_FUNC
void tun_dev_event_hook(int32_t cb_id, void* unused)
{
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

		reconfigure_tun_ins();
	}
}


STATIC_FUNC
void wg_tun_cleanup(void)
{
	/* Harry TODO */
	task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 1));

	purge_wg_tunCatchTree();

	/* The famous wtin variable */
	struct wg_tun_in_node *wtin;
	while ((wtin = avl_remove_first_item(&tun_in_tree, -123456))) {
		configure_wireguard_tunnel_in(DEL, tin, -1);
		debugFree(wtin, -123457);
	}
}

STATIC_FUNC
int32_t wg_tun_init(void)
{
	/* Harry TODO: WTF are these? */
	static const struct field_format tun6_adv_format[] = DESCRIPTION_MSG_TUN6_ADV_FORMAT;
	static const struct field_format tun6in6_adv_format[] = DESCRIPTION_MSG_TUN6IN6_NET_ADV_FORMAT;

	/* HARRY TODO: FIX THESE */
	static const struct field_format wg_tun_format[] = DESCRIPTION_MSG_WG_TUN_FORMAT;
	static const struct field_format wg_tun_adv_format[] = DESCRIPTION_MSG_WG_TUN_ADV_FORMAT;

	/* Message handler declared in msg.h */
	struct frame_handl tlv_handl;
	memset(&tlv_handl, 0, sizeof(tlv_handl));

	/* Register a handler for DSC_TUN6 */
	tlv_handl.name = "DSC_TUN6";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun6);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tun6;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tun6;
	tlv_handl.msg_format = tun6_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN6, &tlv_handl);

	/* Register a handler for DSC_TUN6IN6_NET */
	tlv_handl.name = "DSC_TUN6IN6_NET";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun6in6net);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6net;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6net;
	tlv_handl.msg_format = tun6in6_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN6IN6_NET, &tlv_handl);

	/* Register a handler for  DSC_WG_TUN */
	tlv.handl.name = "DSC_WGTUN";
	tlv.handl.min_msg_size= sizeof(struct dsc_msg_tun_wg);

	/* HARRY TODO */
	// set_tunXin6_net_adv_list = set_tunXin6_net_adv_list_handl;

	register_options_array(wg_tun_options, sizeof(wg_tun_options), CODE_CATEGORY_NAME);

	/* TODO HARRY */
	register_status_handl(sizeof(struct wg_tun_out_status), 1, wg_tun_out_status_format, ARG_TUNS, wg_tun_out_status_creator);

	/* WG Tunnel Plugin initialized properly */
	return SUCCESS;
}

/* Register Plugin and initialize */
struct plugin* get_plugin(void)
{
	/* Register plugin */
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

/*
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
