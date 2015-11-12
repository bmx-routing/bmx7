/*
 * Copyright (c) 2015  Axel Neumann
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



#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "ogm.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "ip.h"
#include "allocate.h"
#include "evil.h"


#define CODE_CATEGORY_NAME "evil"

static int32_t evilRouteDropping = DEF_EVIL_ROUTE_DROPPING;
static int32_t evilDescDropping = DEF_EVIL_DESC_DROPPING;
static int32_t evilOgmDropping = DEF_EVIL_OGM_DROPPING;
static int32_t evilOgmMetrics = DEF_EVIL_OGM_METRICS;
static int32_t evilOgmSqns = DEF_EVIL_OGM_SQNS;

static struct DirWatch *evilDirWatch = NULL;
static int32_t evil_tun_fd = 0;
static int32_t evil_tun_idx = 0;

static int32_t (*orig_tx_frame_desc_adv) (struct tx_frame_iterator *) = NULL;
static int32_t (*orig_tx_msg_dhash_adv) (struct tx_frame_iterator *) = NULL;
static int32_t (*orig_tx_frame_ogm_dhash_aggreg_advs) (struct tx_frame_iterator *) = NULL;

STATIC_FUNC
int32_t evil_tx_frame_description_adv(struct tx_frame_iterator *it)
{

	if (evilDirWatch && evilDescDropping) {

		struct dhash_node *dhn = avl_find_item(&dhash_tree, (DHASH_T*)it->ttn->key.data);

		if (dhn && dhn->descContent && avl_find(&evilDirWatch->node_tree, &dhn->descContent->key->kHash))
			return TLV_TX_DATA_DONE;

	}

	return (*orig_tx_frame_desc_adv)(it);
}

STATIC_FUNC
int32_t evil_tx_msg_dhash_adv(struct tx_frame_iterator *it)
{
	if (evilDirWatch && evilDescDropping) {

		struct dhash_node *dhn = avl_find_item(&dhash_tree, ((DHASH_T*)it->ttn->key.data));

		if (dhn && dhn->descContent && avl_find(&evilDirWatch->node_tree, &dhn->descContent->key->kHash))
			return TLV_TX_DATA_DONE;
	}

	return (*orig_tx_msg_dhash_adv)(it);
}


STATIC_FUNC
int32_t evil_tx_frame_ogm_dhash_aggreg_advs(struct tx_frame_iterator *it)
{
	if (evilDirWatch && (evilOgmDropping || evilOgmMetrics || evilOgmSqns)) {

		struct hdr_ogm_adv *hdr = ((struct hdr_ogm_adv*) tx_iterator_cache_hdr_ptr(it));
		AGGREG_SQN_T *sqn = ((AGGREG_SQN_T *)it->ttn->key.data);
		struct avl_tree *origs = (*ogm_aggreg_origs(*sqn));
		uint16_t o = 0;
		struct avl_node *an = NULL;
		struct orig_node *on;

		hdr->aggregation_sqn = htons(*sqn);

		while (origs && (on = avl_iterate_item(origs, &an))) {

			struct trust_node *tn = avl_find_item(&evilDirWatch->node_tree, &on->key->kHash);

			if (tn && evilOgmDropping)
				continue;

			hdr->msg[o].dhash = on->descContent->dhn->dhash;
			hdr->msg[o].sqn = htons(on->ogmSqn + (tn ? evilOgmSqns : 0));
			hdr->msg[o].metric.val.u16 = htons(umetric_to_fmetric((tn && evilOgmMetrics) ? UMETRIC_MAX : on->ogmMetric).val.u16);

			on->descContent->dhn->referred_by_me_timestamp = bmx_time;
			o++;
		}

		dbgf_all(DBGT_INFO, "aggSqn=%d ogms=%d", *sqn, o);

		return (o * sizeof(struct msg_ogm_dhash_adv));
	}

	return (*orig_tx_frame_ogm_dhash_aggreg_advs)(it);
}


STATIC_FUNC
void idChanged_Evil(IDM_T del, GLOBAL_ID_T *id)
{
	if (evilRouteDropping && id) {
		
		struct net_key routeKey = {.af = AF_INET6, .mask = 128, .ip = create_crypto_IPv6(&autoconf_prefix_cfg, id)};

		dbgf_track(DBGT_WARN, "del=%d route=%s to id=%s table=%d idx=%d", del, netAsStr(&routeKey), cryptShaAsShortStr(id), DEF_EVIL_IP_TABLE, evil_tun_idx);

		iproute(IP_ROUTE_TUNS, del, NO, &routeKey, DEF_EVIL_IP_TABLE, 0, evil_tun_idx, NULL, NULL, DEF_EVIL_IP_METRIC, NULL);
	}
}

STATIC_FUNC
void tun_out_devZero_hook(int fd)
{
	static uint8_t tp[2000];

	while (read(fd, &tp, sizeof(tp)) > 0);
}

STATIC_FUNC
int32_t opt_evil_route(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	static int32_t prevEvilRouteDropping = DEF_EVIL_ROUTE_DROPPING;


	if ((cmd == OPT_APPLY && prevEvilRouteDropping != evilRouteDropping)) {

		dbgf_sys(DBGT_INFO, "changing %s old=%d now=%d next=%s", opt->name, prevEvilRouteDropping, evilRouteDropping, patch->val);

		int32_t nextEvilRouteDropping = evilRouteDropping;
		evilRouteDropping = YES;

		struct trust_node *tn;
		struct avl_node *an = NULL;
		while (evilDirWatch && (tn = avl_iterate_item(&evilDirWatch->node_tree, &an)))
			(*evilDirWatch->idChanged)((nextEvilRouteDropping ? ADD : DEL), &tn->global_id);

		evilRouteDropping = nextEvilRouteDropping;
	}

	if (cmd == OPT_APPLY)
		prevEvilRouteDropping = evilRouteDropping;



	return SUCCESS;
}

STATIC_FUNC
int32_t opt_evil_watch(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	assertion(-500000, ((strcmp(opt->name, ARG_ATTACKED_NODES_DIR) == 0)));

        if (cmd == OPT_CHECK && patch->diff == ADD && check_dir(patch->val, NO/*create*/, NO/*writable*/) == FAILURE)
			return FAILURE;

        if (cmd == OPT_APPLY) {

		if (patch->diff == DEL)
			cleanup_dir_watch(&evilDirWatch);

		if (patch->diff == ADD) {
			assertion(-501286, (patch->val));
			return init_dir_watch(&evilDirWatch, patch->val, idChanged_Evil);
		}
        }

        return SUCCESS;
}

STATIC_FUNC
int32_t opt_evil_init(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd == OPT_CHECK || cmd == OPT_APPLY)
		return FAILURE;

	if (cmd == OPT_SET_POST && initializing) {

		evil_tun_idx = kernel_dev_tun_add( DEF_EVIL_TUN_NAME, &evil_tun_fd, NO);
		set_fd_hook(evil_tun_fd, tun_out_devZero_hook, ADD);

		ip_flush_routes(AF_INET6, DEF_EVIL_IP_TABLE);
		ip_flush_rules(AF_INET6, DEF_EVIL_IP_TABLE);

		// must be configured after general IPv6 options:
		iproute(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET6_KEY, DEF_EVIL_IP_TABLE, DEF_EVIL_IP_RULE, 0, 0, 0, 0, NULL);
	}

	return SUCCESS;
}

static struct opt_type evil_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	{ODI,0,"evilInit",              0,  8,0,A_PS0,A_ADM,A_INI,A_ARG,A_ANY,	0,		0,		0,		0,0,            opt_evil_init,
			NULL,HLP_DUMMY_OPT},
	{ODI,0,ARG_ATTACKED_NODES_DIR,  0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_ATTACKED_NODES_DIR, opt_evil_watch,
			ARG_DIR_FORM,"directory with global-id hashes of this node's attacked other nodes"},
	{ODI,0,ARG_EVIL_ROUTE_DROPPING, 0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &evilRouteDropping,MIN_EVIL_ROUTE_DROPPING,MAX_EVIL_ROUTE_DROPPING,DEF_EVIL_ROUTE_DROPPING,0,opt_evil_route,
			ARG_VALUE_FORM, "do not forward IPv6 packets towards attacked nodes"},
	{ODI,0,ARG_EVIL_DESC_DROPPING,  0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &evilDescDropping,MIN_EVIL_DESC_DROPPING,MAX_EVIL_DESC_DROPPING,DEF_EVIL_DESC_DROPPING,0,NULL,
			ARG_VALUE_FORM, "do not propagate description updates from attacked nodes"},
	{ODI,0,ARG_EVIL_OGM_DROPPING,   0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &evilOgmDropping,MIN_EVIL_OGM_DROPPING,MAX_EVIL_OGM_DROPPING,DEF_EVIL_OGM_DROPPING,0,NULL,
			ARG_VALUE_FORM, "do not propagate routing updates (OGMs) from attacked nodes"},
	{ODI,0,ARG_EVIL_OGM_METRICS,    0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &evilOgmMetrics, MIN_EVIL_OGM_METRICS,MAX_EVIL_OGM_METRICS,DEF_EVIL_OGM_METRICS,0,NULL,
			ARG_VALUE_FORM, "Modify metrics of routing updates (OGMs) from attacked nodes"},
	{ODI,0,ARG_EVIL_OGM_SQNS,       0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &evilOgmSqns,    MIN_EVIL_OGM_SQNS,MAX_EVIL_OGM_SQNS,DEF_EVIL_OGM_SQNS,0,NULL,
			ARG_VALUE_FORM, "Modify SQNs of routing updates (OGMs) from attacked nodes"},
};



static int32_t evil_init( void )
{
        register_options_array(evil_options, sizeof ( evil_options), CODE_CATEGORY_NAME);

	orig_tx_frame_desc_adv = packet_frame_db->handls[FRAME_TYPE_DESC_ADVS].tx_frame_handler;
	packet_frame_db->handls[FRAME_TYPE_DESC_ADVS].tx_frame_handler = evil_tx_frame_description_adv;

	orig_tx_msg_dhash_adv = packet_frame_db->handls[FRAME_TYPE_DHASH_ADV].tx_msg_handler;
	packet_frame_db->handls[FRAME_TYPE_DHASH_ADV].tx_msg_handler = evil_tx_msg_dhash_adv;

	orig_tx_frame_ogm_dhash_aggreg_advs = packet_frame_db->handls[FRAME_TYPE_OGM_DHASH_ADV].tx_frame_handler;
	packet_frame_db->handls[FRAME_TYPE_OGM_DHASH_ADV].tx_frame_handler = evil_tx_frame_ogm_dhash_aggreg_advs;

	return SUCCESS;
}


static void evil_cleanup( void )
{
	packet_frame_db->handls[FRAME_TYPE_DESC_ADVS].tx_frame_handler = orig_tx_frame_desc_adv;
	packet_frame_db->handls[FRAME_TYPE_DHASH_ADV].tx_msg_handler = orig_tx_msg_dhash_adv;
	packet_frame_db->handls[FRAME_TYPE_OGM_DHASH_ADV].tx_frame_handler = orig_tx_frame_ogm_dhash_aggreg_advs;

	cleanup_dir_watch(&evilDirWatch);

	if (evil_tun_fd) {
		iproute(IP_RULE_DEFAULT, DEL, NO, &ZERO_NET6_KEY, DEF_EVIL_IP_TABLE, DEF_EVIL_IP_RULE, 0, 0, 0, 0, NULL);

		ip_flush_routes(AF_INET6, DEF_EVIL_IP_TABLE);
		ip_flush_rules(AF_INET6, DEF_EVIL_IP_TABLE);

		set_fd_hook(evil_tun_fd, tun_out_devZero_hook, DEL);
		kernel_dev_tun_del(DEF_EVIL_TUN_NAME, evil_tun_fd);
		evil_tun_fd = 0;
	}
}


struct plugin* get_plugin( void ) {
	
	static struct plugin evil_plugin;
	
	memset( &evil_plugin, 0, sizeof ( struct plugin ) );
	

	evil_plugin.plugin_name = CODE_CATEGORY_NAME;
	evil_plugin.plugin_size = sizeof ( struct plugin );
	evil_plugin.cb_init = evil_init;
	evil_plugin.cb_cleanup = evil_cleanup;

	return &evil_plugin;
}


