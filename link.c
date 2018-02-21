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



#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
//#include "math.h"


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
#include "link.h"
#include "msg.h"
#include "content.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "allocate.h"
#include "prof.h"

#define CODE_CATEGORY_NAME "metric"


static int32_t my_link_window = DEF_HELLO_SQN_WINDOW;

//int32_t link_ignore_min = DEF_LINK_IGNORE_MIN;

//int32_t link_ignore_max = DEF_LINK_IGNORE_MAX;

int32_t link_purge_to = DEF_LINK_PURGE_TO;
int32_t timeaware_lq_min = DEF_TIMEAWARE_LQ_MIN;


IDM_T min_lq_probe(LinkNode *link)
{

	return (
		(link->timeaware_tq_probe >= timeaware_lq_min) &&
		(link->timeaware_rq_probe >= timeaware_lq_min)
		);
}

STATIC_FUNC
void upd_timeaware_rq_probe(LinkNode *link)
{
        if (((TIME_T) (bmx_time - link->rq_probe_record.hello_time_max)) < ((uint32_t)link_purge_to/10)) {

                link->timeaware_rq_probe = link->rq_probe_record.hello_lq;


        } else if (((TIME_T) (bmx_time - link->rq_probe_record.hello_time_max)) < ((uint32_t)link_purge_to)) {

		link->timeaware_rq_probe =
			(((uint32_t)link->rq_probe_record.hello_lq) * (((uint32_t)link_purge_to) - (bmx_time - link->rq_probe_record.hello_time_max))) / ((uint32_t)link_purge_to);

	} else {

		link->timeaware_rq_probe = 0;
	}
}

STATIC_FUNC
void upd_timeaware_tq_probe(LinkNode *link)
{

	if (((TIME_T) (bmx_time - link->tq_probe_time)) < ((uint32_t)link_purge_to/10)) {

		link->timeaware_tq_probe = link->tq_probe;

	} else if (((TIME_T) (bmx_time - link->tq_probe_time)) < ((uint32_t)link_purge_to)) {

		link->timeaware_tq_probe = ((((uint32_t)link->tq_probe) * ((((uint32_t)link_purge_to) - (bmx_time - link->tq_probe_time)))) / ((uint32_t)link_purge_to));

	} else {

		link->timeaware_tq_probe = 0;
	}
}

STATIC_FUNC
void lndev_assign_best(struct neigh_node *onlyLocal, LinkNode *onlyLink )
{
        TRACE_FUNCTION_CALL;

        assertion(-501133, (IMPLIES(onlyLink, onlyLocal && onlyLocal == onlyLink->k.linkDev->key.local)));
        ASSERTION(-500792, (IMPLIES(onlyLink, onlyLink->k.linkDev == avl_find_item(&onlyLocal->linkDev_tree, &onlyLink->k.linkDev->key.devIdx))));

        dbgf_all(DBGT_INFO, "only_local=%s link: nbLlIp=%s nbIdx=%d mydev=%s",
                onlyLocal ? cryptShaAsString(&onlyLocal->local_id) : 0,
                onlyLink ? ip6AsStr(&onlyLink->k.linkDev->key.llocal_ip) : DBG_NIL,
		onlyLink ? onlyLink->k.linkDev->key.devIdx : 0,
                onlyLink ? onlyLink->k.myDev->ifname_label.str : DBG_NIL);

        struct avl_node *local_an = NULL;
        struct neigh_node *local;

        while ((local = onlyLocal) || (local = avl_iterate_item(&local_tree, &local_an))) {

//		assertion(-500794, (local->linkDev_tree.items));

		LinkDevNode *linkDev = NULL;
                struct avl_node *link_an = NULL;

                if (local->best_rq_link)
                        upd_timeaware_rq_probe(local->best_rq_link);

                if (local->best_tq_link)
                        upd_timeaware_tq_probe(local->best_tq_link);


                dbgf_all(DBGT_INFO, "local_id=%s", cryptShaAsString(&local->local_id));

                while ((onlyLink && (linkDev = onlyLink->k.linkDev)) || (linkDev = avl_iterate_item(&local->linkDev_tree, &link_an))) {

                        LinkNode *currLink = NULL;

                        dbgf_all(DBGT_INFO, "link=%s", ip6AsStr(&linkDev->key.llocal_ip));

			while ((onlyLink && (currLink = onlyLink)) || (currLink = avl_next_item(&linkDev->link_tree, (currLink ? &currLink->k : NULL)))) {

                                dbgf_all(DBGT_INFO, "lndev=%s items=%d",
                                        currLink->k.myDev->ifname_label.str, linkDev->link_tree.items);

				if (local->best_rq_link != currLink) {
					upd_timeaware_rq_probe(currLink);

					if (!local->best_rq_link || local->best_rq_link->timeaware_rq_probe < currLink->timeaware_rq_probe)
						local->best_rq_link = currLink;
				}

				if (local->best_tq_link != currLink) {
					upd_timeaware_tq_probe(currLink);

					if (!local->best_tq_link || local->best_tq_link->timeaware_tq_probe < currLink->timeaware_tq_probe)
						local->best_tq_link = currLink;
				}

                                if (onlyLink)
                                        break;
                        }

                        if (onlyLink)
                                break;
		}


//		assertion(-500406, (local->best_rp_link));
//		assertion(-501086, (local->best_tp_link));

                if (!local->best_tq_link || local->best_tq_link->timeaware_tq_probe == 0)
                        local->best_tq_link = local->best_rq_link;

                if(onlyLocal)
                        break;
        }

}



uint16_t purge_linkDevs(LinkDevNode *onlyLinkDev, struct dev_node *onlyDev, LinkNode *onlyLink, IDM_T onlyExpired, IDM_T purgeLocal)
{
	TRACE_FUNCTION_CALL;

	uint16_t removed = 0;
	LinkDevNode *linkDev;
	LinkDevKey linkDevKey;
	memset(&linkDevKey, 0, sizeof(linkDevKey));

	dbgf_all(DBGT_INFO, "only_link_key=%s llip=%s only_dev=%s purgeLocal=%d",
		onlyLinkDev ? cryptShaAsString(&onlyLinkDev->key.local->local_id) : "---", ip6AsStr(onlyLinkDev ? &onlyLinkDev->key.llocal_ip : NULL),
		onlyDev ? onlyDev->ifname_label.str : DBG_NIL, purgeLocal);

	assertion(-502644, IMPLIES(onlyLinkDev, (!onlyLink || onlyLink->k.linkDev == onlyLinkDev)));
	assertion(-502645, IMPLIES(onlyDev, (!onlyLink || onlyLink->k.myDev == onlyDev)));

	onlyLinkDev = (onlyLink ? onlyLink->k.linkDev : onlyLinkDev);
	onlyDev = (onlyLink ? onlyLink->k.myDev : onlyDev);

	while ((linkDev = (onlyLinkDev ? onlyLinkDev : avl_next_item(&link_dev_tree, &linkDevKey)))) {

		struct neigh_node *local = linkDev->key.local;
		LinkKey linkKey = {NULL,NULL};
		LinkNode *link;

		assertion(-500940, local);
		assertion(-500941, local == avl_find_item(&local_tree, &linkDev->key.local->local_id));
		assertion(-500942, linkDev == avl_find_item(&local->linkDev_tree, &linkDev->key.devIdx));

		linkDevKey = linkDev->key;

		while ((link = (onlyLink ? onlyLink : avl_next_item(&linkDev->link_tree, &linkKey)))) {
			linkKey = link->k;

			if ((!onlyDev || onlyDev == link->k.myDev) &&
				(!onlyExpired || (((TIME_T) (bmx_time - link->rq_probe_record.hello_time_max)) > (TIME_T) link_purge_to))
				) {

				dbgf_track(DBGT_INFO, "purging nbLlIp=%s nbIdx=%d dev=%s",
					ip6AsStr(&linkDev->key.llocal_ip), linkDev->key.devIdx, link->k.myDev->ifname_label.str);

				purge_orig_router(NULL, NULL, link, NO);

				purge_tx_task_tree(link, NULL, NULL, NULL, YES);

				if (link == local->best_rq_link)
					local->best_rq_link = NULL;

				if (link == local->best_tq_link)
					local->best_tq_link = NULL;

				avl_remove(&link_tree, &link->k, -300221);
				avl_remove(&linkDev->link_tree, &link->k, -300749);
				debugFree(link, -300044);

				removed++;
			}

			if (onlyLink)
				break;
		}


//		assertion(-500323, (onlyDev || !linkDev->link_tree.items));

		if (!linkDev->link_tree.items) {

			dbgf_track(DBGT_INFO, "purging: linkDev local_id=%s link_ip=%s only_dev=%s, local->linkDevs=%d",
				cryptShaAsString(&linkDev->key.local->local_id), ip6AsStr(&linkDev->key.llocal_ip),
				onlyDev ? onlyDev->ifname_label.str : "???", local->linkDev_tree.items);

			avl_remove(&link_dev_tree, &linkDev->key, -300193);
			avl_remove(&local->linkDev_tree, &linkDev->key.devIdx, -300330);

			assertion(-502423, IMPLIES(!local->linkDev_tree.items, !local->best_rq_link));
			assertion(-502424, IMPLIES(!local->linkDev_tree.items, !local->best_tq_link));

			debugFree(linkDev, -300045);

			if (purgeLocal && !local->linkDev_tree.items)
				keyNode_schedLowerWeight(local->on->kn, KCPromoted);

		}

		if (onlyLinkDev)
			break;
	}


	if (removed) {
		lndev_assign_best(NULL, NULL);
		cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);
	}

	assertion(-502425, IMPLIES(!(onlyDev || onlyLinkDev || onlyLink || onlyExpired), !link_tree.items));
	assertion(-502425, IMPLIES(!(onlyDev || onlyLinkDev || onlyLink || onlyExpired), !link_dev_tree.items));

	return removed;
}

STATIC_FUNC
IDM_T updateNeighDevId(struct neigh_node *nn, struct desc_content *contents)
{
	struct dsc_msg_llip* msg = (struct dsc_msg_llip*) contents_data(contents, BMX_DSC_TLV_LLIP);
	uint16_t m, msgs = 0;
	LinkDevNode *ldn;
	DEVIDX_T idx = 0;
	struct avl_node *an = NULL;

	if (!contents || (msgs = (contents_dlen(contents, BMX_DSC_TLV_LLIP) / sizeof(struct dsc_msg_llip)))) {

		for (an = NULL; (ldn = avl_iterate_item(&nn->linkDev_tree, &an));)
			ldn->purge = YES;

		for (m = 0; m < msgs; m++) {

			for (an = NULL; (ldn = avl_iterate_item(&nn->linkDev_tree, &an));) {
				
				if (is_ip_equal(&ldn->key.llocal_ip, &msg[m].ip6))
					ldn->purge = NO;
			}
		}

		while ((ldn = avl_next_item(&nn->linkDev_tree, &idx))) {
			idx = ldn->key.devIdx;

			if (ldn->purge)
				purge_linkDevs(ldn, NULL, NULL, NO, YES);

		}
	}

	return SUCCESS;
}

LinkNode *getLinkNode(struct dev_node *dev, IPX_T *llip, DEVIDX_T idx, struct neigh_node *verifiedNeigh)
{
	TRACE_FUNCTION_CALL;

	LinkNode *link = NULL;
	LinkDevNode *linkDev = NULL;

	dbgf_all(DBGT_INFO, "llip=%s local_id=%s local=%s",
		ip6AsStr(llip), cryptShaAsString(&verifiedNeigh->local_id), verifiedNeigh ? "yes" : "no");

	if (!(linkDev = avl_find_item(&verifiedNeigh->linkDev_tree, &idx))) {

		linkDev = debugMallocReset(sizeof(LinkDevNode), -300024);

		AVL_INIT_TREE(linkDev->link_tree, LinkNode, k);

		linkDev->key.llocal_ip = *llip;
		linkDev->key.devIdx = idx;
		linkDev->key.local = verifiedNeigh;

		avl_insert(&link_dev_tree, linkDev, -300147);
		avl_insert(&verifiedNeigh->linkDev_tree, linkDev, -300334);

		dbgf_track(DBGT_INFO, "creating new link=%s (total %d)", ip6AsStr(llip), link_dev_tree.items);

		updateNeighDevId(verifiedNeigh, verifiedNeigh->on->dc);

	} else if (!is_ip_equal(&linkDev->key.llocal_ip, llip)) {

		dbgf_mute(25 , DBGL_SYS, DBGT_ERR, "changed NB=%s devIdx=%d llIp: %s->%s",
			cryptShaAsString(&verifiedNeigh->local_id), idx, ip6AsStr(&linkDev->key.llocal_ip), ip6AsStr(llip));
		purge_linkDevs(linkDev, NULL, NULL, NO, NO);
		return NULL;
	}

	linkDev->pkt_time_max = bmx_time;

	LinkKey linkKey = {.linkDev = linkDev, .myDev = dev};

	if (!(link = avl_find_item(&linkDev->link_tree, &linkKey))) {

		link = debugMallocReset(sizeof(LinkNode), -300023);

		link->k = linkKey;

		dbgf_track(DBGT_INFO, "creating new lndev %16s %s", ip6AsStr(&linkDev->key.llocal_ip), dev->ifname_device.str);

		avl_insert(&linkDev->link_tree, link, -300750);

		ASSERTION(-500489, !avl_find(&link_tree, &link->k));

		avl_insert(&link_tree, link, -300220);

		lndev_assign_best(linkDev->key.local, link);
		cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);
	}

	assertion(-502196, (link->k.linkDev == linkDev));

	lndev_assign_best(NULL, NULL);

	return link;
}


STATIC_FUNC
void update_link_probe_record(LinkNode *link, HELLO_SQN_T sqn, uint8_t probe)
{

        TRACE_FUNCTION_CALL;
	LinkDevNode *linkDev = link->k.linkDev;
        struct lndev_probe_record *lpr = &link->rq_probe_record;

        ASSERTION(-501049, ((sizeof (((struct lndev_probe_record*) NULL)->hello_array)) * 8 == MAX_HELLO_SQN_WINDOW));
        assertion(-501050, (probe <= 1));
        ASSERTION(-501055, (bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK) == lpr->hello_sum));

        if ((linkDev->hello_time_max || linkDev->hello_sqn_max) && linkDev->hello_sqn_max != sqn &&
                ((HELLO_SQN_MASK)&(linkDev->hello_sqn_max - sqn)) < HELLO_SQN_TOLERANCE)
                return;


        if (((HELLO_SQN_MASK)&(sqn - lpr->hello_sqn_max)) >= my_link_window) {

                memset(lpr->hello_array, 0, MAX_HELLO_SQN_WINDOW/8);

                ASSERTION(-500159, is_zero(lpr->hello_array, MAX_HELLO_SQN_WINDOW / 8));

                if (probe)
                        bit_set(lpr->hello_array, MAX_HELLO_SQN_WINDOW, sqn, 1);

                lpr->hello_sum = probe;
                dbgf_all(DBGT_INFO, "probe=%d probe_sum=%d %d",
                        probe, lpr->hello_sum, bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK));

                ASSERTION(-501058, (bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK) == lpr->hello_sum));

        } else {
                if (sqn != lpr->hello_sqn_max) {
                        HELLO_SQN_T prev_sqn_min = (HELLO_SQN_MASK)&(lpr->hello_sqn_max + 1 - ((HELLO_SQN_T) my_link_window));
                        HELLO_SQN_T new_sqn_min_minus_one = (HELLO_SQN_MASK)&(sqn - ((HELLO_SQN_T) my_link_window));

                        dbgf_all(DBGT_INFO, "prev_min=%5d prev_max=%d new_min=%5d sqn=%5d sum=%3d bits=%3d %s",
                                prev_sqn_min,lpr->hello_sqn_max, new_sqn_min_minus_one+1, sqn, lpr->hello_sum,
                                bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK),
                                bits_print(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK));

                        lpr->hello_sum -= bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one, HELLO_SQN_MASK);

                        dbgf_all(DBGT_INFO, "prev_min=%5d prev_max=%d new_min=%5d sqn=%5d sum=%3d bits=%3d %s",
                                prev_sqn_min,lpr->hello_sqn_max, new_sqn_min_minus_one+1, sqn, lpr->hello_sum,
                                bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK),
                                bits_print(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK));

                        bits_clear(lpr->hello_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one, HELLO_SQN_MASK);

                        dbgf_all(DBGT_INFO, "prev_min=%5d prev_max=%d new_min=%5d sqn=%5d sum=%3d bits=%3d %s\n",
                                prev_sqn_min,lpr->hello_sqn_max, new_sqn_min_minus_one+1, sqn, lpr->hello_sum,
                                bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK),
                                bits_print(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK));

                }

                ASSERTION(-501057, (bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK) == lpr->hello_sum));

                if (!bit_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, sqn) && probe) {
                        bit_set(lpr->hello_array, MAX_HELLO_SQN_WINDOW, sqn, 1);
                        lpr->hello_sum++;
                }

                ASSERTION(-501056, (bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK) == lpr->hello_sum));
        }

        lpr->hello_sqn_max = sqn;
	lpr->hello_lq = (LQ_MAX * ((uint32_t)lpr->hello_sum)) / ((uint32_t)my_link_window);
        lpr->hello_time_max = bmx_time;

        linkDev->hello_sqn_max = sqn;
        linkDev->hello_time_max = bmx_time;

        lndev_assign_best(linkDev->key.local, link);

        dbgf_all(DBGT_INFO, "%s metric tq=%d", ip6AsStr(&linkDev->key.llocal_ip), link->timeaware_rq_probe);
}




STATIC_FUNC
int32_t opt_link_metric(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        static int32_t my_link_window_prev = DEF_HELLO_SQN_WINDOW;

        if (cmd == OPT_APPLY && !strcmp(opt->name, ARG_HELLO_SQN_WINDOW)) {

                LinkNode *link;
                struct avl_node *an;

                for (an = NULL; (link = avl_iterate_item(&link_tree, &an));) {

                        struct lndev_probe_record *lpr = &link->rq_probe_record;

                        if (my_link_window < my_link_window_prev) {

                                HELLO_SQN_T prev_sqn_min = (HELLO_SQN_MASK)&(lpr->hello_sqn_max + 1 - my_link_window_prev);
                                HELLO_SQN_T new_sqn_min_minus_one = (HELLO_SQN_MASK)&(lpr->hello_sqn_max - my_link_window);

                                lpr->hello_sum -= bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one, HELLO_SQN_MASK);
                                bits_clear(lpr->hello_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one, HELLO_SQN_MASK);
                        }

                        assertion(-501053, (bits_get(lpr->hello_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1, HELLO_SQN_MASK) == lpr->hello_sum));
                        assertion(-501061, (lpr->hello_sum <= ((uint32_t)my_link_window)));

			lpr->hello_lq = (LQ_MAX * ((uint32_t)lpr->hello_sum)) / ((uint32_t)my_link_window);

                }


                lndev_assign_best(NULL, NULL);
                cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);

                my_link_window_prev = my_link_window;
        }

        return SUCCESS;
}


STATIC_FUNC
int process_dsc_tlv_llip(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        uint8_t op = it->op;

	if (op == TLV_OP_TEST) {

		uint16_t m = 0;
		struct dsc_msg_llip *msg = (struct dsc_msg_llip *)it->f_data;

		if (it->f_msgs_fixed > DEVIDX_MAX)
			return TLV_RX_DATA_FAILURE;

		for (m = 0; m < it->f_msgs_fixed; m++) {

			if (!is_ip_valid(&(msg[m].ip6), AF_INET6))
				return TLV_RX_DATA_FAILURE;

			if( !is_ip_net_equal(&(msg[m].ip6), &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))
				return TLV_RX_DATA_FAILURE;

//			IDM_T TODO_check_for_each_becoming_neighbor_if_llip_is_unused_then_add_linkDev_and_update_neighDevId_otherwise_ignore;
		}
	}

	if ((op == TLV_OP_NEW || op == TLV_OP_DEL) && it->on->neigh)
		updateNeighDevId(it->on->neigh, (op == TLV_OP_NEW ? it->dcOp : NULL));



        return it->f_msgs_len;
}


STATIC_FUNC
int create_dsc_tlv_llip(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct dsc_msg_llip *msg = (struct dsc_msg_llip *)tx_iterator_cache_msg_ptr(it);
        int m = 0;
        struct avl_node *an = NULL;
        struct dev_node *dev;

	if ((int)(dev_ip_tree.items * sizeof(struct dsc_msg_llip)) > tx_iterator_cache_data_space_pref(it, 0, 0))
		return TLV_TX_DATA_FULL;

	while ((dev = avl_iterate_item(&dev_ip_tree, &an))) {
		if (!dev->active || dev->linklayer == TYP_DEV_LL_LO)
			continue;
		if (m > 0 && is_ip_equal(&msg[m-1].ip6, &dev->llipKey.llip))
			continue;
		msg[m++].ip6 = dev->llipKey.llip;
	}

        return m * (sizeof(struct dsc_msg_llip));
}



STATIC_FUNC
int32_t tx_msg_hello_adv(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	assertion(-500771, (tx_iterator_cache_data_space_pref(it, 0, 0) >= ((int) sizeof(struct msg_hello_adv))));

	struct tx_task_node *ttn = it->ttn;
	struct msg_hello_adv *adv = (struct msg_hello_adv *) (tx_iterator_cache_msg_ptr(it));

	HELLO_SQN_T sqn_in = ttn->key.f.p.dev->link_hello_sqn = ((HELLO_SQN_MASK)&(ttn->key.f.p.dev->link_hello_sqn + 1));

	adv->hello_sqn = htons(sqn_in);

	dbgf_all(DBGT_INFO, "%s %s SQN %d", ttn->key.f.p.dev->ifname_label.str, ttn->key.f.p.dev->ip_llocal_str, sqn_in);

	return sizeof(struct msg_hello_adv);
}

STATIC_FUNC
void schedule_hello_adv(void);


STATIC_FUNC
void _hello_dev_capacities(void)
{
	prof_start(_hello_dev_capacities, schedule_hello_adv);
	struct dev_node *dev;
	struct avl_node *dan;

	for (dan = NULL; (dev = avl_iterate_item(&dev_name_tree, &dan));) {

		//IDM_T TODO_WARNING_mac_probes_are_unsigned_messages;
		if (dev->upd_link_capacities)
			(*(dev->upd_link_capacities)) (dev);

	}

	prof_stop();
	return;
}

STATIC_FUNC
void schedule_hello_adv(void)
{
	static TIME_T next = 0;
	prof_start(schedule_hello_adv, tx_packets);

	if (doNowOrLater(&next, txCasualInterval, 0)) {

		if (purge_linkDevs(NULL, NULL, NULL, YES, YES) == 0)
			lndev_assign_best(NULL, NULL);

		_hello_dev_capacities();

		schedule_tx_task(FRAME_TYPE_HELLO_ADV, NULL, NULL, NULL, NULL, SCHEDULE_MIN_MSG_SIZE, 0, 0);
	}
	prof_stop();
}

STATIC_FUNC
int32_t rx_msg_hello_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	struct packet_buff *pb = it->pb;
	assertion(-502427, (pb->i.verifiedLink));
	LinkNode *link = pb->i.verifiedLink;
        struct msg_hello_adv *msg = (struct msg_hello_adv*) (it->f_msg);
        HELLO_SQN_T hello_sqn = ntohs(msg->hello_sqn);

        update_link_probe_record(link, hello_sqn, 1);

	dbgf_all(DBGT_INFO, "NB=%s via llip=%s dev=%s SQN=%d linkDevIdx=%d",
                cryptShaAsShortStr(&pb->p.hdr.keyHash), pb->i.llip_str, pb->i.iif->ifname_label.str, hello_sqn, link->k.linkDev->key.devIdx);

	return TLV_RX_DATA_PROCESSED;
}

STATIC_FUNC
void schedule_hello_reply(void)
{
	LinkNode *link;
	struct avl_node *an = NULL;

	while ((link = avl_iterate_item(&link_tree, &an))) {

		schedule_tx_task(FRAME_TYPE_HELLO_REPLY_DHASH, NULL, &link->k.linkDev->key.local->local_id,
			link->k.linkDev->key.local, link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &link->k.linkDev->key.devIdx, sizeof(DEVIDX_T));
	}
}


STATIC_FUNC
int32_t tx_msg_hello_reply(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	DEVIDX_T *nbDevIdx = ((DEVIDX_T*) it->ttn->key.data);
	struct neigh_node *neigh = it->ttn->neigh;
	LinkDevNode *ldn = avl_find_item(&neigh->linkDev_tree, nbDevIdx);
	LinkKey lk = {.linkDev = ldn, .myDev = it->ttn->key.f.p.dev};
	LinkNode *link = ldn ? avl_find_item(&link_tree, &lk) : NULL;

	assertion(-502561, (it->frame_type == FRAME_TYPE_HELLO_REPLY_DHASH));

	if (!link || !ldn || ldn->key.devIdx < DEVIDX_MIN) {

		dbgf_track(DBGT_INFO, "yet unestablished devIdx=%d link=%p ldn=%p dev=%p neigh=%p for neigh=%s llip=%s dev=%s",
			(ldn ? ldn->key.devIdx : 0), (void*)link, (void*)ldn, (void*)lk.myDev, (void*)neigh, cryptShaAsString(&neigh->local_id),
			ip6AsStr(&ldn->key.llocal_ip), (lk.myDev ? lk.myDev->ifname_label.str : NULL));

		return TLV_TX_DATA_DONE;
	}

	struct msg_hello_reply_dhash* msg = ((struct msg_hello_reply_dhash*) tx_iterator_cache_msg_ptr(it));
	msg->dest_dhash = neigh->on->dc->dHash;
	msg->receiverDevIdx = ldn->key.devIdx;
	msg->rxLq = link->timeaware_rq_probe;

	iid_get_myIID4x_by_node(neigh->on);

	return sizeof(struct msg_hello_reply_dhash);

	return TLV_TX_DATA_DONE;
}

STATIC_FUNC
int32_t rx_msg_hello_reply(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	struct packet_buff *pb = it->pb;
	assertion(-502431, (pb->i.verifiedLink));
	struct msg_hello_reply_dhash *msg = (struct msg_hello_reply_dhash *) it->f_msg;
	assertion(-502562, (it->f_type == FRAME_TYPE_HELLO_REPLY_DHASH));
	LinkNode *link = pb->i.verifiedLink;
	struct neigh_node *neigh = link->k.linkDev->key.local;

	dbgf_all(DBGT_INFO, "dstDHash=%s myDHash=%s rcvDevIdx=%d myDevIdx=%d lastProbeTime=%d lastTqProbe=%d new tqProbe=%d",
		cryptShaAsShortStr(&msg->dest_dhash), cryptShaAsShortStr(&myKey->on->dc->dHash),
		msg->receiverDevIdx, link->k.myDev->llipKey.devIdx, link->tq_probe_time, link->tq_probe, msg->rxLq);

	if (!cryptShasEqual(&msg->dest_dhash, &myKey->on->dc->dHash))
		return TLV_RX_DATA_PROCESSED;

	if (msg->receiverDevIdx != link->k.myDev->llipKey.devIdx)
		return TLV_RX_DATA_PROCESSED;

	link->tq_probe_time = bmx_time;
	link->tq_probe = msg->rxLq;
	lndev_assign_best(neigh, link);

	return TLV_RX_DATA_PROCESSED;
}


char * getLinkKeysAsString(struct orig_node *on)
{
	if (!on)
		return DBG_NIL;

	static char linkKeys[MAX_LINK_KEYS_SIZE];
	struct dsc_msg_pubkey *rsaMsg = contents_data(on->dc, BMX_DSC_TLV_RSA_LINK_PUBKEY);
	struct dsc_msg_dhm_link_key *dhmMsg = contents_data(on->dc, BMX_DSC_TLV_DHM_LINK_PUBKEY);
	snprintf(linkKeys, sizeof(linkKeys), "%s%s%s", (rsaMsg ? cryptRsaKeyTypeAsString(rsaMsg->type) : (dhmMsg ? cryptDhmKeyTypeAsString(dhmMsg->type) : DBG_NIL)),
		(rsaMsg && dhmMsg ? "," : ""), (rsaMsg && dhmMsg ? cryptDhmKeyTypeAsString(dhmMsg->type) : ""));

	return linkKeys;
}

struct link_status {
	GLOBAL_ID_T *shortId;
	GLOBAL_ID_T *nodeId;
	char* name;
	char* nodeKey;
	char* linkKey;
	char linkKeys[MAX_LINK_KEYS_SIZE];
	char linkRsaPk[9];
	char linkDhmPk[9];
	IPX_T nbLocalIp;
	MAC_T nbMac;
	uint16_t nbIdx;
	IPX_T localIp;
	IFNAME_T dev;
	uint16_t rts;
	uint16_t idx;
	IID_T iidMax;
	AGGREG_SQN_T aggSize;
	AGGREG_SQN_T aggMax;
	uint8_t aggRcvd;
	HELLO_SQN_T lastHelloSqn;
	TIME_T lastHelloAdv;

	uint8_t rq;
	uint8_t bestRq;
	uint8_t tq;
	uint8_t bestTq;
	UMETRIC_T rxRate;
	UMETRIC_T txRate;

	// link stats:
	float wLastUpd;

	UMETRIC_T wRxRate;
	uint32_t wRxCnt;
	int8_t wRxMcs;
	uint8_t wRxMhz;
	uint8_t wRxNss;
	int8_t wRxSgi;
	int8_t wRxChw;
	int8_t wRxHt;
	int8_t wRxVht;

	UMETRIC_T wTxRateExpected;
	UMETRIC_T wTxRateAvg;
	UMETRIC_T wTxRate;
	uint32_t cnt;
	int8_t mcs;
	uint8_t mhz;
	uint8_t nss;
	int8_t sgi;
	int8_t chw;
	int8_t ht;
	int8_t vht;
	float wTxLastProbe;
	uint32_t wTxProbe;
	float wTxLastBurst;
	uint32_t wTxBurst;

	int8_t wSignal;
	int8_t wNoise;
	int8_t wSnr;

};

static const struct field_format link_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  link_status, shortId,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, link_status, nodeId,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      link_status, name,             1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      link_status, nodeKey,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      link_status, linkKey,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       link_status, linkKeys,         1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       link_status, linkRsaPk,        1, FIELD_RELEVANCE_MEDI),
	FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       link_status, linkDhmPk,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               link_status, nbLocalIp,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_MAC,               link_status, nbMac,            1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, nbIdx,            1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               link_status, localIp,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       link_status, dev,              1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, rts,              1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, idx,              1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, iidMax,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, aggSize,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, aggMax,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, aggRcvd,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, lastHelloSqn,     1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, lastHelloAdv,     1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, rq,               1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, bestRq,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, tq,               1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, bestTq,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           link_status, rxRate,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           link_status, txRate,           1, FIELD_RELEVANCE_HIGH),

	FIELD_FORMAT_INIT(FIELD_TYPE_FLOAT,             link_status, wLastUpd,         1, FIELD_RELEVANCE_MEDI),

        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           link_status, wRxRate,          1, FIELD_RELEVANCE_MEDI),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wRxCnt,           1, FIELD_RELEVANCE_MEDI),
	FIELD_FORMAT_INIT(FIELD_TYPE_INT,               link_status, wRxMcs,           1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wRxMhz,           1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wRxNss,           1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wRxSgi,           1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wRxChw,           1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wRxHt,            1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wRxVht,           1, FIELD_RELEVANCE_LOW),

        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           link_status, wTxRateAvg,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           link_status, wTxRateExpected,  1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           link_status, wTxRate,          1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, cnt,              1, FIELD_RELEVANCE_MEDI),
	FIELD_FORMAT_INIT(FIELD_TYPE_INT,               link_status, mcs,              1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, mhz,              1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, nss,              1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, sgi,              1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, chw,              1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, ht,               1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, vht,              1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_FLOAT,             link_status, wTxLastProbe,     1, FIELD_RELEVANCE_MEDI),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wTxProbe,         1, FIELD_RELEVANCE_MEDI),
	FIELD_FORMAT_INIT(FIELD_TYPE_FLOAT,             link_status, wTxLastBurst,     1, FIELD_RELEVANCE_MEDI),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wTxBurst,         1, FIELD_RELEVANCE_MEDI),

	FIELD_FORMAT_INIT(FIELD_TYPE_INT,               link_status, wSignal,          1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_INT,               link_status, wNoise,           1, FIELD_RELEVANCE_LOW),
	FIELD_FORMAT_INIT(FIELD_TYPE_INT,               link_status, wSnr,             1, FIELD_RELEVANCE_HIGH),

        FIELD_FORMAT_END
};

static int32_t link_status_creator(struct status_handl *handl, void *data)
{
	struct avl_node *linkDev_it, *local_it;
	LinkDevNode *linkDev;
	struct neigh_node *local;
	uint32_t max_size = link_tree.items * sizeof(struct link_status);
	uint32_t i = 0;

	struct link_status *status = ((struct link_status*) (handl->data = debugRealloc(handl->data, max_size, -300358)));
	memset(status, 0, max_size);

	for (local_it = NULL; (local = avl_iterate_item(&local_tree, &local_it));) {

		struct orig_node *on = local->on;
		assertion(-502210, (on));
		for (linkDev_it = NULL; (linkDev = avl_iterate_item(&local->linkDev_tree, &linkDev_it));) {

			LinkNode *link = NULL;
			while ((link = avl_next_item(&linkDev->link_tree, (link ? &link->k : NULL)))) {

				status[i].nodeId = &on->k.nodeId;
				status[i].shortId = &on->k.nodeId;
				status[i].name = strlen(on->k.hostname) ? on->k.hostname : DBG_NIL;
				status[i].nodeKey = cryptRsaKeyTypeAsString(((struct dsc_msg_pubkey*) on->kn->content->f_body)->type);
				status[i].linkKey = cryptRsaKeyTypeAsString(link->lastRxKey) ? cryptRsaKeyTypeAsString(link->lastRxKey) : cryptDhmKeyTypeAsString(link->lastRxKey);
				struct dsc_msg_pubkey *linkRsaKey = contents_data(on->dc, BMX_DSC_TLV_RSA_LINK_PUBKEY);
				struct dsc_msg_dhm_link_key *linkDhmKey = contents_data(on->dc, BMX_DSC_TLV_DHM_LINK_PUBKEY);
				snprintf(status[i].linkRsaPk, sizeof(status[i].linkRsaPk), "%s", ((linkRsaKey && cryptRsaKeyLenByType(linkRsaKey->type)) ? memAsHexString(linkRsaKey->key, XMIN(cryptRsaKeyLenByType(linkRsaKey->type), ((sizeof(status[i].linkRsaPk) - 1)/2))) : NULL));
				snprintf(status[i].linkDhmPk, sizeof(status[i].linkDhmPk), "%s", ((linkDhmKey && cryptDhmKeyLenByType(linkDhmKey->type)) ? memAsHexString(linkDhmKey->gx,  XMIN(cryptDhmKeyLenByType(linkDhmKey->type), ((sizeof(status[i].linkDhmPk) - 1)/2))) : NULL));
				snprintf(status[i].linkKeys, sizeof(status[i].linkKeys), "%s", getLinkKeysAsString(on));
				status[i].nbLocalIp = linkDev->key.llocal_ip;
				status[i].nbMac = *ip6Eui64ToMac(&linkDev->key.llocal_ip, NULL);
				status[i].nbIdx = linkDev->key.devIdx;
				status[i].dev = link->k.myDev->ifname_label;
				status[i].idx = link->k.myDev->llipKey.devIdx;
				status[i].localIp = link->k.myDev->llipKey.llip;
				status[i].rq = ((link->timeaware_rq_probe * 100) / LQ_MAX);
				status[i].bestRq = (link == local->best_rq_link);
				status[i].tq = ((link->timeaware_tq_probe * 100) / LQ_MAX);
				status[i].bestTq = (link == local->best_tq_link);
				status[i].txRate = link->wifiStats.txRateAvg ? link->wifiStats.txRateAvg : ((link->timeaware_tq_probe * link->k.myDev->umetric_max) / LQ_MAX);
				status[i].rxRate = ((link->timeaware_rq_probe * (link->wifiStats.rxRate ? link->wifiStats.rxRate : link->k.myDev->umetric_max)) / LQ_MAX);

				status[i].wLastUpd = link->wifiStats.updatedTime ? ((float)(((TIME_T)(bmx_time - link->wifiStats.updatedTime))/1000)) : -1;
				status[i].wTxLastProbe = link->wifiStats.txTriggTime ? ((float)(((TIME_T)(bmx_time - link->wifiStats.txTriggTime))/1000)) : -1;
				status[i].wTxProbe = link->wifiStats.txTriggCnt;
				status[i].wTxLastBurst = link->wifiStats.txBurstTime ? ((float)(((TIME_T)(bmx_time - link->wifiStats.txBurstTime))/1000)) : -1;
				status[i].wTxBurst = link->wifiStats.txBurstCnt;
				status[i].wSignal = link->wifiStats.signal;
				status[i].wNoise = link->wifiStats.noise;
				status[i].wSnr = link->wifiStats.signal - link->wifiStats.noise;
				status[i].wTxRate = link->wifiStats.txRate;
				status[i].wTxRateAvg = link->wifiStats.txRateAvg;
				status[i].wTxRateExpected = link->wifiStats.txRateExpected;
				status[i].cnt = link->wifiStats.txPackets;
				status[i].mcs = link->wifiStats.txMcs;
				status[i].mhz = link->wifiStats.txMhz;
				status[i].nss = link->wifiStats.txNss;
				status[i].sgi = link->wifiStats.txShortGi;
				status[i].chw = link->wifiStats.tx40mhz ? 40 : 20;
				status[i].ht = link->wifiStats.txHt;
				status[i].vht = link->wifiStats.txVht;
				status[i].wRxRate = link->wifiStats.rxRate;
				status[i].wRxCnt = link->wifiStats.rxPackets;
				status[i].wRxMcs = link->wifiStats.rxMcs;
				status[i].wRxMhz = link->wifiStats.rxMhz;
				status[i].wRxNss = link->wifiStats.rxNss;
				status[i].wRxSgi = link->wifiStats.rxShortGi;
				status[i].wRxChw = link->wifiStats.rx40mhz ? 40 : 20;
				status[i].wRxHt = link->wifiStats.rxHt;
				status[i].wRxVht = link->wifiStats.rxVht;

				status[i].rts = link->orig_routes;
				status[i].iidMax = linkDev->key.local->neighIID4x_repos.max_free;
				status[i].aggSize = local->ogm_aggreg_size;
				status[i].aggMax = local->ogm_aggreg_max;
				status[i].aggRcvd = bit_get(local->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, local->ogm_aggreg_max);
				status[i].lastHelloSqn = linkDev->hello_sqn_max;
				status[i].lastHelloAdv = ((TIME_T) (bmx_time - linkDev->hello_time_max)) / 1000;

				i++;
				assertion(-501225, (max_size >= i * sizeof(struct link_status)));
			}
		}
	}

	return i * sizeof(struct link_status);
}




STATIC_FUNC
struct opt_type link_options[]=
{
	{ODI,0,ARG_LINKS,		0,  9,1,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show links\n"},
			
	{ODI, 0, ARG_LINK_PURGE_TO,     0, 9, 1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &link_purge_to, MIN_LINK_PURGE_TO, MAX_LINK_PURGE_TO, DEF_LINK_PURGE_TO, 0, 0,
		ARG_VALUE_FORM, "timeout in ms for purging stale links"},

	{ODI, 0, ARG_TIMEAWARE_LQ_MIN,     0, 9, 1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &timeaware_lq_min, MIN_TIMEAWARE_LQ_MIN, MAX_TIMEAWARE_LQ_MIN, DEF_TIMEAWARE_LQ_MIN, 0, 0,
		ARG_VALUE_FORM, "set minimum required link quality"},

        {ODI,0,ARG_HELLO_SQN_WINDOW,       0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_link_window,	MIN_HELLO_SQN_WINDOW, 	MAX_HELLO_SQN_WINDOW,DEF_HELLO_SQN_WINDOW,0,    opt_link_metric,
			ARG_VALUE_FORM,	"set link window size (LWS) for link-quality calculation (link metric)"}
};


STATIC_FUNC
int32_t init_link( void )
{
	register_options_array(link_options, sizeof (link_options), CODE_CATEGORY_NAME);
	register_status_handl(sizeof(struct link_status), 1, link_status_format, ARG_LINKS, link_status_creator);

	struct frame_handl handl;
	memset(&handl, 0, sizeof( handl));

	static const struct field_format llip_format[] = DESCRIPTION_MSG_LLIP_FORMAT;
	handl.name = "DSC_LLIP";
	handl.min_msg_size = sizeof(struct dsc_msg_llip);
	handl.fixed_msg_size = 1;
	handl.positionMandatory = 0;
	handl.dextCompression = (int32_t*) & dflt_fzip;
	handl.dextReferencing = (int32_t*) & fref_dflt;
	handl.tx_frame_handler = create_dsc_tlv_llip;
	handl.rx_frame_handler = process_dsc_tlv_llip;
	handl.msg_format = llip_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_LLIP, &handl);

	handl.name = "HELLO_ADV";
	handl.min_msg_size = sizeof(struct msg_hello_adv);
	handl.fixed_msg_size = 1;
	handl.tx_packet_prepare_casuals = schedule_hello_adv;
	handl.tx_msg_handler = tx_msg_hello_adv;
	handl.rx_msg_handler = rx_msg_hello_adv;
	register_frame_handler(packet_frame_db, FRAME_TYPE_HELLO_ADV, &handl);

        handl.name = "HELLO_REPLY";
        handl.min_msg_size = sizeof (struct msg_hello_reply_dhash);
        handl.fixed_msg_size = 1;
	handl.tx_packet_prepare_casuals = schedule_hello_reply;
        handl.tx_msg_handler = tx_msg_hello_reply;
        handl.rx_msg_handler = rx_msg_hello_reply;
        register_frame_handler(packet_frame_db, FRAME_TYPE_HELLO_REPLY_DHASH, &handl);

        return SUCCESS;
}

STATIC_FUNC
void cleanup_link( void )
{
}





struct plugin *link_get_plugin( void ) {

	static struct plugin link_plugin;
	memset( &link_plugin, 0, sizeof ( struct plugin ) );

	link_plugin.plugin_name = CODE_CATEGORY_NAME;
	link_plugin.plugin_size = sizeof ( struct plugin );
        link_plugin.cb_init = init_link;
	link_plugin.cb_cleanup = cleanup_link;

        return &link_plugin;
}

