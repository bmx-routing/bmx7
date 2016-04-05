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
#include "sec.h"
#include "metrics.h"
#include "ogm.h"
#include "msg.h"
#include "desc.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "allocate.h"
#include "prof.h"

#define CODE_CATEGORY_NAME "ogm"




static int32_t minMyOgmInterval = DEF_OGM_INTERVAL;   /* orginator message interval in miliseconds */
static int32_t maxMyOgmIFactor = DEF_OGM_IFACTOR;

AGGREG_SQN_T ogm_aggreg_sqn_max = 0;
AGGREG_SQN_T ogm_aggreg_sqn_max_window_size = 0;
AGGREG_SQN_T ogm_aggreg_sqn_send = 0;

int32_t sendRevisedOgms = DEF_SEND_REVISED_OGMS;


struct avl_tree **get_my_ogm_aggreg_origs(AGGREG_SQN_T aggSqn)
{
	static struct avl_tree *my_ogm_aggreg_orig_trees[AGGREG_SQN_CACHE_RANGE] = {NULL};

	return &my_ogm_aggreg_orig_trees[(AGGREG_SQN_CACHE_MASK & aggSqn)];
}


void remove_ogm( struct orig_node *on )
{

	if (on->ogmAggregActive) {
		AGGREG_SQN_T aggregSqn = on->ogmAggregSqn;
		struct avl_tree *aggregSqnOrigs = *get_my_ogm_aggreg_origs(aggregSqn);
		ASSERTION(-502280, (aggregSqnOrigs && aggregSqnOrigs->items && avl_find(aggregSqnOrigs, &on->k.nodeId)));

		on->ogmAggregActive = 0;
		avl_remove(aggregSqnOrigs, &on->k.nodeId, -300760);

		if (!aggregSqnOrigs->items) {
			debugFree(aggregSqnOrigs, -300761);
			*get_my_ogm_aggreg_origs(aggregSqn) = (struct avl_tree*) NULL;
		}

		while (ogm_aggreg_sqn_max_window_size && (ogm_aggreg_sqn_max - (ogm_aggreg_sqn_max_window_size - 1)) == aggregSqn && !(*get_my_ogm_aggreg_origs(aggregSqn))) {

			ogm_aggreg_sqn_max_window_size--;
			aggregSqn++;
		}
	}
}


STATIC_FUNC
void schedule_ogm_aggregations(void)
{
	assertion(-502276, ((ogm_aggreg_sqn_max - ogm_aggreg_sqn_send) <= 1));
	assertion(-502471, ((*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))));
	assertion(-502275, ((*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))->items));

	if (ogm_aggreg_sqn_max > ogm_aggreg_sqn_send) {

		ogm_aggreg_sqn_send = ogm_aggreg_sqn_max;
		uint16_t sz = (*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))->items * sizeof(struct msg_ogm_adv);
		schedule_tx_task(FRAME_TYPE_OGM_ADV, NULL, NULL, NULL, sz, &ogm_aggreg_sqn_max, sizeof(ogm_aggreg_sqn_max));
	}
}



STATIC_FUNC
void schedule_ogm( struct orig_node *on, OGM_SQN_T ogmSqn, UMETRIC_T um, uint8_t hopCount )
{
//	assertion(-502281, (on && ogmSqn && um));
        TRACE_FUNCTION_CALL;
	assertion(-502281, (on && um));

	dbgf_track(DBGT_INFO, "ogmSqn=%d maxRcvd=%d maxSend=%d range=%d metric=%s %ju",
		ogmSqn, on->dc->ogmSqnMaxRcvd, on->dc->ogmSqnMaxSend, on->dc->ogmSqnRange, umetric_to_human(um), um);

	assertion_dbg(-500000, ((um & ~UMETRIC_MASK) == 0), "um=%ju mask=%ju max=%ju",um, UMETRIC_MASK, UMETRIC_MAX);

	if ((ogmSqn > on->dc->ogmSqnMaxSend) || (ogmSqn == on->dc->ogmSqnMaxSend && um > on->ogmMetric)) {

		if (on->ogmAggregActive && on->ogmAggregSqn == ogm_aggreg_sqn_max && ogm_aggreg_sqn_max > ogm_aggreg_sqn_send) {

			ASSERTION(-502282, (avl_find((*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max)), &on->k.nodeId)));

		} else {
			remove_ogm(on);

			assertion(-502283, ((ogm_aggreg_sqn_max - ogm_aggreg_sqn_send) <= 1));

			if (ogm_aggreg_sqn_max == ogm_aggreg_sqn_send) {

				if (ogm_aggreg_sqn_max_window_size >= AGGREG_SQN_CACHE_RANGE) {
					struct avl_tree *origs;
					while ((origs = *get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max + 1))) {
						struct orig_node *o = avl_first_item(origs);
						dbgf_sys(DBGT_WARN, "Removing scheduled ogmSqn=%d hostname=%s ogmAggActive=%d ogmAggSqn=%d ogmAggSqnMax=%d",
							o->dc->ogmSqnMaxSend, o->k.hostname, o->ogmAggregActive, o->ogmAggregSqn, ogm_aggreg_sqn_max);
						assertion(-502472, (o->ogmAggregActive && o->ogmAggregSqn == ((AGGREG_SQN_T)(ogm_aggreg_sqn_max+1-AGGREG_SQN_CACHE_RANGE))));
						remove_ogm(o);
					}
					assertion(-502473, (ogm_aggreg_sqn_max_window_size < AGGREG_SQN_CACHE_RANGE));
				}

				ogm_aggreg_sqn_max++;
				ogm_aggreg_sqn_max_window_size++;
			}

			if (!(*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))) {
				(*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max)) = debugMallocReset(sizeof(struct avl_tree), -300762);
				AVL_INIT_TREE((*(*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))), struct orig_node, k.nodeId );
			}

			avl_insert((*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max)), on, -300763);

			on->ogmAggregActive = 1;
			on->ogmAggregSqn = ogm_aggreg_sqn_max;
		}

		struct desc_content *dc = on->dc;
		assertion(-502284, ((ogm_aggreg_sqn_max - ogm_aggreg_sqn_send) == 1));
		assertion(-500000, (dc->ogmSqnMaxRcvd <= dc->ogmSqnRange));
		assertion(-500000, (ogmSqn <= dc->ogmSqnRange));
		assertion(-500000, (dc->ogmSqnMaxRcvd >= ogmSqn));

		on->dc->ogmSqnMaxSend = ogmSqn;
		on->ogmMetric = um;
		on->ogmHopCount = hopCount;

		if ((*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))->items >= OGMS_DHASH_PER_AGGREG_PREF)
			schedule_ogm_aggregations();
	}

}


STATIC_FUNC
void schedule_my_originator_message(void)
{
        TRACE_FUNCTION_CALL;
	struct orig_node *on = myKey->on;

	dbgf_track(DBGT_INFO, "maxSend=%d range=%d", on->dc->ogmSqnMaxSend, on->dc->ogmSqnRange);

	if (on->dc->ogmSqnMaxSend < on->dc->ogmSqnRange) {

		on->dc->chainLinkMaxRcvd = myChainLinkCache(on->dc->ogmSqnMaxSend + 1, on->dc->descSqn).u.e.link;
		on->dc->ogmSqnMaxRcvd = on->dc->ogmSqnMaxSend + 1;

		schedule_ogm(on, on->dc->ogmSqnMaxSend + 1, UMETRIC_MAX, 0);
	} else {
		my_description_changed = YES;
	}
}

STATIC_FUNC
void revise_ogm_aggregations(void)
{
	assertion(-502276, ((ogm_aggreg_sqn_max - ogm_aggreg_sqn_send) <= 1));


	static TIME_T myNextHitchhike = 0;
	static TIME_T myNextGuarantee = 0;

	TIME_T myGuaranteedInterval = ((minMyOgmInterval * maxMyOgmIFactor) / 100);
	IDM_T myNextNow = !my_description_changed && doNowOrLater(&myNextGuarantee, myGuaranteedInterval, (myKey->on->dc->ogmSqnMaxSend == 0));

	if (myNextNow ||
		(ogm_aggreg_sqn_max > ogm_aggreg_sqn_send && *get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max) && (*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))->items)) {

		if (doNowOrLater(&myNextHitchhike, minMyOgmInterval, myNextNow)) {
			doNowOrLater(&myNextGuarantee, myGuaranteedInterval, YES); //sync the two timeouts!
			schedule_my_originator_message();
		}


		dbgf(myNextNow ? DBGL_CHANGES : DBGL_ALL, DBGT_INFO, "myNextNow=%d myGuaranteedInterval=%d sqnMax=%d sqnSend=%d size=%d max=%d ogmSqnMaxSend=%d",
			myNextNow, myGuaranteedInterval, ogm_aggreg_sqn_max, ogm_aggreg_sqn_send,
			(*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max)) ? (*get_my_ogm_aggreg_origs(ogm_aggreg_sqn_max))->items : 0,
			OGMS_DHASH_PER_AGGREG_PREF, myKey->on->dc->ogmSqnMaxSend);

		schedule_ogm_aggregations();
	}
}






STATIC_FUNC
int32_t tx_frame_ogm_aggreg_sqn(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	assertion(-500771, (tx_iterator_cache_data_space_pref(it, 0, 0) >= ((int) sizeof(struct msg_ogm_aggreg_sqn_adv))));

	dbgf_all(DBGT_INFO, "max=%d size=%d", ogm_aggreg_sqn_max, ogm_aggreg_sqn_max_window_size);

	struct msg_ogm_aggreg_sqn_adv *adv = (struct msg_ogm_aggreg_sqn_adv *) (tx_iterator_cache_msg_ptr(it));

	adv->max = htons(ogm_aggreg_sqn_max);
	adv->size = htons(ogm_aggreg_sqn_max_window_size);

	return sizeof(struct msg_ogm_aggreg_sqn_adv);
}


STATIC_FUNC
int32_t rx_frame_ogm_aggreg_sqn(struct rx_frame_iterator *it)
{

	assertion(-502285, (it && it->f_type == FRAME_TYPE_OGM_AGG_SQN_ADV));
	assertion(-502286, (it->pb->i.verifiedLink && it->pb->i.verifiedLink->k.linkDev->key.local));

	AGGREG_SQN_T max = ntohs(((struct msg_ogm_aggreg_sqn_adv *) it->f_msg)->max);
	AGGREG_SQN_T sz = ntohs(((struct msg_ogm_aggreg_sqn_adv *) it->f_msg)->size);
	struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;

	dbgf_all(DBGT_INFO, "from neigh=%s max=%d/%d sz=%d/%d time=%d",
		nn->on->k.hostname, max, nn->ogm_aggreg_max, sz, nn->ogm_aggreg_size, nn->ogm_aggreg_time);


	if ((AGGREG_SQN_MASK & (nn->ogm_aggreg_max - (max + 1))) >= AGGREG_SQN_CACHE_RANGE) {

		sz = XMIN(sz, AGGREG_SQN_CACHE_RANGE);

		if (nn->ogm_aggreg_time && ((AGGREG_SQN_MASK & (max - nn->ogm_aggreg_max)) < AGGREG_SQN_CACHE_RANGE))
			sz = XMIN(sz, (nn->ogm_aggreg_size + (max - nn->ogm_aggreg_max)));
		else
			sz = XMIN(sz, 1);

		nn->ogm_aggreg_size = sz;

		if (max != nn->ogm_aggreg_max) {

			if ((AGGREG_SQN_MASK & (max - nn->ogm_aggreg_max)) >= sz) {

				memset(nn->ogm_aggreg_sqns, 0, sizeof(nn->ogm_aggreg_sqns));

			} else {
				bits_clear(nn->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE,
					((AGGREG_SQN_MASK)& (nn->ogm_aggreg_max + 1)), max, AGGREG_SQN_MASK);
			}

			dbgf_track(DBGT_INFO, "new ogm aggregation from neigh=%s %d/%d", nn->on->k.hostname, nn->ogm_aggreg_max, max);
			nn->ogm_aggreg_max = max;
			nn->ogm_aggreg_time = bmx_time;
		}
	}

	return TLV_RX_DATA_PROCESSED;
}

STATIC_FUNC
void schedule_ogm_req(void)
{
	struct neigh_node *nn = NULL;

	while ((nn = avl_next_item(&local_tree, nn ? &nn->local_id : NULL))) {

		if (/*nn->orig_routes &&*/ nn->best_tp_link && (nn->ogm_aggreg_time || nn->ogm_aggreg_max)) { //ever updated:

			AGGREG_SQN_T cnt = 0;

			for (cnt = 0; cnt < nn->ogm_aggreg_size; cnt++) {

				AGGREG_SQN_T sqn = (nn->ogm_aggreg_max - cnt);

				if (!bit_get(nn->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, sqn)) {
					struct dev_node *dev = nn->best_tp_link->k.myDev;
					schedule_tx_task(FRAME_TYPE_OGM_REQ, &nn->local_id, nn, dev, SCHEDULE_MIN_MSG_SIZE, &sqn, sizeof(sqn));
				}
			}
		}
	}
}


STATIC_FUNC
int32_t tx_msg_ogm_aggreg_request(struct tx_frame_iterator *it)
{
	AGGREG_SQN_T *sqn = (AGGREG_SQN_T *)it->ttn->key.data;
        struct hdr_ogm_aggreg_req *hdr = (struct hdr_ogm_aggreg_req *) tx_iterator_cache_hdr_ptr(it);
	struct msg_ogm_aggreg_req *msg = (struct msg_ogm_aggreg_req *) tx_iterator_cache_msg_ptr(it);

	IDM_T known = bit_get(it->ttn->neigh->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, *sqn);

	dbgf_track(DBGT_INFO, "sqn=%d known=%d to neigh=%s", *sqn, known, it->ttn->neigh->on->k.hostname);

	if (known) {

		return TLV_TX_DATA_DONE;

	} else {

		if (hdr->msg == msg) {
			assertion(-502287, (is_zero(hdr, sizeof (*hdr))));
			hdr->dest_nodeId = it->ttn->key.f.groupId;
		} else {
			assertion(-502288, (cryptShasEqual(&hdr->dest_nodeId, &it->ttn->key.f.groupId)));
		}

		msg->sqn = htons(*sqn);

		return sizeof(struct msg_ogm_aggreg_req);
	}
}


STATIC_FUNC
int32_t rx_msg_ogm_aggreg_request(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

        struct hdr_ogm_aggreg_req *hdr = (struct hdr_ogm_aggreg_req*) (it->f_data);
        struct msg_ogm_aggreg_req *msg = (struct msg_ogm_aggreg_req*) (it->f_msg);
	AGGREG_SQN_T sqn = ntohs(msg->sqn);

        if (cryptShasEqual(&hdr->dest_nodeId, &myKey->kHash) && (((AGGREG_SQN_T)(ogm_aggreg_sqn_max - sqn)) < ogm_aggreg_sqn_max_window_size) ) {

		struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
		uint16_t ogms = (*get_my_ogm_aggreg_origs(sqn)) ? (*get_my_ogm_aggreg_origs(sqn))->items : 0;

		schedule_tx_task(FRAME_TYPE_OGM_ADV, NULL, NULL, nn->best_tp_link->k.myDev, (ogms * sizeof(struct msg_ogm_adv)), &sqn, sizeof(sqn));

		dbgf_track(DBGT_INFO, "sqn=%d ogms=%d", sqn, ogms);
	}
	return TLV_RX_DATA_PROCESSED;
}



STATIC_FUNC
int32_t tx_frame_ogm_aggreg_advs(struct tx_frame_iterator *it)
{
	struct hdr_ogm_adv *hdr = ((struct hdr_ogm_adv*) tx_iterator_cache_hdr_ptr(it));
	AGGREG_SQN_T *sqn = ((AGGREG_SQN_T *)it->ttn->key.data);
	struct avl_tree *origs = (*get_my_ogm_aggreg_origs(*sqn));
	uint16_t ogms = origs ? origs->items : 0;
	struct avl_node *an = NULL;
	struct orig_node *on;
	struct msg_ogm_adv *msg;

	assertion(-500771, (tx_iterator_cache_data_space_pref(it, 0, 0) >= (int)(ogms * sizeof(struct msg_ogm_adv))));

	hdr->aggregation_sqn = htons(*sqn);

	for (msg = hdr->msg; (origs && (on = avl_iterate_item(origs, &an))); msg++) {

		FMETRIC_U16_T fm16 = umetric_to_fmetric(on->ogmMetric);
		msg->u.f.metric_exp = fm16.val.f.exp_fm16;
		msg->u.f.metric_mantissa = fm16.val.f.mantissa_fm16;
		msg->u.f.hopCount = on->ogmHopCount;
		msg->u.f.trustedFlag = 0;
		msg->u.f.transmitterIID4x = iid_get_myIID4x_by_node(on);
		msg->u.u32 = htonl(msg->u.u32);
		msg->chainOgm = chainOgmCalc(on->dc, on->dc->ogmSqnMaxSend);

		dbgf_track(DBGT_INFO, "name=%s dhash=%s sqn=%d metric=%ju cih=%s chainOgm=%s",
			on->k.hostname, cryptShaAsShortStr(&on->dc->dHash), on->dc->ogmSqnMaxSend, on->ogmMetric,
			memAsHexString(&on->dc->chainOgmConstInputHash, sizeof(msg->chainOgm)),
			memAsHexString(&msg->chainOgm, sizeof(msg->chainOgm)));
	}

	dbgf_all(DBGT_INFO, "aggSqn=%d aggSqnMax=%d ogms=%d", *sqn, ogm_aggreg_sqn_max, ogms);

	return (ogms * sizeof(struct msg_ogm_adv));
}

STATIC_FUNC
UMETRIC_T lndev_best_via_router(struct neigh_node *local, struct orig_node *on, UMETRIC_T *ogm_metric, LinkNode **bestPathLink)
{
	assertion(-502474, (local->linkDev_tree.items));
	assertion(-500000, (!(*bestPathLink)));
	assertion_dbg(-500000, ((*ogm_metric & ~UMETRIC_MASK) == 0), "um=%ju mask=%ju max=%ju",*ogm_metric, UMETRIC_MASK, UMETRIC_MAX);

        UMETRIC_T metric_best = 0;

	 struct avl_node *linkDev_an = NULL;
	LinkDevNode *linkDev;

	while ((linkDev = avl_iterate_item(&local->linkDev_tree, &linkDev_an))) {

		LinkNode *link = NULL;

		while ((link = avl_next_item(&linkDev->link_tree, (link ? &link->k : NULL)))) {

			UMETRIC_T um = apply_lndev_metric_algo(link, ogm_metric, on->mtcAlgo);

			if (metric_best < um) {
				metric_best = um;
				if (um > UMETRIC_MIN__NOT_ROUTABLE)
					*bestPathLink = link;
			}
		}
	}

//        assertion(-501088, (*bestPathLink));
        return metric_best;
}





void process_ogm_metric(void *voidRef)
{
	struct NeighRef_node *ref = voidRef;
	struct neigh_node *nn = ref->nn;
	struct key_node *kn = NULL;
	struct orig_node *on = NULL;
	struct desc_content *dc = NULL;
	assertion(-502475, (ref));
	assertion(-500000, (ref->nn));
	assertion(-500000, (ref->kn));

	if (ref->scheduled_ogm_processing) {
		ref->scheduled_ogm_processing = 0;
		task_remove(process_ogm_metric, (void*)ref);
	}

	if (!(kn = ref->kn) || !(on = kn->on) || !(dc = on->dc) || (ref->descSqn != dc->descSqn))
		return;
	
	assertion(-500000, (dc->ogmSqnMaxSend <= dc->ogmSqnRange));
	assertion(-500000, (dc->ogmSqnMaxRcvd <= dc->ogmSqnRange));
	assertion(-500000, (dc->ogmSqnMaxRcvd >= dc->ogmSqnMaxSend));
	
	assertion(-500000, (ref->ogmSqnMaxRcvd <= dc->ogmSqnRange));
	assertion(-500000, (ref->ogmSqnMaxRcvd <= dc->ogmSqnMaxRcvd));



	IDM_T neighTrust = verify_neighTrust(on, nn);
	IDM_T valid_metric = is_fmetric_valid(ref->ogmMtcMaxRcvd);
	UMETRIC_T ogmMetric = valid_metric ? (neighTrust ? fmetric_to_umetric(ref->ogmMtcMaxRcvd) : UMETRIC_MIN__NOT_ROUTABLE) : 0;
	IDM_T discard = (!valid_metric || (ogmMetric < on->mtcAlgo->umetric_min && ogmMetric != UMETRIC_MIN__NOT_ROUTABLE));

	dbgf_track(discard ? DBGT_WARN : DBGT_INFO,
		"orig=%s via neigh=%s nbTrust=%d validMetric=%d ogmMtc=%ju minMtc=%ju ogmSqnRcvd=%d ogmSqnMaxSend=%d",
		cryptShaAsShortStr(&on->k.nodeId), cryptShaAsShortStr(&nn->local_id),
		neighTrust, valid_metric, ogmMetric, on->mtcAlgo->umetric_min, ref->ogmSqnMaxRcvd, on->dc->ogmSqnMaxSend);

	assertion_dbg(-500000, ((ogmMetric & ~UMETRIC_MASK) == 0), "um=%ju mask=%ju max=%ju",ogmMetric, UMETRIC_MASK, UMETRIC_MAX);

	if (kn == myKey && ((ref->ogmSqnMaxRcvd > dc->ogmSqnMaxSend) || (ref->ogmSqnMaxRcvd == dc->ogmSqnMaxSend && ogmMetric >= on->ogmMetric))) {
		dbgf_mute(70, DBGL_SYS, DBGT_WARN, "OGM SQN or metric attack on myself, rcvd via trusted=%d neigh=%s, rcvdSqn=%d sendSqn=%d rcvdMetric=%ju sendMetric=%ju",
			neighTrust, cryptShaAsShortStr(&nn->local_id), ref->ogmSqnMaxRcvd, dc->ogmSqnMaxSend, ogmMetric, on->ogmMetric);
		return;
	}

	if (discard) {
		ref->ogmBestSinceSqn  = 0;
		return;
	}

	if (ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 0)) {

		LinkNode *bestLinkViaNeigh = NULL;
		UMETRIC_T bestMtcViaNeigh = lndev_best_via_router(nn, on, &ogmMetric, &bestLinkViaNeigh);
		assertion(-502478, (bestMtcViaNeigh));
		assertion_dbg(-500000, ((bestMtcViaNeigh & ~UMETRIC_MASK) == 0), "um=%ju mask=%ju max=%ju", bestMtcViaNeigh, UMETRIC_MASK, UMETRIC_MAX);

		if (
			((ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 2))) ||
			((ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 1)) && (((TIME_T)(bmx_time - ref->ogmTimeMaxRcvd)) >= on->mtcAlgo->ogm_sqn_late_hystere)) ||
			((ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 1)) && (bestLinkViaNeigh == on->curr_rt_link)) ||
			(sendRevisedOgms && (
			((ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 0)) && (bestMtcViaNeigh > (((100 + sendRevisedOgms) * on->ogmMetric) / 100)) && (bestLinkViaNeigh == on->curr_rt_link)) ||
			((ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 0)) && ref->ogmBestSinceSqn && (ref->ogmSqnMaxRcvd >= on->mtcAlgo->ogm_sqn_best_hystere + ref->ogmBestSinceSqn)) ||
			((ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 0)) && (bestMtcViaNeigh > ((on->ogmMetric * (100 + on->mtcAlgo->ogm_metric_hystere))/100)))))
			) {

			if (bestLinkViaNeigh != on->curr_rt_link) {

				if (on->curr_rt_link)
					cb_route_change_hooks(DEL, on);

				on->curr_rt_link = bestLinkViaNeigh;

				if (on->curr_rt_link)
					cb_route_change_hooks(ADD, on);
			}

			schedule_ogm(on, ref->ogmSqnMaxRcvd, bestMtcViaNeigh, ref->ogmHopCountMaxRcvd);

			ref->ogmBestSinceSqn = 0;

		} else {
			if ((ref->ogmSqnMaxRcvd >= (dc->ogmSqnMaxSend + 1)) && (((TIME_T)(bmx_time - ref->ogmTimeMaxRcvd)) < on->mtcAlgo->ogm_sqn_late_hystere)) {
				ref->scheduled_ogm_processing++;
				task_register((on->mtcAlgo->ogm_sqn_late_hystere - ((TIME_T) (bmx_time - ref->ogmTimeMaxRcvd))), process_ogm_metric, ref, -300764);
			}

			if ((bestMtcViaNeigh > on->ogmMetric) && !ref->ogmBestSinceSqn)
				ref->ogmBestSinceSqn = ref->ogmSqnMaxRcvd;
			else if (bestMtcViaNeigh <= on->ogmMetric)
				ref->ogmBestSinceSqn = 0;
		}
	}
}

STATIC_FUNC
int32_t rx_frame_ogm_aggreg_advs(struct rx_frame_iterator *it)
{
	struct hdr_ogm_adv *hdr = ((struct hdr_ogm_adv*) it->f_data);
	struct msg_ogm_adv *msg = hdr->msg;
	AGGREG_SQN_T aggSqn = ntohs(hdr->aggregation_sqn);
	struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
	IDM_T new = ((AGGREG_SQN_T) (nn->ogm_aggreg_max - aggSqn)) < nn->ogm_aggreg_size && !bit_get(nn->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, aggSqn);

	dbgf_track(DBGT_INFO, "new=%d neigh=%s aggSqn=%d/%d/%d msgs=%d",
		new, nn->on->k.hostname, aggSqn, nn->ogm_aggreg_max, nn->ogm_aggreg_size, it->f_msgs_fixed);

	if (new) {
		
		bit_set(nn->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, aggSqn, 1);

		for (; msg < &(hdr->msg[it->f_msgs_fixed]); msg++) {

			struct msg_ogm_adv tmp = {.u = {.u32 = ntohl(msg->u.u32) } };
			struct InaptChainOgm chainOgm = { .chainOgm = &msg->chainOgm, .ogmHopCount = (tmp.u.f.hopCount+1), .ogmMtc = {.val = {.f = {.exp_fm16 = tmp.u.f.metric_exp, .mantissa_fm16 = tmp.u.f.metric_mantissa}}}};

			dbgf_track(DBGT_INFO, "iid=%d, ogmSqn=%d ogmMtc=%d hops=%d", tmp.u.f.transmitterIID4x, chainOgm.ogmMtc.val.u16, tmp.u.f.hopCount+1);

			neighRef_update(nn, aggSqn, tmp.u.f.transmitterIID4x, NULL, 0, &chainOgm);

		}
	}

	return TLV_RX_DATA_PROCESSED;
}




STATIC_FUNC
struct opt_type ogm_options[]=
{
        {ODI,0,ARG_SEND_REVISED_OGMS, 0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,   &sendRevisedOgms,MIN_SEND_REVISED_OGMS, MAX_SEND_REVISED_OGMS, DEF_SEND_REVISED_OGMS,0,    NULL,
			ARG_VALUE_FORM,	"send revised ogms (with unchanged sqn) if metric increased by given percent"},
        {ODI,0,ARG_OGM_INTERVAL,        0,9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &minMyOgmInterval,  MIN_OGM_INTERVAL,   MAX_OGM_INTERVAL,   DEF_OGM_INTERVAL,0,   0,
			ARG_VALUE_FORM,	"set interval in ms with which new originator message (OGM) are send"},
        {ODI,0,ARG_OGM_IFACTOR,         0,9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &maxMyOgmIFactor,  MIN_OGM_IFACTOR,   MAX_OGM_IFACTOR,   DEF_OGM_IFACTOR, 0,   0,
			ARG_VALUE_FORM,	"set factor (relative to ogmInterval) for max delay of own ogms"},

};



int32_t init_ogm( void )
{
	register_options_array(ogm_options, sizeof(ogm_options), CODE_CATEGORY_NAME);

	assertion(-500000, (sizeof( ((struct msg_ogm_adv*)NULL)->u) == sizeof( ((struct msg_ogm_adv*)NULL)->u.u32)));

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));

	handl.name = "OGMS_SQNS_ADV";
	handl.min_msg_size = sizeof(struct msg_ogm_aggreg_sqn_adv);
	handl.fixed_msg_size = 1;

	// this might schedule a new tx_packet because schedule_tx_packet() believes
        // the stuff we are about to send now is still waiting to be send.
	handl.tx_packet_prepare_casuals = revise_ogm_aggregations;
	handl.tx_frame_handler = tx_frame_ogm_aggreg_sqn;
	handl.rx_frame_handler = rx_frame_ogm_aggreg_sqn;
	register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_AGG_SQN_ADV, &handl);

	handl.name = "OGMS_REQ";
	handl.data_header_size = sizeof(struct hdr_ogm_aggreg_req);
	handl.min_msg_size = sizeof(struct msg_ogm_aggreg_req);
	handl.fixed_msg_size = 1;
	handl.tx_packet_prepare_casuals = schedule_ogm_req;
	handl.tx_msg_handler = tx_msg_ogm_aggreg_request;
	handl.rx_msg_handler = rx_msg_ogm_aggreg_request;
	register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_REQ, &handl);

	handl.name = "OGMS_DHASH_ADV";
	handl.data_header_size = sizeof(struct hdr_ogm_adv);
	handl.min_msg_size = sizeof(struct msg_ogm_adv);
	handl.fixed_msg_size = 1;
	handl.tx_frame_handler = tx_frame_ogm_aggreg_advs;
	handl.rx_frame_handler = rx_frame_ogm_aggreg_advs;
	register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_ADV, &handl);


        return SUCCESS;

}


