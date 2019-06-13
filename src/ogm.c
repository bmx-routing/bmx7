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
#include "content.h"
#include "desc.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "allocate.h"
#include "prof.h"
#include "key.h"
#include "link.h"

#define CODE_CATEGORY_NAME "ogm"




int32_t my_ogmInterval = DEF_OGM_INTERVAL; /* orginator message interval in miliseconds */
static int32_t maxMyOgmIFactor = DEF_OGM_IFACTOR;


AGGREG_SQN_T ogm_aggreg_sqn_max = 0;
AGGREG_SQN_T ogm_aggreg_sqn_max_window_size = 0;
AGGREG_SQN_T ogm_aggreg_sqn_send = 0;

struct OgmAggreg_node *getOgmAggregNode(AGGREG_SQN_T aggSqn)
{
	static struct OgmAggreg_node my_ogm_aggreg_nodes[AGGREG_SQN_CACHE_RANGE];
	static AGGREG_SQN_T initialized = 0;

	if (!initialized) {
		memset(&my_ogm_aggreg_nodes, 0, sizeof(my_ogm_aggreg_nodes));

		for (; initialized < AGGREG_SQN_CACHE_RANGE; initialized++)
			AVL_INIT_TREE(my_ogm_aggreg_nodes[initialized].tree, struct orig_node, k.nodeId);
	}

	return &my_ogm_aggreg_nodes[(AGGREG_SQN_CACHE_MASK & aggSqn)];
}

void remove_ogm(struct orig_node *on)
{

	if (on->ogmAggregActiveMsgLen) {
		AGGREG_SQN_T aggregSqn = on->ogmAggregSqn;
		AGGREG_SQN_T ogm_aggreg_sqn_min;
		struct OgmAggreg_node *oan = getOgmAggregNode(aggregSqn);
		ASSERTION(-502280, (oan->tree.items && avl_find(&oan->tree, &on->k.nodeId) && oan->msgsLen >= on->ogmAggregActiveMsgLen));

		avl_remove(&oan->tree, &on->k.nodeId, -300760);
		oan->msgsLen -= on->ogmAggregActiveMsgLen;

		assertion(-502658, IMPLIES((!oan->tree.items || !oan->msgsLen), (!oan->tree.items && !oan->msgsLen)));

		on->ogmAggregActiveMsgLen = 0;

		while (ogm_aggreg_sqn_max_window_size &&
			(ogm_aggreg_sqn_min = (ogm_aggreg_sqn_max - (ogm_aggreg_sqn_max_window_size - 1))) == aggregSqn &&
			!(getOgmAggregNode(ogm_aggreg_sqn_min)->tree.items)) {

			ogm_aggreg_sqn_max_window_size--;
			aggregSqn++;
		}
	}
}

STATIC_FUNC
void schedule_ogm_aggregations(void)
{
	assertion(-502276, (((AGGREG_SQN_T) (ogm_aggreg_sqn_max - ogm_aggreg_sqn_send)) <= 1));
	assertion(-502275, ((getOgmAggregNode(ogm_aggreg_sqn_max))->tree.items));

	if (ogm_aggreg_sqn_max /*>*/ != ogm_aggreg_sqn_send) {

		ogm_aggreg_sqn_send = ogm_aggreg_sqn_max;
		int16_t sz = (getOgmAggregNode(ogm_aggreg_sqn_max))->msgsLen;
		schedule_tx_task(FRAME_TYPE_OGM_ADV, NULL, NULL, NULL, NULL, sz, &ogm_aggreg_sqn_max, sizeof(ogm_aggreg_sqn_max));
	}
}

STATIC_FUNC
void schedule_ogm(struct orig_node *on)
{
	//	assertion(-502281, (on && ogmSqn && um));
	assertion(-502281, (on && on->neighPath.um));
	struct desc_content *dc = on->dc;
	UMETRIC_T um = on->neighPath.um;

	dbgf_track(DBGT_INFO, "maxRcvd=%d maxSend=%d range=%d hops=%d metric=%s um=%ju ",
		dc->ogmSqnMaxRcvd, dc->ogmSqnMaxSend, dc->ogmSqnRange, on->ogmHopCount, umetric_to_human(um), um);

	assertion(-502576, (dc->ogmSqnMaxRcvd <= dc->ogmSqnRange));
	assertion(-502577, (dc->ogmSqnMaxSend <= dc->ogmSqnRange));
	assertion(-502578, (dc->ogmSqnMaxRcvd >= dc->ogmSqnMaxSend));
	assertion_dbg(-502574, ((um & ~UMETRIC_MASK) == 0), "um=%ju mask=%ju max=%ju", um, UMETRIC_MASK, UMETRIC_MAX);
	assertion_dbg(-502575, (um >= fmetric_to_umetric(umetric_to_fmetric(um))), "um=%ju um16=%d -> um=%ju", um, umetric_to_fmetric(um).val.u16, fmetric_to_umetric(umetric_to_fmetric(um)));
	assertion(-502759, (((AGGREG_SQN_T) (ogm_aggreg_sqn_max - ogm_aggreg_sqn_send)) <= 1));
	assertion(-502760, (ogm_aggreg_sqn_max_window_size <= AGGREG_SQN_CACHE_RANGE));

	update_ogm_mins(dc->kn, dc->descSqn, dc->ogmSqnMaxSend, &um);

	if (on->ogmHopCount >= on->mtcAlgo->ogm_hops_max) {
		remove_ogm(on);
		return;
	}


	struct OgmAggreg_node *oan = getOgmAggregNode(ogm_aggreg_sqn_max);

	if (on->ogmAggregActiveMsgLen && on->ogmAggregSqn == ogm_aggreg_sqn_max && ogm_aggreg_sqn_max /*>*/ != ogm_aggreg_sqn_send &&
		(oan->msgsLen - on->ogmAggregActiveMsgLen) <= ((int) OGMS_DHASH_MSGS_LEN_PER_AGGREG_PREF - (int) (sizeof(struct msg_ogm_adv) +on->neighPath.pathMetricsByteSize))) {

		ASSERTION(-502282, (avl_find(&oan->tree, &on->k.nodeId)));

	} else {
		remove_ogm(on);

		assertion(-502283, ((ogm_aggreg_sqn_max - ogm_aggreg_sqn_send) <= 1));

		if (ogm_aggreg_sqn_max == ogm_aggreg_sqn_send) {

			if (ogm_aggreg_sqn_max_window_size >= AGGREG_SQN_CACHE_RANGE) {

				while ((oan = getOgmAggregNode(ogm_aggreg_sqn_max + 1)) && oan->tree.items) {
					struct orig_node *o = avl_first_item(&oan->tree);
					dbgf_sys(DBGT_WARN, "Removing scheduled ogmSqn=%d hostname=%s ogmAggActive=%d ogmAggSqn=%d ogmAggSqnMax=%d",
						o->dc->ogmSqnMaxSend, o->k.hostname, o->ogmAggregActiveMsgLen, o->ogmAggregSqn, ogm_aggreg_sqn_max);
					assertion(-502472, (o->ogmAggregActiveMsgLen && o->ogmAggregSqn == ((AGGREG_SQN_T) (ogm_aggreg_sqn_max + 1 - AGGREG_SQN_CACHE_RANGE))));
					remove_ogm(o);
				}
				assertion(-502761, (ogm_aggreg_sqn_max_window_size < AGGREG_SQN_CACHE_RANGE));
			}

			ogm_aggreg_sqn_max++;
			ogm_aggreg_sqn_max_window_size++;
		}

		on->ogmAggregSqn = ogm_aggreg_sqn_max;
		oan = getOgmAggregNode(ogm_aggreg_sqn_max);
		avl_insert(&(oan->tree), on, -300763);
	}

	oan->msgsLen += (sizeof(struct msg_ogm_adv) +on->neighPath.pathMetricsByteSize) - on->ogmAggregActiveMsgLen;
	on->ogmAggregActiveMsgLen = (sizeof(struct msg_ogm_adv) +on->neighPath.pathMetricsByteSize);

	assertion(-502284, (((AGGREG_SQN_T) (ogm_aggreg_sqn_max - ogm_aggreg_sqn_send)) == 1));

	if (oan->msgsLen > (int) (OGMS_DHASH_MSGS_LEN_PER_AGGREG_PREF - (sizeof(struct msg_ogm_adv) + (MAX_OGM_HOP_HISTORY_SZ * sizeof(struct msg_ogm_adv_metric_t0)))))
		schedule_ogm_aggregations();

}

STATIC_FUNC
void schedule_my_originator_message(void)
{
	struct orig_node *on = myKey->on;

	dbgf_track(DBGT_INFO, "maxSend=%d range=%d", on->dc->ogmSqnMaxSend, on->dc->ogmSqnRange);

	if (on->dc->ogmSqnMaxSend < on->dc->ogmSqnRange) {

		OGM_SQN_T nextOgmSqn = on->dc->ogmSqnMaxSend + 1;

		on->dc->chainLinkMaxRcvd = myChainLinkCache(nextOgmSqn, on->dc->descSqn).u.e.link;
		on->dc->ogmSqnMaxRcvd = nextOgmSqn;
		on->dc->ogmSqnMaxSend = nextOgmSqn;
		on->neighPath.um = UMETRIC_MAX;
		on->ogmHopCount = 0;


		schedule_ogm(on);
	} else {
		my_description_changed = YES;
	}
}

STATIC_FUNC
void revise_ogm_aggregations(void)
{
	assertion(-502276, (((AGGREG_SQN_T) (ogm_aggreg_sqn_max - ogm_aggreg_sqn_send)) <= 1));


	static TIME_T myNextHitchhike = 0;
	static TIME_T myNextGuarantee = 0;

	TIME_T myGuaranteedInterval = ((my_ogmInterval * maxMyOgmIFactor) / 100);
	IDM_T myNextNow = !my_description_changed && doNowOrLater(&myNextGuarantee, myGuaranteedInterval, (myKey->on->dc->ogmSqnMaxSend == 0));

	if (myNextNow || (ogm_aggreg_sqn_max /*>*/ != ogm_aggreg_sqn_send && getOgmAggregNode(ogm_aggreg_sqn_max)->tree.items)) {

		if (doNowOrLater(&myNextHitchhike, my_ogmInterval, myNextNow)) {
			doNowOrLater(&myNextGuarantee, myGuaranteedInterval, YES); //sync the two timeouts!
			schedule_my_originator_message();
		}

		struct OgmAggreg_node *oan = getOgmAggregNode(ogm_aggreg_sqn_max);

		dbgf(myNextNow ? DBGL_CHANGES : DBGL_ALL, DBGT_INFO,
			"myNextNow=%d myGuaranteedInterval=%d aggSqnMax=%d aggSqnSend=%d msgs=%d size=%d max=%lu ogmSqnMaxSend=%d",
			myNextNow, myGuaranteedInterval, ogm_aggreg_sqn_max, ogm_aggreg_sqn_send,
			oan->tree.items, oan->msgsLen, OGMS_DHASH_MSGS_LEN_PER_AGGREG_PREF, myKey->on->dc->ogmSqnMaxSend);

		if (oan->tree.items)
			schedule_ogm_aggregations();
	}
}

STATIC_FUNC
int32_t iterate_msg_ogm_adv(uint8_t *msgs, int32_t msgs_len, int32_t pos, IDM_T all, struct msg_ogm_adv_metric_t0 *hm, uint8_t *hmItems)
{
	assertion(-502659, (msgs && msgs_len));
	assertion(-502660, IMPLIES(hm || hmItems, hm && hmItems));

	while ((pos + (int) sizeof(struct msg_ogm_adv)) <= msgs_len) {

		union msg_ogm_adv_metric m0 = { .u32 = ntohl(((struct msg_ogm_adv*) (msgs + pos))->u.u32) };
		FMETRIC_U16_T fmm0 = {.val = {.f = {.exp_fm16 = m0.f.metric_exp, .mantissa_fm16 = m0.f.metric_mantissa}}};
		uint8_t more = (m0.f.more);
		uint8_t moreCnt = more;

		dbgf_track(DBGT_INFO, "len=%d pos=%-3d more=%d metric=%-10s hopCount=%-2d iid=%d", msgs_len, pos, more, umetric_to_human(fmetric_to_umetric(fmm0)), m0.f.hopCount, m0.f.transmitterIID4x);


		pos += sizeof(struct msg_ogm_adv);
		if (moreCnt) {

			while (more && moreCnt <= MAX_OGM_HOP_HISTORY_SZ &&
				(pos + (int) sizeof(struct msg_ogm_adv_metric_tAny)) <= msgs_len) {

				struct msg_ogm_adv_metric_tAny *tMore = ((struct msg_ogm_adv_metric_tAny *) (msgs + pos));

				if (tMore->u.f.type == 0 && (pos + (int) sizeof(struct msg_ogm_adv_metric_t0)) <= msgs_len) {

					struct msg_ogm_adv_metric_t0 t0 = {.u = {.u16 = ntohs(((struct msg_ogm_adv_metric_t0*) tMore)->u.u16)}, .channel = ((struct msg_ogm_adv_metric_t0*) tMore)->channel};
					FMETRIC_U16_T fmt0 = {.val = {.f = {.exp_fm16 = t0.u.f.metric_exp, .mantissa_fm16 = t0.u.f.metric_mantissa}}};

					dbgf_track(DBGT_INFO, "len=%d pos=%-3d more=%d metric=%-10s channel=%d", msgs_len, pos, t0.u.f.more, umetric_to_human(fmetric_to_umetric(fmt0)), t0.channel);

					if (hm) {
						hm[moreCnt - 1] = t0;

						if (moreCnt >= 2)
							hm[moreCnt - 2].u.f.more = 1;
					}

					pos += sizeof(struct msg_ogm_adv_metric_t0);

				} else {
					return FAILURE;
				}

				moreCnt = moreCnt + (more = tMore->u.f.more);
			}

			if (more)
				return FAILURE;
		}

		if (hmItems)
			*hmItems = moreCnt;

		if (!all)
			break;
	}

	return pos;
}

STATIC_FUNC
int32_t tx_frame_ogm_aggreg_sqn(struct tx_frame_iterator *it)
{
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

	dbgf_track(DBGT_INFO, "from neigh=%s max=%d/%d sz=%d/%d time=%d",
		nn->on->k.hostname, max, nn->ogm_aggreg_max, sz, nn->ogm_aggreg_size, nn->ogm_aggreg_time);


	if ((AGGREG_SQN_MASK & (nn->ogm_aggreg_max - (max + 1))) >= AGGREG_SQN_CACHE_RANGE) {

		sz = XMIN(sz, AGGREG_SQN_CACHE_RANGE);
		/*
				if (nn->ogm_aggreg_time && ((AGGREG_SQN_MASK & (max - nn->ogm_aggreg_max)) < AGGREG_SQN_CACHE_RANGE))
					sz = XMIN(sz, (nn->ogm_aggreg_size + (max - nn->ogm_aggreg_max)));
				else
					sz = XMIN(sz, 1);
		 */
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

	while ((nn = avl_next_item(&local_tree, nn ? &nn->k.nodeId : NULL))) {

		if (/*nn->orig_routes &&*/ nn->best_tq_link && (nn->ogm_aggreg_time || nn->ogm_aggreg_max)) { //ever updated:

			AGGREG_SQN_T cnt = 0;

			for (cnt = 0; cnt < nn->ogm_aggreg_size; cnt++) {

				AGGREG_SQN_T sqn = (nn->ogm_aggreg_max - cnt);

				if (!bit_get(nn->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, sqn)) {
					struct dev_node *dev = nn->best_tq_link->k.myDev;
					schedule_tx_task(FRAME_TYPE_OGM_REQ, NULL, &nn->k.nodeId, nn, dev, SCHEDULE_MIN_MSG_SIZE, &sqn, sizeof(sqn));
				}
			}
		}
	}
}

STATIC_FUNC
int32_t tx_msg_ogm_aggreg_request(struct tx_frame_iterator *it)
{
	AGGREG_SQN_T *sqn = (AGGREG_SQN_T *) it->ttn->key.data;
	struct hdr_ogm_aggreg_req *hdr = (struct hdr_ogm_aggreg_req *) tx_iterator_cache_hdr_ptr(it);
	struct msg_ogm_aggreg_req *msg = (struct msg_ogm_aggreg_req *) tx_iterator_cache_msg_ptr(it);

	IDM_T known = bit_get(it->ttn->neigh->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, *sqn);

	dbgf_track(DBGT_INFO, "sqn=%d known=%d to neigh=%s", *sqn, known, it->ttn->neigh->on->k.hostname);

	if (known) {

		return TLV_TX_DATA_DONE;

	} else {

		if (hdr->msg == msg) {
			assertion(-502287, (is_zero(hdr, sizeof(*hdr))));
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
	struct hdr_ogm_aggreg_req *hdr = (struct hdr_ogm_aggreg_req*) (it->f_data);
	struct msg_ogm_aggreg_req *msg = (struct msg_ogm_aggreg_req*) (it->f_msg);
	AGGREG_SQN_T sqn = ntohs(msg->sqn);

	if (cryptShasEqual(&hdr->dest_nodeId, &myKey->kHash) && (((AGGREG_SQN_T) (ogm_aggreg_sqn_max - sqn)) < ogm_aggreg_sqn_max_window_size)) {

		struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
		struct OgmAggreg_node *oan = getOgmAggregNode(sqn);

		schedule_tx_task(FRAME_TYPE_OGM_ADV, NULL, NULL, NULL, nn->best_tq_link->k.myDev, oan->msgsLen, &sqn, sizeof(sqn));

		dbgf_track(DBGT_INFO, "sqn=%d ogms=%d size=%d", sqn, oan->tree.items, oan->msgsLen);
	}
	return TLV_RX_DATA_PROCESSED;
}

STATIC_FUNC
int32_t tx_frame_ogm_aggreg_advs(struct tx_frame_iterator *it)
{
	struct hdr_ogm_adv *hdr = ((struct hdr_ogm_adv*) tx_iterator_cache_hdr_ptr(it));
	AGGREG_SQN_T *sqn = ((AGGREG_SQN_T *) it->ttn->key.data);
	struct OgmAggreg_node *oan = getOgmAggregNode(*sqn);
	struct avl_node *an = NULL;
	struct orig_node *on;
	struct msg_ogm_adv *msg = (struct msg_ogm_adv*) tx_iterator_cache_msg_ptr(it);

	if (tx_iterator_cache_data_space_max(it, 0, 0) < oan->msgsLen)
		return TLV_TX_DATA_FULL;

	hdr->aggregation_sqn = htons(*sqn);

	while ((on = avl_iterate_item(&oan->tree, &an))) {

		assertion(-502661, (on->ogmAggregActiveMsgLen));
		assertion(-502662, (on->dc->ogmSqnMaxSend)); //otherwise on->neighPath might be from last description, but ogm should have been removed during descupdate

		msg->chainOgm = chainOgmCalc(on->dc, on->dc->ogmSqnMaxSend);

		FMETRIC_U16_T fm16 = umetric_to_fmetric(on->neighPath.um);
		msg->u.f.metric_exp = fm16.val.f.exp_fm16;
		msg->u.f.metric_mantissa = fm16.val.f.mantissa_fm16;
		msg->u.f.hopCount = on->ogmHopCount;
		msg->u.f.transmitterIID4x = iid_get_myIID4x_by_node(on);
		msg->u.f.more = !!on->neighPath.pathMetricsByteSize;

		dbgf_track(DBGT_INFO, "name=%s nodeId=%s iid=%d sqn=%d metric=%ju more=%d hops=%lu (%d) cih=%s chainOgm=%s viaDev=%s",
			on->k.hostname, cryptShaAsShortStr(&on->kn->kHash), msg->u.f.transmitterIID4x, on->dc->ogmSqnMaxSend,
			on->neighPath.um, msg->u.f.more, (on->neighPath.pathMetricsByteSize / sizeof(struct msg_ogm_adv_metric_t0)), on->ogmHopCount,
			memAsHexString(&on->dc->chainOgmConstInputHash, sizeof(msg->chainOgm)),
			memAsHexString(&msg->chainOgm, sizeof(msg->chainOgm)), it->ttn->key.f.p.dev->ifname_label.str);

		msg->u.u32 = htonl(msg->u.u32);

		assertion(-502663, ((on->neighPath.pathMetricsByteSize % sizeof(struct msg_ogm_adv_metric_t0)) == 0));
		uint16_t p;
		for (p = 0; p < (on->neighPath.pathMetricsByteSize / sizeof(struct msg_ogm_adv_metric_t0)); p++) {

			struct msg_ogm_adv_metric_t0 *t0Out = ((struct msg_ogm_adv_metric_t0*) &(msg->mt0[p]));
			struct msg_ogm_adv_metric_t0 *t0In = &(on->neighPath.pathMetrics[p]);
			FMETRIC_U16_T fm = {.val = {.f = {.exp_fm16 = t0In->u.f.metric_exp, .mantissa_fm16 = t0In->u.f.metric_mantissa}}};

			dbgf_track(DBGT_INFO, "ogmHist=%d more=%d channel=%d mtc=%s", p + 1, t0In->u.f.more, t0In->channel, umetric_to_human(fmetric_to_umetric(fm)));

			assertion(-502664, (on->neighPath.pathMetrics[p].u.f.more == ((p + 1) < (on->neighPath.pathMetricsByteSize / (uint16_t)sizeof(struct msg_ogm_adv_metric_t0)))));
			t0Out->channel = t0In->channel;
			t0Out->u.u16 = htons(t0In->u.u16);
		}

		assertion(-502665, (on->ogmAggregActiveMsgLen == ((int) (sizeof(struct msg_ogm_adv) + (p * sizeof(struct msg_ogm_adv_metric_t0))))));

		msg = (struct msg_ogm_adv*) (((uint8_t*) msg) + on->ogmAggregActiveMsgLen);
	}

	dbgf_track(DBGT_INFO, "aggSqn=%d aggSqnMax=%d ogms=%d size=%d", *sqn, ogm_aggreg_sqn_max, oan->tree.items, oan->msgsLen);

	assertion(-502666, (((uint32_t) oan->msgsLen) == ((uint32_t) (((uint8_t*) msg) - tx_iterator_cache_msg_ptr(it)))));
	assertion(-502667, IMPLIES(oan->msgsLen, iterate_msg_ogm_adv(tx_iterator_cache_msg_ptr(it), oan->msgsLen, 0, YES, NULL, NULL) == oan->msgsLen));

	return oan->msgsLen;
}

STATIC_FUNC
struct NeighPath *lndev_best_via_router(struct NeighRef_node *ref)
{
	assertion(-502668, (ref));
	assertion(-502669, (ref->kn));
	assertion(-502670, (ref->kn->on));
	assertion(-502671, (ref->nn));
	assertion(-502672, (ref->kn->on->mtcAlgo->umetric_min >= UMETRIC_MIN__NOT_ROUTABLE));
	assertion(-502474, (ref->nn->linkDev_tree.items));

	static struct NeighPath bestNeighPath;
	struct avl_node *linkDev_an = NULL;
	LinkDevNode *linkDev;
	struct neigh_node *nn = ref->nn;
	struct orig_node *on = ref->kn->on;
	struct desc_content *dc = on->dc;
	IDM_T neighTrust = verify_neighTrust(on, nn);
	UMETRIC_T refMetric = fmetric_to_umetric(ref->ogmSqnMaxClaimedMetric);
	IDM_T newOgmMins = is_new_ogm_mins(ref->kn, ref->descSqn, ref->ogmSqnMax, &refMetric);

	bestNeighPath.link = NULL;
	bestNeighPath.pathMetricsByteSize = 0;
	bestNeighPath.um = UMETRIC_MIN__NOT_ROUTABLE;

	dbgf_track(refMetric <= on->mtcAlgo->umetric_min ? DBGT_WARN : DBGT_INFO,
		"orig=%s descSqn=%d via neigh=%s trusted=%d newOgmMin=%d (knDescSqn=%d refDescSqn=%d knOgmSqn=%d refOgmSqn=%d knMetricMin=%d refMetric=%d ogmSqnFirstSec=%d nowSec=%d) hops=%d refMtc=%ju refOgmHist=%d/%d minMtc=%ju ogmSqnRcvd=%d ogmSqnMaxSend=%d onSendMtc=%ju onSqnHystere=%d onMtcHystere=%d RefSqnBestSince=%d",
		cryptShaAsShortStr(&on->k.nodeId), dc->descSqn, cryptShaAsShortStr(&nn->k.nodeId),
		neighTrust, newOgmMins, ref->kn->descSqnMin, ref->descSqn, ref->kn->ogmSqnMin, ref->ogmSqnMax, ref->kn->ogmMetricMin.val.u16, umetric_to_fmetric(refMetric).val.u16, ref->kn->ogmSqnFirst_sec, bmx_time_sec,
		ref->ogmSqnMaxClaimedHops, refMetric,
		(int) (ref->ogmSqnMaxPathMetricsByteSize / sizeof(struct msg_ogm_adv_metric_t0)), on->mtcAlgo->ogm_hop_history,
		on->mtcAlgo->umetric_min, ref->ogmSqnMax, dc->ogmSqnMaxSend, on->neighPath.um,
		on->mtcAlgo->ogm_sqn_late_hystere_100ms, on->mtcAlgo->ogm_metric_hystere_new_path, ref->ogmBestSinceSqn);

	if (!neighTrust || !newOgmMins || refMetric < on->mtcAlgo->umetric_min || refMetric == UMETRIC_MIN__NOT_ROUTABLE || !ref->ogmSqnMaxClaimedHops)
		return &bestNeighPath;

	while ((linkDev = avl_iterate_item(&nn->linkDev_tree, &linkDev_an))) {

		LinkNode *link = NULL;
		struct avl_node *link_an = NULL;

		while ((link = avl_iterate_item(&linkDev->link_tree, &link_an))) {
			//		while ((link = avl_next_item(&linkDev->link_tree, (link ? &link->k : NULL)))) {

			if (min_lq_probe(link)) {

				struct NeighPath *tmpNeighPath = apply_metric_algo(ref, link, on->mtcAlgo);

				if (tmpNeighPath->um > bestNeighPath.um)
					bestNeighPath = *tmpNeighPath;

				assertion(-502673, (bestNeighPath.um >= on->mtcAlgo->umetric_min || bestNeighPath.um == UMETRIC_MIN__NOT_ROUTABLE));
				assertion(-502674, IMPLIES(bestNeighPath.link, bestNeighPath.um >= on->mtcAlgo->umetric_min && bestNeighPath.um > UMETRIC_MIN__NOT_ROUTABLE));
			}
		}
	}

	return &bestNeighPath;
}

void process_ogm_metric(void *voidRef)
{
	prof_start(process_ogm_metric, main);
	struct NeighRef_node *ref = voidRef;
	struct orig_node *on = NULL;
	struct desc_content *dc = NULL;
	struct key_node *kn = NULL;
	assertion(-502475, (ref));
	assertion(-502581, (ref->nn));

	if (ref->scheduled_ogm_processing) {
		ref->scheduled_ogm_processing = NO;
		task_remove(process_ogm_metric, (void*) ref);
	}

	if (((kn = ref->kn) && (on = kn->on) && (dc = on->dc) && (ref->descSqn == dc->descSqn)) &&
		(
		ref->ogmSqnMax &&
		(dc->ogmSqnMaxSend <= dc->ogmSqnRange) &&
		(dc->ogmSqnMaxSend <= dc->ogmSqnMaxRcvd) &&
		(dc->ogmSqnMaxRcvd <= dc->ogmSqnRange) &&
		(ref->ogmSqnMax <= dc->ogmSqnRange) &&
		(ref->ogmSqnMax <= dc->ogmSqnMaxRcvd) &&
		(ref->ogmSqnMax >= dc->ogmSqnMaxSend) &&
		(is_fmetric_valid(ref->ogmSqnMaxClaimedMetric)) &&
		(ref->ogmSqnMax > dc->ogmSqnMaxSend || fmetric_to_umetric(ref->ogmSqnMaxClaimedMetric) > on->neighPath.um)
		)
		) {

		assertion(-502583, (dc->ogmSqnMaxSend <= dc->ogmSqnRange));
		assertion(-502584, (dc->ogmSqnMaxRcvd <= dc->ogmSqnRange));
		assertion(-502585, (dc->ogmSqnMaxRcvd >= dc->ogmSqnMaxSend));
		assertion(-502586, (ref->ogmSqnMax <= dc->ogmSqnRange));
		assertion(-502587, (ref->ogmSqnMax <= dc->ogmSqnMaxRcvd));
		assertion(-502675, (ref->ogmSqnMax >= dc->ogmSqnMaxSend));

		struct NeighPath *bestNeighPath = lndev_best_via_router(ref);

		dbgf_track(DBGT_INFO, "to id=%s hostname=%s currMetric=%s=%ju minMetric=%ju ogmSqnMaxSend=%d currNeigh=%s  viaNeigh=%s bestMtcViaNeigh=%ju ogmSqn=%d ogmSqnBestSince=%d",
			cryptShaAsShortStr(&on->k.nodeId), on->k.hostname, umetric_to_human(on->neighPath.um), on->neighPath.um, UMETRIC_MIN__NOT_ROUTABLE, dc->ogmSqnMaxSend,
			(on->neighPath.link ? on->neighPath.link->k.linkDev->key.local->on->k.hostname : NULL),
			(bestNeighPath->link ? bestNeighPath->link->k.linkDev->key.local->on->k.hostname : NULL),
			bestNeighPath->um, ref->ogmSqnMax, ref->ogmBestSinceSqn);

		assertion_dbg(-502589, (
			((bestNeighPath->um & ~UMETRIC_MASK) == 0) && bestNeighPath->um &&
			(bestNeighPath->um == UMETRIC_MIN__NOT_ROUTABLE || bestNeighPath->um >= on->mtcAlgo->umetric_min) &&
			IMPLIES(bestNeighPath->link, bestNeighPath->um >= on->mtcAlgo->umetric_min) &&
			IMPLIES(!bestNeighPath->link, bestNeighPath->um == UMETRIC_MIN__NOT_ROUTABLE)),
			"um=%ju mask=%ju max=%ju minRoutable=%ju mitAlgo=%ju link=%d",
			bestNeighPath->um, UMETRIC_MASK, UMETRIC_MAX, UMETRIC_MIN__NOT_ROUTABLE, on->mtcAlgo->umetric_min, !!bestNeighPath->link);

		char *why = NULL;

		if (
			((why = "A") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + (on->mtcAlgo->ogm_sqn_diff_max + 1)))) ||
			((why = "B") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 1)) && (on->neighPath.um <= UMETRIC_MIN__NOT_ROUTABLE)) ||
			((why = "C") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 1)) && (bestNeighPath->um > on->mtcAlgo->umetric_min) && (((TIME_T) (bmx_time - ref->ogmSqnMaxTime)) >= (100 * on->mtcAlgo->ogm_sqn_late_hystere_100ms))) ||
			((why = "D") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 1)) && (bestNeighPath->um > on->mtcAlgo->umetric_min) && (bestNeighPath->link == on->neighPath.link)) ||
			((why = "E") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 0)) && (bestNeighPath->um > ((on->neighPath.um))) && on->neighPath.um <= UMETRIC_MIN__NOT_ROUTABLE) ||
			((why = "G") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 0)) && (bestNeighPath->um > ((on->neighPath.um * (100 + on->mtcAlgo->ogm_metric_hystere_old_path)) / 100)) && (bestNeighPath->link == on->neighPath.link)) ||
			((why = "H") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 0)) && (bestNeighPath->um > ((on->neighPath.um * (100 + on->mtcAlgo->ogm_metric_hystere_new_path)) / 100)) && (bestNeighPath->link != on->neighPath.link)) ||
			((why = "I") && (ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 0)) && (bestNeighPath->um > ((on->neighPath.um))) && ref->ogmBestSinceSqn && on->mtcAlgo->ogm_sqn_best_hystere && (ref->ogmSqnMax >= on->mtcAlgo->ogm_sqn_best_hystere + ref->ogmBestSinceSqn))
			) {

			if (bestNeighPath->link != on->neighPath.link) {

				dbgf_track(DBGT_INFO, "to id=%s changed route, why=%s,  %ju %d %ju %d,   %d %d %d %d,   %d %d %d %d %d", cryptShaAsShortStr(&ref->kn->kHash), why,
					bestNeighPath->um, !!bestNeighPath->link, on->neighPath.um, !!on->neighPath.link,
					ref->ogmSqnMax, dc->ogmSqnMaxSend, ref->ogmSqnMaxTime, ref->ogmBestSinceSqn,
					on->mtcAlgo->ogm_sqn_diff_max, on->mtcAlgo->ogm_sqn_late_hystere_100ms, on->mtcAlgo->ogm_metric_hystere_old_path, on->mtcAlgo->ogm_metric_hystere_new_path, on->mtcAlgo->ogm_sqn_best_hystere);

				if (on->neighPath.link)
					cb_route_change_hooks(DEL, on);

				on->neighPath.link = bestNeighPath->link;

				if (on->neighPath.link)
					cb_route_change_hooks(ADD, on);
			} else {
				dbgf_track(DBGT_INFO, "to id=%s best unchanged path", cryptShaAsShortStr(&on->k.nodeId));
			}


			on->dc->ogmSqnMaxSend = ref->ogmSqnMax;
			on->neighPath = *bestNeighPath;
			on->ogmHopCount = ref->ogmSqnMaxClaimedHops;

			schedule_ogm(on);

			ref->ogmBestSinceSqn = 0;

		} else {
			if ((ref->ogmSqnMax >= (dc->ogmSqnMaxSend + 1)) && (bestNeighPath->um > on->mtcAlgo->umetric_min) && (((TIME_T) (bmx_time - ref->ogmSqnMaxTime)) < (100 * on->mtcAlgo->ogm_sqn_late_hystere_100ms))) {
				ref->scheduled_ogm_processing = YES;
				task_register((((TIME_T) (100 * (TIME_T) on->mtcAlgo->ogm_sqn_late_hystere_100ms)) - ((TIME_T) (bmx_time - ref->ogmSqnMaxTime))), process_ogm_metric, ref, -300764);
				dbgf_track(DBGT_INFO, "to id=%s postponed", cryptShaAsShortStr(&on->k.nodeId));
			} else {
				dbgf_track(DBGT_INFO, "to id=%s discarded", cryptShaAsShortStr(&on->k.nodeId));
			}

			if (bestNeighPath->um > on->neighPath.um && bestNeighPath->um > on->mtcAlgo->umetric_min && !ref->ogmBestSinceSqn)
				ref->ogmBestSinceSqn = ref->ogmSqnMax;
			else if (bestNeighPath->um <= on->neighPath.um)
				ref->ogmBestSinceSqn = 0;
		}
	}
	prof_stop();
}

STATIC_FUNC
int32_t rx_frame_ogm_aggreg_advs(struct rx_frame_iterator *it)
{

	struct hdr_ogm_adv *hdr = ((struct hdr_ogm_adv*) it->f_data);
	AGGREG_SQN_T aggSqn = ntohs(hdr->aggregation_sqn);
	struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
	IDM_T new = ((AGGREG_SQN_T) (nn->ogm_aggreg_max - aggSqn)) < nn->ogm_aggreg_size && !bit_get(nn->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, aggSqn);
	int32_t processed;

	dbgf_track(DBGT_INFO, "new=%d neigh=%s aggSqn=%d/%d/%d size=%d",
		new, nn->on->k.hostname, aggSqn, nn->ogm_aggreg_max, nn->ogm_aggreg_size, it->f_msgs_len);

	if (new) {

		bit_set(nn->ogm_aggreg_sqns, AGGREG_SQN_CACHE_RANGE, aggSqn, 1);

		if (!it->f_msg || !it->f_msgs_len)
			return TLV_RX_DATA_PROCESSED;

		if ((processed = iterate_msg_ogm_adv(it->f_msg, it->f_msgs_len, 0, YES, NULL, NULL)) != it->f_msgs_len) {
			dbgf_track(DBGT_INFO, "Ignoreing ogm with non-matching hop-metrics history (processed=%d f_msgs_len=%d", processed, it->f_msgs_len);
			return TLV_RX_DATA_PROCESSED;
		}

		int32_t pos = 0;
		int32_t nxt = 0;
		uint8_t moreCnt = 0;

		uint8_t chainOgmBuff[sizeof(struct InaptChainOgm) + (MAX_OGM_HOP_HISTORY_SZ * sizeof(struct msg_ogm_adv_metric_t0))];
		struct InaptChainOgm *chainOgm = (struct InaptChainOgm*) &chainOgmBuff[0];
		struct msg_ogm_adv_metric_t0 *hm = (struct msg_ogm_adv_metric_t0 *) &chainOgm->pathMetrics[0];

		while ((nxt = iterate_msg_ogm_adv(it->f_msg, it->f_msgs_len, pos, NO, hm, &moreCnt)) <= it->f_msgs_len) {

			struct msg_ogm_adv *msg = (struct msg_ogm_adv*) (it->f_msg + pos);
			struct msg_ogm_adv tmp = { .u =
				{.u32 = ntohl(msg->u.u32) } };

			chainOgm->chainOgm = msg->chainOgm;
			chainOgm->claimedHops = (tmp.u.f.hopCount + 1);
			chainOgm->claimedChain = 0;
			chainOgm->claimedMetric.val.f.exp_fm16 = tmp.u.f.metric_exp;
			chainOgm->claimedMetric.val.f.mantissa_fm16 = tmp.u.f.metric_mantissa;
			chainOgm->pathMetricsByteSize = moreCnt * sizeof(struct msg_ogm_adv_metric_t0);

			dbgf_track(DBGT_INFO, "iid=%d ogmMtc=%d ogmHist=%d hops=%d", tmp.u.f.transmitterIID4x, chainOgm->claimedMetric.val.u16, moreCnt, tmp.u.f.hopCount + 1);

			neighRef_update(nn, aggSqn, tmp.u.f.transmitterIID4x, NULL, 0, chainOgm);

			if ((pos = nxt) == it->f_msgs_len)
				break;
		}
	}

	return TLV_RX_DATA_PROCESSED;
}

#ifdef WITH_DEVEL

int32_t opt_fake_agg_sqns(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	if (cmd == OPT_APPLY) {

		int32_t val = patch->val ? strtol(patch->val, NULL, 10) : 0;

		if (val) {

			struct orig_node *on;
			struct avl_node *an = NULL;

			while ((on = avl_iterate_item(&orig_tree, &an)))
				remove_ogm(on);

			assertion(-502762, (!ogm_aggreg_sqn_max_window_size));

			AGGREG_SQN_T diff = ((AGGREG_SQN_T) - val) - ogm_aggreg_sqn_max;
			ogm_aggreg_sqn_max += diff;
			ogm_aggreg_sqn_send += diff;
		}
	}

	return SUCCESS;
}
#endif


STATIC_FUNC
	struct opt_type ogm_options[] ={
	{ODI, 0, ARG_OGM_IFACTOR, 0, 9, 1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &maxMyOgmIFactor, MIN_OGM_IFACTOR, MAX_OGM_IFACTOR, DEF_OGM_IFACTOR, 0, 0,
		ARG_VALUE_FORM, "set factor (relative to ogmInterval) for max delay of own ogms" },
#ifdef WITH_DEVEL
	{ODI, 0, "fakeOgmAggSqn", 0, 9, 0, A_PS1, A_ADM, A_DYN, A_ARG, A_ANY, NULL, 0, ((AGGREG_SQN_T) - 1), 0, 0, opt_fake_agg_sqns,
		NULL, "exceed ogm aggregation sqn range" },
#endif

};

int32_t init_ogm(void)
{
	register_options_array(ogm_options, sizeof(ogm_options), CODE_CATEGORY_NAME);

	assertion(-502590, (sizeof( ((struct msg_ogm_adv*) NULL)->u) == sizeof( ((struct msg_ogm_adv*) NULL)->u.u32)));

	struct frame_handl handl;
	memset(&handl, 0, sizeof( handl));

	handl.name = "OGMS_SQNS_ADV";
	handl.min_msg_size = sizeof(struct msg_ogm_aggreg_sqn_adv);
	handl.fixed_msg_size = 1;

	// this might schedule a new tx_packet because schedule_tx_packet() believes
	// the stuff we are about to send now is still waiting to be send.
	handl.tx_packet_prepare_casuals = revise_ogm_aggregations;
	handl.tx_frame_handler = tx_frame_ogm_aggreg_sqn;
	handl.rx_frame_handler = rx_frame_ogm_aggreg_sqn;
	handl.rx_minNeighCol = KCNeighbor;
	handl.rx_minNeighCond = kPref_neighbor_metric;
	register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_AGG_SQN_ADV, &handl);

	handl.name = "OGMS_REQ";
	handl.data_header_size = sizeof(struct hdr_ogm_aggreg_req);
	handl.min_msg_size = sizeof(struct msg_ogm_aggreg_req);
	handl.fixed_msg_size = 1;
	handl.tx_packet_prepare_casuals = schedule_ogm_req;
	handl.tx_msg_handler = tx_msg_ogm_aggreg_request;
	handl.rx_msg_handler = rx_msg_ogm_aggreg_request;
	handl.rx_minNeighCol = KCNeighbor;
	handl.rx_minNeighCond = kPref_neighbor_metric;
	register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_REQ, &handl);

	handl.name = "OGMS_ADV";
	handl.data_header_size = sizeof(struct hdr_ogm_adv);
	handl.min_msg_size = sizeof(struct msg_ogm_adv);
	handl.fixed_msg_size = 0;
	handl.tx_frame_handler = tx_frame_ogm_aggreg_advs;
	handl.rx_frame_handler = rx_frame_ogm_aggreg_advs;
	handl.rx_minNeighCol = KCNeighbor;
	handl.rx_minNeighCond = kPref_neighbor_metric;
	register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_ADV, &handl);


	return SUCCESS;

}
