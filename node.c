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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>


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
#include "desc.h"
#include "content.h"
#include "ip.h"
#include "hna.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"
#include "z.h"

#define CODE_CATEGORY_NAME "node"

IDM_T my_description_changed = YES;

struct key_node *myKey = NULL;


AVL_TREE(link_tree, LinkNode, k);

AVL_TREE(link_dev_tree, LinkDevNode, key);

AVL_TREE(local_tree, struct neigh_node, local_id);

AVL_TREE(descContent_tree, struct desc_content, dHash);


AVL_TREE(orig_tree, struct orig_node, k.nodeId);

STATIC_FUNC
void inaptChainOgm_destroy_(struct NeighRef_node *ref)
{
	if (ref->inaptChainOgm) {
		debugFree(ref->inaptChainOgm, -300787);
		ref->inaptChainOgm = NULL;
	}
}


STATIC_FUNC
void inaptChainOgm_update_(struct NeighRef_node *ref, struct InaptChainOgm *inaptChainOgm, uint8_t claimedChain)
{
	assertion(-502657, (ref && inaptChainOgm));

	if (ref->inaptChainOgm != inaptChainOgm) {
		
		if (!ref->inaptChainOgm || (
			memcmp(&ref->inaptChainOgm->chainOgm, &inaptChainOgm->chainOgm, sizeof(ChainLink_T)) == 0 &&
			(ref->inaptChainOgm->claimedMetric.val.u16 < inaptChainOgm->claimedMetric.val.u16)
			)) {

			ref->inaptChainOgm = debugRealloc(ref->inaptChainOgm, ((sizeof(struct InaptChainOgm) + inaptChainOgm->pathMetricsByteSize)), -300824);
			memcpy(ref->inaptChainOgm, inaptChainOgm, ((sizeof(struct InaptChainOgm) + inaptChainOgm->pathMetricsByteSize)));
		}
	}

	ref->inaptChainOgm->claimedChain = claimedChain;
}

void neighRef_destroy(struct NeighRef_node *ref, IDM_T reAssessState)
{
	assertion(-502454, (ref && ref->nn));
	struct key_node *kn = ref->kn;

	if (ref->scheduled_ogm_processing)
		task_remove(process_ogm_metric, (void*)ref);

	iid_free(&ref->nn->neighIID4x_repos, iid_get_neighIID4x_by_node(ref));

	if (kn) {
		struct key_credits kc = {.neighRef = ref};
		keyNode_delCredits(NULL, kn, &kc, (reAssessState && kn != ref->nn->on->kn));
	}

	if (ref->ogmSqnMaxPathMetrics)
		debugFree(ref->ogmSqnMaxPathMetrics, -300825);

	inaptChainOgm_destroy_(ref);

	debugFree(ref, -300721);
}


STATIC_FUNC
struct NeighRef_node *neighRef_create_(struct neigh_node *neigh, AGGREG_SQN_T aggSqn, IID_T neighIID4x)
{
	assertion(-502455, (neigh));
	assertion(-502565, (!iid_get_node_by_neighIID4x(&neigh->neighIID4x_repos, neighIID4x, NO)));

	struct NeighRef_node *ref = debugMallocReset(sizeof(struct NeighRef_node), -300789);

	ref->nn = neigh;
	ref->aggSqn = aggSqn;
	iid_set_neighIID4x(&neigh->neighIID4x_repos, neighIID4x, ref);

	return ref;
}


struct NeighRef_node *neighRef_resolve_or_destroy(struct NeighRef_node *ref, IDM_T reassessState)
{
	IID_T iid;

	if ((iid = iid_get_neighIID4x_by_node(ref)) && iid_get_neighIID4x_timeout_by_node(ref)) {

		struct key_node *kn = ref->kn;
		struct neigh_node *nn = ref->nn;

		if (!kn || (ref->inaptChainOgm && !ref->inaptChainOgm->claimedChain)) {

			schedule_tx_task(FRAME_TYPE_IID_REQ, NULL, &nn->local_id, nn, nn->best_tq_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &iid, sizeof(iid));

		} else if (kn->bookedState->i.c >= KCTracked && kn->content->f_body && ref->inaptChainOgm && ref->inaptChainOgm->claimedChain  &&
			(ref->descSqn >= kn->descSqnMin) && (ref->descSqn > (kn->nextDesc ? kn->nextDesc->descSqn : 0)) && (ref->descSqn > (kn->on ? kn->on->dc->descSqn : 0))) {

			struct schedule_dsc_req req = {.iid = iid, .descSqn = ref->descSqn};
			schedule_tx_task(FRAME_TYPE_DESC_REQ, NULL, &nn->local_id, nn, nn->best_tq_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &req, sizeof(req));

		} else if (kn->bookedState->i.c >= KCTracked) {

			content_resolve(kn, ref->nn);
		}

		return ref;


	} else {
		neighRef_destroy(ref, reassessState);
		return NULL;
	}
}




void neighRefs_resolve_or_destroy(void)
{
	static TIME_T next = 0;
	GLOBAL_ID_T nid = ZERO_CYRYPSHA;
	struct neigh_node *nn;
	IID_T iid;
	struct NeighRef_node *ref;

	if (!doNowOrLater(&next, maintainanceInterval, 0))
		return;

	while ((nn = avl_next_item(&local_tree, &nid))) {
		nid = nn->local_id;

		for (iid = 0; iid < nn->neighIID4x_repos.max_free; iid++) {

			if ((ref = iid_get_node_by_neighIID4x(&nn->neighIID4x_repos, iid, NO)))
				neighRef_resolve_or_destroy(ref, YES);

		}
	}
}

STATIC_FUNC
void set_ref_ogmSqnMaxMetric(struct NeighRef_node *ref, DESC_SQN_T descSqn, OGM_SQN_T ogmSqn, struct InaptChainOgm *chainOgm)
{

	ref->reqCnt = 0;

	if (chainOgm) {

		ref->ogmSqnMaxClaimedMetric.val.u16 = chainOgm->claimedMetric.val.u16;
		ref->ogmSqnMaxClaimedHops = chainOgm->claimedHops;
		ref->ogmSqnMaxPathMetricsByteSize = chainOgm->pathMetricsByteSize;
		ref->ogmSqnMaxPathMetrics = debugRealloc(ref->ogmSqnMaxPathMetrics, chainOgm->pathMetricsByteSize, -300826);
		memcpy(ref->ogmSqnMaxPathMetrics, &chainOgm->pathMetrics[0], chainOgm->pathMetricsByteSize);

	} else {
		ref->descSqn = descSqn;
		ref->ogmSqnMax = ogmSqn;
		ref->ogmSqnMaxTime = bmx_time;

		if (!ogmSqn)
			ref->ogmBestSinceSqn = 0;

		ref->ogmSqnMaxClaimedMetric.val.u16 = 0;
		ref->ogmSqnMaxClaimedHops = 0;
		ref->ogmSqnMaxPathMetricsByteSize = 0;
		if (ref->ogmSqnMaxPathMetrics) {
			debugFree(ref->ogmSqnMaxPathMetrics, -300827);
			ref->ogmSqnMaxPathMetrics = NULL;
		}
	}
}


void update_ogm_mins(struct key_node *kn, DESC_SQN_T minDescSqn, OGM_SQN_T minOgmSqn, UMETRIC_T *minUMetric)
{
	assertion(-502727, (kn));
	assertion(-502728, (minDescSqn));
	assertion(-502729, IMPLIES(minUMetric, minOgmSqn));

	FMETRIC_U16_T minFMetric = {.val = {.u16 = 0}};
		
	if (minUMetric)
		minFMetric = umetric_to_fmetric(*minUMetric);

	if (!kn->ogmSqnFirst_sec /*&& !kn->ogmSqnMin*/ && minOgmSqn)
		kn->ogmSqnFirst_sec = bmx_time_sec;

	if (!kn->ogmSqnFirst_sec || (((TIME_SEC_T) (bmx_time_sec - kn->ogmSqnFirst_sec)) < 5)) {
		minOgmSqn++;
		minFMetric.val.u16 = 0;
	}

	if (minDescSqn > kn->descSqnMin) {

		kn->descSqnMin = minDescSqn;
		kn->ogmSqnMin = minOgmSqn;
		kn->ogmMetricMin = minFMetric;

	} else if (minDescSqn == kn->descSqnMin) {

		if (minOgmSqn > kn->ogmSqnMin) {

			kn->ogmSqnMin = minOgmSqn;
			kn->ogmMetricMin = minFMetric;

		} else if (minOgmSqn == kn->ogmSqnMin) {

			if (minFMetric.val.u16 > kn->ogmMetricMin.val.u16) {

				kn->ogmMetricMin = minFMetric;
			}
		}
	}
}

IDM_T is_new_ogm_mins(struct key_node *kn, DESC_SQN_T minDescSqn, OGM_SQN_T minOgmSqn, UMETRIC_T *minUMetric)
{
	assertion(-502730, (kn));
	assertion(-502731, (minDescSqn));
	assertion(-502732, IMPLIES(minUMetric, minOgmSqn));

	FMETRIC_U16_T minFMetric = {.val = {.u16 = 0}};

	if (minUMetric)
		minFMetric = umetric_to_fmetric(*minUMetric);

	if (minDescSqn > kn->descSqnMin) {

		return YES;

	} else if (minDescSqn == kn->descSqnMin) {

		if (minOgmSqn > kn->ogmSqnMin) {

			return YES;

		} else if (minOgmSqn == kn->ogmSqnMin) {

			if (minFMetric.val.u16 > kn->ogmMetricMin.val.u16) {

				return YES;
			}
		}
	}

	return NO;
}


struct NeighRef_node *neighRef_update(struct neigh_node *nn, AGGREG_SQN_T aggSqn, IID_T neighIID4x, CRYPTSHA_T *kHash, DESC_SQN_T descSqn, struct InaptChainOgm *inChainOgm)
{
	assertion(-502459, (nn));
	assertion(-502566, (neighIID4x));
	assertion(-502567, IMPLIES((kHash || descSqn), (kHash && descSqn)));

	char *goto_error_code = NULL;
	struct NeighRef_node *goto_error_ret = NULL;
	struct NeighRef_node *ref = NULL;
	struct key_node *kn = NULL;
	struct desc_content *dc = NULL;
	OGM_SQN_T ogmSqn = 0;
	struct InaptChainOgm *chainOgm = NULL;

	if (neighIID4x > IID_REPOS_SIZE_MAX || neighIID4x > keyMatrix[KCListed][KRQualifying].i.setMaxUse)
		goto_error_return(finish, "oversized IID", NULL);

	if (!(ref = iid_get_node_by_neighIID4x(&nn->neighIID4x_repos, neighIID4x, !!inChainOgm)) && !(ref = neighRef_create_(nn, aggSqn, neighIID4x)))
		goto_error_return( finish, "No neighRef!!!", NULL);

	ref->aggSqn = (((AGGREG_SQN_T) (ref->aggSqn - aggSqn)) < AGGREG_SQN_CACHE_RANGE) ? ref->aggSqn : aggSqn;

	if (kHash) {

		ref->reqCnt = 0;

		if (ref->kn && cryptShasEqual(&ref->kn->kHash, kHash) && ref->descSqn <= descSqn) {

			kn = ref->kn;

		} else if (ref->kn && cryptShasEqual(&ref->kn->kHash, kHash)) {

			goto_error_return(finish, "outdated descSqn", NULL);

		} else {

			struct key_node *oldKn;
			struct NeighRef_node *oldRef;

			if ((oldKn = keyNode_get(kHash)) && (oldRef = avl_find_item(&oldKn->neighRefs_tree, &nn)))
				neighRef_destroy(oldRef, NO);

			if (ref->kn) {
				neighRef_destroy(ref, YES);
				ref = neighRef_create_(nn, aggSqn, neighIID4x);
			}

			struct key_credits kc = {.neighRef = ref};
			if (!(kn = keyNode_updCredits(kHash, NULL, &kc))) {
				neighRef_destroy(ref, YES);
				ref = NULL;
				goto_error_return( finish, "Insufficient credits", NULL);
			}
		}

		if (ref->descSqn < descSqn)
			set_ref_ogmSqnMaxMetric(ref, descSqn, 0, NULL);

	} else {
		kn = ref->kn;
	}


	if ((chainOgm = inChainOgm ? inChainOgm : ref->inaptChainOgm)) {

//		if ((dc = (kn && kn->nextDesc) ? kn->nextDesc : (kn && kn->on ? kn->on->dc : NULL)) &&
//			(ref->descSqn <= dc->descSqn) && (ogmSqn = chainOgmFind(&chainOgm->chainOgm, dc, !!descSqn))) {

		if ((kn && kn->on && (dc = kn->on->dc) && ref->descSqn <= dc->descSqn && (ogmSqn = chainOgmFind(&chainOgm->chainOgm, dc, !!descSqn))) ||
			(kn && (dc = kn->nextDesc) && ref->descSqn <= dc->descSqn && (ogmSqn = chainOgmFind(&chainOgm->chainOgm, dc, (!!descSqn /*|| ref->descSqn < dc->descSqn*/))))) {

			assertion(-502568, (ogmSqn <= dc->ogmSqnRange));
			assertion(-502569, (dc->ogmSqnMaxRcvd <= dc->ogmSqnRange));
			assertion(-502570, (dc->ogmSqnMaxRcvd >= ogmSqn));
			assertion(-502571, (ref->descSqn <= dc->descSqn));

			if (ref->descSqn < dc->descSqn)
				set_ref_ogmSqnMaxMetric( ref, dc->descSqn, 0, NULL);


			if (ref->ogmSqnMax < ogmSqn)
				set_ref_ogmSqnMaxMetric( ref, dc->descSqn, ogmSqn, NULL);
			else if (ref->ogmSqnMax > ogmSqn)
				goto_error_return(finish, "Outdated ogmSqn", NULL);


			if (ref->inaptChainOgm && ref->inaptChainOgm != chainOgm &&
				memcmp(&ref->inaptChainOgm->chainOgm, &chainOgm->chainOgm, sizeof(ChainLink_T)) == 0 &&
				ref->inaptChainOgm->claimedMetric.val.u16 > ref->ogmSqnMaxClaimedMetric.val.u16 &&
				ref->inaptChainOgm->claimedMetric.val.u16 > chainOgm->claimedMetric.val.u16)
			{

				set_ref_ogmSqnMaxMetric( ref, dc->descSqn, ogmSqn, ref->inaptChainOgm);

			} else if (chainOgm->claimedMetric.val.u16 > ref->ogmSqnMaxClaimedMetric.val.u16) {

				set_ref_ogmSqnMaxMetric( ref, dc->descSqn, ogmSqn, chainOgm);
			}

			dc->referred_by_others_timestamp = bmx_time;

			inaptChainOgm_destroy_(ref);

			if (kn == myKey && ((ref->ogmSqnMax > dc->ogmSqnMaxSend) || (ref->ogmSqnMax == dc->ogmSqnMaxSend && fmetric_to_umetric(ref->ogmSqnMaxClaimedMetric) >= myKey->on->neighPath.um))) {
				dbgf_mute(70, DBGL_SYS, DBGT_WARN, "OGM SQN or metric attack on myself, rcvd via neigh=%s, rcvdSqn=%d sendSqn=%d rcvdMetric=%ju sendMetric=%ju",
					cryptShaAsShortStr(&nn->local_id), ref->ogmSqnMax, dc->ogmSqnMaxSend, fmetric_to_umetric(ref->ogmSqnMaxClaimedMetric), myKey->on->neighPath.um);

				update_ogm_mins(nn->on->kn, nn->on->dc->descSqn + 1, 0, NULL);
				keyNode_schedLowerWeight(nn->on->kn, KCListed);
				ref = NULL;
				nn = NULL;
				dc = NULL;
				goto_error_return(finish, "Metric Attack", NULL);
			}



			content_resolve(kn, ref->nn);

			goto_error_code = "SUCCESS";
		} else {

			inaptChainOgm_update_(ref, chainOgm, (!!descSqn));
			ref = neighRef_resolve_or_destroy(ref, YES);

			goto_error_return(finish, "Unresolved ogmSqn", NULL);
		}
	}

	if (ref)
		process_ogm_metric(ref);
	
finish: {

	dbgf_track(DBGT_INFO, 
		"problem=%s neigh=%s aggSqn=%d IID=%d kHash=%s descSqn=%d chainOgm=%s ogmMtc=%d \n"
		"REF: nodeId=%s descSqn=%d hostname=%s ogmSqnMaxRcvd=%d ogmMtcMaxRcvd=%d inaptChainOgmRcvd=%s inaptMtcRcvd=%d\n"
		"DC: ogmSqnRange=%d  ogmSqnMaxRcvd=%d \n"
		"OUT: ogmSqn=%d ",
		goto_error_code, ((nn && nn->on) ? nn->on->k.hostname : NULL), aggSqn, neighIID4x, cryptShaAsShortStr(kHash), descSqn,
		memAsHexString(inChainOgm ? &inChainOgm->chainOgm : NULL, sizeof(ChainLink_T)), (inChainOgm ? (int)inChainOgm->claimedMetric.val.u16 : -1),

		cryptShaAsShortStr(ref && ref->kn ? &ref->kn->kHash : NULL),
		(ref ? (int)ref->descSqn : -1 ),
		(ref && ref->kn && ref->kn->on ? ref->kn->on->k.hostname : NULL),
		(ref ? (int)ref->ogmSqnMax : -1),
		(ref ? (int)ref->ogmSqnMaxClaimedMetric.val.u16 : -1),
		(ref && ref->inaptChainOgm ? memAsHexString(&ref->inaptChainOgm->chainOgm, sizeof(ChainLink_T)): NULL),
		(ref && ref->inaptChainOgm? (int)ref->inaptChainOgm->claimedMetric.val.u16 : -1),

		(dc ? (int)dc->ogmSqnRange : -1), (dc ? (int)dc->ogmSqnMaxRcvd : -1),
		ogmSqn);


	return goto_error_ret;
}
}

void neighRefs_update(struct key_node *kn) {

	assertion(-502572, (kn && (kn->nextDesc || kn->on)));

	dbgf_track(DBGT_INFO, "id=%s name=%s", cryptShaAsShortStr(&kn->kHash), kn->on ? kn->on->k.hostname : NULL);
	struct NeighRef_node *nref;
	struct neigh_node *nn;
	IID_T iid;
	uint32_t c = 0;
	for (nn = NULL; (nref = avl_next_item(&kn->neighRefs_tree, &nn)); c++) {
		nn = nref->nn;
		assertion(-502573, (c <= kn->neighRefs_tree.items));
		if ((iid = iid_get_neighIID4x_by_node(nref)) && iid_get_neighIID4x_timeout_by_node(nref))
			neighRef_update(nn, nref->aggSqn, iid, NULL, 0, NULL);
		else
			neighRef_destroy(nref, YES);
	}
}


int purge_orig_router(struct orig_node *onlyOrig, struct neigh_node *onlyNeigh, LinkNode *onlyLink, IDM_T onlyUseless)
{
	TRACE_FUNCTION_CALL;
	int removed = 0;
	struct orig_node *on;
	struct avl_node *an = NULL;
	while ((on = onlyOrig) || (on = avl_iterate_item(&orig_tree, &an))) {

		if (
			(on->neighPath.link) &&
			(!onlyUseless || (on->neighPath.um < UMETRIC_ROUTABLE)) &&
			(!onlyNeigh || on->neighPath.link->k.linkDev->key.local == onlyNeigh) &&
			(!onlyLink || on->neighPath.link == onlyLink)
			) {

			dbgf_track(DBGT_INFO, "only_orig=%s only_lndev=%s,%s onlyUseless=%d purging metric=%s neigh=%s link=%s dev=%s",
				onlyOrig ? cryptShaAsString(&onlyOrig->k.nodeId) : DBG_NIL,
				onlyLink ? ip6AsStr(&onlyLink->k.linkDev->key.llocal_ip) : DBG_NIL,
				onlyLink ? onlyLink->k.myDev->ifname_label.str : DBG_NIL,
				onlyUseless, umetric_to_human(on->neighPath.um),
				cryptShaAsString(&on->neighPath.link->k.linkDev->key.local->local_id),
				ip6AsStr(&on->neighPath.link->k.linkDev->key.llocal_ip),
				on->neighPath.link->k.myDev->ifname_label.str);

			cb_route_change_hooks(DEL, on);
			on->neighPath.link = NULL;

			removed++;
		}

		if (onlyOrig)
			break;
	}

	return removed;
}





void neigh_destroy(struct orig_node *on)
{
	struct neigh_node *local = on->neigh;
	LinkDevNode *linkDev;

	if (on->kn == myKey)
		return;

	dbgf_track(DBGT_INFO, "purging local_id=%s curr_rx_packet=%d thisNeighsPacket=%d verified_link=%d",
		cryptShaAsString(&local->local_id), !!curr_rx_packet,
		(curr_rx_packet && curr_rx_packet->i.claimedKey == local->on->kn),
		(curr_rx_packet && curr_rx_packet->i.verifiedLink));

	if (curr_rx_packet && curr_rx_packet->i.claimedKey == local->on->kn)
		curr_rx_packet->i.verifiedLink = NULL;

	while ((linkDev = avl_first_item(&local->linkDev_tree)))
		purge_linkDevs(linkDev, NULL, NULL, NO, NO);


	assertion(-502639, (!local->linkDev_tree.items));
	assertion(-502640, (!local->orig_routes));
	assertion(-502465, (!local->best_rq_link));
	assertion(-502466, (!local->best_tq_link));


	IID_T iid;
	for (iid = 0; iid < local->neighIID4x_repos.max_free; iid++) {
		struct NeighRef_node *ref;
		if ((ref = iid_get_node_by_neighIID4x(&local->neighIID4x_repos, iid, NO)))
			neighRef_destroy(ref, YES);
	}


	purge_tx_task_tree(NULL, local, NULL, NULL, YES);

	local->on->neigh = NULL;
	local->on = NULL;

	if (local->rsaLinkKey)
		cryptRsaKeyFree(&local->rsaLinkKey);

	free_internalNeighId(local->internalNeighId);

	avl_remove(&local_tree, &local->local_id, -300331);
	debugFree(local, -300333);
}





struct neigh_node *neigh_create(struct orig_node *on)
{
	if (on->kn == myKey)
		return NULL;

	struct neigh_node *nn = (on->neigh = debugMallocReset(sizeof(struct neigh_node), -300757));
	nn->local_id = on->k.nodeId;
	avl_insert(&local_tree, nn, -300758);
	struct dsc_msg_pubkey *rsaKey;
	int rsaMsgLen, rsaKeyLen;

	AVL_INIT_TREE(nn->linkDev_tree, LinkDevNode, key.devIdx);

	nn->internalNeighId = allocate_internalNeighId(nn);

	if ((rsaKey  = contents_data(on->dc, BMX_DSC_TLV_RSA_LINK_PUBKEY)) && 
		(rsaMsgLen = contents_dlen(on->dc, BMX_DSC_TLV_RSA_LINK_PUBKEY)) &&
		(rsaKey->type) && (rsaKeyLen = cryptRsaKeyLenByType(rsaKey->type)) &&
		(rsaMsgLen == (rsaKeyLen + (int)sizeof(struct dsc_msg_pubkey)))) {

		nn->rsaLinkKey = cryptRsaPubKeyFromRaw(rsaKey->key, rsaKeyLen);
	}
/*
	struct dsc_msg_dhm_link_key *neighDhmKey;
	int neighDhmLen;
	if (my_DhmLinkKey &&
		(neighDhmKey = contents_data(on->dc, BMX_DSC_TLV_DHM_LINK_PUBKEY)) &&
		(neighDhmLen = contents_dlen(on->dc, BMX_DSC_TLV_DHM_LINK_PUBKEY)) &&
		(neighDhmLen == my_DhmLinkKey->rawGXLen) && (neighDhmKey->type == my_DhmLinkKey->rawGXType)) {

		nn->on->dhmSecret = cryptDhmSecretForNeigh(my_DhmLinkKey, neighDhmKey->gx, neighDhmLen);
	}
*/
	nn->on = on;
	return nn;
}










void destroy_orig_node(struct orig_node *on)
{
	dbgf_track(DBGT_INFO, "id=%s name=%s", cryptShaAsString(&on->k.nodeId), on->k.hostname);

	assertion(-502474, (on && on->dc && on->kn && on->dc->descSqn));
	assertion(-502475, (on->dc->on == on && on->dc->kn == on->kn && on->kn->on == on));
	assertion(-502180, IMPLIES(!terminating, on != myKey->on));
	assertion(-502476, (!on->neigh));

	purge_orig_router(on, NULL, NULL, NO);

	cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

	process_description_tlvs(NULL, on, NULL, on->dc, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL);

	assertion(-502758, (!on->dhmSecret));
//	if (on->dhmSecret)
//		debugFreeReset(&on->dhmSecret, sizeof(CRYPTSHA_T), -300835);


	if (on->trustedNeighsBitArray)
		debugFree(on->trustedNeighsBitArray, -300653);

	avl_remove(&orig_tree, &on->k.nodeId, -300200);
	cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

	uint16_t i;
	for (i = 0; i < plugin_data_registries[PLUGIN_DATA_ORIG]; i++) {
		assertion(-501269, (!on->plugin_data[i]));
	}

	on->kn->on = NULL;
	on->dc->on = NULL;

	if (on->kn->nextDesc)
		descContent_destroy(on->dc);
	else
		on->kn->nextDesc = on->dc;

	iid_free(NULL, on->__myIID4x);

	if (terminating && !orig_tree.items)
		iid_purge_repos(&my_iid_repos);

	debugFree(on, -300759);
}

void init_self(void)
{
	assertion(-502094, (my_NodeKey && my_NodeKey->rawKeyType && my_NodeKey->rawKeyLen));
	assertion(-502477, (!myKey));

	struct key_credits friend_kc = {.dFriend = TYP_TRUST_LEVEL_IMPORT};
	struct dsc_msg_pubkey *msg = debugMallocReset(sizeof(struct dsc_msg_pubkey) + my_NodeKey->rawKeyLen, -300631);
	int ret = cryptRsaPubKeyGetRaw(my_NodeKey, msg->key, my_NodeKey->rawKeyLen);

	assertion(-502733, (ret==SUCCESS));

	msg->type = my_NodeKey->rawKeyType;

	struct content_node *cn = content_add_body((uint8_t*)msg, sizeof(struct dsc_msg_pubkey) + my_NodeKey->rawKeyLen, 0, 0, YES);

	myKey = keyNode_updCredits(&cn->chash, NULL, &friend_kc);

	debugFree(msg, -300600);
}

