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
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/rtnetlink.h>
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

AVL_TREE(dhash_tree, struct dhash_node, dhash);

AVL_TREE(orig_tree, struct orig_node, k.nodeId);


void refNode_destroy(struct reference_node *ref, IDM_T reAssessState)
{
	assertion(-502454, (ref && ref->neigh));

	if (ref->claimedKey) {
		avl_remove(&ref->claimedKey->neighRefs_tree, &ref->neigh, -300717);
		avl_remove(&ref->neigh->refsByKhash_tree, &ref->claimedKey, -300718);
	}

	if (ref->dhn) {
		avl_remove(&ref->neigh->refsByDhash_tree, &ref->dhn, -300719);
		avl_remove(&ref->dhn->neighRefs_tree, &ref->neigh, -300720);
		if (!ref->dhn->descContent && !ref->dhn->neighRefs_tree.items)
			dhash_clean_data(ref->dhn);
	}

	if (reAssessState && ref->claimedKey) {
		keyNode_delCredits(NULL, ref->claimedKey, NULL);
	}

	if (ref->scheduled_ogm_processing)
		task_remove(process_ogm_metric, (void*)ref);


	debugFree(ref, -300721);
}


STATIC_FUNC
struct reference_node *refNode_create_(struct neigh_node *neigh, AGGREG_SQN_T aggSqn, struct dhash_node *dhn, DESC_SQN_T claimedSqn)
{
	assertion(-502455, (neigh));
	assertion(-502456, (dhn));
	assertion(-502457, (!avl_find_item(&neigh->refsByDhash_tree, &dhn)));
	assertion(-502458, (!avl_find_item(&dhn->neighRefs_tree, &neigh)));

	struct reference_node *ref= debugMallocReset(sizeof(struct reference_node), -300722);
	ref->dhn = dhn;
	ref->neigh = neigh;
	ref->aggSqn = aggSqn;
	ref->claimedDescSqn = dhn->descContent ? dhn->descContent->descSqn : claimedSqn;
	avl_insert(&neigh->refsByDhash_tree, ref, -300723);
	avl_insert(&dhn->neighRefs_tree, ref, -300724);
	return ref;
}


/*
 * returns NULL on failure. Then given neigh must be removed
 * */
struct reference_node *refNode_update(struct neigh_node *neigh, AGGREG_SQN_T aggSqn, DHASH_T *descHash, struct CRYPTSHA1_T *claimedKey, DESC_SQN_T claimedSqn )
{
	assertion(-502459, (neigh));
	assertion(-502460, (descHash));
	assertion(-502461, (curr_rx_packet->i.verifiedLink->k.linkDev->key.local == neigh));
	assertion(-502462, IMPLIES(claimedKey || claimedSqn, descHash  && claimedKey && claimedSqn));

	struct dhash_node *oDhn = NULL, *nDhn = NULL;
	struct reference_node *oRef = NULL, *nRef = NULL;

	if ((oDhn = avl_find_item(&dhash_tree, descHash)) || (oDhn = (nDhn = dhash_node_create(descHash, neigh)))) {

		if (claimedKey && oDhn->descContent &&
			(!cryptShasEqual(claimedKey, &oDhn->descContent->key->kHash) || claimedSqn != oDhn->descContent->descSqn))
			goto error;

		if ((oRef = avl_find_item(&oDhn->neighRefs_tree, &neigh))) {

			if (!IMPLIES(claimedKey && oRef->claimedKey, (cryptShasEqual(claimedKey, &oRef->claimedKey->kHash))))
				goto error;

			if (!IMPLIES(claimedKey && (oRef->claimedKey || oRef->claimedDescSqn), (claimedSqn == oRef->claimedDescSqn)))
				goto error;

			if (!IMPLIES(oDhn->descContent && oRef->claimedKey, (oDhn->descContent->key == oRef->claimedKey)))
				goto error;

			if (!IMPLIES(oDhn->descContent && (oRef->claimedKey || oRef->claimedDescSqn), (oDhn->descContent->descSqn == oRef->claimedDescSqn)))
				goto error;

			oRef->aggSqn = (((AGGREG_SQN_T) (oRef->aggSqn - aggSqn)) < AGGREG_SQN_CACHE_RANGE) ? oRef->aggSqn : aggSqn;

			if (!oRef->claimedDescSqn)
				oRef->claimedDescSqn = oDhn->descContent ? oDhn->descContent->descSqn : claimedSqn;

		} else {
			oRef = (nRef = refNode_create_(neigh, aggSqn, oDhn, claimedSqn));
		}

		struct key_node *kn = NULL;

		if (!oRef->claimedKey && ((kn = (oDhn->descContent ? oDhn->descContent->key : NULL)) || claimedKey)) {

			assertion(-502464, IMPLIES(claimedKey && kn, cryptShasEqual(claimedKey, &kn->kHash)));

			struct key_credits ref_kc = {.ref = oRef};

			if (!keyNode_updCredits(claimedKey, kn, &ref_kc))
				goto error;
		}

		oRef->mentionedRefTime = bmx_time;
		oDhn->referred_by_others_timestamp = bmx_time;

		return oRef;
	}


error:
	dbgf_sys(DBGT_ERR, "neigh=%s nRef=%d nDhn=%d", neigh->on->k.hostname, !!nRef, !!nDhn);

	if (nRef)
		refNode_destroy(nRef, NO);

	if (nDhn)
		dhash_clean_data(nDhn);

	return NULL;
}




int purge_orig_router(struct orig_node *onlyOrig, struct neigh_node *onlyNeigh, LinkNode *onlyLink, IDM_T onlyUseless)
{
	TRACE_FUNCTION_CALL;
	int removed = 0;
	struct orig_node *on;
	struct avl_node *an = NULL;
	while ((on = onlyOrig) || (on = avl_iterate_item(&orig_tree, &an))) {

		if (
			(on->curr_rt_link) &&
			(!onlyUseless || (on->ogmMetric < UMETRIC_ROUTABLE)) &&
			(!onlyNeigh || on->curr_rt_link->k.linkDev->key.local == onlyNeigh) &&
			(!onlyLink || on->curr_rt_link == onlyLink)
			) {

			dbgf_track(DBGT_INFO, "only_orig=%s only_lndev=%s,%s onlyUseless=%d purging metric=%s neigh=%s link=%s dev=%s",
				onlyOrig ? cryptShaAsString(&onlyOrig->k.nodeId) : DBG_NIL,
				onlyLink ? ip6AsStr(&onlyLink->k.linkDev->key.llocal_ip) : DBG_NIL,
				onlyLink ? onlyLink->k.myDev->label_cfg.str : DBG_NIL,
				onlyUseless, umetric_to_human(on->ogmMetric),
				cryptShaAsString(&on->curr_rt_link->k.linkDev->key.local->local_id),
				ip6AsStr(&on->curr_rt_link->k.linkDev->key.llocal_ip),
				on->curr_rt_link->k.myDev->label_cfg.str);

			cb_route_change_hooks(DEL, on);
			on->curr_rt_link = NULL;

			removed++;
		}

		if (onlyOrig)
			break;
	}

	return removed;
}





void neigh_destroy(struct neigh_node *local)
{
	LinkDevNode *linkDev;

	dbgf_sys(DBGT_INFO, "purging local_id=%s curr_rx_packet=%d thisNeighsPacket=%d verified_link=%d",
		cryptShaAsString(&local->local_id), !!curr_rx_packet,
		(curr_rx_packet && curr_rx_packet->i.claimedKey == local->on->key),
		(curr_rx_packet && curr_rx_packet->i.verifiedLink));

	if (curr_rx_packet && curr_rx_packet->i.claimedKey == local->on->key)
		curr_rx_packet->i.verifiedLink = NULL;

	while ((linkDev = avl_first_item(&local->linkDev_tree)))
		purge_linkDevs(&linkDev->key, NULL, NO);


	assertion(-501135, (!local->linkDev_tree.items));
	assertion(-501135, (!local->orig_routes));
	assertion(-502465, (!local->best_rp_link));
	assertion(-502466, (!local->best_tp_link));

	while (local->refsByDhash_tree.items)
		refNode_destroy(avl_first_item(&local->refsByDhash_tree), YES);

	while (local->refsByKhash_tree.items)
		refNode_destroy(avl_first_item(&local->refsByKhash_tree), YES);


	purge_tx_task_tree(local, NULL, NULL, YES);

	local->on->neigh = NULL;
	local->on = NULL;

	if (local->linkKey)
		cryptKeyFree(&local->linkKey);

	free_internalNeighId(local->internalNeighId);

	avl_remove(&local_tree, &local->local_id, -300331);
	debugFree(local, -300333);
}

struct neigh_node *neigh_create(struct orig_node *on)
{
	struct neigh_node *nn = (on->neigh = debugMallocReset(sizeof(struct neigh_node), -300757));
	nn->local_id = on->k.nodeId;
	avl_insert(&local_tree, nn, -300758);

	AVL_INIT_TREE(nn->linkDev_tree, LinkDevNode, key.devIdx);
	AVL_INIT_TREE(nn->refsByDhash_tree, struct reference_node, dhn);
	AVL_INIT_TREE(nn->refsByKhash_tree, struct reference_node, claimedKey);

	nn->internalNeighId = allocate_internalNeighId(nn);

	struct dsc_msg_pubkey *pkey_msg = contents_data(on->descContent, BMX_DSC_TLV_LINK_PUBKEY);

	if (pkey_msg)
		nn->linkKey = cryptPubKeyFromRaw(pkey_msg->key, cryptKeyLenByType(pkey_msg->type));

	nn->on = on;
	return nn;
}







STATIC_FUNC
void free_dhash_(struct dhash_node *dhn)
{
	// only/exactly destroyed if neither references nor key
	dbgf_track(DBGT_INFO, "dhash=%s rejected=%d", cryptShaAsShortStr(&dhn->dhash), dhn->rejected);

	assertion(-502466, (!dhn->neighRefs_tree.items));
	assertion(-502467, (!dhn->descContent));

	avl_remove(&dhash_tree, &dhn->dhash, -300195);
	debugFree(dhn, -300737);
}


void dhash_clean_data(struct dhash_node *dhn)
{
	if (dhn->descContent)
		descContent_destroy(dhn->descContent);

	if (!dhn->neighRefs_tree.items)
		free_dhash_(dhn);
}

void dhash_node_reject(struct dhash_node *dhn)
{
	struct desc_content *dc = dhn->descContent;

	dbgf_track(DBGT_INFO, "dhash=%s kHash=%s hostname=%s descSqn=%d nextSqn=%d",
		cryptShaAsShortStr(&dhn->dhash),
		cryptShaAsShortStr(dc ? &dc->key->kHash : NULL),
		dc && dc->key->currOrig ? dc->key->currOrig->k.hostname : NULL,
		dc ? dc->descSqn : 0, dc && dc->key->nextDesc ? dc->key->nextDesc->descSqn : 0);

	dhn->rejected = 1;
	dhash_clean_data(dhn);
}

struct dhash_node* dhash_node_create(DHASH_T *dhash, struct neigh_node *neigh)
{

	assertion(-502468, IMPLIES(neigh, (neigh->on->key->bookedState->i.c >= KCNeighbor)));

	struct dhash_node *dhn = avl_find_item(&dhash_tree, dhash);

	if (!dhn) {
		dhn = debugMallocReset(sizeof( struct dhash_node), -300001);
		dhn->dhash = *dhash;
		dhn->referred_by_others_timestamp = bmx_time;
		dhn->referred_by_me_timestamp = bmx_time;
		AVL_INIT_TREE(dhn->neighRefs_tree, struct reference_node, neigh);
		avl_insert(&dhash_tree, dhn, -300142);
	}

	return dhn;
}






void destroy_orig_node(struct orig_node *on)
{
	dbgf_sys(DBGT_INFO, "id=%s name=%s", cryptShaAsString(&on->k.nodeId), on->k.hostname);

	assertion(-502474, (on && on->descContent && on->key && on->descContent->descSqn));
	assertion(-502475, (on->descContent->orig == on && on->descContent->key == on->key && on->key->currOrig == on));
	assertion(-502180, IMPLIES(!terminating, on != myKey->currOrig));
	assertion(-502476, (!on->neigh));

	purge_orig_router(on, NULL, NULL, NO);

	cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

	process_description_tlvs(NULL, on, NULL, on->descContent, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL);

	if (on->trustedNeighsBitArray)
		debugFree(on->trustedNeighsBitArray, -300653);

	avl_remove(&orig_tree, &on->k.nodeId, -300200);
	cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

	uint16_t i;
	for (i = 0; i < plugin_data_registries[PLUGIN_DATA_ORIG]; i++) {
		assertion(-501269, (!on->plugin_data[i]));
	}

	on->key->currOrig = NULL;
	on->descContent->orig = NULL;

	if (on->key->nextDesc)
		dhash_node_reject(on->descContent->dhn);
	else
		on->key->nextDesc = on->descContent;

	debugFree(on, -300759);
}

void init_self(void)
{
	assertion(-502094, (my_NodeKey));
	assertion(-502477, (!myKey));

	struct key_credits friend_kc = {.friend=1};
	struct dsc_msg_pubkey *msg = debugMallocReset(sizeof(struct dsc_msg_pubkey) +my_NodeKey->rawKeyLen, -300631);
	msg->type = my_NodeKey->rawKeyType;
	memcpy(msg->key, my_NodeKey->rawKey, my_NodeKey->rawKeyLen);

	struct content_node *cn = content_add_body((uint8_t*)msg, sizeof(struct dsc_msg_pubkey) +my_NodeKey->rawKeyLen, 0, 0, YES);

	myKey = keyNode_updCredits(&cn->chash, NULL, &friend_kc);

	debugFree(msg, -300600);
}

