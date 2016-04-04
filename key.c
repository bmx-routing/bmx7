/*
 * Copyright (c) 2014  Axel Neumann
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
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "ogm.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "schedule.h"
#include "tools.h"
#include "plugin.h"
#include "allocate.h"

#define CODE_CATEGORY_NAME "key"

int32_t link_purge_to = DEF_LINK_PURGE_TO;
int32_t tracked_timeout = 20000;
int32_t neigh_qualifying_to = 30000;

AVL_TREE(schedDecreasedEffectiveState_tree, struct schedDecreasedEffectiveState_node, kn);
AVL_TREE(key_tree, struct key_node, kHash);
static uint8_t key_tree_exceptions = 0;


int32_t maxDescRefsPerNeigh = 1000;
int32_t maxContentRefsPerDesc = 50;
int32_t maxKeySupportsPerOrig = 1000;

struct key_credits zeroKeyCredit = {.dFriend = 0};

//void keyNode_schedLowerState(struct key_node *kn, struct KeyState *s);

#define KS_INIT {0,0,0,0,0, NULL, NULL, NULL, NULL}



STATIC_FUNC
int8_t kRowCond_qualifying(struct key_node *kn, struct key_credits *kc)
{
	return(kc->nQualifying || (kn && kn->nQTime));
}

STATIC_FUNC
int8_t kRowCond_friend(struct key_node *kn, struct key_credits *kc)
{
	return(kc->dFriend >= TYP_TRUST_LEVEL_DIRECT || (kn && kn->dFriend >= TYP_TRUST_LEVEL_DIRECT));
}

STATIC_FUNC
int8_t kRowCond_recommended(struct key_node *kn, struct key_credits *kc)
{
	return(kc->recom || (kn && kn->recommendations_tree.items));
}

STATIC_FUNC
int8_t kRowCond_alien(struct key_node *kn, struct key_credits *kc)
{
	return(kc->pktId || (kn && kn->pktIdTime) || kc->neighRef || (kn && kn->neighRefs_tree.items) || kc->trusteeRef || (kn && kn->trustees_tree.items));
}


STATIC_FUNC
int16_t kPref_listedAlien(struct key_node *kn)
{
	int32_t referencingNeighsPref = 0;
	struct NeighRef_node *ref;
	struct avl_node *an = NULL;

	assertion(-502336, (kn && kn->bookedState == &(keyMatrix[KCListed][KRAlien])));

	while ((ref = avl_iterate_item(&kn->neighRefs_tree, &an))) {

		assertion(-502337, (ref->nn->on->kn->bookedState->i.c == KCNeighbor));

		referencingNeighsPref += (*(ref->nn->on->kn->bookedState->prefGet))(ref->nn->on->kn);
	}

	return XMIN(
		((int32_t)keyMatrix[KCListed][KRAlien].i.right->prefBase - 1),
		((int32_t)keyMatrix[KCListed][KRAlien].prefBase + (referencingNeighsPref / 1000))
		);
}

STATIC_FUNC
void kSetInAction_alien(GLOBAL_ID_T *kHash, struct key_node **kn, struct KeyState *next)
{
	assertion(-502338, (kHash && kn && *kn && next));

	if (next->i.c >= KCTracked && next->i.c < KCPromoted)
		(*kn)->TAPTime = bmx_time;

}

STATIC_FUNC
void kSetOutAction_alien(struct key_node **kn, struct KeyState *next)
{
	(*kn)->TAPTime = 0;
}

STATIC_FUNC
int8_t keyNode_compoundsLessPrefSecItem(struct KeyState *test, uint16_t prefBase)
{

	assertion(-502339, IMPLIES(test && test->i.down, test->prefBase > test->i.down->prefBase));
	assertion(-502340, IMPLIES(test && test->i.right, test->prefBase < test->i.right->prefBase));

	if (!test)
		return NO;

	if (test->prefBase >= prefBase)
		return NO;

	if (test->i.numSet > (test->i.right ? test->i.right->i.numSet : 0))
		return YES;

	return keyNode_compoundsLessPrefSecItem(test->i.right, prefBase);
}

STATIC_FUNC
int8_t keyNode_hasFreeSecItem(struct KeyState *test, struct KeyState *applicant)
{
	if (!test)
		return YES;

	if (((applicant ? applicant->i.flags : 0) & test->i.flags) == test->i.flags)
		return YES;

	return ((test->i.numSet < test->maxSet) &&
		keyNode_hasFreeSecItem(test->i.up, applicant) &&
		keyNode_hasFreeSecItem(test->i.left, applicant));
}

STATIC_FUNC
int8_t kCol_TRUE(struct key_node *kn)
{
	return YES;
}

STATIC_FUNC
int8_t kCol_FALSE(struct key_node *kn)
{
	return NO;
}

STATIC_FUNC
int8_t kColCond_listed(uint8_t asRow, struct key_node *kn)
{
	struct KeyState *lTarget = &(keyMatrix[KCListed][asRow]);

	if (keyNode_compoundsLessPrefSecItem(lTarget->i.down, lTarget->prefBase))
		return YES;

	if (keyNode_hasFreeSecItem(lTarget, kn ? kn->bookedState : NULL))
		return YES;

	return NO;
}


STATIC_FUNC
struct key_node *keyNode_create(GLOBAL_ID_T *kHash)
{
	struct key_node *kn = debugMallocReset(sizeof(struct key_node), -300703);
	kn->kHash = *kHash;
	AVL_INIT_TREE(kn->recommendations_tree, struct orig_node, kn);
	AVL_INIT_TREE(kn->neighRefs_tree, struct NeighRef_node, nn);
	AVL_INIT_TREE(kn->trustees_tree, struct orig_node, kn);

	avl_insert(&key_tree, kn, -300704);

	if (curr_rx_packet && cryptShasEqual(&curr_rx_packet->p.hdr.keyHash, kHash)) {
		assertion(-502341, (!curr_rx_packet->i.claimedKey));
		curr_rx_packet->i.claimedKey = kn;
	}

	return kn;
}



STATIC_FUNC
void kSetInAction_listed(GLOBAL_ID_T *kHash, struct key_node **knp, struct KeyState *next)
{
	assertion(-502342, (kHash && knp && !(*knp) && next));
	//(*knp) = keyNode_create(kHash);
	//STATIC_FUNC struct key_node *keyNode_create(GLOBAL_ID_T *kHash) {
	assertion(-502343, (!avl_find(&key_tree, kHash)));

	(*knp) = keyNode_create(kHash);
}

STATIC_FUNC
void keyNode_destroy_(struct key_node *kn)
{
	if (curr_rx_packet && curr_rx_packet->i.claimedKey == kn)
		curr_rx_packet->i.claimedKey = NULL;

	assertion(-502344, (!kn->on && !kn->nextDesc && !kn->recommendations_tree.items) && !kn->trustees_tree.items);
	assertion(-502345, (!kn->neighRefs_tree.items));
	assertion(-502346, (!kn->content));


	if (kn->decreasedEffectiveState != kn->bookedState)
		avl_remove(&schedDecreasedEffectiveState_tree, kn, -300705);

	avl_remove(&key_tree, &kn->kHash, -300706);
	debugFree(kn, -300707);
}

STATIC_FUNC
void kSetOutAction_listed(struct key_node **knp, struct KeyState *next)
{
	assertion(-502347, (knp && *knp));
	assertion(-502348, IMPLIES((*knp)->dFriend != TYP_TRUST_LEVEL_NONE, terminating));

	struct NeighRef_node *rn;
	while ((rn = avl_first_item(&(*knp)->neighRefs_tree))) {
		struct key_node *refNeighKey = rn->nn->on->kn;
		neighRef_destroy(rn, NO);
		keyNode_schedLowerWeight(refNeighKey, KCPromoted);
	}

	struct orig_node *on;
	while ((on = avl_remove_first_item(&(*knp)->recommendations_tree, -300708)))
		keyNode_schedLowerWeight(on->kn, KCListed);

	while ((on = avl_remove_first_item(&(*knp)->trustees_tree, -300000)))
		keyNode_schedLowerWeight(on->kn, KCListed);

	keyNode_destroy_(*knp);
	(*knp) = NULL;
}


STATIC_FUNC
int8_t kColCond_tracked(uint8_t asRow, struct key_node *kn)
{
	struct KeyState *tTarget = &(keyMatrix[KCTracked][asRow]);

	if (keyNode_compoundsLessPrefSecItem(tTarget->i.down, tTarget->prefBase))
		return YES;

	if (keyNode_hasFreeSecItem(tTarget, kn->bookedState))
		return YES;

	return NO;
}



STATIC_FUNC
void kSetInAction_tracked(GLOBAL_ID_T *kHash, struct key_node **kn, struct KeyState *next)
{
	assertion(-502349, (kn && *kn && cryptShasEqual(kHash, &(*kn)->kHash) && next));

	if (next->i.r == KRAlien)
		(*kn)->TAPTime = bmx_time;

	(*kn)->content = content_add_hash(kHash);
	(*kn)->content->kn = (*kn);


}

STATIC_FUNC
void kSetOutAction_tracked(struct key_node **kn, struct KeyState *next)
{
	assertion(-502350, (kn && *kn));
	assertion(-502351, (!(*kn)->on));
	assertion(-502352, ((*kn)->content && (*kn)->content->kn == (*kn)));

	(*kn)->TAPTime = 0;

	if ((*kn)->nextDesc)
		descContent_destroy((*kn)->nextDesc);

	(*kn)->content->kn = NULL;
	content_purge_unused((*kn)->content);
	(*kn)->content = NULL;

}

STATIC_FUNC
int8_t kColCond_certified(uint8_t asRow, struct key_node *kn)
{

	return (kn &&
		kn->content &&
		kn->content->f_body_len &&
		(kn->on || kn->nextDesc)
		);
}

STATIC_FUNC
void kSetInAction_certified(GLOBAL_ID_T *kHash, struct key_node **kn, struct KeyState *next)
{
	assertion(-502353, (kn && *kn && cryptShasEqual(kHash, &(*kn)->kHash)));
}

STATIC_FUNC
void kSetOutAction_certified(struct key_node **kn, struct KeyState *next)
{
	assertion(-502354, (kn && *kn));
}




STATIC_FUNC
int8_t kColCond_promoted(uint8_t asRow, struct key_node *kn)
{

	return (kn && (kn->pktSignTime || kn->neighRefs_tree.items || kn == myKey) && (
		(kn->on) ||
		(kn->nextDesc && kn->nextDesc->unresolvedContentCounter == 0 &&
		process_description_tlvs(NULL, kn->on, (kn->on ? kn->on->dc : NULL), kn->nextDesc, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL) == TLV_RX_DATA_DONE)
		));
}

STATIC_FUNC
void kSetInAction_promoted(GLOBAL_ID_T *kHash, struct key_node **kn, struct KeyState *next)
{
	assertion(-502355, (kn && *kn && cryptShasEqual(kHash, &(*kn)->kHash)));
	(*kn)->TAPTime = 0;


	update_orig_dhash( (*kn)->nextDesc );
}

STATIC_FUNC
int8_t kColMaintain_promoted(struct key_node *kn)
{
	assertion(-502356, kColCond_promoted(kn->bookedState->i.r, kn));

	if (!kn->nextDesc || kn->nextDesc->unresolvedContentCounter)
		return YES;

	if (process_description_tlvs(NULL, kn->on, (kn->on ? kn->on->dc : NULL), kn->nextDesc, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL) != TLV_RX_DATA_DONE)
		return NO;

	update_orig_dhash(kn->nextDesc);
	return YES;
}


STATIC_FUNC
void kSetOutAction_promoted(struct key_node **kn, struct KeyState *next)
{
	assertion(-502357, (kn && *kn && (*kn)->on));

	destroy_orig_node( (*kn)->on );
}


STATIC_FUNC
int16_t kPref_neighbor_metric(struct key_node *kn)
{
	IDM_T TODO_returnTrustedRoutesToFriendsAndRecommendeds;

	if (kn->on && kn->on->neigh && kn->on->neigh->best_tp_link) {

		return ((!!kn->on->neigh->best_tp_link->timeaware_tx_probe)
//		* kn->currOrig->neigh->orig_routes
		);
	}

	return 0;
}

STATIC_FUNC
int16_t kPref_neighbor(struct key_node *kn)
{
	return kn->bookedState->prefBase + kPref_neighbor_metric(kn);
}

STATIC_FUNC
int8_t kColCond_neighbor(uint8_t asRow, struct key_node *kn)
{
	return (kn && kn->pktSignTime &&
		(kn->nQTime || (kn->bookedState->i.c >= KCNeighbor && kPref_neighbor_metric(kn))));
}


STATIC_FUNC
void kSetInAction_neighbor(GLOBAL_ID_T *kHash, struct key_node **kn, struct KeyState *next)
{
	assertion(-502358, (kn && *kn && cryptShasEqual(kHash, &(*kn)->kHash) && (*kn)->on));
	neigh_create((*kn)->on);
}

STATIC_FUNC
void kSetOutAction_neighbor(struct key_node **kn, struct KeyState *next)
{
	assertion(-502360, (kn && *kn && (*kn)->on && (*kn)->on->neigh));

	neigh_destroy((*kn)->on->neigh);
}



struct KeyState keyMatrix[KCSize][KRSize] = {
	{
		{KS_INIT, "Listed", "qualifying", "listedQualifying", 4000, NULL, 10000, kSetInAction_listed, kSetOutAction_listed, kCol_TRUE, kColCond_listed, kRowCond_qualifying},
		{KS_INIT, "Qualified", "friend", "listedFriend", 3000, NULL, 0, NULL, NULL, NULL, NULL, kRowCond_friend},
		{KS_INIT, "Stranger", "recommended", "listedRecommended", 2000, NULL, 0, NULL, NULL, NULL, NULL, kRowCond_recommended},
		{KS_INIT, "Alien", "alien", "listedAlien", 0, kPref_listedAlien, 0, kSetInAction_alien, kSetOutAction_alien, NULL, NULL, kRowCond_alien},
	},
	{
		{KS_INIT, "Tracked", "qualifying", "trackedQualifying", 4001, NULL, 1100, kSetInAction_tracked, kSetOutAction_tracked, kCol_TRUE, kColCond_tracked, NULL},
		{KS_INIT, "TrackedQualified", "friend", "trackedFriend", 3001, NULL, 0, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "TrackedStranger", "recommended", "trackedRecommended", 2001, NULL, 0, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "TrackedAlien", "alien", "trackedAlien", 1001, NULL, 0, NULL, NULL, NULL, NULL, NULL},
	},
	{
		{KS_INIT, "Certified", "qualifying", "certifiedQualifying", 4002, NULL, 0, kSetInAction_certified, kSetOutAction_certified, kCol_TRUE, kColCond_certified, NULL},
		{KS_INIT, "CertifiedQualified", "friend", "certifiedFriend", 3002, NULL, 0, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "CertifiedStranger", "recommended", "certifiedRecommended", 2002, NULL, 0, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "CertifiedAlien", "alien", "certifiedAlien", 1002, NULL, 0, NULL, NULL, NULL, NULL, NULL},
	},
	{
		{KS_INIT, "Promoted", "qualifying", "promotedQualifying", 4003, NULL, XMIN(1000, IID_REPOS_SIZE_MAX), kSetInAction_promoted, kSetOutAction_promoted, kColMaintain_promoted, kColCond_promoted, NULL},
		{KS_INIT, "PromotedQualified", "friend", "promotedFriend", 3003, NULL, 0, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "PromotedStranger", "recommended", "promotedRecommended", 2003, NULL, 0, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "PromotedAlien", "alien", "promotedAlien", 1003, NULL, 0, NULL, NULL, NULL, NULL, NULL},
	},
	{
		{KS_INIT, "Neighbor", "qualifying", "neighboringQualifying", 9999, NULL, 100, kSetInAction_neighbor, kSetOutAction_neighbor, kCol_TRUE, kColCond_neighbor, NULL},
		{KS_INIT, "NeighboringQualified", "friend", "neighboringFriend", 7000, kPref_neighbor, 50, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "NeighboringStranger", "recommended", "neighboringRecommended", 6000, kPref_neighbor, 0, NULL, NULL, NULL, NULL, NULL},
		{KS_INIT, "NeighboringAlien", "alien", "neighboringAlien", 5000, kPref_neighbor, 25, NULL, NULL, NULL, NULL, NULL},
	},
};

STATIC_FUNC
int16_t kPref_base(struct key_node *kn)
{
	return kn->bookedState->prefBase;
}

STATIC_FUNC
void keyNode_initMatrix(void)
{
	uint8_t c = 0;
	for (; c < KCSize; c++) {
		uint8_t r = 0;
		for (; r < KRSize; r++) {
			struct KeyState *curr = &(keyMatrix[c][r]);
			struct KeyState *left = (c > 0) ? &(keyMatrix[c - 1][r]) : NULL;
			struct KeyState *up = (r > 0) ? &(keyMatrix[c][r - 1]) : NULL;
			assertion(-502361, IMPLIES(r, !curr->colCond));
			assertion(-502362, IMPLIES(c, !curr->rowCond));
			assertion(-502363, IMPLIES(c&&r, !curr->setInAction));
			assertion(-502364, IMPLIES(c&&r, !curr->setOutAction));
			assertion(-502365, IMPLIES(!r, curr->colCond));
			assertion(-502366, IMPLIES(!r, curr->colMaintain));
			assertion(-502367, IMPLIES(!c, curr->rowCond));

			curr->prefGet = curr->prefGet ? curr->prefGet : kPref_base;
			curr->i.flags |= ((up ? up->i.flags : 0) | (left ? left->i.flags : 0) | (1 << (c + KRSize)) | (1 << (r)));

			if (!curr->maxSet)
				curr->maxSet = (left && up) ? XMIN(left->maxSet, up->maxSet) : (left ? left->maxSet : (up ? up->maxSet : 0));

			curr->i.c = c;
			curr->i.r = r;
			curr->i.down = (r < (KRSize - 1)) ? &(keyMatrix[c][r + 1]) : NULL;
			curr->i.up = up;
			curr->i.right = (c < (KCSize - 1)) ? &(keyMatrix[c + 1][r]) : NULL;
			curr->i.left = left;

			assertion(-502368, IMPLIES(left, left->maxSet >= curr->maxSet));
			assertion(-502369, IMPLIES(left, left->prefBase < curr->prefBase));
			assertion(-502370, IMPLIES(up, up->maxSet >= curr->maxSet));
			assertion(-502371, IMPLIES(up, up->prefBase > curr->prefBase));

		}
	}
}

STATIC_FUNC
struct key_node * keyNode_setState(GLOBAL_ID_T *kHash, struct key_node *kn, struct KeyState *new)
{
	assertion(-502372, (kHash));
	assertion(-502373, IMPLIES(kn, kn->bookedState && cryptShasEqual(kHash, &kn->kHash)));
	assertion(-502374, IMPLIES(!kn, !avl_find_item(&key_tree, kHash)));
	assertion(-502375, IMPLIES(kn, !avl_find(&schedDecreasedEffectiveState_tree, &kn)));

	struct KeyState *old = kn ? kn->bookedState : NULL;
	int8_t oc = old ? old->i.c : 0;
	int8_t or = old ? old->i.r : 0;
	int8_t nc = new ? new->i.c : 0;
	int8_t nr = new ? new->i.r : 0;

	dbgf_sys(DBGT_INFO, "nodeId=%s old=%s or=%d oc=%d new=%s nr=%d nc=%d",
		cryptShaAsShortStr(kHash), old ? old->secName : NULL, or, oc, new ? new->secName : NULL, nr, nc);

	if (old != new) {
		int8_t c, r;

		if (old)
			old->i.numSec--;

		if (new)
			new->i.numSec++;

		for (c = 0; c <= XMAX(oc, nc); c++) {
			for (r = 0; r <= XMAX(or, nr); r++) {
				struct KeyState *t = &(keyMatrix[c][r]);
				uint8_t was = old && ((old->i.flags & t->i.flags) == t->i.flags);
				uint8_t will = new && ((new->i.flags & t->i.flags) == t->i.flags);
				int8_t diff = ((!was && will) ? (+1) : ((was && !will) ? (-1) : (0)));

				dbgf_all(DBGT_INFO, "c=%d r=%d numSet=%d diff=%-2d maxSet=%-5d exception=%d/%d setName=%s",
					c, r, t->i.numSet, diff, t->maxSet, (t->i.numSet + diff > t->maxSet), key_tree_exceptions, t->setName);

				t->i.numSet += diff;

				if (t->i.numSet > t->maxSet)
					key_tree_exceptions = YES;
			}
		}

		for (r = or; (or <= nr ? r <= nr : r >= XMAX(nr,1)); r += (or <= nr ? +1 : -1)) {

			struct KeyState *t = &(keyMatrix[0][r]);
			uint8_t was = old && or >= r;
			uint8_t will = new && nr >= r;

			dbgf_all(DBGT_INFO, "or=%d nr=%d r=%d was=%d will=%d %s set=%s sec=%s",
				or, nr, r, was, will, ((!was&&will)?"enter":(was&&!will?"leave":"nop")), t->setName, keyMatrix[oc][r].secName);

			if (!was && will && t->setInAction)
				(*(t->setInAction))(kHash, &kn, new);
			if (was && !will && t->setOutAction && r)
				(*(t->setOutAction))(&kn, new);
		}
		// oc=0, nc=0:  (c=0; c>=nc; c-=1)
		// oc=1, nc=0:  (c=1; c>=nc; c-=1)
		for (c = (oc < nc ? XMAX(oc,1) : oc); (oc < nc ? c <= nc : c >= nc); c += (oc < nc ? +1 : -1)) {
			struct KeyState *t = &(keyMatrix[c][0]);
			uint8_t was = old && oc >= c;
			uint8_t will = new && nc >= c;

			dbgf_all(DBGT_INFO, "oc=%d nc=%d c=%d was=%d will=%d %s set=%s",
				oc, nc, c, was, will, ((!was&&will)?"enter":(was&&!will?"leave":"nop")), t->setName);

			if (!was && will && t->setInAction && c)
				(*(t->setInAction))(kHash, &kn, new);
			if (was && !will && t->setOutAction)
				(*(t->setOutAction))(&kn, new);
		}
	}

	if (kn)
		kn->bookedState = kn->decreasedEffectiveState = new;


	assertion(-502376, IMPLIES(kn, new));
	assertion(-502377, IMPLIES(new, kn));
	assertion(-502378, IMPLIES(!kn, !new));
	assertion(-502379, IMPLIES(!new, !kn));
	
	assertion(-502380, IMPLIES(new, new->i.numSec == (new->i.numSet - (
		((new->i.right ? new->i.right->i.numSet : 0)) +
		((new->i.down ? new->i.down->i.numSet : 0) - ((new->i.down && new->i.down->i.right) ? new->i.down->i.right->i.numSet : 0))
		))));

	return kn;
}

STATIC_FUNC
struct KeyState *keySec_getLeast(struct KeyState *in, struct KeyState *out)
{
	in = in ? in : &(keyMatrix[0][0]);

	uint8_t r, c;
	struct KeyState *least = NULL;

	for (r = in->i.r; r < KRSize; r++) {

		for (c = in->i.c; c < KCSize; c++) {

			struct KeyState *curr = &(keyMatrix[c][r]);

			if (out && c >= out->i.c && r >= out->i.r)
				continue;

			if (curr->i.numSec && curr->prefBase <= (least ? least->prefBase : 0))
				least = curr;
		}
	}

	return least;
}

STATIC_FUNC
struct key_node *keyNode_getLeast(struct KeyState *inSet, struct KeyState *outSet)
{
//	IDM_T TODO_cacheLeastInKeyMatrixAndTrackwith_KeyNode_fixState;

	struct KeyState *ks = keySec_getLeast(inSet, outSet);
	if (ks) {
		//find first random node in section...
		CRYPTSHA1_T k;
		cryptRand(&k, sizeof(k));
		struct key_node *kCurr = avl_next_item(&key_tree, &k);
		struct key_node *kLast = kCurr;
		struct key_node *kLeast = NULL;
		uint16_t prefLeast = 0;
		uint16_t currLeast = 0;

		while ((kCurr = avl_next_item(&key_tree, kCurr ? &kCurr->kHash : NULL)) || (kCurr = avl_next_item(&key_tree, kCurr ? &kCurr->kHash : NULL))) {

			if (kCurr->bookedState == ks) {
				assertion(-502381, ((kCurr->bookedState->i.flags & inSet->i.flags) == inSet->i.flags));

				if (kCurr->bookedState->prefGet == kPref_base) {

					return kCurr;

				} else if (!kLeast || prefLeast < (currLeast = (*(kCurr->bookedState->prefGet))(kCurr))) {

					kLeast = kCurr;
					prefLeast = currLeast;
				}
			}

			if (kLast == kCurr)
				return kLeast;
		}
	}
	return NULL;
}



STATIC_FUNC
struct KeyState *keyNode_getMinMaxState(struct key_node *kn)
{
	uint8_t r , c = 0;
	struct KeyState *deservedState = NULL;
	struct KeyState *testState = NULL;
	int8_t rc = 0, cc=0, cm=0;

	dbgf_all(DBGT_INFO, "id=%s", cryptShaAsShortStr(&kn->kHash));
	dbgf_all(DBGT_INFO, "bookedSec=%s schedSec=%s", kn->bookedState->secName, kn->decreasedEffectiveState ? kn->decreasedEffectiveState->secName : NULL);

	for (r = kn->bookedState->i.r; r < KRSize; r++) {

		testState = &keyMatrix[0][r];

		if ((rc=(*(keyMatrix[0][r].rowCond))(kn, &zeroKeyCredit))) {

			for (c = 0; c <= kn->bookedState->i.c; c++) {

				testState = &(keyMatrix[c][r]);

				if ((cc=(*(keyMatrix[c][0].colCond))(r, kn)) &&
					(cm=(*(keyMatrix[c][0].colMaintain))(kn))) {

					deservedState = testState;

				} else {

					break;
				}
			}
			break;
		}
	}

	dbgf((c <= kn->bookedState->i.c ? DBGL_SYS : DBGL_ALL), DBGT_INFO,
		"Failed testing id=%s sec=%s from bookedSec=%s schedSec=%s rc=%d cc=%d cm=%d deservedState=%s",
		cryptShaAsShortStr(&kn->kHash), testState->secName, kn->bookedState->secName,
		kn->decreasedEffectiveState ? kn->decreasedEffectiveState->secName : NULL, rc, cc, cm,
		deservedState ? deservedState->secName : NULL);

	return deservedState;
}

STATIC_FUNC
struct KeyState *keyState_getMin(struct KeyState *a, struct KeyState *b)
{
	return (a && b) ? &(keyMatrix[XMIN(a->i.c, b->i.c)][XMAX(a->i.r, b->i.r)]) : NULL;
}

STATIC_FUNC
void keyNode_schedLowerState(struct key_node *kn, struct KeyState *s)
{
	uint32_t blockId = keyNodes_block_and_sync(0, NO);
	struct KeyState *min = keyState_getMin(kn->decreasedEffectiveState, s);
	//min can be different from s, minEffectiveState, and bookedState

	dbgf_all(DBGT_INFO, "id=%s booked=%s decreased=%s min=%s set=%s",
		cryptShaAsShortStr(&kn->kHash),
		kn->bookedState->secName,
		kn->decreasedEffectiveState ? kn->decreasedEffectiveState->secName : NULL,
		min ? min->secName : NULL,
		s ? s->secName : NULL
		);
	
	if ( kn->decreasedEffectiveState != min ) {

		if (kn->decreasedEffectiveState == kn->bookedState)
			avl_insert(&schedDecreasedEffectiveState_tree, kn, -300709);

		kn->decreasedEffectiveState = min;
	}
	assertion(-502382, (kn->decreasedEffectiveState == keyState_getMin(kn->decreasedEffectiveState, kn->bookedState)));
	assertion(-502383, (kn->decreasedEffectiveState == keyState_getMin(kn->decreasedEffectiveState, s)));
	keyNodes_block_and_sync(blockId, NO);
}

void keyNode_schedLowerWeight(struct key_node *kn, int8_t weight)
{
	assertion(-502384, (kn && kn->bookedState));
	assertion(-502385, (weight >= -1 && weight < KCSize));
	keyNode_schedLowerState(kn, weight>=0 ? &(keyMatrix[weight][kn->bookedState->i.r]) : NULL );
}


void keyNodes_cleanup(int8_t keyStateColumn, struct key_node *except)
{
	assertion(-502386, (keyStateColumn >= -1 && keyStateColumn < KCSize));

	struct key_node *kn = NULL;
	GLOBAL_ID_T curr = ZERO_CYRYPSHA1;

	while((kn = avl_next_item(&key_tree, &curr))) {

		curr = kn->kHash;
		assertion(-502387, (kn->bookedState));
		if (kn != except && kn->bookedState->i.c > keyStateColumn) {

			keyNode_schedLowerWeight(kn,
				(!terminating && kn == myKey && keyStateColumn < KCPromoted) ? KCPromoted : (
					(!terminating && (kn->dFriend != TYP_TRUST_LEVEL_NONE) && keyStateColumn < KCTracked) ? KCTracked :
						keyStateColumn ) );
		}
	}
}

STATIC_FUNC
IDM_T keyNode_getNQualifyingCredits(GLOBAL_ID_T *kHash, struct key_node *kn)
{
	assertion(-502388, (kHash));
	assertion(-502389, (kn == keyNode_get(kHash)));

	if (kn && (kn->nQTime || kn->bookedState->i.c >= KCNeighbor))
		return NO;

	return (
		(keyMatrix[KCListed][KRQualifying].i.numSet - keyMatrix[KCListed][KRFriend].i.numSet)
		<
		((keyMatrix[KCNeighbor][KRQualifying].maxSet - keyMatrix[KCNeighbor][KRFriend].i.numSet) /
		((kn && kn->bookedState->i.c >= KCPromoted && kn->bookedState->i.r < KRAlien) ? 1 : 2)
		)
		);

}


void keyNode_delCredits_(const char* f, GLOBAL_ID_T *kHash, struct key_node *kn, struct key_credits *kc)
{
	uint32_t blockId = keyNodes_block_and_sync(0, NO);

	assertion(-502390, (kHash || kn));

	kn = kn ? kn : avl_find_item(&key_tree, kHash);

	assertion(-502391, (kn && kn->bookedState));

	if (kc) {

		if (kc->dFriend || kc->recom || kc->trusteeRef || kc->pktId || kc->pktSign || kc->nQualifying) {
			dbgf_sys(DBGT_INFO, "%s now=%d id=%s bookedState=%s friend=%d/%d recom=%d/%d trustees=%d/%d pktId=%d/%d pktSing=%d/%d nQ=%d/%d",
				f, bmx_time, cryptShaAsShortStr(&kn->kHash), kn->bookedState->secName,
				kc->dFriend, kn->dFriend, !!kc->recom, kn->recommendations_tree.items, !!kc->trusteeRef, kn->trustees_tree.items,
				kc->pktId, kn->pktIdTime, kc->pktSign, kn->pktSignTime, kc->nQualifying, kn->nQTime);
		}

		assertion(-500000, (kc->dFriend == TYP_TRUST_LEVEL_NONE || (kc->dFriend >= TYP_TRUST_LEVEL_DIRECT && kc->dFriend <= MAX_TRUST_LEVEL)));
		assertion(-500000, (kn->dFriend == TYP_TRUST_LEVEL_NONE || (kn->dFriend >= TYP_TRUST_LEVEL_DIRECT && kn->dFriend <= MAX_TRUST_LEVEL)));
		assertion(-502392, IMPLIES(kc->dFriend, kn->dFriend));
		assertion(-502393, IMPLIES(kc->recom, avl_find(&kn->recommendations_tree, &kc->recom->kn)));
		assertion(-500000, IMPLIES(kc->trusteeRef, avl_find(&kn->trustees_tree, &kc->trusteeRef->kn)));
		assertion(-502394, (!kc->neighRef)); // this function is called from refNode_destroy()! Not the other way around!
		assertion(-502395, IMPLIES(kc->pktId, (kn->pktIdTime)));
		assertion(-502396, IMPLIES(kc->pktSign, (kn->pktSignTime)));
		assertion(-502397, IMPLIES(kc->nQualifying, (kn->nQTime)));

		if (kc->dFriend) {
			if (kn->on && kn->dFriend >= TYP_TRUST_LEVEL_IMPORT)
				apply_trust_changes(BMX_DSC_TLV_SUPPORTS, kn->on, kn->on->dc, NULL);

			kn->dFriend = TYP_TRUST_LEVEL_NONE;
		}


		if (kc->recom)
			avl_remove(&kn->recommendations_tree, &kc->recom->kn, -300710);

		if (kc->trusteeRef)
			avl_remove(&kn->trustees_tree, &kc->trusteeRef->kn, -300000);
/*
		if (kc->ref)
			refNode_destroy(kc->ref);
*/
		if (kc->pktId)
			kn->pktIdTime = 0;


		if (kc->pktSign)
			kn->pktSignTime = 0;

		if (kc->pktId || kc->nQualifying)
			kn->nQTime = 0;
	}

	keyNode_schedLowerState(kn, keyNode_getMinMaxState(kn));
	keyNodes_block_and_sync(blockId, NO);
}


STATIC_FUNC
void keyNode_addCredits_(struct key_node *kn, struct key_credits *kc)
{
	assertion(-502398, (kn && kc));
	assertion(-500000, (kc->dFriend == TYP_TRUST_LEVEL_NONE || (kc->dFriend >= TYP_TRUST_LEVEL_DIRECT && kc->dFriend <= MAX_TRUST_LEVEL)));

	if (kc->dFriend && (kc->dFriend != kn->dFriend)) {

		IDM_T willImport = (kc->dFriend >= TYP_TRUST_LEVEL_IMPORT);
		IDM_T wasImport = (kn->dFriend >= TYP_TRUST_LEVEL_IMPORT);

		kn->dFriend = kc->dFriend;

		if (kn->on && (willImport != wasImport)) {

			struct desc_content *dc = kn->on->dc;
			apply_trust_changes(BMX_DSC_TLV_SUPPORTS, kn->on, wasImport ? dc : NULL, willImport ? dc : NULL);
		}

	}

	if (kc->recom) {
		assertion(-502399, (!avl_find(&kn->recommendations_tree, &kc->recom->kn)));
		avl_insert(&kn->recommendations_tree, kc->recom, -300711);
	}

	if (kc->trusteeRef) {
		assertion(-500000, (!avl_find(&kn->trustees_tree, &kc->trusteeRef->kn)));
		avl_insert(&kn->trustees_tree, kc->trusteeRef, -300000);
	}

	if (kc->neighRef) {

		if (!kc->neighRef->kn) {
			kc->neighRef->kn = kn;
			avl_insert(&kn->neighRefs_tree, kc->neighRef, -300712);
		}
	}

	if (kc->pktId) {
		kn->pktIdTime = bmx_time;
	}


	if (kc->pktSign) {
		kn->pktSignTime = bmx_time;
	}

	if (kc->nQualifying) {
		assertion(-502403, (kc->pktId && !kn->nQTime));
		kn->nQTime = bmx_time;
	}
}


struct key_node *keyNode_updCredits(GLOBAL_ID_T *kHash, struct key_node *kn, struct key_credits *kc)
{
	kHash = kHash ? kHash : (kn ? &kn->kHash : NULL);
	kn = kn ? kn : (kHash ? avl_find_item(&key_tree, kHash) : NULL);
	
	dbgf_all(DBGT_INFO, "id=%s", cryptShaAsShortStr(kHash));
	dbgf_all(DBGT_INFO, "bookedSec=%s schedSec=%s",	kn ? kn->bookedState->secName : NULL,
		kn && kn->decreasedEffectiveState ? kn->decreasedEffectiveState->secName : NULL);

	assertion(-502404, (kHash));
	assertion(-500000, IMPLIES(kc, kc->dFriend == TYP_TRUST_LEVEL_NONE || (kc->dFriend >= TYP_TRUST_LEVEL_DIRECT && kc->dFriend <= MAX_TRUST_LEVEL)));
	assertion(-502405, IMPLIES(kc && kc->pktSign, kc->pktId));
	assertion(-502406, IMPLIES(kc && kc->neighRef, kc->neighRef->nn));
	assertion(-502407, IMPLIES(kn, cryptShasEqual(kHash, &kn->kHash)));
	assertion(-502408, IMPLIES(kn, kn->bookedState));
	assertion(-502409, IMPLIES(kn, !(kc && kc->nQualifying && kn->nQTime)));

	if (kc && kc->pktId)
		kc->nQualifying = keyNode_getNQualifyingCredits(kHash, kn);

	if (kn) {
		if (kc)
			keyNode_addCredits_(kn, kc);

		keyNode_schedLowerState(kn, keyNode_getMinMaxState(kn));

		assertion(-502410, ((kn = avl_find_item(&key_tree, kHash)))); //IMO kn may disappear during prev call and should be set to NULL then!
	}

	uint32_t blockId = keyNodes_block_and_sync(0, NO);
	uint8_t r, c;

	dbgf_all(DBGT_INFO, "bookedSec=%s schedSec=%s",	kn ? kn->bookedState->secName : NULL,
		kn && kn->decreasedEffectiveState ? kn->decreasedEffectiveState->secName : NULL);

	IDM_T condSuccess = NO;
	struct KeyState *testState = NULL;

	if (!kn || kn->decreasedEffectiveState == kn->bookedState) {

		for (r = 0; r < (kn ? kn->bookedState->i.r + 1 : KRSize); r++) {
			dbgf_all(DBGT_INFO, "testing row=%-10s from sec=%s",
				keyMatrix[0][r].rowName, kn ? kn->bookedState->secName : NULL);

			if ((condSuccess = (*(keyMatrix[0][r].rowCond))(kn, (kc ? kc : (struct key_credits*) &zeroKeyCredit)))) {

				for (c = (kn ? kn->bookedState->i.c + (r < kn->bookedState->i.r ? 0 : 1) : 0); c < KCSize; c++) {
					dbgf_all(DBGT_INFO, "testing set=%-10s from sec=%s",
						keyMatrix[c][0].setName, kn ? kn->bookedState->secName: NULL);

					testState = &(keyMatrix[c][r]);

					if ((condSuccess = (*(keyMatrix[c][0].colCond))(r, kn)) &&
						(kn = keyNode_setState(kHash, kn, testState)) &&
						(kn->bookedState == testState)
						) {

						if (c==KCListed && kc)
							keyNode_addCredits_(kn, kc);

						if ((*(keyMatrix[c][0].colMaintain))(kn) )
							continue;
						else
							keyNode_schedLowerState(kn, kn->bookedState->i.left);
					}
					break;
				}
				break;
			}
		}
	}


	keyNodes_block_and_sync(blockId, NO);

	dbgf_all(DBGT_INFO, "bookedSec=%s schedSec=%s testSec=%s condSuccess=%d ", kn ? kn->bookedState->secName : NULL,
		kn && kn->decreasedEffectiveState ? kn->decreasedEffectiveState->secName : NULL,
		testState ? testState->secName : NULL, condSuccess);

	return kn;
}


STATIC_FUNC
void keyNodes_updCredits(void)
{
	struct KeyState *ks;

	ks = &(keyMatrix[KCListed][0]);
	if (ks->i.numSet > ks->i.right->i.numSet && ks->i.right->i.numSet < ks->i.right->maxSet ) {

		struct key_node *kn = NULL;

		while ((kn = avl_next_item(&key_tree, kn ? &kn->kHash : NULL))) {

			if (kn->bookedState->i.c == KCListed)
				keyNode_updCredits(NULL, kn, NULL);
		}

	}
}



void keyNode_fixTimeouts()
{
	int32_t keys_cleanup_to = 1000;
	static TIME_T last_cleanup = 0;

	if (((TIME_T) (bmx_time - last_cleanup))<=((TIME_T) keys_cleanup_to))
		return;

	last_cleanup = bmx_time;

	uint32_t blockId = keyNodes_block_and_sync(0, NO);

	struct key_node *kn = NULL;
	while ((kn = avl_next_item(&key_tree, kn ? &kn->kHash : NULL))) {
		
		struct key_credits kc = {
			.pktId = (kn->pktIdTime && (((TIME_T) (bmx_time - kn->pktIdTime))>((TIME_T) link_purge_to))),
			.nQualifying = (kn->nQTime && (((TIME_T) (bmx_time - kn->nQTime))>((TIME_T) neigh_qualifying_to))),
			.pktSign = (kn->pktSignTime && (((TIME_T) (bmx_time - kn->pktSignTime))>((TIME_T) link_purge_to)))
		};
		if (kc.pktId || kc.nQualifying || kc.pktSign)
			keyNode_delCredits(NULL, kn, &kc);


		struct neigh_node * neigh = NULL;
		struct NeighRef_node * ref = NULL;
		while ((ref = avl_next_item(&kn->neighRefs_tree, &neigh))) {
			neigh = ref->nn;
			
			if (!iid_get_neighIID4x_timeout_by_node(ref))
				neighRef_destroy(ref, YES);

		}


		if (kn->TAPTime && (((TIME_T) (bmx_time - kn->TAPTime))>((TIME_T) tracked_timeout))) {
			assertion(-502412, (kn->bookedState->i.r == KRAlien));
			assertion(-502413, (kn->bookedState->i.c >= KCTracked));
			assertion(-502414, (kn->bookedState->i.c < KCPromoted));
			keyNode_schedLowerWeight(kn, KCListed);
		}
	}

	keyNodes_block_and_sync(blockId, NO);

	keyNodes_updCredits();
}

STATIC_FUNC
uint32_t keyNodes_setDecreasedStates_(const char *f)
{
	uint32_t changes = 0;
	struct key_node *kn = NULL;

	while ((kn = avl_remove_first_item(&schedDecreasedEffectiveState_tree, -300714))) {

		dbgf_sys(DBGT_INFO, "f=%s id=%s bookedSec=%s schedSec=%s", f, cryptShaAsShortStr(&kn->kHash), kn->bookedState->secName,
			kn->decreasedEffectiveState ? kn->decreasedEffectiveState->secName : NULL);

		assertion(-502415, (kn->decreasedEffectiveState != kn->bookedState));
		assertion(-502416, (kn->decreasedEffectiveState==keyState_getMin(kn->decreasedEffectiveState, kn->bookedState)));

		keyNode_setState(&kn->kHash, kn, kn->decreasedEffectiveState);
		changes++;
	}
	return changes;
}

STATIC_FUNC
uint32_t keyNodes_fixLimits()
{
	uint32_t changes = 0;
	dbgf_all(DBGT_INFO, "exceptions=%d", key_tree_exceptions);

	while(key_tree_exceptions) {
		key_tree_exceptions = NO;
		int8_t c, r;
		for (c = KCSize-1; c >= 0; c--) {
			for (r = KRSize-1; r >= 0; r--) {
				struct KeyState *ks = &(keyMatrix[c][r]);

				while (ks->i.numSet > ks->maxSet) {

					//keyNode_reduceSet(ks);
					struct key_node *least = keyNode_getLeast(ks, NULL);
					assertion(-502417, (least));
					struct KeyState *newState = (least->bookedState->i.c) ? &(keyMatrix[least->bookedState->i.c - 1][least->bookedState->i.r]) : NULL;

					dbgf_sys(DBGT_INFO, "c=%d r=%d set=%s %d/%d sec=%s %d, least=%s old=%s new=%s",
						c, r, ks->setName, ks->i.numSet, ks->maxSet, ks->secName, ks->i.numSec,
						cryptShaAsShortStr(&least->kHash), least->bookedState->secName, newState->secName);

					keyNode_setState(&least->kHash, least, newState);
					changes++;
				}
			}
		}
	}
	return changes;
}

/*
 * if called with force: syncs immediately
 * if called without id: blocks syncing and returns id
 * if called without id and already synced: leaves syncing to previous blocking
 * if called with id: completes sync and releases id
 */
uint32_t keyNodes_block_and_sync_(const char *f, uint32_t id, IDM_T force)
{
	static uint32_t keyNodes_next_block_id = KEYNODES_BLOCKING_ID;
	
	dbgf_all(DBGT_INFO, "func=%s, force=%d id=%d blockId=%d", f, force, id, keyNodes_next_block_id);

	assertion(-502418, (keyNodes_next_block_id >= KEYNODES_BLOCKING_ID ));
	assertion(-502419, IMPLIES(id, id >= KEYNODES_BLOCKING_ID));
	assertion(-502420, IMPLIES(id, id == keyNodes_next_block_id-1));
	assertion(-502421, IMPLIES(force, !id && keyNodes_next_block_id == KEYNODES_BLOCKING_ID));

	if ( force || id ) {

		if (id)
			keyNodes_next_block_id--;

		if (force || keyNodes_next_block_id == KEYNODES_BLOCKING_ID) {
			uint32_t changes = 0;
			changes += keyNodes_setDecreasedStates_(f);
			changes += keyNodes_fixLimits();
			return YES + changes;
		}

		return NO;

	} else {
		keyNodes_next_block_id++;
		return (keyNodes_next_block_id-1);
	}
}


struct key_node *keyNode_get(GLOBAL_ID_T *kHash)
{
	return avl_find_item(&key_tree, kHash);
}



struct credits_status {
#define CSFSize 20
	char *row;
	char *set;
	char Listed[CSFSize];
	char Tracked[CSFSize];
	char Certified[CSFSize];
	char Promoted[CSFSize];
	char Neighbor[CSFSize];
};

static const struct field_format credits_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,   credits_status, row,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,   credits_status, set,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,    credits_status, Listed,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,    credits_status, Tracked,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,    credits_status, Certified, 1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,    credits_status, Promoted,  1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,    credits_status, Neighbor,  1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t credits_creator(struct status_handl *handl, void *data)
{
	uint16_t cSize = KRSize * sizeof(struct credits_status);
        struct credits_status *s = ((struct credits_status*) (handl->data ? handl->data : (handl->data = debugMallocReset(cSize, -300358))));
	uint8_t r,c;

	for (r = 0; r < KRSize; r++) {
		s[r].set = keyMatrix[KCListed][r].setName;
		s[r].row = keyMatrix[KCListed][r].rowName;
		for (c = KCListed; c < KCSize; c++) {
			sprintf((s[r].Listed + (c * CSFSize)), "%d/%d/%d",
				keyMatrix[c][r].i.numSec, keyMatrix[c][r].i.numSet, keyMatrix[c][r].maxSet);
		}
	}
	return cSize;
}




static struct opt_type key_options[] = {

	{ODI,0,ARG_CREDITS,	        0,  9,1,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show credits\n"},
#ifndef LESS_OPTIONS
	{ODI, 0, ARG_LINK_PURGE_TO, 0, 9, 1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &link_purge_to, MIN_LINK_PURGE_TO, MAX_LINK_PURGE_TO, DEF_LINK_PURGE_TO, 0, 0,
		ARG_VALUE_FORM, "timeout in ms for purging stale links"}
#endif
};

void init_key(void)
{

	register_options_array(key_options, sizeof(key_options), CODE_CATEGORY_NAME);
	register_status_handl(sizeof(struct credits_status), 1, credits_format, ARG_CREDITS, credits_creator);

	keyNode_initMatrix();
}
