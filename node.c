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
#include "sec.h"
#include "metrics.h"
#include "msg.h"
#include "ip.h"
#include "hna.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"

#define CODE_CATEGORY_NAME "node"

IDM_T my_description_changed = YES;

struct orig_node *self = NULL;




static int32_t link_purge_to = DEF_LINK_PURGE_TO;
static int32_t ogm_purge_to = DEF_OGM_PURGE_TO;


AVL_TREE(link_tree, LinkNode, k);

AVL_TREE(link_dev_tree, LinkDevNode, key);

AVL_TREE(local_tree, struct neigh_node, local_id);

AVL_TREE(dhash_tree, struct dhash_node, dhash);
AVL_TREE(deprecated_dhash_tree, struct dhash_node, dhash);
AVL_TREE(deprecated_globalId_tree, struct deprecated_globalId_node, globalId);

AVL_TREE(orig_tree, struct orig_node, nodeId);

AVL_TREE(status_tree, struct status_handl, status_name);

static AVL_TREE(blocked_tree, struct orig_node, nodeId);




/***********************************************************
 IID Infrastructure
 ************************************************************/


struct iid_repos my_iid_repos = { 0,0,0,0,{NULL} };

int8_t iid_extend_repos(struct iid_repos *rep)
{
        TRACE_FUNCTION_CALL;

        dbgf_all(DBGT_INFO, "sizeof iid: %zu,  tot_used %d  arr_size %d ",
                (rep == &my_iid_repos) ? sizeof (IID_NODE_T*) : sizeof (IID_T), rep->tot_used, rep->arr_size);

        assertion(-500217, (rep != &my_iid_repos || IID_SPREAD_FK != 1 || rep->tot_used == rep->arr_size));

        if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_WARN) {

                dbgf_sys(DBGT_WARN, "%d", rep->arr_size);

                if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_MAX)
                        return FAILURE;
        }

        int field_size = (rep == &my_iid_repos) ? sizeof (IID_NODE_T*) : sizeof (struct iid_ref);

        if (rep->arr_size) {

                rep->arr.u8 = debugRealloc(rep->arr.u8, (rep->arr_size + IID_REPOS_SIZE_BLOCK) * field_size, -300035);

        } else {

                rep->arr.u8 = debugMalloc(IID_REPOS_SIZE_BLOCK * field_size, -300085);
                rep->tot_used = IID_RSVD_MAX+1;
                rep->min_free = IID_RSVD_MAX+1;
                rep->max_free = IID_RSVD_MAX+1;
        }

        memset(&(rep->arr.u8[rep->arr_size * field_size]), 0, IID_REPOS_SIZE_BLOCK * field_size);

        rep->arr_size += IID_REPOS_SIZE_BLOCK;

        return SUCCESS;
}


void iid_purge_repos( struct iid_repos *rep )
{
        TRACE_FUNCTION_CALL;

        if (rep->arr.u8)
                debugFree(rep->arr.u8, -300135);

        memset(rep, 0, sizeof ( struct iid_repos));

}

void iid_free(struct iid_repos *rep, IID_T iid)
{
        TRACE_FUNCTION_CALL;
        int m = (rep == &my_iid_repos);

        assertion(-500330, (iid > IID_RSVD_MAX));
        assertion(-500228, (iid < rep->arr_size && iid < rep->max_free && rep->tot_used > IID_RSVD_MAX));
        assertion(-500229, ((m ? (rep->arr.node[iid] != NULL) : (rep->arr.ref[iid].myIID4x) != 0)));

        if (m) {
                rep->arr.node[iid] = NULL;
        } else {
                rep->arr.ref[iid].myIID4x = 0;
                rep->arr.ref[iid].referred_by_neigh_timestamp_sec = 0;
        }

        rep->min_free = XMIN(rep->min_free, iid);

        if (rep->max_free == iid + 1) {

                IID_T i;

                for (i = iid; i > IID_MIN_USED; i--) {

                        if (m ? (rep->arr.node[i - 1] != NULL) : (rep->arr.ref[i - 1].myIID4x) != 0)
                                break;
                }

                rep->max_free = i;
        }

        rep->tot_used--;

        dbgf_all( DBGT_INFO, "mine %d, iid %d tot_used %d, min_free %d max_free %d",
                m, iid, rep->tot_used, rep->min_free, rep->max_free);

        if (rep->tot_used > 0 && rep->tot_used <= IID_MIN_USED) {

                assertion(-500362, (rep->tot_used == IID_MIN_USED && rep->max_free == IID_MIN_USED && rep->min_free == IID_MIN_USED));

                iid_purge_repos( rep );

        }

}

IID_NODE_T* iid_get_node_by_myIID4x(IID_T myIID4x)
{
        TRACE_FUNCTION_CALL;

        if ( my_iid_repos.max_free <= myIID4x )
                return NULL;

        IID_NODE_T *dhn = my_iid_repos.arr.node[myIID4x];

        assertion(-500328, (!dhn || dhn->myIID4orig == myIID4x));

        if (dhn && !dhn->on) {

                dbgf_track(DBGT_INFO, "myIID4x %d INVALIDATED %d sec ago",
                        myIID4x, (bmx_time - dhn->referred_by_me_timestamp) / 1000);

                return NULL;
        }


        return dhn;
}


IID_NODE_T* iid_get_node_by_neighIID4x(IID_NEIGH_T *nn, IID_T neighIID4x, IDM_T verbose)
{
        TRACE_FUNCTION_CALL;

        if (!nn || nn->neighIID4x_repos.max_free <= neighIID4x) {

                if (verbose) {
                        dbgf_all(DBGT_INFO, "NB: global_id=%s neighIID4x=%d to large for neighIID4x_repos",
                                nn ? cryptShaAsString(&nn->dhn->on->nodeId) : "???", neighIID4x);
                }
                return NULL;
        }

        struct iid_ref *ref = &(nn->neighIID4x_repos.arr.ref[neighIID4x]);


        if (!ref->myIID4x ) {
                if (verbose) {
                        dbgf_all(DBGT_WARN, "neighIID4x=%d not recorded by neighIID4x_repos", neighIID4x);
                }
        } else if (((((uint16_t) bmx_time_sec) - ref->referred_by_neigh_timestamp_sec) >
                ((MIN_DHASH_TO - (MIN_DHASH_TO / DHASH_TO_TOLERANCE_FK)) / 1000))) {

                if (verbose) {
                        dbgf_track(DBGT_WARN, "neighIID4x=%d outdated in neighIID4x_repos, now_sec=%d, ref_sec=%d",
                                neighIID4x, bmx_time_sec, ref->referred_by_neigh_timestamp_sec);
                }

        } else {

                ref->referred_by_neigh_timestamp_sec = bmx_time_sec;

                if (ref->myIID4x < my_iid_repos.max_free) {

                        IID_NODE_T *dhn = my_iid_repos.arr.node[ref->myIID4x];

                        if (dhn)
                                return dhn;

                        if (verbose) {
                                dbgf_track(DBGT_WARN, "neighIID4x=%d -> myIID4x=%d empty!", neighIID4x, ref->myIID4x);
                        }

                } else {

                        if (verbose) {
                                dbgf_track(DBGT_WARN, "neighIID4x=%d -> myIID4x=%d to large!", neighIID4x, ref->myIID4x);
                        }
                }
        }

        return NULL;
}


STATIC_FUNC
void _iid_set(struct iid_repos *rep, IID_T IIDpos, IID_T myIID4x, IID_NODE_T *dhn)
{
        TRACE_FUNCTION_CALL;
        assertion(-500530, (rep && XOR(myIID4x, dhn))); // eihter the one ore the other !!
        assertion(-500531, (!dhn || rep == &my_iid_repos));
        assertion(-500535, (IIDpos >= IID_MIN_USED));

        rep->tot_used++;
        rep->max_free = XMAX( rep->max_free, IIDpos+1 );

        IID_T min = rep->min_free;

        if (min == IIDpos) {
                for (min++; min < rep->arr_size; min++) {

                        if (myIID4x ? !(rep->arr.ref[min].myIID4x) : !(rep->arr.node[min]))
                                break;
                }
        }

        assertion(-500244, (min <= rep->max_free));

        rep->min_free = min;

        if (myIID4x) {
                rep->arr.ref[IIDpos].myIID4x = myIID4x;
                rep->arr.ref[IIDpos].referred_by_neigh_timestamp_sec = bmx_time_sec;
        } else {
                rep->arr.node[IIDpos] = dhn;
                dhn->referred_by_me_timestamp = bmx_time;
        }
}


IID_T iid_new_myIID4x(IID_NODE_T *dhn)
{
        TRACE_FUNCTION_CALL;
        IID_T mid;
#ifndef NO_ASSERTIONS
        IDM_T warn = 0;
#endif

        assertion(-500216, (my_iid_repos.tot_used <= my_iid_repos.arr_size));

        while (my_iid_repos.arr_size <= my_iid_repos.tot_used * IID_SPREAD_FK)
                iid_extend_repos( &my_iid_repos );

        if (IID_SPREAD_FK > 1) {

                uint32_t random = rand_num(my_iid_repos.arr_size);

                // Never put random function intro MAX()! It would be called twice
                mid = XMAX(IID_MIN_USED, random);

                while (my_iid_repos.arr.node[mid]) {

                        mid++;
                        if (mid >= my_iid_repos.arr_size) {

                                mid = IID_MIN_USED;

                                assertion(-500533, (!(warn++)));
                        }
                }

        } else {

                mid = my_iid_repos.min_free;
        }

        _iid_set(&my_iid_repos, mid, 0, dhn);

        return mid;

}


IDM_T iid_set_neighIID4x(struct iid_repos *neigh_rep, IID_T neighIID4x, IID_T myIID4x)
{
        TRACE_FUNCTION_CALL;
        assertion(-500326, (neighIID4x > IID_RSVD_MAX));
        assertion(-500327, (myIID4x > IID_RSVD_MAX));
        assertion(-500384, (neigh_rep && neigh_rep != &my_iid_repos));

        assertion(-500245, (my_iid_repos.max_free > myIID4x));

        IID_NODE_T *dhn = my_iid_repos.arr.node[myIID4x];

        assertion(-500485, (dhn && dhn->on));

        dhn->referred_by_me_timestamp = bmx_time;

        if (neigh_rep->max_free > neighIID4x) {

                struct iid_ref *ref = &(neigh_rep->arr.ref[neighIID4x]);

                if (ref->myIID4x > IID_RSVD_MAX) {

                        if (ref->myIID4x == myIID4x ||
                                (((uint16_t)(((uint16_t) bmx_time_sec) - ref->referred_by_neigh_timestamp_sec)) >=
                                ((MIN_DHASH_TO - (MIN_DHASH_TO / DHASH_TO_TOLERANCE_FK)) / 1000))) {

                                ref->myIID4x = myIID4x;
                                ref->referred_by_neigh_timestamp_sec = bmx_time_sec;
                                return SUCCESS;
                        }

                        IID_NODE_T *dhn_old;
                        dhn_old = my_iid_repos.arr.node[ref->myIID4x]; // avoid -DNO_DEBUG_SYS warnings
                        dbgf_sys(DBGT_ERR, "demanding mapping: neighIID4x=%d to myIID4x=%d "
                                "(global_id=%s updated=%d last_referred_by_me=%d)  "
                                "already used for ref->myIID4x=%d (last_referred_by_neigh_sec=%d %s=%s last_referred_by_me=%jd)! Reused faster than allowed!!",
                                neighIID4x, myIID4x, cryptShaAsString(&dhn->on->nodeId), dhn->on->updated_timestamp,
                                dhn->referred_by_me_timestamp,
                                ref->myIID4x,
                                ref->referred_by_neigh_timestamp_sec,
                                (!dhn_old ? "???" : (dhn_old->on ? cryptShaAsString(&dhn_old->on->nodeId) :
                                (is_zero(&dhn_old->dhash, sizeof (dhn_old->dhash)) ? "FREED" : "INVALIDATED"))),
                                dhn_old ? cryptShaAsString(&dhn_old->dhash) : "???",
                                dhn_old ? (int64_t)dhn_old->referred_by_me_timestamp : -1
                                );

//                        EXITERROR(-500701, (0));

                        return FAILURE;
                }

                assertion(-500242, (ref->myIID4x == IID_RSVD_UNUSED));
        }


        while (neigh_rep->arr_size <= neighIID4x) {

                if (
                        neigh_rep->arr_size > IID_REPOS_SIZE_BLOCK &&
                        neigh_rep->arr_size > my_iid_repos.arr_size &&
                        neigh_rep->tot_used < neigh_rep->arr_size / (2 * IID_SPREAD_FK)) {

                        dbgf_sys(DBGT_WARN, "IID_REPOS USAGE WARNING neighIID4x %d myIID4x %d arr_size %d used %d",
                                neighIID4x, myIID4x, neigh_rep->arr_size, neigh_rep->tot_used );
                }

                iid_extend_repos(neigh_rep);
        }

        assertion(-500243, ((neigh_rep->arr_size > neighIID4x &&
                (neigh_rep->max_free <= neighIID4x || neigh_rep->arr.ref[neighIID4x].myIID4x == IID_RSVD_UNUSED))));

        _iid_set( neigh_rep, neighIID4x, myIID4x, NULL);

        return SUCCESS;
}


void iid_free_neighIID4x_by_myIID4x( struct iid_repos *rep, IID_T myIID4x)
{
        TRACE_FUNCTION_CALL;
        assertion(-500282, (rep != &my_iid_repos));
        assertion(-500328, (myIID4x > IID_RSVD_MAX));

        IID_T p;
        uint16_t removed = 0;

        for (p = IID_RSVD_MAX + 1; p < rep->max_free; p++) {

                if (rep->arr.ref[p].myIID4x == myIID4x) {

                        if (removed++) {
                                // there could indeed be several (if the neigh has timeouted this node and learned it again later)
                                dbgf(DBGL_TEST, DBGT_INFO, "removed %d. stale rep->arr.sid[%d] = %d", removed, p, myIID4x);
                        }

                        iid_free(rep, p);
                }
        }
}




/***********************************************************
 Data Infrastructure
 ************************************************************/

void badlist_neighbor_if_verified(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        dbgf_sys(DBGT_ERR, "%s via %s verifiedLinkDhn=%p", pb->i.llip_str, pb->i.iif->label_cfg.str, (void*)pb->i.verifiedLinkDhn);

	if (pb->i.verifiedLinkDhn) {
		//TODO: only badlist neighbor if verifiedLinkDhn
	}

        EXITERROR(-500697, (0));
}


IDM_T badlist_neighbor(struct packet_buff *pb, DHASH_T *dhash)
{
        TRACE_FUNCTION_CALL;
        //dbgf_all(DBGT_INFO, "%s via %s", pb->i.neigh_str, pb->i.iif->label_cfg.str);
        return NO;
}




STATIC_FUNC
void purge_dhash_iid(IID_T myIID4orig)
{
        TRACE_FUNCTION_CALL;
        struct avl_node *an;
        struct neigh_node *local;

        //reset all neigh_node->oid_repos[x]=dhn->mid4o entries
        for (an = NULL; (local = avl_iterate_item(&local_tree, &an));) {

                iid_free_neighIID4x_by_myIID4x(&local->neighIID4x_repos, myIID4orig);

        }
}

STATIC_FUNC
void purge_deprecated_dhash_tree( struct dhash_node *onlyDhn, IDM_T onlyExpired ) {

        TRACE_FUNCTION_CALL;
        struct dhash_node *dhn;
	DHASH_T dhash = ZERO_CYRYPSHA1;

	dbgf_all(DBGT_INFO, "dhash=%s onlyExpired=%d",
		(onlyDhn ? cryptShaAsString(&onlyDhn->dhash) : NULL), onlyExpired);

	assertion(-500000, IMPLIES(onlyDhn, onlyDhn == avl_find_item(&deprecated_dhash_tree, &onlyDhn->dhash)));

	while ((dhn = onlyDhn ? onlyDhn : avl_next_item(&deprecated_dhash_tree, &dhash))) {

		dhash = dhn->dhash;

                if (!onlyExpired || ((uint32_t) (bmx_time - dhn->referred_by_me_timestamp) > MIN_DHASH_TO)) {

			if (dhn->deprecated_globalId) {

				assertion(-500000, (dhn->deprecated_globalId->deprecated_dhash_tree.items));
				assertion(-500000, (avl_find(&dhn->deprecated_globalId->deprecated_dhash_tree, &dhash)));

				avl_remove(&dhn->deprecated_globalId->deprecated_dhash_tree, &dhash, -300000);

				if (!dhn->deprecated_globalId->deprecated_dhash_tree.items) {
					avl_remove(&deprecated_globalId_tree, &dhn->deprecated_globalId->globalId, -300000);
					debugFree(dhn->deprecated_globalId, -300000);
				}
			}

			dbgf_all(DBGT_INFO, "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

			avl_remove(&deprecated_dhash_tree, &dhash, -300194);

			if (dhn->myIID4orig > IID_RSVD_MAX) {

				iid_free(&my_iid_repos, dhn->myIID4orig);

				purge_dhash_iid(dhn->myIID4orig);
			}

			debugFree(dhn, -300112);
                }

		if (onlyDhn)
			break;
        }
}

void purge_deprecated_globalId_tree( GLOBAL_ID_T *globalId ) {

	struct deprecated_globalId_node *dgn;
	struct dhash_node *dhn;

	while ((dgn = avl_find_item(&deprecated_globalId_tree, globalId)) && (dhn = avl_first_item(&dgn->deprecated_dhash_tree)))
		purge_deprecated_dhash_tree(dhn, NO);

}

void deprecate_dhash_iid( struct dhash_node *dhn, DHASH_T *dhash, GLOBAL_ID_T *globalId )
{
        TRACE_FUNCTION_CALL;
	IDM_T TODO_if_items_of_deprecated_dhashs_exceeds_max_acceptable_then_stop_adding_and_stop_requesting;
	assertion( -502087, XOR(dhn, dhash));

	if (!dhn) {
		dhn = debugMallocReset(sizeof(struct dhash_node), -300628);
		dhn->dhash = *dhash;
	} else {
		dext_free(&dhn->dext);
		debugFree(dhn->desc_frame, -300629);
		dhn->desc_frame = NULL;
		dhn->desc_frame_len = 0;
	}

        dbgf_track(DBGT_INFO,
                "dhash=%s globalId=%s myIID4orig=%d, my_iid_repository: used=%d, inactive=%d  min_free=%d  max_free=%d ",
                cryptShaAsString(&dhn->dhash), cryptShaAsString(globalId), dhn->myIID4orig,
                my_iid_repos.tot_used, deprecated_dhash_tree.items+1, my_iid_repos.min_free, my_iid_repos.max_free);

	assertion( -500000, (!avl_find(&deprecated_dhash_tree, &dhn->dhash)));
        assertion( -500698, (!dhn->on));
        assertion( -500699, (!dhn->local));
	assertion( -502088, !avl_find(&dhash_tree, &dhn->dhash));

        avl_insert(&deprecated_dhash_tree, dhn, -300168);

	if (globalId) {
		struct deprecated_globalId_node *dgn;

		if (!(dgn = avl_find_item(&deprecated_globalId_tree, globalId))) {
			dgn = debugMallocReset(sizeof(struct deprecated_globalId_node), -300000);
			dgn->globalId = *globalId;
			AVL_INIT_TREE(dgn->deprecated_dhash_tree, struct dhash_node, dhash);
			avl_insert(&deprecated_globalId_tree, dgn, -300000);
		}

		avl_insert(&dgn->deprecated_dhash_tree, dhn, -300000);
		dhn->deprecated_globalId = dgn;
	}

        dhn->referred_by_me_timestamp = bmx_time;
}

// called to not leave blocked dhash values:
STATIC_FUNC
void free_dhash( struct dhash_node *dhn )
{
        TRACE_FUNCTION_CALL;
        static uint32_t blocked_counter = 1;

        dbgf(terminating ? DBGL_CHANGES : DBGL_SYS, DBGT_INFO,
                "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        assertion(-500961, (!dhn->on));
        assertion(-500962, (!dhn->local));

        avl_remove(&dhash_tree, &dhn->dhash, -300195);

        purge_dhash_iid(dhn->myIID4orig);

        // It must be ensured that I am not reusing this IID for a while, so it must be invalidated
        // but the description and its' resulting dhash might become valid again, so I give it a unique and illegal value.
        memset(&dhn->dhash, 0, sizeof ( DHASH_T));
        dhn->dhash.h.u32[(sizeof ( DHASH_T) / sizeof (uint32_t)) - 1] = blocked_counter++;

	deprecate_dhash_iid(dhn, NULL, NULL);
}

struct dhash_node* create_dext_dhash(uint8_t *desc_frame, uint32_t desc_frame_len, struct desc_extension* dext, DHASH_T *dhash)
{

        dext->dhn = debugMallocReset(sizeof ( struct dhash_node), -300001);
	dext->dhn->desc_frame = desc_frame;
	dext->dhn->desc_frame_len = desc_frame_len;
	dext->dhn->dext = dext;
	dext->dhn->dhash = *dhash;

	return dext->dhn;
}


struct dhash_node *get_dhash_tree_node(DHASH_T *dhash) {

	struct dhash_node *dhn = avl_find_item(&dhash_tree, dhash);

	if (dhn) {
		assertion(-502216, (dhn->on));
		assertion(-502217, (dhn->on->dhn));
		assertion(-502218, (dhn->on->dhn == dhn));
		assertion(-502219, (dhn->dext));
		assertion(-502220, (dhn->dext->dhn));
		assertion(-502221, (dhn->dext->dhn == dhn));
		assertion(-502222, (dhn->desc_frame));
		assertion(-502223, (dhn->desc_frame_len));
		ASSERTION(-502224, (!avl_find(&deprecated_dhash_tree, &dhn->dhash)));
		ASSERTION(-500000, (nodeIdFromDescAdv(dhn->desc_frame)));
		ASSERTION(-500310, (dhn->on == avl_find_item(&orig_tree, nodeIdFromDescAdv(dhn->desc_frame))));
	}

	return dhn;
}

void update_orig_dhash(struct orig_node *on, struct dhash_node *dhn)
{
	assertion(-502225, (on));
	assertion(-502226, (dhn));

        struct neigh_node *neigh = NULL;

        if (on->dhn) {
                neigh = on->dhn->local;

                on->dhn->local = NULL;
                on->dhn->on = NULL;

		avl_remove(&dhash_tree, &on->dhn->dhash, -300195);

                deprecate_dhash_iid(on->dhn, NULL, NULL);
        }

        dhn->myIID4orig = iid_new_myIID4x(dhn);
        dhn->on = on;
        avl_insert(&dhash_tree, dhn, -300142);

        on->dhn = dhn;
        on->updated_timestamp = bmx_time;

        dbgf_track(DBGT_INFO, "dhash %8X.. myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        if (neigh) {
                neigh->dhn = on->dhn;
                on->dhn->local = neigh;
        }

	ASSERTION(-502227, (get_dhash_tree_node(&dhn->dhash)));
}





void purge_orig_router(struct orig_node *onlyOrig, struct neigh_node *onlyNeigh, LinkNode *onlyLink, IDM_T only_useless)
{
        TRACE_FUNCTION_CALL;
        struct orig_node *on;
        struct avl_node *an = NULL;
        while ((on = onlyOrig) || (on = avl_iterate_item( &orig_tree, &an))) {

                struct neigh_node *local_key = NULL;
                struct router_node *rt;

                while ((rt = avl_next_item(&on->rt_tree, &local_key)) && (local_key = rt->local_key)) {

                        if (only_useless && (rt->mr.umetric >= UMETRIC_ROUTABLE))
                                continue;

			if (onlyNeigh && (rt->local_key != onlyNeigh))
				continue;

                        if (onlyLink && (rt->local_key != onlyLink->k.linkDev->local))
                                continue;

                        if (onlyLink && (rt->best_path_link != onlyLink) && (on->curr_rt_link != onlyLink))
                                continue;

                        dbgf_track(DBGT_INFO, "only_orig=%s only_lndev=%s,%s only_useless=%d purging metric=%ju router=%s (%s)",
                                onlyOrig ? cryptShaAsString(&onlyOrig->nodeId) : DBG_NIL,
                                onlyLink ? ip6AsStr(&onlyLink->k.linkDev->link_ip):DBG_NIL,
                                onlyLink ? onlyLink->k.myDev->label_cfg.str : DBG_NIL,
                                only_useless,rt->mr.umetric,
                                cryptShaAsString(&rt->local_key->local_id),
                                rt->local_key ? cryptShaAsString(&rt->local_key->dhn->on->nodeId) : "???");

                        if (on->curr_rt_local == rt) {

                                set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_maxRcvd, on->ogmSqn_maxRcvd);

                                cb_route_change_hooks(DEL, on);
                                on->curr_rt_local = NULL;
                                on->curr_rt_link = NULL;
                        }

                        avl_remove(&on->rt_tree, &rt->local_key, -300226);

                        debugFree(rt, -300225);


                        if (onlyLink)
                                break;
                }

                if (onlyOrig)
                        break;
        }
}



void purge_linkDevs(LinkDevKey *onlyLinkDev, struct dev_node *only_dev, IDM_T only_expired)
{
        TRACE_FUNCTION_CALL;

	LinkDevNode *linkDev;
        LinkDevKey linkDevKey;
        memset(&linkDevKey, 0, sizeof(linkDevKey));
        IDM_T removed_link_adv = NO;

        dbgf_all( DBGT_INFO, "only_link_key=%s,%d only_dev=%s only_expired=%d",
                onlyLinkDev ? cryptShaAsString(&onlyLinkDev->local_id) : "---", onlyLinkDev ? onlyLinkDev->dev_idx : -1,
                only_dev ? only_dev->label_cfg.str : DBG_NIL, only_expired);

        while ((linkDev = (onlyLinkDev ? avl_find_item(&link_dev_tree, onlyLinkDev) : avl_next_item(&link_dev_tree, &linkDevKey)))) {

                struct neigh_node *local = linkDev->local;

                assertion(-500940, local);
                assertion(-500941, local == avl_find_item(&local_tree, &linkDev->key.local_id));
                assertion(-500942, linkDev == avl_find_item(&local->linkDev_tree, &linkDev->key.dev_idx));

                struct list_node *pos, *tmp, *prev = (struct list_node *) & linkDev->link_list;

                linkDevKey = linkDev->key;

                list_for_each_safe(pos, tmp, &linkDev->link_list)
                {
                        LinkNode *link = list_entry(pos, LinkNode, list);

                        if ((!only_dev || only_dev == link->k.myDev) &&
                                (!only_expired || (((TIME_T) (bmx_time - link->pkt_time_max)) > (TIME_T) link_purge_to))) {

                                dbgf_track(DBGT_INFO, "purging lndev link=%s dev=%s",
                                        ip6AsStr( &linkDev->link_ip), link->k.myDev->label_cfg.str);

                                purge_orig_router(NULL, NULL, link, NO);

                                purge_tx_task_list(link->tx_task_lists, NULL, NULL);

                                if (link->myLinkId != LINKADV_ID_IGNORED)
                                        removed_link_adv = YES; // delay update_my_link_adv() until trees are clean again!

                                if (link == local->best_link)
                                        local->best_link = NULL;

                                if (link == local->best_rp_link)
                                        local->best_rp_link = NULL;

                                if (link == local->best_tp_link)
                                        local->best_tp_link = NULL;


                                list_del_next(&linkDev->link_list, prev);
                                avl_remove(&link_tree, &link->k, -300221);
                                debugFree(link, -300044);

                        } else {
                                prev = pos;
                        }
                }

                assertion(-500323, (only_dev || only_expired || !linkDev->link_list.items));

                if (!linkDev->link_list.items) {

                        dbgf_track(DBGT_INFO, "purging: link local_id=%s link_ip=%s dev_idx=%d only_dev=%s",
                                cryptShaAsString(&linkDev->key.local_id), ip6AsStr( &linkDev->link_ip),
				linkDev->key.dev_idx, only_dev ? only_dev->label_cfg.str : "???");

                        struct avl_node *dev_avl;
                        struct dev_node *dev;
                        for(dev_avl = NULL; (dev = avl_iterate_item(&dev_ip_tree, &dev_avl));) {
                                purge_tx_task_list(dev->tx_task_lists, linkDev, NULL);
                        }

                        avl_remove(&link_dev_tree, &linkDev->key, -300193);
                        avl_remove(&local->linkDev_tree, &linkDev->key.dev_idx, -300330);

                        if (!local->linkDev_tree.items) {

                                dbgf_track(DBGT_INFO, "purging: local local_id=%s", cryptShaAsString(&linkDev->key.local_id));

				iid_purge_repos(&local->neighIID4x_repos);

				local->dhn->local = NULL;
				local->dhn = NULL;

				if (local->pktKey)
					cryptKeyFree(&local->pktKey);

                                if (local->dev_adv)
                                        debugFree(local->dev_adv, -300339);

                                if (local->link_adv)
                                        debugFree(local->link_adv, -300347);

				free_internalNeighId(local->internalNeighId);

                                assertion(-501135, (!local->orig_routes));

                                avl_remove(&local_tree, &linkDev->key.local_id, -300331);

                                debugFree(local, -300333);
                                local = NULL;
                        }

                        debugFree( linkDev, -300045 );
                }

                if (onlyLinkDev)
                        break;
        }

        lndev_assign_best(NULL, NULL);
        cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);


        if (removed_link_adv)
                update_my_link_adv(LINKADV_CHANGES_REMOVED);

	assertion(-500000, IMPLIES(!only_dev && !onlyLinkDev && !only_expired, !local_tree.items));
	assertion(-500000, IMPLIES(!only_dev && !onlyLinkDev && !only_expired, !link_tree.items));
	assertion(-500000, IMPLIES(!only_dev && !onlyLinkDev && !only_expired, !link_dev_tree.items));


}

void purge_local_node(struct neigh_node *local)
{
        TRACE_FUNCTION_CALL;

        uint16_t linkDev_tree_items = local->linkDev_tree.items;
	LinkDevNode *linkDev;

        assertion(-501015, (linkDev_tree_items));

        while (linkDev_tree_items && (linkDev = avl_first_item(&local->linkDev_tree))) {

                assertion(-501016, (linkDev_tree_items == local->linkDev_tree.items));
                purge_linkDevs(&linkDev->key, NULL, NO);
                linkDev_tree_items--;
        }

}

void block_orig_node(IDM_T block, struct orig_node *on)
{

        if (block && !on->blocked) {

                on->blocked = YES;

                if (!avl_find(&blocked_tree, &on->nodeId))
                        avl_insert(&blocked_tree, on, -300165);


        } else if (!block && on->blocked) {

                on->blocked = NO;
                avl_remove(&blocked_tree, &on->nodeId, -300201);
        }
}

void free_orig_node(struct orig_node *on)
{
        TRACE_FUNCTION_CALL;
        dbgf_sys(DBGT_INFO, "id=%s ip=%s", cryptShaAsString(&on->nodeId), on->primary_ip_str);

        //cb_route_change_hooks(DEL, on, 0, &on->ort.rt_key.llip);

/*	if (on==self)
		return;
*/
	assertion(-502180, IMPLIES(!terminating, on != self));

        purge_orig_router(on, NULL, NULL, NO);

        if (on->added) {
		assertion(-502090, (on->dhn && on->dhn->desc_frame));
                process_description_tlvs(NULL, on, on->dhn, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL);
        }

        if ( on->dhn ) {
                on->dhn->on = NULL;

                if (on->dhn->local)
			purge_local_node(on->dhn->local);

                free_dhash(on->dhn);
        }

	if (on->trustedNeighsBitArray)
		debugFree(on->trustedNeighsBitArray, -300653);

        avl_remove(&orig_tree, &on->nodeId, -300200);
        cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

        uint16_t i;
        for (i = 0; i < plugin_data_registries[PLUGIN_DATA_ORIG]; i++) {
                assertion(-501269, (!on->plugin_data[i]));
        }


        block_orig_node(NO, on);

        debugFree( on, -300086 );
}


void purge_link_route_orig_nodes(struct dev_node *only_dev, IDM_T only_expired, struct orig_node *except_on)
{
        TRACE_FUNCTION_CALL;

        dbgf_all( DBGT_INFO, "%s %s only expired",
                only_dev ? only_dev->label_cfg.str : DBG_NIL, only_expired ? " " : "NOT");

        purge_linkDevs(NULL, only_dev, only_expired);

        int i;
        for (i = IID_RSVD_MAX + 1; i < my_iid_repos.max_free; i++) {

                struct dhash_node *dhn;

                if ((dhn = my_iid_repos.arr.node[i]) && dhn->on) {

			if (dhn->on == except_on) {
				continue;

			} else if (!only_dev && (!only_expired ||
                                ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)) > (TIME_T) ogm_purge_to)) {

                                dbgf_all(DBGT_INFO, "id=%s referred before: %d > purge_to=%d",
                                        cryptShaAsString(&dhn->on->nodeId),
                                        ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)), (TIME_T) ogm_purge_to);


                                if (dhn->desc_frame && dhn->on != self)
                                        cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, dhn->on);

                                free_orig_node(dhn->on);

                        } else if (only_expired) {

                                purge_orig_router(dhn->on, NULL, NULL, YES /*only_useless*/);
                        }
                }
        }

	assertion(-500000, IMPLIES(!only_dev && !only_expired, orig_tree.items == (except_on ? 1 : 0)));
}



SHA1_T *nodeIdFromDescAdv( uint8_t *desc_adv )
{
	struct tlv_hdr tlvHdr = { .u.u16 = ntohs(((struct tlv_hdr*)desc_adv)->u.u16) };

	if (tlvHdr.u.tlv.type != BMX_DSC_TLV_RHASH )
		return NULL;

	if (tlvHdr.u.tlv.length != sizeof(struct tlv_hdr) + sizeof(struct desc_hdr_rhash) + sizeof(struct desc_msg_rhash) )
		return NULL;

	struct desc_hdr_rhash *rhashHdr = ((struct desc_hdr_rhash*)(desc_adv + sizeof(struct tlv_hdr)));

	if (rhashHdr->compression || rhashHdr->reserved || rhashHdr->expanded_type != BMX_DSC_TLV_DSC_PUBKEY)
		return NULL;

	return &rhashHdr->msg->rframe_hash;
}

char *nodeIdAsStringFromDescAdv( uint8_t *desc_adv )
{
	return cryptShaAsString(nodeIdFromDescAdv(desc_adv));
}


struct orig_node *init_orig_node(GLOBAL_ID_T *id)
{
        TRACE_FUNCTION_CALL;
        struct orig_node *on = debugMallocReset(sizeof ( struct orig_node) + (sizeof (void*) * plugin_data_registries[PLUGIN_DATA_ORIG]), -300128);
        on->nodeId = *id;

        AVL_INIT_TREE(on->rt_tree, struct router_node, local_key);

	on->trustedNeighsBitArray = init_neighTrust(on);

        avl_insert(&orig_tree, on, -300148);

        cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

        return on;
}


void init_self(void)
{
        GLOBAL_ID_T id;
	memset(&id, 0, sizeof(id));

	assertion(-502094, (my_PubKey));
	assertion(-502095, (sizeof(SHA1_T)==sizeof(id)));

	struct dsc_msg_pubkey *msg = debugMallocReset(sizeof(struct dsc_msg_pubkey) + my_PubKey->rawKeyLen, -300631);
	msg->type = my_PubKey->rawKeyType;
	memcpy(msg->key, my_PubKey->rawKey, my_PubKey->rawKeyLen);
	id = *ref_node_key((uint8_t*)msg, sizeof(struct dsc_msg_pubkey) + my_PubKey->rawKeyLen, 0, 0, 0);
	debugFree(msg, -300600);

        self = init_orig_node(&id);

        self->ogmSqn_rangeMin = ((OGM_SQN_MASK) & rand_num(OGM_SQN_MAX));
}



STATIC_FUNC
LinkDevNode *getLinkDevNode(struct dev_node *iif, IPX_T *llip, LINKADV_SQN_T link_sqn, struct dhash_node *verifiedLinkDhn, DEVADV_IDX_T dev_idx )
{
        TRACE_FUNCTION_CALL;

	assertion(-502181, (verifiedLinkDhn));

	if (dev_idx < DEVADV_IDX_MIN)
		return NULL;

	LOCAL_ID_T *local_id = &verifiedLinkDhn->on->nodeId;
        struct neigh_node *local = avl_find_item(&local_tree, local_id);

	dbgf_all(DBGT_INFO, "NB=%s local_id=%s dev_idx=0x%X", ip6AsStr(llip), cryptShaAsString(local_id), dev_idx);

	assertion(-502182, (local_id && !is_zero(local_id, sizeof(LOCAL_ID_T))));



        if (local) {
		assertion(-502183, IMPLIES(verifiedLinkDhn->local, verifiedLinkDhn->local == local));
		assertion(-502184, (cryptShasEqual(&local->local_id, &verifiedLinkDhn->on->nodeId)));
		assertion(-500517, (verifiedLinkDhn != self->dhn));
		assertion(-500390, (verifiedLinkDhn && verifiedLinkDhn->on && verifiedLinkDhn->on->dhn == verifiedLinkDhn));

                if ((((LINKADV_SQN_T) (link_sqn - local->packet_link_sqn_ref)) > LINKADV_SQN_DAD_RANGE)) {

                        dbgf_sys(DBGT_ERR, "DAD-Alert NB=%s local_id=%s dev=%s link_sqn=%d link_sqn_max=%d dad_range=%d dad_to=%d",
                                ip6AsStr(llip), cryptShaAsString(local_id), iif->label_cfg.str, link_sqn, local->packet_link_sqn_ref,
                                LINKADV_SQN_DAD_RANGE, LINKADV_SQN_DAD_RANGE * my_tx_interval);

                        purge_local_node(local);

                        assertion(-500984, (!avl_find_item(&local_tree, local_id)));

                        local = NULL;
                }
        }

	LinkDevKey linkDevKey = {.local_id = *local_id, .dev_idx = dev_idx};
	
	LinkDevNode *linkDev = NULL;

        if (local) {

                linkDev = avl_find_item(&local->linkDev_tree, &dev_idx);

                assertion(-500943, (linkDev == avl_find_item(&link_dev_tree, &linkDevKey)));

                if (linkDev && !is_ip_equal(llip, &linkDev->link_ip)) {

                        dbgf_sys(DBGT_WARN, "Reinitialized! NB=%s via dev=%s "
                                "cached llIP=%s local_id=%s dev_idx=0x%X ! Reinitializing link_node...",
                                ip6AsStr(llip), iif->label_cfg.str, ip6AsStr( &linkDev->link_ip),
                                cryptShaAsString(local_id), dev_idx);

                        purge_linkDevs(&linkDev->key, NULL, NO);
                        ASSERTION(-500213, !avl_find(&link_dev_tree, &linkDevKey));
                        linkDev = NULL;
			local = avl_find_item(&local_tree, local_id);
                }
	}

	if (!local) {

                if (local_tree.items >= LOCALS_MAX) {
                        dbgf_sys(DBGT_WARN, "max number of locals reached");
                        return NULL;
                }

                assertion(-500944, (!avl_find_item(&link_dev_tree, &linkDevKey)));
                local = debugMallocReset(sizeof(struct neigh_node), -300336);
                AVL_INIT_TREE(local->linkDev_tree, LinkDevNode, key.dev_idx);
                local->local_id = *local_id;
                local->neighLinkId = LINKADV_ID_IGNORED;
                local->myLinkId = LINKADV_ID_IGNORED;
		local->internalNeighId = allocate_internalNeighId(local);
                avl_insert(&local_tree, local, -300337);

		assertion(-502185, (!verifiedLinkDhn->local));
		local->dhn = verifiedLinkDhn;
		verifiedLinkDhn->local = local;

		struct dsc_msg_pubkey *pkey_msg = dext_dptr(verifiedLinkDhn->dext, BMX_DSC_TLV_PKT_PUBKEY);

		if (pkey_msg)
			local->pktKey = cryptPubKeyFromRaw(pkey_msg->key, cryptKeyLenByType(pkey_msg->type));

		assertion(-502186, IMPLIES(pkey_msg, local->pktKey && cryptPubKeyCheck(local->pktKey) == SUCCESS));
		assertion(-500953, (verifiedLinkDhn->local->dhn == verifiedLinkDhn));
		assertion(-500949, (local->dhn->local == local));
	}

        local->packet_link_sqn_ref = link_sqn;
        local->packet_time = bmx_time;


        if (!linkDev) {

                linkDev = debugMallocReset(sizeof (LinkDevNode), -300024);

                LIST_INIT_HEAD(linkDev->link_list, LinkNode, list, list);

                linkDev->key = linkDevKey;
                linkDev->link_ip = *llip;
                linkDev->local = local;

                avl_insert(&link_dev_tree, linkDev, -300147);
                avl_insert(&local->linkDev_tree, linkDev, -300334);

                dbgf_track(DBGT_INFO, "creating new link=%s (total %d)", ip6AsStr(llip), link_dev_tree.items);

        }

        linkDev->pkt_time_max = bmx_time;

	assertion(-502187, (local));
	assertion(-502188, (verifiedLinkDhn->local == local));
	assertion(-502189, (cryptShasEqual(&local->local_id, &verifiedLinkDhn->on->nodeId)));
        assertion(-502190, (verifiedLinkDhn != self->dhn));
        ASSERTION(-502191, (linkDev == avl_find_item(&local->linkDev_tree, &linkDev->key.dev_idx)));
        assertion(-502192, (verifiedLinkDhn && verifiedLinkDhn->on && verifiedLinkDhn->on->dhn == verifiedLinkDhn));
        assertion(-502193, (verifiedLinkDhn->local->dhn == verifiedLinkDhn));
        assertion(-502194, (local->dhn->local == local));

        return linkDev;
}



LinkNode *getLinkNode(struct dev_node *dev, IPX_T *llip, LINKADV_SQN_T link_sqn, struct dhash_node *verifiedLinkDhn, DEVADV_IDX_T dev_idx)
{
        TRACE_FUNCTION_CALL;

	assertion(-502195, (verifiedLinkDhn));

        LinkNode *link = NULL;
	LinkDevNode *linkDev = getLinkDevNode(dev, llip, link_sqn, verifiedLinkDhn, dev_idx);

	if (!linkDev)
		return NULL;

        while ((link = list_iterate(&linkDev->link_list, link))) {

                if (link->k.myDev == dev)
                        break;
        }

        if (!link) {

                link = debugMallocReset(sizeof (LinkNode), -300023);

                link->k.myDev = dev;
                link->k.linkDev = linkDev;
                link->myLinkId = LINKADV_ID_IGNORED;


                int i;
                for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {
                        LIST_INIT_HEAD(link->tx_task_lists[i], struct tx_task_node, list, list);
                }


                dbgf_track(DBGT_INFO, "creating new lndev %16s %s", ip6AsStr(&linkDev->link_ip), dev->name_phy_cfg.str);

                list_add_tail(&linkDev->link_list, &link->list);

                ASSERTION(-500489, !avl_find(&link_tree, &link->k));

                avl_insert(&link_tree, link, -300220);

                lndev_assign_best(linkDev->local, link);
                cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);

        }

	assertion(-502196, (link->k.linkDev == linkDev));

        link->pkt_time_max = bmx_time;

        return link;
}


void node_tasks(void) {

	struct orig_node *on;
	GLOBAL_ID_T id;
	memset(&id, 0, sizeof (GLOBAL_ID_T));

	purge_link_route_orig_nodes(NULL, YES, self);

	purge_deprecated_dhash_tree(NULL, YES);

	while ((on = avl_next_item(&blocked_tree, &id))) {

		id = on->nodeId;

		dbgf_all( DBGT_INFO, "trying to unblock nodeId=%s...", nodeIdAsStringFromDescAdv(on->dhn->desc_frame) );

		assertion(-501351, (on->blocked && !on->added));

		int32_t result = process_description_tlvs(NULL, on, on->dhn, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL);

		assertion(-502096, (result==TLV_RX_DATA_DONE || result==TLV_RX_DATA_BLOCKED));

		if (result == TLV_RX_DATA_DONE) {

			cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

			result = process_description_tlvs(NULL, on, on->dhn, TLV_OP_NEW, FRAME_TYPE_PROCESS_ALL);

			assertion(-500364, (result == TLV_RX_DATA_DONE)); // checked, so MUST SUCCEED!!

			cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_CREATED, on);
		}

		dbgf_track(DBGT_INFO, "unblocking nodeId=%s %s !",
			nodeIdAsStringFromDescAdv(on->dhn->desc_frame), tlv_rx_result_str(result));
	}
}

static struct opt_type node_options[]=
{
#ifndef LESS_OPTIONS
	{ODI,0,ARG_OGM_PURGE_TO,    	0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&ogm_purge_to,	MIN_OGM_PURGE_TO,	MAX_OGM_PURGE_TO,	DEF_OGM_PURGE_TO,0,	0,
			ARG_VALUE_FORM,	"timeout in ms for purging stale originators"}
        ,
	{ODI,0,ARG_LINK_PURGE_TO,    	0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&link_purge_to,	MIN_LINK_PURGE_TO,MAX_LINK_PURGE_TO,DEF_LINK_PURGE_TO,0,0,
			ARG_VALUE_FORM,	"timeout in ms for purging stale links"}
        ,
#endif
};


void init_node(void) {
        register_options_array(node_options, sizeof ( node_options), CODE_CATEGORY_NAME);

}

void cleanup_node(void) {

/*	if (self) {
		if (self->dhn) {
			self->dhn->on = NULL;
			release_dhash(self->dhn);
		}

		avl_remove(&orig_tree, &(self->nodeId), -300203);
		debugFree(self, -300386);
		self = NULL;
	}
*/
	while (status_tree.items) {
		struct status_handl *handl = avl_remove_first_item(&status_tree, -300357);
		if (handl->data)
			debugFree(handl->data, -300359);
		debugFree(handl, -300363);
	}

	purge_deprecated_dhash_tree(NULL, NO);

}