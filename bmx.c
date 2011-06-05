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

#include "bmx.h"
#include "msg.h"
#include "ip.h"
#include "schedule.h"
#include "tools.h"
#include "metrics.h"
#include "plugin.h"

#define CODE_CATEGORY_NAME "general"

int32_t drop_all_frames = DEF_DROP_ALL_FRAMES;
int32_t drop_all_packets = DEF_DROP_ALL_PACKETS;


int32_t dad_to = DEF_DAD_TO;

int32_t my_ttl = DEF_TTL;


static int32_t ogm_purge_to = DEF_OGM_PURGE_TO;

int32_t my_tx_interval = DEF_TX_INTERVAL;

int32_t my_ogm_interval = DEF_OGM_INTERVAL;   /* orginator message interval in miliseconds */

static int32_t link_purge_to = DEF_LINK_PURGE_TO;


IDM_T terminating = 0;
IDM_T initializing = YES;
IDM_T cleaning_up = NO;

static struct timeval start_time_tv;
static struct timeval curr_tv;


static RNG rng;

TIME_T bmx_time = 0;
TIME_SEC_T bmx_time_sec = 0;


uint32_t s_curr_avg_cpu_load = 0;

IDM_T my_description_changed = YES;

struct orig_node self;

LOCAL_ID_T my_local_id = LOCAL_ID_INVALID;

TIME_T my_local_id_timestamp = 0;



AVL_TREE(link_dev_tree, struct link_dev_node, key);

AVL_TREE(link_tree, struct link_node, key);

AVL_TREE(local_tree, struct local_node, local_id);
AVL_TREE(neigh_tree, struct neigh_node, nnkey);

AVL_TREE(dhash_tree, struct dhash_node, dhash);
AVL_TREE(dhash_invalid_tree, struct dhash_node, dhash);
LIST_SIMPEL( dhash_invalid_plist, struct plist_node, list, list );

AVL_TREE(orig_tree, struct orig_node, global_id);
AVL_TREE(blocked_tree, struct orig_node, global_id);

AVL_TREE(blacklisted_tree, struct black_node, dhash);

AVL_TREE(status_tree, struct status_handl, status_name);

/***********************************************************
 Data Infrastructure
 ************************************************************/




void blacklist_neighbor(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        dbgf_sys(DBGT_ERR, "%s via %s", pb->i.llip_str, pb->i.iif->label_cfg.str);

        EXITERROR(-500697, (0));
}


IDM_T blacklisted_neighbor(struct packet_buff *pb, struct description_hash *dhash)
{
        TRACE_FUNCTION_CALL;
        //dbgf_all(DBGT_INFO, "%s via %s", pb->i.neigh_str, pb->i.iif->label_cfg.str);
        return NO;
}

IDM_T equal_link_key( struct link_dev_key *a, struct link_dev_key *b )
{
        return (a->dev == b->dev && a->link == b->link);
}

IDM_T validate_param(int32_t probe, int32_t min, int32_t max, char *name)
{

        if ( probe < min || probe > max ) {

                dbgf_sys(DBGT_ERR, "Illegal %s parameter value %d ( min %d  max %d )", name, probe, min, max);

                return FAILURE;
        }

        return SUCCESS;
}


struct neigh_node *is_described_neigh( struct link_node *link, IID_T transmittersIID4x )
{
        assertion(-500730, (link));
        assertion(-500958, (link->local));
        struct neigh_node *neigh = link->local->neigh;

        if (neigh && neigh->dhn && neigh->dhn->on &&
                neigh->dhn == iid_get_node_by_neighIID4x(neigh, transmittersIID4x, YES/*verbose*/)) {

                assertion(-500938, (neigh->dhn->neigh == neigh));

                return neigh;
        }

        return NULL;
}








STATIC_FUNC
struct dhash_node* create_dhash_node(struct description_hash *dhash, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        struct dhash_node * dhn = debugMalloc(sizeof ( struct dhash_node), -300001);
        memset(dhn, 0, sizeof ( struct dhash_node));
        memcpy(&dhn->dhash, dhash, HASH_SHA1_LEN);
        avl_insert(&dhash_tree, dhn, -300142);

        dhn->myIID4orig = iid_new_myIID4x(dhn);

        on->updated_timestamp = bmx_time;
        dhn->on = on;
        on->dhn = dhn;

        dbgf_track(DBGT_INFO, "dhash %8X.. myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        return dhn;
}

STATIC_FUNC
void purge_dhash_iid(struct dhash_node *dhn)
{
        TRACE_FUNCTION_CALL;
        struct avl_node *an;
        struct neigh_node *neigh;

        //reset all neigh_node->oid_repos[x]=dhn->mid4o entries
        for (an = NULL; (neigh = avl_iterate_item(&neigh_tree, &an));) {

                iid_free_neighIID4x_by_myIID4x(&neigh->neighIID4x_repos, dhn->myIID4orig);

        }
}

STATIC_FUNC
 void purge_dhash_invalid_list( IDM_T force_purge_all ) {

        TRACE_FUNCTION_CALL;
        struct dhash_node *dhn;

        dbgf_all( DBGT_INFO, "%s", force_purge_all ? "force_purge_all" : "only_expired");

        while ((dhn = plist_get_first(&dhash_invalid_plist)) ) {

                if (force_purge_all || ((uint32_t) (bmx_time - dhn->referred_by_me_timestamp) > MIN_DHASH_TO)) {

                        dbgf_all( DBGT_INFO, "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

                        plist_del_head(&dhash_invalid_plist);
                        avl_remove(&dhash_invalid_tree, &dhn->dhash, -300194);

                        iid_free(&my_iid_repos, dhn->myIID4orig);

                        purge_dhash_iid(dhn);

                        debugFree(dhn, -300112);

                } else {
                        break;
                }
        }
}

// called to not leave blocked dhash values:
STATIC_FUNC
void free_dhash_node( struct dhash_node *dhn )
{
        TRACE_FUNCTION_CALL;
        static uint32_t blocked_counter = 1;

        dbgf(terminating ? DBGL_CHANGES : DBGL_SYS, DBGT_INFO,
                "dhash %8X myIID4orig %d", dhn->dhash.h.u32[0], dhn->myIID4orig);

        assertion(-500961, (!dhn->on));
        assertion(-500962, (!dhn->neigh));

        avl_remove(&dhash_tree, &dhn->dhash, -300195);

        purge_dhash_iid(dhn);

        // It must be ensured that I am not reusing this IID for a while, so it must be invalidated
        // but the description and its' resulting dhash might become valid again, so I give it a unique and illegal value.
        memset(&dhn->dhash, 0, sizeof ( struct description_hash));
        dhn->dhash.h.u32[(sizeof ( struct description_hash) / sizeof (uint32_t)) - 1] = blocked_counter++;

        avl_insert(&dhash_invalid_tree, dhn, -300168);
        plist_add_tail(&dhash_invalid_plist, dhn);
        dhn->referred_by_me_timestamp = bmx_time;
}


// called due to updated description, block previously used dhash:
STATIC_FUNC
void invalidate_dhash_node( struct dhash_node *dhn )
{
        TRACE_FUNCTION_CALL;

        dbgf_track(DBGT_INFO,
                "dhash %8X myIID4orig %d, my_iid_repository: used=%d, inactive=%d  min_free=%d  max_free=%d ",
                dhn->dhash.h.u32[0], dhn->myIID4orig,
                my_iid_repos.tot_used, dhash_invalid_tree.items+1, my_iid_repos.min_free, my_iid_repos.max_free);

        assertion( -500698, (!dhn->on));
        assertion( -500699, (!dhn->neigh));

        avl_remove(&dhash_tree, &dhn->dhash, -300195);

        avl_insert(&dhash_invalid_tree, dhn, -300168);
        plist_add_tail(&dhash_invalid_plist, dhn);
        dhn->referred_by_me_timestamp = bmx_time;
}


void update_neigh_dhash(struct orig_node *on, struct description_hash *dhash)
{

        struct neigh_node *neigh = NULL;

        if (on->dhn) {
                neigh = on->dhn->neigh;
                on->dhn->neigh = NULL;
                on->dhn->on = NULL;
                invalidate_dhash_node(on->dhn);
        }

        on->dhn = create_dhash_node(dhash, on);

        if (neigh) {
                neigh->dhn = on->dhn;
                on->dhn->neigh = neigh;
        }

}



STATIC_FUNC
void free_neigh_node(struct neigh_node *neigh)
{
        TRACE_FUNCTION_CALL;

        dbgf_track(DBGT_INFO, "freeing id=%s",
                neigh && neigh->dhn && neigh->dhn->on ? globalIdAsString(&neigh->dhn->on->global_id) : "---");

        assertion(-500963, (neigh));
        assertion(-500964, (neigh->dhn));
        assertion(-500965, (neigh->dhn->neigh == neigh));
        assertion(-500966, (neigh->local));
        assertion(-500967, (neigh->local->neigh == neigh));

        avl_remove(&neigh_tree, &neigh->nnkey, -300196);
        iid_purge_repos(&neigh->neighIID4x_repos);

        neigh->dhn->neigh = NULL;
        neigh->dhn = NULL;
        neigh->local->neigh = NULL;
        neigh->local = NULL;

        debugFree(neigh, -300129);
}



STATIC_FUNC
void create_neigh_node(struct local_node *local, struct dhash_node * dhn)
{
        TRACE_FUNCTION_CALL;
        assertion(-500400, (dhn && !dhn->neigh));

        struct neigh_node *neigh = debugMalloc(sizeof ( struct neigh_node), -300131);

        memset(neigh, 0, sizeof ( struct neigh_node));

        local->neigh = neigh;
        local->neigh->local = local;

        neigh->dhn = dhn;
        dhn->neigh = neigh->nnkey = neigh;
        avl_insert(&neigh_tree, neigh, -300141);
}



IDM_T update_local_neigh(struct packet_buff *pb, struct dhash_node *dhn)
{
        TRACE_FUNCTION_CALL;
        struct local_node *local = pb->i.link->local;

        dbgf_all(DBGT_INFO, "local_id=0x%X  dhn->id=%s", local->local_id, globalIdAsString(&dhn->on->desc->globalId));

        assertion(-500517, (dhn != self.dhn));
        ASSERTION(-500392, (pb->i.link == avl_find_item(&local->link_tree, &pb->i.link->key.dev_idx)));
        assertion(-500390, (dhn && dhn->on && dhn->on->dhn == dhn));

        if (!local->neigh && dhn->neigh) {

                assertion(-500956, (dhn->neigh->dhn == dhn));
                assertion(-500955, (dhn->neigh->local->neigh == dhn->neigh));

                dbgf_track(DBGT_INFO, "CHANGED link=%s -> LOCAL=%d->%d <- neighIID4me=%d <- dhn->id=%s",
                        pb->i.llip_str, dhn->neigh->local->local_id, local->local_id, dhn->neigh->neighIID4me, 
                        globalIdAsString(&dhn->on->desc->globalId));

                dhn->neigh->local->neigh = NULL;
                local->neigh = dhn->neigh;
                local->neigh->local = local;

                goto update_local_neigh_success;


        } else if (!local->neigh && !dhn->neigh) {

                create_neigh_node(local, dhn);
                
                dbgf_track(DBGT_INFO, "NEW link=%s <-> LOCAL=%d <-> NEIGHIID4me=%d <-> dhn->id=%s",
                        pb->i.llip_str, local->local_id, local->neigh->neighIID4me, 
                        globalIdAsString(&dhn->on->desc->globalId));

                goto update_local_neigh_success;


        } else if (
                dhn->neigh &&
                dhn->neigh->dhn == dhn &&
                dhn->neigh->local->neigh == dhn->neigh &&

                local->neigh &&
                local->neigh->local == local &&
                local->neigh->dhn->neigh == local->neigh
                ) {

                goto update_local_neigh_success;
        }

        dbgf_sys(DBGT_ERR, "NONMATCHING LINK=%s -> local=%d -> neighIID4me=%d -> dhn->id=%s",
                pb->i.llip_str, local->local_id,
                local->neigh ? local->neigh->neighIID4me : 0,
                local->neigh && local->neigh->dhn->on ? globalIdAsString(&local->neigh->dhn->on->global_id) : "---");
        dbgf_sys(DBGT_ERR, "NONMATCHING local=%d <- neighIID4me=%d <- DHN=%s",
                dhn->neigh && dhn->neigh->local ? dhn->neigh->local->local_id : 0,
                dhn->neigh ? dhn->neigh->neighIID4me : 0,
                globalIdAsString(&dhn->on->desc->globalId));

        if (dhn->neigh)
                free_neigh_node(dhn->neigh);

        if (local->neigh)
                free_neigh_node(local->neigh);

        return FAILURE;



update_local_neigh_success:

        assertion(-500954, (dhn->neigh));
        assertion(-500953, (dhn->neigh->dhn == dhn));
        assertion(-500952, (dhn->neigh->local->neigh == dhn->neigh));

        assertion(-500951, (local->neigh));
        assertion(-500050, (local->neigh->local == local));
        assertion(-500949, (local->neigh->dhn->neigh == local->neigh));


        return SUCCESS;
}







STATIC_FUNC
void purge_orig_router(struct orig_node *only_orig, struct link_dev_node *only_lndev, IDM_T only_useless)
{
        TRACE_FUNCTION_CALL;
        struct orig_node *on;
        struct avl_node *an = NULL;
        while ((on = only_orig) || (on = avl_iterate_item( &orig_tree, &an))) {

                struct local_node *local_key = NULL;
                struct router_node *rt;

                while ((rt = avl_next_item(&on->rt_tree, &local_key)) && (local_key = rt->local_key)) {

                        if (only_useless && (rt->mr.umetric >= UMETRIC_ROUTABLE))
                                continue;

                        if (only_lndev && (rt->local_key != only_lndev->key.link->local))
                                continue;

                        if (only_lndev && (rt->path_lndev_best != only_lndev) && (on->curr_rt_lndev != only_lndev))
                                continue;

                        dbgf_track(DBGT_INFO, "only_orig=%s only_lndev=%s,%s only_useless=%d purging metric=%ju router=%X (%s)",
                                only_orig ? globalIdAsString(&only_orig->global_id) : "---",
                                only_lndev ? ipXAsStr(af_cfg, &only_lndev->key.link->link_ip):"---",
                                only_lndev ? only_lndev->key.dev->label_cfg.str : "...",
                                only_useless,rt->mr.umetric,
                                ntohl(rt->local_key->local_id),
                                rt->local_key && rt->local_key->neigh ? globalIdAsString(&rt->local_key->neigh->dhn->on->global_id) : "???");

                        if (on->best_rt_local == rt)
                                on->best_rt_local = NULL;

                        if (on->curr_rt_local == rt) {

                                set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_maxRcvd, on->ogmSqn_maxRcvd);

                                cb_route_change_hooks(DEL, on);
                                on->curr_rt_local = NULL;
                                on->curr_rt_lndev = NULL;
                        }

                        avl_remove(&on->rt_tree, &rt->local_key, -300226);

                        debugFree(rt, -300225);


                        if (only_lndev)
                                break;
                }

                if (only_orig)
                        break;
        }
}


STATIC_FUNC
void purge_link_node(struct link_node_key *only_link_key, struct dev_node *only_dev, IDM_T only_expired)
{
        TRACE_FUNCTION_CALL;

        struct link_node *link;
        struct link_node_key link_key_it;
        memset(&link_key_it, 0, sizeof(link_key_it));
        IDM_T removed_link_adv = NO;

        dbgf_all( DBGT_INFO, "only_link_key=%X,%d only_dev=%s only_expired=%d",
                only_link_key ? ntohl(only_link_key->local_id) : 0, only_link_key ? only_link_key->dev_idx : -1,
                only_dev ? only_dev->label_cfg.str : "---", only_expired);

        while ((link = (only_link_key ? avl_find_item(&link_tree, only_link_key) : avl_next_item(&link_tree, &link_key_it)))) {

                struct local_node *local = link->local;

                assertion(-500940, local);
                assertion(-500941, local == avl_find_item(&local_tree, &link->key.local_id));
                assertion(-500942, link == avl_find_item(&local->link_tree, &link->key.dev_idx));

                struct list_node *pos, *tmp, *prev = (struct list_node *) & link->lndev_list;
                
                IDM_T removed_link_lndev = NO;

                link_key_it = link->key;

                list_for_each_safe(pos, tmp, &link->lndev_list)
                {
                        struct link_dev_node *lndev = list_entry(pos, struct link_dev_node, list);

                        if ((!only_dev || only_dev == lndev->key.dev) &&
                                (!only_expired || (((TIME_T) (bmx_time - lndev->pkt_time_max)) > (TIME_T) link_purge_to))) {

                                dbgf_track(DBGT_INFO, "purging lndev link=%s dev=%s",
                                        ipXAsStr(af_cfg, &link->link_ip), lndev->key.dev->label_cfg.str);

                                purge_orig_router(NULL, lndev, NO);

                                purge_tx_task_list(lndev->tx_task_lists, NULL, NULL);

                                if (lndev->link_adv_msg != LINKADV_MSG_IGNORED)
                                        removed_link_adv = YES; // delay update_my_link_adv() until trees are clean again!

                                if (lndev == local->best_lndev)
                                        local->best_lndev = NULL;

                                if (lndev == local->best_rp_lndev)
                                        local->best_rp_lndev = NULL;

                                if (lndev == local->best_tp_lndev)
                                        local->best_tp_lndev = NULL;


                                list_del_next(&link->lndev_list, prev);
                                avl_remove(&link_dev_tree, &lndev->key, -300221);
                                debugFree(lndev, -300044);
                                removed_link_lndev = YES;

                        } else {
                                prev = pos;
                        }
                }

                assertion(-500323, (only_dev || only_expired || !link->lndev_list.items));

                if (!link->lndev_list.items) {

                        dbgf_track(DBGT_INFO, "purging: link local_id=%X link_ip=%s dev_idx=%d only_dev=%s",
                                ntohl(link->key.local_id), ipXAsStr(af_cfg, &link->link_ip),
                                 link->key.dev_idx, only_dev ? only_dev->label_cfg.str : "???");

                        struct avl_node *dev_avl;
                        struct dev_node *dev;
                        for(dev_avl = NULL; (dev = avl_iterate_item(&dev_ip_tree, &dev_avl));) {
                                purge_tx_task_list(dev->tx_task_lists, link, NULL);
                        }

                        avl_remove(&link_tree, &link->key, -300193);
                        avl_remove(&local->link_tree, &link->key.dev_idx, -300330);

                        if (!local->link_tree.items) {

                                dbgf_track(DBGT_INFO, "purging: local local_id=%X", ntohl(link->key.local_id));

                                if (local->neigh)
                                        free_neigh_node(local->neigh);

                                if (local->dev_adv)
                                        debugFree(local->dev_adv, -300339);

                                if (local->link_adv)
                                        debugFree(local->link_adv, -300347);

                                assertion(-501135, (!local->orig_routes));

                                avl_remove(&local_tree, &link->key.local_id, -300331);

                                debugFree(local, -300333);
                                local = NULL;
                        }

                        debugFree( link, -300045 );
                }

/*
                if (local && removed_link_lndev)
                        lndev_assign_best(local, NULL);
*/

                if (only_link_key)
                        break;
        }

        lndev_assign_best(NULL, NULL);
        cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);


        if (removed_link_adv)
                update_my_link_adv(LINKADV_CHANGES_REMOVED);

}

void purge_local_node(struct local_node *local)
{
        TRACE_FUNCTION_CALL;

        uint16_t link_tree_items = local->link_tree.items;
        struct link_node *link;

        assertion(-501015, (link_tree_items));

        while (link_tree_items && (link = avl_first_item(&local->link_tree))) {

                assertion(-501016, (link_tree_items == local->link_tree.items));
                purge_link_node(&link->key, NULL, NO);
                link_tree_items--;
        }

}

void free_orig_node(struct orig_node *on)
{
        TRACE_FUNCTION_CALL;
        dbgf_all(DBGT_INFO, "id=%s ip=%s", globalIdAsString(&on->global_id), on->primary_ip_str);

        if ( on == &self)
                return;

        //cb_route_change_hooks(DEL, on, 0, &on->ort.rt_key.llip);

        purge_orig_router(on, NULL, NO);

        if (on->desc)
                cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

        if (on->desc && !on->blocked)
                process_description_tlvs(NULL, on, on->desc, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL, NULL);

        if ( on->dhn ) {
                on->dhn->on = NULL;

                if (on->dhn->neigh)
                        free_neigh_node(on->dhn->neigh);

                free_dhash_node(on->dhn);
        }

        avl_remove(&orig_tree, &on->global_id, -300200);
        cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);

        avl_remove(&blocked_tree, &on->global_id, -300201);

        if (on->desc)
                debugFree(on->desc, -300228);

        debugFree( on, -300086 );
}


void purge_link_route_orig_nodes(struct dev_node *only_dev, IDM_T only_expired)
{
        TRACE_FUNCTION_CALL;

        dbgf_all( DBGT_INFO, "%s %s only expired",
                only_dev ? only_dev->label_cfg.str : "---", only_expired ? " " : "NOT");

        purge_link_node(NULL, only_dev, only_expired);

        int i;
        for (i = IID_RSVD_MAX + 1; i < my_iid_repos.max_free; i++) {

                struct dhash_node *dhn;

                if ((dhn = my_iid_repos.arr.node[i]) && dhn->on) {

                        if (!only_dev && (!only_expired ||
                                ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)) > (TIME_T) ogm_purge_to)) {

                                dbgf_all(DBGT_INFO, "id=%s referred before: %d > purge_to=%d",
                                        globalIdAsString(&dhn->on->global_id),
                                        ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)), (TIME_T) ogm_purge_to);

                                free_orig_node(dhn->on);

                        } else if (only_expired) {

                                purge_orig_router(dhn->on, NULL, YES /*only_useless*/);
                        }
                }
        }
}


LOCAL_ID_T new_local_id(struct dev_node *dev)
{
        uint16_t tries = 0;
        LOCAL_ID_T new_local_id = LOCAL_ID_INVALID;

        if (!my_local_id_timestamp) {

                // first time we try our mac address:
                if (dev && !is_zero(&dev->mac, sizeof (dev->mac))) {

                        memcpy(&(((char*) &new_local_id)[1]), &(dev->mac.u8[3]), sizeof ( LOCAL_ID_T) - 1);
                        ((char*) &new_local_id)[0] = rand_num(255);
                }


#ifdef TEST_LINK_ID_COLLISION_DETECTION
                new_local_id = LOCAL_ID_MIN;
#endif
        }

        while (new_local_id == LOCAL_ID_INVALID && tries < LOCAL_ID_ITERATIONS_MAX) {

                new_local_id = htonl(rand_num(LOCAL_ID_MAX - LOCAL_ID_MIN) + LOCAL_ID_MIN);
                struct avl_node *an = NULL;
                struct local_node *local;
                while ((local = avl_iterate_item(&local_tree, &an))) {

                        if (new_local_id == local->local_id) {

                                tries++;

                                if (tries % LOCAL_ID_ITERATIONS_WARN == 0) {
                                        dbgf_sys(DBGT_ERR, "No free dev_id after %d trials (local_tree.items=%d, dev_ip_tree.items=%d)!",
                                                tries, local_tree.items, dev_ip_tree.items);
                                }

                                new_local_id = LOCAL_ID_INVALID;
                                break;
                        }
                }
        }

        my_local_id_timestamp = bmx_time;
        return (my_local_id = new_local_id);
}



STATIC_FUNC
struct link_node *get_link_node(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        struct link_node *link;
        dbgf_all(DBGT_INFO, "NB=%s, local_id=%X dev_idx=0x%X",
                pb->i.llip_str, ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx);

        struct local_node *local = avl_find_item(&local_tree, &pb->i.link_key.local_id);


        if (local) {

                if ((((PKT_SQN_T) (pb->i.pkt_sqn + PKT_SQN_DAD_TOLERANCE - local->packet_sqn)) > (PKT_SQN_DAD_RANGE + PKT_SQN_DAD_TOLERANCE))) {

                        if (((TIME_T) (bmx_time - local->packet_time) < (TIME_T) PKT_SQN_DAD_RANGE * my_tx_interval)) {

                                dbgf_sys(DBGT_WARN, "DAD-Alert NB=%s local_id=%X dev=%s pkt_sqn=%d pkt_sqn_max=%d dad_range=%d dad_to=%d",
                                        pb->i.llip_str, ntohl(pb->i.link_key.local_id), pb->i.iif->label_cfg.str, pb->i.pkt_sqn, local->packet_sqn,
                                        PKT_SQN_DAD_RANGE, PKT_SQN_DAD_RANGE * my_tx_interval);

                                schedule_tx_task(&pb->i.iif->dummy_lndev, FRAME_TYPE_PROBLEM_ADV, sizeof (struct msg_problem_adv),
                                        FRAME_TYPE_PROBLEM_CODE_DUP_LINK_ID, local->local_id, 0, pb->i.transmittersIID);

                                // its safer to purge the old one, otherwise we might end up with hundrets
                                //return NULL;
                        }

                        purge_local_node(local);

                        assertion(-500983, (!avl_find_item(&local_tree, &pb->i.link_key.local_id)));

                        return NULL;
                }

                if ((((LINKADV_SQN_T) (pb->i.link_sqn - local->packet_link_sqn_ref)) > LINKADV_SQN_DAD_RANGE)) {

                        dbgf_sys(DBGT_ERR, "DAD-Alert NB=%s local_id=%X dev=%s link_sqn=%d link_sqn_max=%d dad_range=%d dad_to=%d",
                                pb->i.llip_str, ntohl(pb->i.link_key.local_id), pb->i.iif->label_cfg.str, pb->i.link_sqn, local->packet_link_sqn_ref,
                                LINKADV_SQN_DAD_RANGE, LINKADV_SQN_DAD_RANGE * my_tx_interval);

                        purge_local_node(local);

                        assertion(-500984, (!avl_find_item(&local_tree, &pb->i.link_key.local_id)));

                        return NULL;
                }
        }


        link = NULL;

        if (local) {
                
                link = avl_find_item(&local->link_tree, &pb->i.link_key.dev_idx);

                assertion(-500943, (link == avl_find_item(&link_tree, &pb->i.link_key)));

                if (link && !is_ip_equal(&pb->i.llip, &link->link_ip)) {

                        if (((TIME_T) (bmx_time - link->pkt_time_max)) < (TIME_T) dad_to) {

                                dbgf_sys(DBGT_WARN,
                                        "DAD-Alert (local_id collision, this can happen)! NB=%s via dev=%s"
                                        "cached llIP=%s local_id=%X dev_idx=0x%X ! sending problem adv...",
                                        pb->i.llip_str, pb->i.iif->label_cfg.str, ipXAsStr(af_cfg, &link->link_ip),
                                        ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx);

                                // be carefull here. Errornous PROBLEM_ADVs cause neighboring nodes to cease!!!
                                //struct link_dev_node dummy_lndev = {.key ={.dev = pb->i.iif, .link = link}, .mr = {ZERO_METRIC_RECORD, ZERO_METRIC_RECORD}};

                                schedule_tx_task(&pb->i.iif->dummy_lndev, FRAME_TYPE_PROBLEM_ADV, sizeof (struct msg_problem_adv),
                                        FRAME_TYPE_PROBLEM_CODE_DUP_LINK_ID, link->key.local_id, 0, pb->i.transmittersIID);

                                // its safer to purge the old one, otherwise we might end up with hundrets
                                //return NULL;
                        }



                        dbgf_sys(DBGT_WARN, "Reinitialized! NB=%s via dev=%s "
                                "cached llIP=%s local_id=%X dev_idx=0x%X ! Reinitializing link_node...",
                                pb->i.llip_str, pb->i.iif->label_cfg.str, ipXAsStr(af_cfg, &link->link_ip),
                                ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx);

                        purge_link_node(&link->key, NULL, NO);
                        ASSERTION(-500213, !avl_find(&link_tree, &pb->i.link_key));
                        link = NULL;
                }
                
        } else {

                if (local_tree.items >= LOCALS_MAX) {
                        dbgf_sys(DBGT_WARN, "max number of locals reached");
                        return NULL;
                }

                assertion(-500944, (!avl_find_item(&link_tree, &pb->i.link_key)));
                local = debugMalloc(sizeof(struct local_node), -300336);
                memset(local, 0, sizeof(struct local_node));
                AVL_INIT_TREE(local->link_tree, struct link_node, key.dev_idx);
                local->local_id = pb->i.link_key.local_id;
                local->link_adv_msg_for_me = LINKADV_MSG_IGNORED;
                local->link_adv_msg_for_him = LINKADV_MSG_IGNORED;
                avl_insert(&local_tree, local, -300337);
        }

        local->packet_sqn = pb->i.pkt_sqn;
        local->packet_link_sqn_ref = pb->i.link_sqn;
        local->packet_time = bmx_time;


        if (!link) {

                link = debugMalloc(sizeof (struct link_node), -300024);
                memset(link, 0, sizeof (struct link_node));

                LIST_INIT_HEAD(link->lndev_list, struct link_dev_node, list, list);

                link->key = pb->i.link_key;
                link->link_ip = pb->i.llip;
                link->local = local;

                avl_insert(&link_tree, link, -300147);
                avl_insert(&local->link_tree, link, -300334);

                dbgf_track(DBGT_INFO, "creating new link=%s (total %d)", pb->i.llip_str, link_tree.items);

        }

        link->pkt_time_max = bmx_time;

        return link;
}


STATIC_FUNC
struct link_dev_node *get_link_dev_node(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;

        assertion(-500607, (pb->i.iif));

        struct link_dev_node *lndev = NULL;
        struct dev_node *dev = pb->i.iif;

        struct link_node *link = get_link_node(pb);

        if (!(pb->i.link = link))
                return NULL;


        while ((lndev = list_iterate(&link->lndev_list, lndev))) {

                if (lndev->key.dev == dev)
                        break;
        }

        if (!lndev) {

                lndev = debugMalloc(sizeof ( struct link_dev_node), -300023);

                memset(lndev, 0, sizeof ( struct link_dev_node));

                lndev->key.dev = dev;
                lndev->key.link = link;
                lndev->link_adv_msg = LINKADV_MSG_IGNORED;


                int i;
                for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {
                        LIST_INIT_HEAD(lndev->tx_task_lists[i], struct tx_task_node, list, list);
                }


                dbgf_track(DBGT_INFO, "creating new lndev %16s %s", ipXAsStr(af_cfg, &link->link_ip), dev->name_phy_cfg.str);

                list_add_tail(&link->lndev_list, &lndev->list);

                ASSERTION(-500489, !avl_find(&link_dev_tree, &lndev->key));

                avl_insert(&link_dev_tree, lndev, -300220);

                lndev_assign_best(link->local, lndev);
                cb_plugin_hooks(PLUGIN_CB_LINKS_EVENT, NULL);

        }

        lndev->pkt_time_max = bmx_time;

        return lndev;
}


void rx_packet( struct packet_buff *pb )
{
        TRACE_FUNCTION_CALL;
        assertion(-501105, (af_cfg == AF_INET || af_cfg == AF_INET6));

        struct dev_node *oif, *iif = pb->i.iif;
        
        if (drop_all_packets)
                return;

        assertion(-500841, ((iif->active && iif->if_llocal_addr)));

        if (af_cfg == AF_INET) {
                ip42X(&pb->i.llip, (*((struct sockaddr_in*)&(pb->i.addr))).sin_addr.s_addr);

        } else {
                pb->i.llip = (*((struct sockaddr_in6*) &(pb->i.addr))).sin6_addr;

                if (!is_ip_net_equal(&pb->i.llip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)) {
                        dbgf_all(DBGT_ERR, "non-link-local IPv6 source address %s", ip6Str(&pb->i.llip));
                        return;
                }
        }
        //TODO: check broadcast source!!

        struct packet_header *hdr = &pb->packet.header;
        uint16_t pkt_length = ntohs(hdr->pkt_length);
        pb->i.transmittersIID = ntohs(hdr->transmitterIID);
        pb->i.pkt_sqn = ntohl(hdr->pkt_sqn);
        pb->i.link_sqn = ntohs(hdr->link_adv_sqn);

        pb->i.link_key.dev_idx = hdr->dev_idx;
        pb->i.link_key.local_id = hdr->local_id;


        ip2Str(af_cfg, &pb->i.llip, pb->i.llip_str);

        dbgf_all(DBGT_INFO, "via %s %s %s size %d", iif->label_cfg.str, iif->ip_llocal_str, pb->i.llip_str, pkt_length);

	// immediately drop invalid packets...
	// we acceppt longer packets than specified by pos->size to allow padding for equal packet sizes
        if (    pb->i.total_length < (int) (sizeof (struct packet_header) + sizeof (struct frame_header_long)) ||
                pkt_length < (int) (sizeof (struct packet_header) + sizeof (struct frame_header_long)) ||
                hdr->bmx_version != COMPATIBILITY_VERSION ||
                pkt_length > pb->i.total_length || pkt_length > MAX_UDPD_SIZE ||
                pb->i.link_key.dev_idx < DEVADV_IDX_MIN || pb->i.link_key.local_id == LOCAL_ID_INVALID ) {

                goto process_packet_error;
        }

        if ((oif = avl_find_item(&dev_ip_tree, &pb->i.llip))) {

                ASSERTION(-500840, (oif == iif)); // so far, only unique own interface IPs are allowed!!

                if (((my_local_id != pb->i.link_key.local_id || oif->dev_adv_idx != pb->i.link_key.dev_idx) &&
                        (((TIME_T) (bmx_time - my_local_id_timestamp)) > (4 * (TIME_T) my_tx_interval))) ||
                        ((myIID4me != pb->i.transmittersIID) && (((TIME_T) (bmx_time - myIID4me_timestamp)) > (4 * (TIME_T) my_tx_interval)))) {

                        // my local_id  or myIID4me might have just changed and then, due to delay,
                        // I might receive my own packet back containing my previous (now non-matching) local_id of myIID4me
                        dbgf_sys(DBGT_ERR, "DAD-Alert (duplicate Address) from NB=%s via dev=%s "
                                "my_local_id=%X dev_idx=0x%X  rcvd local_id=%X dev_idx=0x%X  myIID4me=%d rcvdIID=%d",
                                oif->ip_llocal_str, iif->label_cfg.str,
                                ntohl(my_local_id), iif->dev_adv_idx, ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx,
                                myIID4me, pb->i.transmittersIID);

                        goto process_packet_error;
                }

                return;
        }

        if (my_local_id == pb->i.link_key.local_id) {

                if (new_local_id(NULL) == LOCAL_ID_INVALID) {
                        goto process_packet_error;
                }

                dbgf_sys(DBGT_WARN, "DAD-Alert (duplicate link ID, this can happen) via dev=%s NB=%s "
                        "is using my local_id=%X dev_idx=0x%X!  Choosing new local_id=%X dev_idx=0x%X for myself, dropping packet",
                        iif->label_cfg.str, pb->i.llip_str, ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx, ntohl(my_local_id), iif->dev_adv_idx);

                return;
        }


        if (!(pb->i.lndev = get_link_dev_node(pb)))
                return;


        dbgf_all(DBGT_INFO, "version=%i, reserved=%X, size=%i IID=%d rcvd udp_len=%d via NB %s %s %s",
                hdr->bmx_version, hdr->reserved, pkt_length, pb->i.transmittersIID,
                pb->i.total_length, pb->i.llip_str, iif->label_cfg.str, pb->i.unicast ? "UNICAST" : "BRC");


        cb_packet_hooks(pb);

        if (blacklisted_neighbor(pb, NULL))
                return;
        
        if (drop_all_frames)
                return;

        if (rx_frames(pb) == SUCCESS)
                return;


process_packet_error:

        dbgf_sys(DBGT_WARN,
                "Drop (remaining) packet: rcvd problematic packet via NB=%s dev=%s "
                "(version=%i, local_id=%X dev_idx=0x%X, reserved=0x%X, pkt_size=%i), udp_len=%d my_version=%d, max_udpd_size=%d",
                pb->i.llip_str, iif->label_cfg.str, hdr->bmx_version,
                ntohl(pb->i.link_key.local_id), pb->i.link_key.dev_idx, hdr->reserved, pkt_length, pb->i.total_length,
                COMPATIBILITY_VERSION, MAX_UDPD_SIZE);

        blacklist_neighbor(pb);

        return;
}




/***********************************************************
 Runtime Infrastructure
************************************************************/


#ifndef NO_TRACE_FUNCTION_CALLS
static char* function_call_buffer_name_array[FUNCTION_CALL_BUFFER_SIZE] = {0};
static TIME_T function_call_buffer_time_array[FUNCTION_CALL_BUFFER_SIZE] = {0};
static uint8_t function_call_buffer_pos = 0;

static void debug_function_calls(void)
{
        uint8_t i;
        for (i = function_call_buffer_pos + 1; i != function_call_buffer_pos; i = ((i+1) % FUNCTION_CALL_BUFFER_SIZE)) {

                if (!function_call_buffer_name_array[i])
                        continue;

                dbgf_sys(DBGT_ERR, "%10d %s()", function_call_buffer_time_array[i], function_call_buffer_name_array[i]);

        }
}


void trace_function_call(const char *func)
{
        if (function_call_buffer_name_array[function_call_buffer_pos] != func) {
                function_call_buffer_time_array[function_call_buffer_pos] = bmx_time;
                function_call_buffer_name_array[function_call_buffer_pos] = (char*)func;
                function_call_buffer_pos = ((function_call_buffer_pos+1) % FUNCTION_CALL_BUFFER_SIZE);
        }
}


#endif

void upd_time(struct timeval *precise_tv)
{
        static const struct timeval MAX_TV = {(((MAX_SELECT_TIMEOUT_MS + MAX_SELECT_SAFETY_MS) / 1000)), (((MAX_SELECT_TIMEOUT_MS + MAX_SELECT_SAFETY_MS) % 1000)*1000)};

        struct timeval bmx_tv, diff_tv, acceptable_max_tv, acceptable_min_tv = curr_tv;

        timeradd( &MAX_TV, &curr_tv, &acceptable_max_tv );

	gettimeofday( &curr_tv, NULL );

	if ( timercmp( &curr_tv, &acceptable_max_tv, > ) ) {

		timersub( &curr_tv, &acceptable_max_tv, &diff_tv );
		timeradd( &start_time_tv, &diff_tv, &start_time_tv );

                dbg_sys(DBGT_WARN, "critical system time drift detected: ++ca %ld s, %ld us! Correcting reference!",
		     diff_tv.tv_sec, diff_tv.tv_usec );

                if ( diff_tv.tv_sec > CRITICAL_PURGE_TIME_DRIFT )
                        purge_link_route_orig_nodes(NULL, NO);

	} else 	if ( timercmp( &curr_tv, &acceptable_min_tv, < ) ) {

		timersub( &acceptable_min_tv, &curr_tv, &diff_tv );
		timersub( &start_time_tv, &diff_tv, &start_time_tv );

                dbg_sys(DBGT_WARN, "critical system time drift detected: --ca %ld s, %ld us! Correcting reference!",
		     diff_tv.tv_sec, diff_tv.tv_usec );

                if ( diff_tv.tv_sec > CRITICAL_PURGE_TIME_DRIFT )
                        purge_link_route_orig_nodes(NULL, NO);

	}

	timersub( &curr_tv, &start_time_tv, &bmx_tv );

	if ( precise_tv ) {
		precise_tv->tv_sec = bmx_tv.tv_sec;
		precise_tv->tv_usec = bmx_tv.tv_usec;
	}

	bmx_time = ( (bmx_tv.tv_sec * 1000) + (bmx_tv.tv_usec / 1000) );
	bmx_time_sec = bmx_tv.tv_sec;
}

char *get_human_uptime(uint32_t reference)
{
	//                  DD:HH:MM:SS
	static char ut[32]="00:00:00:00";

	sprintf( ut, "%i:%i%i:%i%i:%i%i",
	         (((bmx_time_sec-reference)/86400)),
	         (((bmx_time_sec-reference)%86400)/36000)%10,
	         (((bmx_time_sec-reference)%86400)/3600)%10,
	         (((bmx_time_sec-reference)%3600)/600)%10,
	         (((bmx_time_sec-reference)%3600)/60)%10,
	         (((bmx_time_sec-reference)%60)/10)%10,
	         (((bmx_time_sec-reference)%60))%10
	       );

	return ut;
}


void wait_sec_msec(TIME_SEC_T sec, TIME_T msec)
{

        TRACE_FUNCTION_CALL;
	struct timeval time;

	//no debugging here because this is called from debug_output() -> dbg_fprintf() which may case a loop!

	time.tv_sec = sec + (msec/1000) ;
	time.tv_usec = ( msec * 1000 ) % 1000000;

	select( 0, NULL, NULL, NULL, &time );

	return;
}

static void handler(int32_t sig)
{

        TRACE_FUNCTION_CALL;
	if ( !Client_mode ) {
                dbgf_sys(DBGT_ERR, "called with signal %d", sig);
	}

	printf("\n");// to have a newline after ^C

	terminating = YES;
}





static void segmentation_fault(int32_t sig)
{
        TRACE_FUNCTION_CALL;
        static int segfault = NO;

        if (!segfault) {

                segfault = YES;

                dbg_sys(DBGT_ERR, "First SIGSEGV %d received, try cleaning up...", sig);

#ifndef NO_TRACE_FUNCTION_CALLS
                debug_function_calls();
#endif

                dbg(DBGL_SYS, DBGT_ERR, "Terminating with error code %d (%s-%s-cv%d)! Please notify a developer",
                        sig, BMX_BRANCH, BRANCH_VERSION, CODE_VERSION);

                if (initializing) {
                        dbg_sys(DBGT_ERR,
                        "check up-to-dateness of bmx libs in default lib path %s or customized lib path defined by %s !",
                        BMX_DEF_LIB_PATH, BMX_ENV_LIB_PATH);
                }

                if (!cleaning_up)
                        cleanup_all(CLEANUP_RETURN);

                dbg_sys(DBGT_ERR, "raising SIGSEGV again ...");

        } else {
                dbg(DBGL_SYS, DBGT_ERR, "Second SIGSEGV %d received, giving up! core contains second SIGSEV!", sig);
        }

        signal(SIGSEGV, SIG_DFL);
        errno=0;
	if ( raise( SIGSEGV ) ) {
		dbg_sys(DBGT_ERR, "raising SIGSEGV failed: %s...", strerror(errno) );
        }
}


void cleanup_all(int32_t status)
{
        TRACE_FUNCTION_CALL;

        if (status < 0) {
                segmentation_fault(status);
        }

        if (!cleaning_up) {

                dbgf_all(DBGT_INFO, "cleaning up (status %d)...", status);

                cleaning_up = YES;

                terminating = YES;

                // first, restore defaults...
                cb_plugin_hooks(PLUGIN_CB_TERM, NULL);


		cleanup_schedule();

                if (self.dhn) {
                        self.dhn->on = NULL;
                        free_dhash_node(self.dhn);
                }

                avl_remove(&orig_tree, &(self.global_id), -300203);

                while (status_tree.items) {
                        struct status_handl *handl = avl_first_item(&status_tree);
                        avl_remove(&status_tree, handl->status_name, -300357);
                        if (handl->data)
                                debugFree(handl->data, -300359);
                        debugFree(handl, -300363);
                }

                purge_link_route_orig_nodes(NULL, NO);

		cleanup_plugin();

		cleanup_config();

                cleanup_ip();

                purge_dhash_invalid_list(YES);


		// last, close debugging system and check for forgotten resources...

		cleanup_control();

                checkLeak();


                if (status == CLEANUP_SUCCESS)
                        exit(EXIT_SUCCESS);

                dbgf_all(DBGT_INFO, "...cleaning up done");

                if (status == CLEANUP_RETURN)
                        return;

                exit(EXIT_FAILURE);
        }
}











/***********************************************************
 Configuration data and handlers
************************************************************/



static const int32_t field_standard_sizes[FIELD_TYPE_END] = FIELD_STANDARD_SIZES;

int64_t field_get_value(const struct field_format *format, uint16_t min_msg_size, uint8_t *data, uint32_t pos_bit, uint32_t bits)
{
        uint8_t host_order = format->field_host_order;

        assertion(-501221, (format->field_type == FIELD_TYPE_UINT || format->field_type == FIELD_TYPE_HEX || format->field_type == FIELD_TYPE_STRING_SIZE));
        assertion(-501222, (bits <= 32));

        if ((bits % 8) == 0) {

                assertion(-501223, (bits == 8 || bits == 16 || bits == 32));
                assertion(-501168, ((pos_bit % 8) == 0));

                if (bits == 8) {

                        return data[pos_bit / 8];

                } else if (bits == 16) {

                        if(host_order)
                                return *((uint16_t*) & data[pos_bit / 8]);
                        else
                                return ntohs(*((uint16_t*) & data[pos_bit / 8]));

                } else if (bits == 32) {

                        if(host_order)
                                return *((uint32_t*) & data[pos_bit / 8]);
                        else
                                return ntohs(*((uint32_t*) & data[pos_bit / 8]));
                }

        } else if (bits < 8) {

                uint8_t bit = 0;
                uint8_t result = 0;

                for (bit = 0; bit < bits; bit++) {
                        uint8_t val = bit_get(data, (8 * min_msg_size), (pos_bit + bit));
                        bit_set(&result, 8, bit, val);
                }

                return result;
        }

        return FAILURE;
}

char *field_dbg_value(const struct field_format *format, uint16_t min_msg_size, uint8_t *data, uint32_t pos_bit, uint32_t bits)
{

        assertion(-501200, (format && min_msg_size && data && bits));

        uint8_t field_type = format->field_type;
        char *val = NULL;

        if (field_type == FIELD_TYPE_UINT || field_type == FIELD_TYPE_HEX || field_type == FIELD_TYPE_STRING_SIZE) {

                if (bits <= 32) {

                        static char uint32_out[ 16 ] = {0};

                        int64_t field_val = field_get_value(format, min_msg_size, data, pos_bit, bits);

                        if (format->field_type == FIELD_TYPE_HEX)
                                snprintf(uint32_out, sizeof (uint32_out), "%jX", field_val);
                        else
                                snprintf(uint32_out, sizeof (uint32_out), "%ji", field_val);

                        assertion(-501243, (strlen(uint32_out) < sizeof (uint32_out)));
                        val = uint32_out;


                } else {
                        val = memAsHexString(&data[pos_bit / 8], bits / 8);
                }

        } else if (field_type == FIELD_TYPE_IP4) {

                val = ip4AsStr(*((IP4_T*) & data[pos_bit / 8]));

        } else if (field_type == FIELD_TYPE_IPX4) {

                val =  ipXAsStr(AF_INET, (IPX_T*) & data[pos_bit / 8]);

        } else if (field_type == FIELD_TYPE_IPX6) {

                val =  ipXAsStr(AF_INET6, (IPX_T*) & data[pos_bit / 8]);

        } else if (field_type == FIELD_TYPE_IPX) {

                val = ipXAsStr(af_cfg, (IPX_T*) & data[pos_bit / 8]);

        } else if (field_type == FIELD_TYPE_MAC) {

                val = macAsStr((MAC_T*) & data[pos_bit / 8]);

        } else if (field_type == FIELD_TYPE_STRING_BINARY) {

                val =  memAsHexString(&data[pos_bit / 8], bits / 8);

        } else if (field_type == FIELD_TYPE_STRING_CHAR) {

                val = memAsCharString((char*) &data[pos_bit / 8], bits / 8);

        } else if (field_type == FIELD_TYPE_POINTER_CHAR) {

                val = memAsCharString(*((char**) (&data[pos_bit / 8])), strlen(*((char**) (&data[pos_bit / 8]))));

        } else if (field_type == FIELD_TYPE_POINTER_GLOBAL_ID) {

                val = globalIdAsString(*((GLOBAL_ID_T**) (&data[pos_bit / 8])));

        } else if (field_type == FIELD_TYPE_GLOBAL_ID) {

                val = globalIdAsString(((GLOBAL_ID_T*) (&data[pos_bit / 8])));

        } else if (field_type == FIELD_TYPE_UMETRIC) {

                val = umetric_to_human(*((UMETRIC_T*) (&data[pos_bit / 8])));
        } else {

                assertion(-501202, 0);
        }

        return val ? val : "ERROR";
}


uint32_t field_iterate(struct field_iterator *it)
{
        TRACE_FUNCTION_CALL;
        assertion(-501171, IMPLIES(it->data_size, it->data));

        const struct field_format *format;


        it->field = (it->field_bits || it->field) ? (it->field + 1) : 0;

        format = &(it->format[it->field]);

        if (format->field_type == FIELD_TYPE_END) {

                it->field = 0;
                it->msg_bit_pos += ((it->min_msg_size * 8) + it->var_bits);
                it->var_bits = 0;
                format = &(it->format[0]);
        }

        it->field_bit_pos = (format->field_pos == -1) ?
                it->field_bit_pos + it->field_bits : it->msg_bit_pos + format->field_pos;

        dbgf_all(DBGT_INFO, "field_name=%s max_data_size=%d min_msg_size=%d msg_bit_pos=%d data=%p field=%d field_bits=%d field_bit_pos=%d var_bits=%d field_type=%d field_bits=%d std_bits=%d\n",
                format->field_name, it->data_size, it->min_msg_size, it->msg_bit_pos, it->data, it->field, it->field_bits, it->field_bit_pos, it->var_bits,
                format->field_type, format->field_bits, field_standard_sizes[format->field_type]);


        if (it->msg_bit_pos + (it->min_msg_size * 8) + it->var_bits <=
                8 * (it->data_size ? it->data_size : it->min_msg_size)) {

                //printf("msg_name=%s field_name=%s\n", handl->name, format->msg_field_name);

                uint8_t field_type = format->field_type;
                uint32_t field_bits = format->field_bits ? format->field_bits : it->var_bits;
                int32_t std_bits;
                std_bits = field_standard_sizes[field_type];

                assertion(-501172, IMPLIES(field_type == FIELD_TYPE_STRING_SIZE, !it->var_bits));

                assertion(-501203, IMPLIES(field_type == FIELD_TYPE_UINT, (field_bits <= 8 || field_bits == 16 || field_bits == 32)));
                assertion(-501204, IMPLIES(field_type == FIELD_TYPE_HEX, (field_bits <= 8 || field_bits == 16 || field_bits == 32)));
                assertion(-501205, IMPLIES(field_type == FIELD_TYPE_STRING_SIZE, (field_bits <= 8 || field_bits == 16 || field_bits == 32)));

//                assertion(-501186, IMPLIES(it->fixed_msg_size && it->data_size, it->data_size % it->fixed_msg_size == 0));
//                assertion(-501187, IMPLIES(it->fixed_msg_size, field_type != FIELD_TYPE_STRING_SIZE || !format->field_bits));
//                assertion(-501188, IMPLIES(!format->field_bits && it->data_size, it->var_bits));
                assertion(-501189, IMPLIES(!format->field_bits, field_type == FIELD_TYPE_STRING_CHAR || field_type == FIELD_TYPE_STRING_BINARY));


                assertion(-501173, IMPLIES(field_bits == 0, format[1].field_type == FIELD_TYPE_END));

                assertion(-501174, (std_bits != 0));
                assertion(-501175, IMPLIES(std_bits > 0, (field_bits == (uint32_t)std_bits)));
                assertion(-501176, IMPLIES(std_bits < 0, !(field_bits % (-std_bits))));

                assertion(-501206, IMPLIES(field_bits >= 8, !(field_bits % 8)));
                assertion(-501177, IMPLIES((field_bits % 8), field_bits < 8));
                assertion(-501178, IMPLIES(!(field_bits % 8), !(it->field_bit_pos % 8)));

//                assertion(-501182, (it->min_msg_size * 8 >= it->field_bit_pos + field_bits));

                assertion(-501183, IMPLIES(it->data_size, it->min_msg_size <= it->data_size));
//                assertion(-501184, IMPLIES(it->data_size, field_bits));
                assertion(-501185, IMPLIES(it->data_size, it->field_bit_pos + field_bits  <= it->data_size * 8));

                assertion(-501190, IMPLIES(!format->field_host_order, (field_bits == 16 || field_bits == 32)));
                assertion(-501191, IMPLIES(!format->field_host_order, (field_type == FIELD_TYPE_UINT || field_type == FIELD_TYPE_HEX || field_type == FIELD_TYPE_STRING_SIZE)));

                assertion(-501192, IMPLIES((field_type == FIELD_TYPE_UINT || field_type == FIELD_TYPE_HEX || field_type == FIELD_TYPE_STRING_SIZE), field_bits <= 32));


                if (it->data_size) {

                        if (field_type == FIELD_TYPE_STRING_SIZE) {
                                int64_t var_bytes = field_get_value(format, it->min_msg_size, it->data, it->field_bit_pos, field_bits);
                                assertion(-501207, (var_bytes >= SUCCESS));
                                it->var_bits = 8 * var_bytes;
                        }

                        //msg_field_dbg(it->handl, it->field, it->data, it->pos_bit, field_bits, cn);
                }

                it->field_bits = field_bits;


                //dbgf_all(DBGT_INFO,

                return SUCCESS;
        }

        assertion(-501163, IMPLIES(!it->data_size, (it->field_bit_pos % (it->min_msg_size * 8) == 0)));
        assertion(-501164, IMPLIES(it->data_size, it->data_size * 8 == it->field_bit_pos));
        assertion(-501208, ((it->field_bit_pos % 8) == 0));

        return (it->msg_bit_pos / 8);
}

int16_t field_format_get_items(const struct field_format *format) {

        int16_t i=-1;

        while (format[++i].field_type != FIELD_TYPE_END) {
                assertion(-501244, (i < FIELD_FORMAT_MAX_ITEMS));
        }

        return i;
}

uint32_t fields_dbg_lines(struct ctrl_node *cn, uint16_t relevance, uint16_t data_size, uint8_t *data,
                          uint16_t min_msg_size, const struct field_format *format)
{
        TRACE_FUNCTION_CALL;
        assertion(-501209, format);

        uint32_t msgs_size = 0;
        struct field_iterator it = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};

        while ((msgs_size = field_iterate(&it)) == SUCCESS) {

                if (data && cn) {

                        if (format[it.field].field_relevance >= relevance) {
                                dbg_printf(cn, " %s=%s", format[it.field].field_name,
                                        field_dbg_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
                        }

                        if (format[it.field + 1].field_type == FIELD_TYPE_END)
                                dbg_printf(cn, "\n");

                }
        }

        assertion(-501210, (data_size ? msgs_size == data_size : msgs_size == min_msg_size));

        return msgs_size;
}

void fields_dbg_table(struct ctrl_node *cn, uint16_t relevance, uint16_t data_size, uint8_t *data,
                          uint16_t min_msg_size, const struct field_format *format)
{
        TRACE_FUNCTION_CALL;
        assertion(-501209, (format && data && cn));

        uint16_t field_string_sizes[FIELD_FORMAT_MAX_ITEMS] = {0};
        uint32_t columns = field_format_get_items(format);
        uint32_t rows = 1/*the headline*/, bytes_per_row = 1/*the trailing '\n' or '\0'*/;

        assertion(-501256, (columns && columns <= FIELD_FORMAT_MAX_ITEMS));

        struct field_iterator i1 = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};

        while (field_iterate(&i1) == SUCCESS) {

                if (format[i1.field].field_relevance >= relevance) {

                        char *val = field_dbg_value(&format[i1.field], min_msg_size, data, i1.field_bit_pos, i1.field_bits);

                        field_string_sizes[i1.field] = max_i32(field_string_sizes[i1.field], strlen(val));

                        if (i1.field == 0) {
                                rows++;
                                bytes_per_row = 1;
                        }

                        if (rows == 2) {
                                field_string_sizes[i1.field] =
                                        max_i32(field_string_sizes[i1.field], strlen(format[i1.field].field_name));
                        }

                        bytes_per_row += field_string_sizes[i1.field] + 1/* the separating ' '*/;
                }
        }

        char * out = debugMalloc(((rows * bytes_per_row) + 1), -300383);
        memset(out, ' ', (rows * bytes_per_row));

        uint32_t i = 0, pos = 0;

        for (i = 0; i < columns; i++) {

                if (format[i].field_relevance >= relevance) {

                        memcpy(&out[pos], format[i].field_name, strlen(format[i].field_name));
                        pos += field_string_sizes[i] + 1;

                        //dbg_printf(cn, "%s", format[i].field_name);
                        //dbg_spaces(cn, field_string_sizes[i] - strlen(format[i].field_name) + (i == columns - 1 ? 0 : 1));
                }
                if (i == columns - 1) {
                        out[pos++] = '\n';
                        //dbg_printf(cn, "\n");
                }
        }



        struct field_iterator i2 = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};
        while(field_iterate(&i2) == SUCCESS) {

                if (format[i2.field].field_relevance >= relevance) {

                        char *val = field_dbg_value(&format[i2.field], min_msg_size, data, i2.field_bit_pos, i2.field_bits);

                        memcpy(&out[pos], val, strlen(val));
                        pos += field_string_sizes[i2.field]+ (i2.field == columns - 1 ? 0 : 1);

                        //dbg_spaces(cn, field_string_sizes[i2.field] - strlen(val));
                        //dbg_printf(cn, "%s%s", val, (i2.field == columns - 1 ? "" : " "));
                }

                if (i2.field == columns - 1) {
                        out[pos++] = '\n';
                        //dbg_printf(cn, "\n");
                }
        }
        out[pos++] = '\0';
        dbg_printf(cn, "%s", out);
        debugFree(out, -300384);
}



void register_status_handl(uint16_t min_msg_size, const struct field_format* format, char *name,
                            int32_t(*creator) (struct status_handl *status_handl, void *data))
{
        struct status_handl *handl = debugMalloc(sizeof (struct status_handl), -300364);
        memset(handl, 0, sizeof (handl));

        handl->min_msg_size = min_msg_size;
        handl->format = format;
        strcpy(handl->status_name, name);
        handl->frame_creator = creator;

        assertion(-501224, !avl_find(&status_tree, &handl->status_name));
        avl_insert(&status_tree, (void*) handl, -300357);
}




struct bmx_status {
        char version[strlen(BMX_BRANCH) + strlen("-") + strlen(BRANCH_VERSION) + 1];
        uint16_t compatibility;
        uint16_t codeVersion;
        GLOBAL_ID_T *globalId;
        IPX_T primaryIp;
        LOCAL_ID_T myLocalId;
        char *uptime;
        char cpu[6];
        uint16_t nodes;
};

static const struct field_format bmx_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, version,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              bmx_status, compatibility, 1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              bmx_status, codeVersion,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, bmx_status, globalId,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               bmx_status, primaryIp,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_BINARY,     bmx_status, myLocalId,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      bmx_status, uptime,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, cpu,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              bmx_status, nodes,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t bmx_status_creator(struct status_handl *handl, void *data)
{
        struct bmx_status *status = (struct bmx_status *) (handl->data = debugRealloc(handl->data, sizeof (struct bmx_status), -300365));
        sprintf(status->version, "%s-%s", BMX_BRANCH, BRANCH_VERSION);
        status->compatibility = COMPATIBILITY_VERSION;
        status->codeVersion = CODE_VERSION;
        status->globalId = &self.global_id;
        status->primaryIp = self.primary_ip;
        status->myLocalId = my_local_id;
        status->uptime = get_human_uptime(0);
        sprintf(status->cpu, "%d.%1d", s_curr_avg_cpu_load / 10, s_curr_avg_cpu_load % 10);
        status->nodes = orig_tree.items;
        return sizeof (struct bmx_status);
}






struct link_status {
        GLOBAL_ID_T *globalId;
        IPX_T llocalIp;
        IFNAME_T viaDev;
        uint8_t rxRate;
        uint8_t bestRxLink;
        uint8_t txRate;
        uint8_t bestTxLink;
        uint8_t routes;
        uint8_t wantsOgms;
        DEVADV_IDX_T myDevIdx;
        DEVADV_IDX_T nbDevIdx;
        HELLO_SQN_T lastHelloSqn;
        TIME_T lastHelloAdv;

        LOCAL_ID_T nbLocalId;
        IID_T nbIid4Me;
        uint8_t linkAdv4Him;
        uint8_t linkAdv4Me;
        DEVADV_SQN_T devAdvSqn;
        DEVADV_SQN_T devAdvSqnDiff;
        LINKADV_SQN_T linkAdvSqn;
        LINKADV_SQN_T linkAdvSqnDiff;
        TIME_T lastLinkAdv;
};

static const struct field_format link_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, link_status, globalId,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               link_status, llocalIp,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       link_status, viaDev,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, rxRate,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, bestRxLink,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, txRate,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, bestTxLink,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, routes,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, wantsOgms,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, myDevIdx,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, nbDevIdx,         1, FIELD_RELEVANCE_MEDI),

        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, lastHelloSqn,     1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, lastHelloAdv,     1, FIELD_RELEVANCE_MEDI),

        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_BINARY,     link_status, nbLocalId,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, nbIid4Me,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, linkAdv4Him,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, linkAdv4Me,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, devAdvSqn,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, devAdvSqnDiff,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, linkAdvSqn,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, linkAdvSqnDiff,   1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              link_status, lastLinkAdv,      1, FIELD_RELEVANCE_MEDI),

        FIELD_FORMAT_END
};

static int32_t link_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *link_it, *local_it;
        struct link_node *link;
        struct local_node *local;
        uint32_t max_size = link_dev_tree.items * sizeof (struct link_status);
        uint32_t i = 0;

        struct link_status *status = ((struct link_status*) (handl->data = debugRealloc(handl->data, max_size, -300358)));
        memset(status, 0, max_size);

        for (local_it = NULL; (local = avl_iterate_item(&local_tree, &local_it));) {

                struct orig_node *on = local->neigh ? local->neigh->dhn->on : NULL;

                for (link_it = NULL; on && (link = avl_iterate_item(&local->link_tree, &link_it));) {
                        struct link_dev_node *lndev = NULL;

                        while ((lndev = list_iterate(&link->lndev_list, lndev))) {

                                status[i].globalId = &on->global_id;
                                status[i].llocalIp = link->link_ip;
                                status[i].viaDev = lndev->key.dev->label_cfg;
                                status[i].rxRate = ((lndev->timeaware_rx_probe * 100) / UMETRIC_MAX);
                                status[i].bestRxLink = (lndev == local->best_rp_lndev);
                                status[i].txRate = ((lndev->timeaware_tx_probe * 100) / UMETRIC_MAX);
                                status[i].bestTxLink = (lndev == local->best_tp_lndev);
                                status[i].routes = (lndev == local->best_rp_lndev) ? local->orig_routes : 0;
                                status[i].wantsOgms = (lndev == local->best_rp_lndev) ? local->rp_ogm_request_rcvd : 0;
                                status[i].myDevIdx = lndev->key.dev->dev_adv_idx;
                                status[i].nbDevIdx = link->key.dev_idx;
                                status[i].lastHelloSqn = link->hello_sqn_max;
                                status[i].lastHelloAdv = ((TIME_T) (bmx_time - link->hello_time_max)) / 1000;

                                status[i].nbLocalId = link->key.local_id;
                                status[i].nbIid4Me = local->neigh ? local->neigh->neighIID4me : 0;
                                status[i].linkAdv4Him = local->link_adv_msg_for_him;
                                status[i].linkAdv4Me = local->link_adv_msg_for_me;
                                status[i].devAdvSqn = local->dev_adv_sqn;
                                status[i].devAdvSqnDiff = ((DEVADV_SQN_T) (local->link_adv_dev_sqn_ref - local->dev_adv_sqn));
                                status[i].linkAdvSqn = local->link_adv_sqn;
                                status[i].linkAdvSqnDiff = ((LINKADV_SQN_T) (local->packet_link_sqn_ref - local->link_adv_sqn));
                                status[i].lastLinkAdv = ((TIME_T) (bmx_time - local->link_adv_time)) / 1000;

                                i++;
                                assertion(-501225, (max_size >= i * sizeof (struct link_status)));
                        }
                }
        }

        return i * sizeof (struct link_status);
}





struct orig_status {
        GLOBAL_ID_T *globalId;
        uint8_t blocked;
        IPX_T primaryIp;
        uint16_t routes;
        IPX_T viaIp;
        char *viaDev;
        UMETRIC_T metric;
        IID_T myIid4x;
        DESC_SQN_T descSqn;
        OGM_SQN_T ogmSqn;
        OGM_SQN_T ogmSqnDiff;
        uint16_t lastDesc;
        uint16_t lastRef;
};

static const struct field_format orig_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, orig_status, globalId,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, blocked,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               orig_status, primaryIp,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, routes,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               orig_status, viaIp,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      orig_status, viaDev,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           orig_status, metric,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, myIid4x,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, descSqn,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, ogmSqn,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, ogmSqnDiff,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, lastDesc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, lastRef,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t orig_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *it = NULL;
        struct orig_node *on = data;
        uint32_t status_size = (data ? 1 : orig_tree.items) * sizeof (struct orig_status);
        uint32_t i = 0;
        struct orig_status *status = ((struct orig_status*) (handl->data = debugRealloc(handl->data, status_size, -300366)));
        memset(status, 0, status_size);

        while (data ? (on = data) : (on = avl_iterate_item(&orig_tree, &it))) {
                status[i].globalId = &on->global_id;
                status[i].blocked = on->blocked;
                status[i].primaryIp = on->primary_ip;
                status[i].routes = on->rt_tree.items;
                status[i].viaIp = (on->curr_rt_lndev ? on->curr_rt_lndev->key.link->link_ip : ZERO_IP);
                status[i].viaDev = on->curr_rt_lndev && on->curr_rt_lndev->key.dev ? on->curr_rt_lndev->key.dev->name_phy_cfg.str : "";
                status[i].metric = (on->curr_rt_local ? (on->curr_rt_local->mr.umetric) : (on == &self ? UMETRIC_MAX : 0));
                status[i].myIid4x = on->dhn->myIID4orig;
                status[i].descSqn = on->descSqn;
                status[i].ogmSqn = on->ogmSqn_next;
                status[i].ogmSqnDiff = (on->ogmSqn_maxRcvd - on->ogmSqn_next);
                status[i].lastDesc = (bmx_time - on->updated_timestamp) / 1000;
                status[i].lastRef = (bmx_time - on->dhn->referred_by_me_timestamp) / 1000;
                i++;
                if(data)
                        break;
        }
        return status_size;
}


STATIC_FUNC
int32_t opt_version(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd != OPT_APPLY )
		return SUCCESS;

        assertion(-501257, !strcmp(opt->long_name, ARG_VERSION));

        dbg_printf(cn, "%s-%s compatibility=%d codeVersion=%d\n",
                        BMX_BRANCH, BRANCH_VERSION, COMPATIBILITY_VERSION, CODE_VERSION);

        if (initializing)
                cleanup_all(CLEANUP_SUCCESS);

        return SUCCESS;
 }

STATIC_FUNC
int32_t opt_status(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if ( cmd == OPT_APPLY ) {


                struct status_handl *handl = NULL;
                uint32_t data_len;
                char status_name[sizeof (handl->status_name)] = {0};
                strcpy(status_name, opt->long_name);

                int32_t relevance = DEF_RELEVANCE;
                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->c_opt->long_name, ARG_RELEVANCE)) {
                                relevance = strtol(c->c_val, NULL, 10);
                        }
		}


                if ((handl = avl_find_item(&status_tree, status_name)) && (data_len = ((*(handl->frame_creator))(handl, NULL)))) {

                        dbg_printf(cn, "%s:\n", handl->status_name);
                        fields_dbg_table(cn, relevance, data_len, handl->data, handl->min_msg_size, handl->format);
                }
	}

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_purge(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY)
                purge_link_route_orig_nodes(NULL, NO);

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_update_description(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY )
		my_description_changed = YES;

	return SUCCESS;
}



static struct opt_type bmx_options[]=
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	{ODI,0,ARG_VERSION,		'v',0,A_PS0,A_USR,A_DYI,A_ARG,A_END,	0,		0, 		0,		0,0, 		opt_version,
			0,		"show version"},

	{ODI,0,ARG_STATUS,		0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show status\n"},

/*
	{ODI,0,ARG_ROUTES,		0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show routes\n"},
*/

	{ODI,0,ARG_INTERFACES,	        0,  5,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show interfaces\n"}
        ,
	{ODI,0,ARG_LINKS,		0,  5,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show links\n"},
	{ODI,ARG_LINKS,ARG_RELEVANCE,   'r',5,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,	0,	       MIN_RELEVANCE,   MAX_RELEVANCE,  DEF_RELEVANCE,0, opt_status,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
        ,
	{ODI,0,ARG_ORIGINATORS,	        0,  5,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show originators\n"},
	{ODI,ARG_ORIGINATORS,ARG_RELEVANCE,'r',5,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,	0,	       MIN_RELEVANCE,   MAX_RELEVANCE,  DEF_RELEVANCE,0, opt_status,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
        ,
	{ODI,0,ARG_TTL,			't',5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_ttl,	MIN_TTL,	MAX_TTL,	DEF_TTL,0,	opt_update_description,
			ARG_VALUE_FORM,	"set time-to-live (TTL) for OGMs"}
        ,
        {ODI,0,ARG_TX_INTERVAL,         0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_tx_interval, MIN_TX_INTERVAL, MAX_TX_INTERVAL, DEF_TX_INTERVAL,0, opt_update_description,
			ARG_VALUE_FORM,	"set aggregation interval (SHOULD be smaller than the half of your and others OGM interval)"}
        ,
        {ODI,0,ARG_OGM_INTERVAL,        'o',5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_ogm_interval,  MIN_OGM_INTERVAL,   MAX_OGM_INTERVAL,   DEF_OGM_INTERVAL,0,   0,
			ARG_VALUE_FORM,	"set interval in ms with which new originator message (OGM) are send"}
        ,
	{ODI,0,ARG_OGM_PURGE_TO,    	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&ogm_purge_to,	MIN_OGM_PURGE_TO,	MAX_OGM_PURGE_TO,	DEF_OGM_PURGE_TO,0,	0,
			ARG_VALUE_FORM,	"timeout in ms for purging stale originators"}
        ,
	{ODI,0,ARG_LINK_PURGE_TO,    	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&link_purge_to,	MIN_LINK_PURGE_TO,MAX_LINK_PURGE_TO,DEF_LINK_PURGE_TO,0,0,
			ARG_VALUE_FORM,	"timeout in ms for purging stale originators"}
        ,
	{ODI,0,ARG_DAD_TO,        	0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&dad_to,	MIN_DAD_TO,	MAX_DAD_TO,	DEF_DAD_TO,0,	0,
			ARG_VALUE_FORM,	"duplicate address (DAD) detection timout in ms"}
        ,
	{ODI,0,"flush_all",		0,  5,A_PS0,A_ADM,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_purge,
			0,		"purge all neighbors and routes on the fly"}
        ,
	{ODI,0,ARG_DROP_ALL_FRAMES,     0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&drop_all_frames,	MIN_DROP_ALL_FRAMES,	MAX_DROP_ALL_FRAMES,	DEF_DROP_ALL_FRAMES,0,	0,
			ARG_VALUE_FORM,	"drop all received frames (but process packet header)"}
        ,
	{ODI,0,ARG_DROP_ALL_PACKETS,     0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&drop_all_packets,	MIN_DROP_ALL_PACKETS,	MAX_DROP_ALL_PACKETS,	DEF_DROP_ALL_PACKETS,0,	0,
			ARG_VALUE_FORM,	"drop all received packets"}

};


char *globalIdAsString( struct GLOBAL_ID *id ) {


        if ( id ) {
                uint8_t i;
#define MAX_IDS_PER_PRINTF 4
                static char id_str[MAX_IDS_PER_PRINTF][GLOBAL_ID_NAME_LEN + strlen(".") + (GLOBAL_ID_PKID_LEN * 2) + 1];
                static uint8_t a = 0;

                a = (a + 1) % MAX_IDS_PER_PRINTF;

                for (i = 0; !id->pkid.u8[i] && i < GLOBAL_ID_PKID_LEN; i++);

                snprintf(id_str[a], GLOBAL_ID_NAME_LEN, "%s.%s",
                        validate_name_string(id->name, GLOBAL_ID_NAME_LEN) == SUCCESS ? id->name : "ILLEGAL_HOSTNAME",
                        memAsHexString(&(id->pkid.u8[i]), GLOBAL_ID_PKID_LEN - i));

                return id_str[a];
        }

        return NULL;
}


void init_orig_node(struct orig_node *on, GLOBAL_ID_T *id)
{
        TRACE_FUNCTION_CALL;
        memset(on, 0, sizeof ( struct orig_node));
        on->global_id = *id;

        AVL_INIT_TREE(on->rt_tree, struct router_node, local_key);

        avl_insert(&orig_tree, on, -300148);

        cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);
}


STATIC_FUNC
void init_bmx(void)
{

        static uint8_t my_desc0[MAX_PKT_MSG_SIZE];
        static GLOBAL_ID_T id;
        memset(&id, 0, sizeof (id));

        if (gethostname(id.name, GLOBAL_ID_NAME_LEN))
                cleanup_all(-500240);

        id.name[GLOBAL_ID_NAME_LEN - 1] = 0;

        if (validate_name_string(id.name, GLOBAL_ID_NAME_LEN) == FAILURE) {
                dbg_sys(DBGT_ERR, "illegal hostname %s", id.name);
                cleanup_all(-500272);
        }

        RNG_GenerateBlock(&rng, &(id.pkid.u8[GLOBAL_ID_PKID_RAND_POS]), GLOBAL_ID_PKID_RAND_LEN);

        init_orig_node(&self, &id);

        self.desc = (struct description *) my_desc0;


        self.ogmSqn_rangeMin = ((OGM_SQN_MASK) & rand_num(OGM_SQN_MAX));

        self.descSqn = ((DESC_SQN_MASK) & rand_num(DESC_SQN_MAX));

        register_options_array(bmx_options, sizeof ( bmx_options), CODE_CATEGORY_NAME);

        register_status_handl(sizeof (struct bmx_status), bmx_status_format, ARG_STATUS, bmx_status_creator);
        register_status_handl(sizeof (struct link_status), link_status_format, ARG_LINKS, link_status_creator);
        //register_status_handl(sizeof (struct local_status), local_status_format, ARG_LOCALS, locals_status_creator);
        register_status_handl(sizeof (struct orig_status), orig_status_format, ARG_ORIGINATORS, orig_status_creator);
}




STATIC_FUNC
void bmx(void)
{

        struct avl_node *an;
	struct dev_node *dev;
	TIME_T frequent_timeout, seldom_timeout;

	TIME_T s_last_cpu_time = 0, s_curr_cpu_time = 0;

	frequent_timeout = seldom_timeout = bmx_time;

        update_my_description_adv();

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {
                if (dev->linklayer == TYP_DEV_LL_LO)
                        continue;

                schedule_tx_task(&dev->dummy_lndev, FRAME_TYPE_DEV_ADV, SCHEDULE_UNKNOWN_MSGS_SIZE, 0, 0, 0, 0);
                schedule_tx_task(&dev->dummy_lndev, FRAME_TYPE_DESC_ADV, ntohs(self.desc->extensionLen) + sizeof ( struct msg_description_adv), 0, 0, myIID4me, 0);
        }

        initializing = NO;

        while (!terminating) {

		TIME_T wait = task_next( );

		if ( wait )
			wait4Event( MIN( wait, MAX_SELECT_TIMEOUT_MS ) );

                if (my_description_changed)
                        update_my_description_adv();

		// The regular tasks...
		if ( U32_LT( frequent_timeout + 1000,  bmx_time ) ) {

			// check for changed interface konfigurations...
                        for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));) {

				if ( dev->active )
                                        sysctl_config( dev );

                        }


			close_ctrl_node( CTRL_CLEANUP, NULL );

/*
	                struct list_node *list_pos;
			list_for_each( list_pos, &dbgl_clients[DBGL_ALL] ) {

				struct ctrl_node *cn = (list_entry( list_pos, struct dbgl_node, list ))->cn;

				dbg_printf( cn, "------------------ DEBUG ------------------ \n" );

				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_STATUS ), 0, cn );
				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_LINKS ), 0, cn );
				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_LOCALS ), 0, cn );
                                check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_ORIGINATORS ), 0, cn );
				dbg_printf( cn, "--------------- END DEBUG ---------------\n" );
			}
*/

			/* preparing the next debug_timeout */
			frequent_timeout = bmx_time;
		}


		if ( U32_LT( seldom_timeout + 5000, bmx_time ) ) {

                        struct orig_node *on;
                        GLOBAL_ID_T id;
                        memset(&id, 0, sizeof (GLOBAL_ID_T));

                        purge_link_route_orig_nodes(NULL, YES);

                        purge_dhash_invalid_list(NO);

                        while ((on = avl_next_item(&blocked_tree, &id))) {

                                id = on->global_id;

                                dbgf_all( DBGT_INFO, "trying to unblock %s...", on->desc->globalId.name);

                                IDM_T tlvs_res;
                                if ((tlvs_res = process_description_tlvs
                                        (NULL, on, on->desc, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL, NULL)) ==
                                        TLV_RX_DATA_DONE) {

                                        tlvs_res = process_description_tlvs
                                                (NULL, on, on->desc, TLV_OP_ADD, FRAME_TYPE_PROCESS_ALL, NULL);

                                        assertion(-500364, (tlvs_res == TLV_RX_DATA_DONE)); // checked, so MUST SUCCEED!!
                                }

                                dbgf_track(DBGT_INFO, "unblocking %s %s !",
                                        on->desc->globalId.name, tlvs_res == TLV_RX_DATA_DONE ? "success" : "failed");

                        }

			// check for corrupted memory..
			checkIntegrity();


			/* generating cpu load statistics... */
			s_curr_cpu_time = (TIME_T)clock();
			s_curr_avg_cpu_load = ( (s_curr_cpu_time - s_last_cpu_time) / (TIME_T)(bmx_time - seldom_timeout) );
			s_last_cpu_time = s_curr_cpu_time;

			seldom_timeout = bmx_time;
		}
	}
}



int main(int argc, char *argv[])
{
        // make sure we are using compatible description0 sizes:
        assertion(-500201, (MSG_DESCRIPTION0_ADV_SIZE == sizeof ( struct msg_description_adv)));
        assertion(-500996, (sizeof (FMETRIC_U16_T) == 2));
        assertion(-500997, (sizeof (FMETRIC_U8_T) == 1));
        assertion(-500998, (sizeof(struct frame_header_short) == 2));
        assertion(-500999, (sizeof(struct frame_header_long) == 4));


	gettimeofday( &start_time_tv, NULL );
        curr_tv = start_time_tv;

	upd_time( NULL );

	My_pid = getpid();


        if ( InitRng(&rng) != 0 ) {
                cleanup_all( -500525 );
        }

        unsigned int random;

        RNG_GenerateBlock(&rng, (byte*)&random, sizeof (random));

	srand( random );


	signal( SIGINT, handler );
	signal( SIGTERM, handler );
	signal( SIGPIPE, SIG_IGN );
	signal( SIGSEGV, segmentation_fault );

        init_tools();

	init_control();

        init_ip();

	init_bmx();

	//init_schedule();

        init_avl();


        if (init_plugin() == SUCCESS) {

                activate_plugin((msg_get_plugin()), NULL, NULL);

                activate_plugin((metrics_get_plugin()), NULL, NULL);

                struct plugin * hna_get_plugin(void);
                activate_plugin((hna_get_plugin()), NULL, NULL);

#ifndef NO_TRAFFIC_DUMP
                struct plugin * dump_get_plugin(void);
                activate_plugin((dump_get_plugin()), NULL, NULL);
#endif


#ifdef BMX6_TODO

#ifndef	NO_VIS
                activate_plugin((vis_get_plugin_v1()), NULL, NULL);
#endif

#ifndef	NO_TUNNEL
                activate_plugin((tun_get_plugin_v1()), NULL, NULL);
#endif

#ifndef	NO_SRV
                activate_plugin((srv_get_plugin_v1()), NULL, NULL);
#endif

#endif

        } else {
                assertion(-500809, (0));
        }


	apply_init_args( argc, argv );

        bmx();

	cleanup_all( CLEANUP_SUCCESS );

	return -1;
}


