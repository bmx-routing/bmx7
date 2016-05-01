/*
 * Copyright (c) 2013  Axel Neumann
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

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "ip.h"
#include "hna.h"
#include "tun.h"
#include "redist.h"
#include "schedule.h"
#include "plugin.h"
#include "prof.h"
#include "tools.h"
#include "iptools.h"
#include "allocate.h"


void redist_dbg(int8_t dbgl, int8_t dbgt, const char *func, struct redist_in_node *zrn, char* misc1, char* misc2)
{
        dbgf(dbgl, dbgt, "%s %s %s old=%d cnt=%d %s route=%s via=%s proto=%d table=%d ifidx=%d metric=%d distance=%d flags=%X message=%X",
                func, misc1, misc2, zrn->old, zrn->cnt,
                (zrn->cnt < 0) ? "INVALID" : (zrn->old != (!!zrn->cnt)) ? "CHANGED" : "UNCHANGED",
                netAsStr(&zrn->k.net), ipXAsStr(zrn->k.net.af, &zrn->k.via),
		zrn->k.proto_type, zrn->k.table, zrn->k.ifindex, zrn->metric, zrn->distance, zrn->flags, zrn->message);
}


void update_tunXin6_net_adv_list(struct avl_tree *redist_out_tree, struct tunXin6_net_adv_node **tunXin6_net_adv_list )
{

	prof_start(update_tunXin6_net_adv_list, main);
	dbgf_track(DBGT_INFO, "redist changed");

	struct avl_node *ran = NULL;
	struct redist_out_node *routn;
	struct tunXin6_net_adv_node *p = (*tunXin6_net_adv_list = debugRealloc(*tunXin6_net_adv_list, redist_out_tree->items * sizeof(struct tunXin6_net_adv_node), -300790));


	for (;(routn = avl_iterate_item(redist_out_tree, &ran)); p++) {
		memset(p, 0, sizeof (*p));
		p->more = (ran->right ? YES : NO);
		p->af = routn->k.net.af;
		p->adv.bandwidth = routn->k.bandwidth;
		p->adv.proto_type = routn->k.proto_type;
		p->adv.network = routn->k.net.ip;
		p->adv.networkLen = routn->k.net.mask;
		p->tunInDev = strlen(routn->k.tunInDev.str) ? routn->k.tunInDev.str : NULL;
	}

	my_description_changed = YES;
	prof_stop();
}

STATIC_FUNC
void redist_rm_overlapping(struct avl_tree *redist_out_tree)
{
	prof_start(redist_rm_overlapping, redistribute_routes);

        dbgf_track(DBGT_INFO, " ");

        struct redist_out_node *routn;
        struct avl_node *an = NULL;

        while ((routn = avl_iterate_item(redist_out_tree, &an))) {

                if (!routn->new)
                        continue;

                // find overlapping route entry:
                if (routn->minAggregatePrefixLen != MAX_REDIST_AGGREGATE) {
                        struct redist_out_node *ovlp = NULL;
                        struct redist_out_node t = {.k =
                                {.bandwidth = routn->k.bandwidth, .tunInDev = routn->k.tunInDev,
				.proto_type = routn->k.proto_type, .net = {.af = routn->k.net.af}}};

                        while ((ovlp = avl_next_item(redist_out_tree, ovlp ? &ovlp->k : &t.k))) {

                                dbgf_all(DBGT_INFO, "checking overlapping net=%s rtype=%d bw=%d tunIndev=%s, min=%d new=%d in favor of net=%s rtype=%d bw=%d tunInDev=%s min=%d new=%d",
                                        netAsStr(&routn->k.net), routn->k.proto_type, routn->k.bandwidth.val.u8, routn->k.tunInDev.str, routn->minAggregatePrefixLen, routn->new,
                                        netAsStr(&ovlp->k.net), ovlp->k.proto_type, ovlp->k.bandwidth.val.u8, ovlp->k.tunInDev.str, ovlp->minAggregatePrefixLen, ovlp->new);

                                if (memcmp(&ovlp->k.tunInDev, &routn->k.tunInDev, sizeof(IFNAME_T)) ||
					ovlp->k.bandwidth.val.u8 != routn->k.bandwidth.val.u8 ||
                                        ovlp->k.proto_type != routn->k.proto_type ||
                                        ovlp->k.net.af != routn->k.net.af ||
                                        ovlp->k.net.mask >= routn->k.net.mask)
                                        break;

                                if (!ovlp->new || ovlp->k.net.mask < routn->minAggregatePrefixLen)
                                        continue;

                                if (is_ip_net_equal(&ovlp->k.net.ip, &routn->k.net.ip, ovlp->k.net.mask, routn->k.net.af)) {
                                        routn->new = 0;
                                        ovlp->minAggregatePrefixLen = XMAX(ovlp->minAggregatePrefixLen, routn->minAggregatePrefixLen);
                                        dbgf_all(DBGT_INFO, "disable overlapping net=%s in favor of net=%s",
                                                netAsStr(&routn->k.net), netAsStr(&ovlp->k.net));
                                        break;
                                }
                        }
                }
        }

	prof_stop();
}

STATIC_FUNC
void redist_rm_aggregatable(struct avl_tree *redist_out_tree)
{
	prof_start(redist_rm_aggregatable, redistribute_routes);

        struct redist_out_node *r1;
        struct avl_node *an = NULL;

        struct redist_out_node rtn;
        memset(&rtn, 0, sizeof (rtn));

        uint8_t more = YES;

        while (more) {

                dbgf_track(DBGT_INFO, " ");

                more = NO;

                while ((r1 = avl_iterate_item(redist_out_tree, &an))) {

                        uint8_t v4 = (r1->k.net.af == AF_INET);
                        uint8_t b1 = bit_get((uint8_t*)&(r1->k.net.ip), 128, r1->k.net.mask + (v4 ? 96 : 0) - 1);

                        dbgf_all(DBGT_INFO, "checking aggregation for net=%s rtype=%d bw=%d tunInDev=%s min=%d new=%d lastBit=%d %s",
                                netAsStr(&r1->k.net), r1->k.proto_type, r1->k.bandwidth.val.u8, r1->k.tunInDev.str, r1->minAggregatePrefixLen,
                                r1->new, b1, memAsHexStringSep(&r1->k.net.ip, 16, 2, NULL));

                        if (!r1->new || !r1->k.net.mask || r1->k.net.mask <= r1->minAggregatePrefixLen || !b1)
                                continue;


                        struct redist_out_node s0 = *r1;
                        bit_set((uint8_t*)&(s0.k.net.ip), 128, s0.k.net.mask + (v4 ? 96 : 0) - 1, 0);

                        struct redist_out_node *r0 = avl_find_item(redist_out_tree, &s0.k);

                        dbgf_all(DBGT_INFO, "                    with net=%s rtype=%d bw=%d tunInDev=%s min=%d new=%d %s",
                                netAsStr(&s0.k.net), s0.k.proto_type, s0.k.bandwidth.val.u8, s0.k.tunInDev.str, s0.minAggregatePrefixLen,
                                s0.new, memAsHexStringSep(&s0.k.net.ip, 16, 2, NULL));

                        if (r0 && r0->new && r0->k.net.mask > r0->minAggregatePrefixLen) {

                                struct redist_out_node *ra;

                                s0.k.net.mask--;

                                if ((ra = avl_find_item(redist_out_tree, &s0.k))) {
                                        assertion(-501426, (!ra->new));
                                } else {
                                        ra = debugMalloc(sizeof (s0), -300503);
                                        *ra = s0;
                                        avl_insert(redist_out_tree, ra, -300504);
                                }

                                ra->new = 1;
                                r0->new = 0;
                                r1->new = 0;
                                ra->minAggregatePrefixLen = XMAX(r0->minAggregatePrefixLen, r1->minAggregatePrefixLen);
                                more = YES;

                                dbgf_track(DBGT_INFO, "                    aggregate neighboring net0=%s net1=%s into new=%s",
                                        netAsStr(&r0->k.net), netAsStr(&r1->k.net), netAsStr(&ra->k.net));

                        }

                }
        }

	prof_stop();
}

struct redistr_opt_node *matching_redist_opt(struct redist_in_node *rin, struct avl_tree *redist_opt_tree)
{
        struct redistr_opt_node *roptn;
        struct avl_node *ropti;


	for (ropti = NULL; (roptn = avl_iterate_item(redist_opt_tree, &ropti));) {

		if (roptn->net.af && roptn->net.af != rin->k.net.af) {
			dbgf_all(DBGT_INFO, "skipping %s AF", roptn->nameKey);
			continue;
		}

		if (roptn->table != rin->k.table) {
			dbgf_all(DBGT_INFO, "skipping %s table", roptn->nameKey);
			continue;
		}

		if (roptn->bandwidth.val.u8 == 0) {
			dbgf_all(DBGT_INFO, "skipping %s bandwidth", roptn->nameKey);
			continue;
		}

		if (!(roptn->searchProto == TYP_TUN_PROTO_ALL || roptn->searchProto == rin->k.proto_type)) {
			dbgf_all(DBGT_INFO, "skipping non-matching %s proto=%d != %d", roptn->nameKey, roptn->searchProto, rin->k.proto_type);
			continue;
		}

		if ((roptn->net.mask != MIN_REDIST_PREFIX ||
			roptn->netPrefixMin != DEF_REDIST_PREFIX_MIN ||
			roptn->netPrefixMax != DEF_REDIST_PREFIX_MAX)
			&& !(
			(roptn->netPrefixMax == TYP_REDIST_PREFIX_NET ?
                                roptn->net.mask >= rin->k.net.mask : roptn->netPrefixMax >= rin->k.net.mask) &&
			(roptn->netPrefixMin == TYP_REDIST_PREFIX_NET ?
                                roptn->net.mask <= rin->k.net.mask : roptn->netPrefixMin <= rin->k.net.mask) &&
			is_ip_net_equal(&roptn->net.ip, &rin->k.net.ip, XMIN(roptn->net.mask, rin->k.net.mask), roptn->net.af))) {

			dbgf_all(DBGT_INFO, "skipping %s prefix", roptn->nameKey);
			continue;
		}

		return roptn;
	}
	return NULL;
}

IDM_T redistribute_routes(struct avl_tree *redist_out_tree, struct avl_tree *redist_in_tree, struct avl_tree *redist_opt_tree)
{

	prof_start(redistribute_routes, main);

        dbgf_track(DBGT_INFO, " ");
	IDM_T redist_changed = NO;


        struct redist_in_node *rin;
        struct avl_node *rii;

        struct redistr_opt_node *roptn;

        struct redist_out_node *routn;
        struct avl_node *routi;

	struct redist_out_node routf;

        for (routi = NULL; (routn = avl_iterate_item(redist_out_tree, &routi));) {
                routn->new = 0;
                routn->minAggregatePrefixLen = 0;
        }

        for (rii = NULL; (rin = avl_iterate_item(redist_in_tree, &rii));) {

		ASSERTION(-502479, IMPLIES(rin->roptn, rin->roptn == matching_redist_opt(rin, redist_opt_tree)));

		if ((roptn = rin->roptn ? rin->roptn : matching_redist_opt(rin, redist_opt_tree))) {

			memset(&routf, 0, sizeof (routf));

			routf.k.proto_type = roptn->advProto;
			routf.k.net = roptn->net.mask >= rin->k.net.mask ? roptn->net : rin->k.net;
			routf.k.bandwidth = roptn->bandwidth;
			if ( roptn->tunInDev )
				strcpy(routf.k.tunInDev.str, roptn->tunInDev);
			routf.k.must_be_one = 1; // to let alv_next_item find the first one
			routf.minAggregatePrefixLen = roptn->minAggregatePrefixLen;

                        if (!(routn = avl_find_item(redist_out_tree, &routf.k))) {
                                *(routn = debugMalloc(sizeof (routf), -300505)) = routf;
                                avl_insert(redist_out_tree, routn, -300506);
                                if ( __dbgf_track() ) {
                                        redist_dbg(DBGL_CHANGES, DBGT_INFO, __FUNCTION__, rin, "parsing", "adding");
                                }
                        } else {
                                if ( __dbgf_track() ) {
                                        redist_dbg(DBGL_CHANGES, DBGT_INFO, __FUNCTION__, rin, "parsing", "reusing");
                                }
                        }

                        routn->new = 1;
                        routn->minAggregatePrefixLen = XMAX(routn->minAggregatePrefixLen, roptn->minAggregatePrefixLen);
                }
        }

        redist_rm_overlapping(redist_out_tree);

        redist_rm_aggregatable(redist_out_tree);


        // remove_old_routes:

        memset(&routf, 0, sizeof (routf));
        while ((routn = avl_next_item(redist_out_tree, &routf.k))) {
                routf = *routn;

                if (routn->new != routn->old) { // 10, 11, 01, 00
                        redist_changed = YES;
			dbgf_track(DBGT_INFO, "CHANGED: old=%d new=%d rtype=%d bandwith=%d net=%s",
				routn->old, routn->new, routn->k.proto_type, routn->k.bandwidth.val.u8, netAsStr(&routn->k.net));
		}


                if (!routn->new) {
                        avl_remove(redist_out_tree, &routn->k, -300507);
                        debugFree(routn, -300508);
                        continue;
                }

                routn->new = 0;
                routn->old = 1;
        }

	prof_stop();
	return redist_changed;
}



int32_t opt_redist(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn, struct avl_tree *redist_opt_tree, uint8_t *changed)
{
        TRACE_FUNCTION_CALL;
        struct redistr_opt_node *ron = NULL;

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

                struct opt_child *c = NULL;
                char name[NETWORK_NAME_LEN] = {0};

                dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (AF_CFG != AF_INET6)
                        return FAILURE;

                if (strlen(patch->val) >= NETWORK_NAME_LEN || validate_name_string(patch->val, strlen(patch->val) + 1, NULL) != SUCCESS)
                        return FAILURE;

                strcpy(name, patch->val);

                ron = avl_find_item(redist_opt_tree, name);

                struct net_key net = ZERO_NET_KEY;
                net.af = ron ? ron->net.af : 0; // family of ARG_TUN_SEARCH_NETWORK and ARG_TUN_SEARCH_SRC must be the same!!!

                if (cmd == OPT_APPLY) {

                        *changed = YES;

                        //unlink_tun_net(NULL, NULL, NULL);

                        if (!ron && patch->diff != DEL) {
                                ron = debugMalloc(sizeof (struct redistr_opt_node), -300496);
                                memset(ron, 0, sizeof (struct redistr_opt_node));
                                strcpy(ron->nameKey, name);
                                avl_insert(redist_opt_tree, ron, -300497);

                                ron->hysteresis = DEF_REDIST_HYSTERESIS;
                                ron->netPrefixMin = DEF_REDIST_PREFIX_MIN;
                                ron->netPrefixMax = DEF_REDIST_PREFIX_MAX;
				ron->table = DEF_REDIST_TABLE;
				UMETRIC_T bw = DEF_TUN_IN_BW;
				ron->bandwidth = umetric_to_fmu8(&bw);
				ron->searchProto = DEF_TUN_PROTO_SEARCH;
				ron->advProto = DEF_TUN_PROTO_ADV;

                        } else if (ron && patch->diff == DEL) {
                                avl_remove(redist_opt_tree, &ron->nameKey, -300498);
                                debugFree(ron, -300499);
                        }
                }

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_REDIST_NET)) {

                                if (c->val) {

                                        if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, NO) == FAILURE)
                                                return FAILURE;

                                        set_opt_child_val(c, netAsStr(&net));

                                        if (cmd == OPT_APPLY && ron)
                                                ron->net = net;


                                } else if (cmd == OPT_APPLY && ron) {
                                        setNet(&ron->net, net.af, 0, NULL);
                                }

                        } else if (!strcmp(c->opt->name, ARG_REDIST_BW)) {

                                if (c->val) {
                                        char *endptr;
                                        unsigned long long int ull = strtoull(c->val, &endptr, 10);

                                        if (ull > MAX_TUN_IN_BW || ull < MIN_TUN_IN_BW || *endptr != '\0')
                                                return FAILURE;

                                        assertion(-501430, (sizeof (ull) == sizeof (UMETRIC_T)));

                                        if (cmd == OPT_APPLY && ron)
                                                ron->bandwidth = umetric_to_fmu8((UMETRIC_T*) & ull);

                                } else if (cmd == OPT_APPLY && ron) {
					UMETRIC_T bw = DEF_TUN_IN_BW;
                                        ron->bandwidth = umetric_to_fmu8(&bw);
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_DEV)) {

				if (c->val ) {

					if (strlen(c->val) >= NETWORK_NAME_LEN ||
						validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS ||
						strncmp(tun_name_prefix.str, c->val, strlen(tun_name_prefix.str))) {

						dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
							c->val, tun_name_prefix.str);

						return FAILURE;
					}

					if (cmd == OPT_APPLY && ron)
                                                ron->tunInDev = c->val;

				} else if (cmd == OPT_APPLY && ron) {
					ron->tunInDev = NULL;
				}


                        } else if (cmd == OPT_APPLY && ron) {

                                if (!strcmp(c->opt->name, ARG_REDIST_PREFIX_MIN)) {
                                        ron->netPrefixMin = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_PREFIX_MIN;

                                } else if (!strcmp(c->opt->name, ARG_REDIST_PREFIX_MAX)) {
                                        ron->netPrefixMax = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_PREFIX_MAX;

                                } else if (!strcmp(c->opt->name, ARG_REDIST_TABLE)) {
                                        ron->table = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_TABLE;

                                } else if (!strcmp(c->opt->name, ARG_REDIST_AGGREGATE)) {
                                        ron->minAggregatePrefixLen = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_AGGREGATE;

                                } else if (!strcmp(c->opt->name, ARG_REDIST_HYSTERESIS)) {
                                        ron->hysteresis = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_HYSTERESIS;

                                } else if (!strcmp(c->opt->name, ARG_TUN_PROTO_SEARCH)) {
                                        ron->searchProto = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_PROTO_SEARCH;

                                } else if (!strcmp(c->opt->name, ARG_TUN_PROTO_ADV)) {
                                        ron->advProto = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_PROTO_ADV;
                                }
                        }
                }

        } else if (cmd == OPT_UNREGISTER) {

                struct avl_node *an = NULL;

                while ((ron = avl_iterate_item(redist_opt_tree, &an))) {
                        avl_remove(redist_opt_tree, &ron->nameKey, -300501);
                        debugFree(ron, -300502);
                }

        }


        return SUCCESS;
}
