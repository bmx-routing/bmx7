/*
 * Copyright (c) 2012-2013  Axel Neumann
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
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "ip.h"
#include "hna.h"
#include "redist.h"
#include "allocate.h"
#include "table.h"


#define CODE_CATEGORY_NAME "table"


static AVL_TREE(redist_filter_tree, struct redist_in_node, k);
static AVL_TREE(redist_in_tree, struct redist_in_node, k);
static AVL_TREE(redist_opt_tree, struct redistr_opt_node, nameKey);
static AVL_TREE(redist_out_tree, struct redist_out_node, k);

static LIST_SIMPEL(table_net_adv_list, struct tunXin6_net_adv_node, list, list);

static struct sys_route_dict rtredist_rt_dict[BMX6_ROUTE_MAX_SUPP+1];


int32_t rtredist_delay = DEF_REDIST_DELAY;
int32_t rtfilter_delay = DEF_FILTER_DELAY;



STATIC_FUNC
void redist_table_routes(IDM_T forceChanged)
{
	struct redist_in_node *rin;
	struct redist_in_node rii;
	struct avl_node *an=NULL;
	memset(&rii, 0, sizeof (rii));

	while ((rin = avl_next_item(&redist_in_tree, &rii.k))) {
		rii = *rin;

		ASSERTION(-502300, matching_redist_opt(rin, &redist_opt_tree, rtredist_rt_dict));

		if (!forceChanged && rin->old != (!!rin->cnt))
			forceChanged = YES;

		if (rin->cnt <= 0)
			debugFree( avl_remove(&redist_in_tree, &rin->k, -300551), -300554);
	}

	if ( forceChanged) {
		if ( redistribute_routes(&redist_out_tree, &redist_in_tree, &redist_opt_tree, rtredist_rt_dict) )
			update_tunXin6_net_adv_list(&redist_out_tree, &table_net_adv_list);
	}

	while ((rin=avl_iterate_item(&redist_in_tree, &an)))
		rin->old = 1;

	dbgf(forceChanged ? DBGL_SYS : DBGL_CHANGES, DBGT_INFO, " %sCHANGED out.items=%d in.items=%d opt.items=%d net_advs=%d",
		forceChanged ? "" : "UN",
		redist_out_tree.items, redist_in_tree.items, redist_opt_tree.items, table_net_adv_list.items);
}


STATIC_FUNC
void schedule_table_routes(void* nowPtr)
{
	static IDM_T scheduled = NO;


	dbgf_track(DBGT_INFO, "%s", nowPtr ? "NOW" : "later");

	if (nowPtr) {

		scheduled = NO;
		task_remove(schedule_table_routes, (void*)YES);

		redist_table_routes(NO);

	} else if (!scheduled) {

		scheduled = YES;
		task_register(rtredist_delay, schedule_table_routes, (void*)YES, -300550);
	}
}

STATIC_FUNC
void filter_temporary_route_changes(void *newP)
{
	static IDM_T scheduled = NO;
	struct redist_in_node *rfn;

	TIME_T next_check = rtfilter_delay;

	dbgf_track(DBGT_INFO, "%s", newP ? "new" : "check...");

	if (newP == NULL) {

		assertion(-500000, (scheduled));
		assertion(-500000, (redist_filter_tree.items));

		scheduled = NO;
		struct redist_in_node tmp = {.k={.ifindex=0}};

		for (rfn = NULL; (rfn = avl_next_item(&redist_filter_tree, &tmp.k));) {

			tmp.k = rfn->k;

			TIME_T passed = (bmx_time - rfn->stamp);

			if (passed >= ((TIME_T)(rtfilter_delay - (MIN_REDIST_DELAY/2)))) {

				struct redist_in_node *rin;

				if ((rin = avl_find_item(&redist_in_tree, &rfn->k))) {
					ASSERTION(-502301, (rin->roptn && rin->roptn == matching_redist_opt(rfn, &redist_opt_tree, rtredist_rt_dict)));

					rin->cnt += rfn->cnt;
					schedule_table_routes((void*) NO);

				} else {

					ASSERTION(-500000, (rfn->roptn && rfn->roptn == matching_redist_opt(rfn, &redist_opt_tree, rtredist_rt_dict)));
					assertion(-502302, (rfn->cnt >= 1));

					rin = debugMalloc(sizeof(*rfn), -300552);
					*rin = *rfn;
					avl_insert(&redist_in_tree, rin, -300553);
					schedule_table_routes((void*) NO);
				}

				avl_remove(&redist_filter_tree, &rfn->k, -300000);
				debugFree(rfn, -300000);

			} else {
				next_check = XMIN(next_check, (rtfilter_delay - passed));
			}
		}
		
	} else if (newP == (void*) 1 /* purge*/) {

		while (redist_filter_tree.items)
			debugFree(avl_remove_first_item(&redist_filter_tree, -300000), -3000000);
		
	} else if (newP) {

		struct redist_in_node *new = newP;

		if ((rfn = avl_find_item(&redist_filter_tree, &new->k))) {

			if (!(rfn->cnt += new->cnt)) {
				avl_remove(&redist_filter_tree, &rfn->k, -300000);
				debugFree(rfn, -300000);
				dbgf_track(DBGT_INFO, "filtering temporary change");
			}

		} else {
			rfn = debugMalloc(sizeof(*new), -300552);
			*rfn = *new;
			avl_insert(&redist_filter_tree, rfn, -300553);
			rfn->stamp = bmx_time;
		}

	}

	if (redist_filter_tree.items) {
		if (!scheduled) {
			scheduled = YES;
			task_register(next_check, filter_temporary_route_changes, NULL, -300000);
		}
	} else {
		if (scheduled) {
			scheduled = NO;
			task_remove(filter_temporary_route_changes, NULL);
		}
	}
}

void get_route_list_nlhdr(struct nlmsghdr *nh, void *unused )
{
        struct rtmsg *rtm = (struct rtmsg *) NLMSG_DATA(nh);
        struct rtattr *rtap = (struct rtattr *) RTM_RTA(rtm);
        int rtl = RTM_PAYLOAD(nh);

        while (RTA_OK(rtap, rtl)) {

		if ( rtap->rta_type==RTA_DST && (nh->nlmsg_type==RTM_NEWROUTE || nh->nlmsg_type==RTM_DELROUTE) &&
			rtm->rtm_table!=ip_table_tun_cfg ) {

			struct net_key net = {.af=rtm->rtm_family, .mask=rtm->rtm_dst_len,
			.ip=(rtm->rtm_family==AF_INET6) ? *((IPX_T *) RTA_DATA(rtap)) : ip4ToX(*((IP4_T *) RTA_DATA(rtap))) };

			dbgf_track(DBGT_INFO, "%s route=%s table=%d protocol=%s",	nh->nlmsg_type==RTM_NEWROUTE?"ADD":"DEL",
				netAsStr(&net), rtm->rtm_table, memAsHexStringSep(&rtm->rtm_protocol, 1, 0, NULL));

			struct redist_in_node new = {
				.k = {.table = rtm->rtm_table, .inType = rtm->rtm_protocol, .net = net},
				.cnt = ((nh->nlmsg_type == RTM_NEWROUTE)?1:-1)
			};

			if ((new.roptn = matching_redist_opt(&new, &redist_opt_tree, rtredist_rt_dict))) {

				filter_temporary_route_changes(&new);
			}
		}
                rtap = RTA_NEXT(rtap, rtl);
        }
}

STATIC_FUNC
int32_t sync_redist_routes(IDM_T cleanup, IDM_T resync);

static void recv_rtevent_netlink_sk(int sk)
{
        TRACE_FUNCTION_CALL;
//	char buf[4096]; //test this with a very small value !!
//	struct sockaddr_nl sa;
//	struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
//	assertion(-501528, (sk==rtevent_sk));

        dbgf_all(DBGT_INFO, "detected changed routes! Going to check...");
/*
        struct msghdr msg; // = {(void *) & sa, sizeof (sa), &iov, 1, NULL, 0, 0};
        memset( &msg, 0, sizeof( struct msghdr));
        msg.msg_name = (void *)&sa;
        msg.msg_namelen = sizeof(sa); // Length of address data.
        msg.msg_iov = &iov; // Vector of data to send/receive into.
        msg.msg_iovlen = 1; // Number of elements in the vector.
*/
	int result = rtnl_rcv( sk, 0, 0, IP_ROUTE_GET, NO, get_route_list_nlhdr, NULL );

	if (result != SUCCESS)
		sync_redist_routes(NO, YES);
}

STATIC_FUNC
int32_t resync_routes(int32_t rtevent_sk)
{
	const uint32_t nlgroups = nl_mgrp(RTNLGRP_IPV4_ROUTE) | nl_mgrp(RTNLGRP_IPV6_ROUTE);
	const int buffsize = 266240; // 133120 // 66560 // RTNL_RCV_MAX //seems all too small for 2K+ routes and heavy CPU load

	fd_set sockset;
	int cnt = 1;

	while (1) {
		dbgf_sys(DBGT_WARN, "rt-events out of sync. Trying to resync (round=%d) ...", cnt);

		if (rtevent_sk)
			rtevent_sk = unregister_netlink_event_hook(rtevent_sk, recv_rtevent_netlink_sk);

		filter_temporary_route_changes((void*)1/*purge*/);

		while (redist_in_tree.items)
			debugFree(avl_remove_first_item(&redist_in_tree, -300487), -300488);



		wait_sec_msec(0, 500);
		dbgf_track(DBGT_WARN, "now");

		rtevent_sk = register_netlink_event_hook(nlgroups, buffsize, recv_rtevent_netlink_sk);
		assertion(-502504, (rtevent_sk > 0));

		kernel_get_route(NO, AF_INET, RTM_GETROUTE, 0, get_route_list_nlhdr);
		kernel_get_route(NO, AF_INET6, RTM_GETROUTE, 0, get_route_list_nlhdr);

		FD_ZERO(&sockset);
		FD_SET(rtevent_sk, &sockset);
		struct timeval to = {0, 0};

		if (!select(rtevent_sk + 1, &sockset, NULL, NULL, &to))
			break;

		cnt++;

		assertion(-502505, (cnt<100));
	}

	dbgf_track(DBGT_WARN, "success");
	return rtevent_sk;

}
STATIC_FUNC
int32_t sync_redist_routes(IDM_T cleanup, IDM_T resync)
{
	static int rtevent_sk = 0;

	if (cleanup) {

		rtevent_sk = unregister_netlink_event_hook(rtevent_sk, recv_rtevent_netlink_sk);

		set_tunXin6_net_adv_list(DEL, &table_net_adv_list);

		filter_temporary_route_changes((void*)1/*purge*/);


		while (redist_in_tree.items)
			debugFree(avl_remove_first_item(&redist_in_tree, -300487), -300488);

		while (redist_out_tree.items) {
			debugFree(avl_remove_first_item(&redist_out_tree, -300513), -300514);
			my_description_changed = YES;
		}

		while (table_net_adv_list.items)
			debugFree(list_del_head(&table_net_adv_list), -300515);

	} else if (resync) {

		rtevent_sk = resync_routes(rtevent_sk);

		redist_table_routes(YES);

	} else {

		set_tunXin6_net_adv_list(ADD, &table_net_adv_list);

		rtevent_sk = resync_routes(rtevent_sk);
	}


	return rtevent_sk;
}


STATIC_FUNC
int32_t opt_redistribute(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        static uint8_t changed = NO;
	static uint8_t initialized = NO;

	int32_t redist = opt_redist(cmd, _save, opt, patch, cn, &redist_opt_tree, &changed);

	if (redist!=SUCCESS)
		return redist;

	if (cmd == OPT_SET_POST && redist_opt_tree.items && !initialized ) {

		dbgf_track(DBGT_INFO, "Initializing...");

		sync_redist_routes(NO, NO);
		initialized = YES;
	}

	if (cmd == OPT_SET_POST && initialized && changed) {

		dbgf_track(DBGT_INFO, "Updating...");
//		redist_table_routes(YES);
		sync_redist_routes(NO, YES);

		changed = NO;
	}

	if ((cmd == OPT_UNREGISTER || (cmd == OPT_SET_POST && !redist_opt_tree.items)) && initialized ) {

		dbgf_track(DBGT_INFO, "Cleaning up...");

		sync_redist_routes(YES, NO);

		initialized = NO;
		changed = NO;
	}

        return SUCCESS;
}


static struct opt_type rtredist_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

        {ODI,0,ARG_FILTER_DELAY,          0,9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &rtfilter_delay,MIN_REDIST_DELAY,MAX_REDIST_DELAY,DEF_FILTER_DELAY,0,   0,
			ARG_VALUE_FORM,	HLP_FILTER_DELAY}
        ,
        {ODI,0,ARG_REDIST_DELAY,          0,9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &rtredist_delay,MIN_REDIST_DELAY,MAX_REDIST_DELAY,DEF_REDIST_DELAY,0,   0,
			ARG_VALUE_FORM,	HLP_REDIST_DELAY}
        ,
 	{ODI,0,ARG_REDIST,     	          0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_redistribute,
		        ARG_NAME_FORM,  HLP_REDIST},
	{ODI,ARG_REDIST,ARG_REDIST_NET, 'n',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,              0,              0,              0,0,            opt_redistribute,
			ARG_NETW_FORM, HLP_REDIST_NET},
	{ODI,ARG_REDIST,ARG_REDIST_PREFIX_MIN,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_PREFIX,MAX_REDIST_PREFIX,DEF_REDIST_PREFIX_MIN,0,opt_redistribute,
			ARG_VALUE_FORM, HLP_REDIST_PREFIX_MIN},
	{ODI,ARG_REDIST,ARG_REDIST_PREFIX_MAX,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_PREFIX,MAX_REDIST_PREFIX,DEF_REDIST_PREFIX_MAX,0,opt_redistribute,
			ARG_VALUE_FORM, HLP_REDIST_PREFIX_MAX},
	{ODI,ARG_REDIST,ARG_REDIST_TABLE, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_TABLE,MAX_REDIST_TABLE,DEF_REDIST_TABLE,0,           opt_redistribute,
			ARG_VALUE_FORM, HLP_REDIST_TABLE},
	{ODI,ARG_REDIST,ARG_TUN_DEV,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,		0,              0,              0,0,            opt_redistribute,
			ARG_NAME_FORM,	HLP_TUN_IN_DEV},
	{ODI,ARG_REDIST,ARG_REDIST_AGGREGATE,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_AGGREGATE,MAX_REDIST_AGGREGATE,DEF_REDIST_AGGREGATE,0,opt_redistribute,
			ARG_VALUE_FORM, HLP_REDIST_AGGREGATE},
	{ODI,ARG_REDIST,ARG_REDIST_BW,   'b',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,		 0,	         0,              0,0,            opt_redistribute,
			ARG_VALUE_FORM,	HLP_REDIST_BW},
	{ODI,ARG_REDIST,ARG_ROUTE_SYS,    0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              BMX6_ROUTE_MAX_SUPP,0,0,        opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_SYS},
	{ODI,ARG_REDIST,ARG_ROUTE_ALL,    0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_KERNEL, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_BOOT,   0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_STATIC, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},

};


static void rtredist_cleanup( void )
{
}



static int32_t rtredist_init( void )
{

	memset(&rtredist_rt_dict, 0, sizeof(rtredist_rt_dict));
        set_rt_dict(rtredist_rt_dict, RTPROT_UNSPEC,  'u', ARG_ROUTE_UNSPEC,   BMX6_ROUTE_UNSPEC);
        set_rt_dict(rtredist_rt_dict, RTPROT_REDIRECT,'r', ARG_ROUTE_REDIRECT, BMX6_ROUTE_REDIRECT);
        set_rt_dict(rtredist_rt_dict, RTPROT_KERNEL,  'K', ARG_ROUTE_KERNEL,   BMX6_ROUTE_KERNEL);
        set_rt_dict(rtredist_rt_dict, RTPROT_BOOT,    't', ARG_ROUTE_BOOT,     BMX6_ROUTE_BOOT);
        set_rt_dict(rtredist_rt_dict, RTPROT_STATIC,  'S', ARG_ROUTE_STATIC,   BMX6_ROUTE_STATIC);
        set_rt_dict(rtredist_rt_dict, RTPROT_GATED,   'g', ARG_ROUTE_GATED,    BMX6_ROUTE_GATED);
        set_rt_dict(rtredist_rt_dict, RTPROT_RA,      'a', ARG_ROUTE_RA,       BMX6_ROUTE_RA);
        set_rt_dict(rtredist_rt_dict, RTPROT_MRT,     'm', ARG_ROUTE_MRT,      BMX6_ROUTE_MRT);
        set_rt_dict(rtredist_rt_dict, RTPROT_ZEBRA,   'z', ARG_ROUTE_ZEBRA,    BMX6_ROUTE_ZEBRA);
        set_rt_dict(rtredist_rt_dict, RTPROT_BIRD,    'd', ARG_ROUTE_BIRD,     BMX6_ROUTE_BIRD);
        set_rt_dict(rtredist_rt_dict, RTPROT_DNROUTED,'n', ARG_ROUTE_DNROUTED, BMX6_ROUTE_DNROUTED);
        set_rt_dict(rtredist_rt_dict, RTPROT_XORP,    'p', ARG_ROUTE_XORP,     BMX6_ROUTE_XORP);
        set_rt_dict(rtredist_rt_dict, RTPROT_NTK,     'k', ARG_ROUTE_NTK,      BMX6_ROUTE_NTK);
        set_rt_dict(rtredist_rt_dict, RTPROT_DHCP,    'd', ARG_ROUTE_DHCP,     BMX6_ROUTE_DHCP);

        register_options_array(rtredist_options, sizeof ( rtredist_options), CODE_CATEGORY_NAME);

	return SUCCESS;
}


struct plugin* get_plugin( void ) {
	
	static struct plugin rtredist_plugin;
	
	memset( &rtredist_plugin, 0, sizeof ( struct plugin ) );
	

	rtredist_plugin.plugin_name = CODE_CATEGORY_NAME;
	rtredist_plugin.plugin_size = sizeof ( struct plugin );
	rtredist_plugin.cb_init = rtredist_init;
	rtredist_plugin.cb_cleanup = rtredist_cleanup;

	return &rtredist_plugin;
}


