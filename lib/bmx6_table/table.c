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
#include "allocate.h"
#include "table.h"
#include "redist.c"


#define CODE_CATEGORY_NAME "table"


static AVL_TREE(redist_in_tree, struct redist_in_node, k);
static AVL_TREE(redist_opt_tree, struct redistr_opt_node, nameKey);
static AVL_TREE(redist_out_tree, struct redist_out_node, k);

static LIST_SIMPEL(tunXin6_net_adv_list, struct tunXin6_net_adv_node, list, list);

static struct sys_route_dict rtredist_rt_dict[BMX6_ROUTE_MAX];



int rtevent_sk = 0;
int32_t rtredist_delay = 200;

STATIC_FUNC
void redist_table_routes(void* laterp)
{
	static IDM_T scheduled = NO;

	if ( laterp && !scheduled) {
		scheduled = YES;
		task_register(rtredist_delay, redist_table_routes, NULL, -300550);

	} else if ( !laterp ) {

		dbgf_track(DBGT_INFO, " ");
		scheduled = NO;
		task_remove(redist_table_routes, NULL);

		IDM_T changed = NO;

                struct redist_in_node *rin;
                struct redist_in_node rii;
		struct avl_node *an=NULL;
                memset(&rii, 0, sizeof (rii));
                while ((rin = avl_next_item(&redist_in_tree, &rii.k))) {
                        rii = *rin;

                        if (rin->old != rin->cnt)
                                 changed = YES;

			if (rin->cnt <= 0)
				debugFree( avl_remove(&redist_in_tree, &rin->k, -300551), -300554);
                }

                if ( changed) {
			if ( redistribute_routes(&redist_out_tree, &redist_in_tree, &redist_opt_tree, rtredist_rt_dict) )
				update_tunXin6_net_adv_list(&redist_out_tree, &tunXin6_net_adv_list);
		}
		
		while ((rin=avl_iterate_item(&redist_in_tree, &an)))
			rin->old = 1;

		dbgf_track(DBGT_INFO, "%sCHANGED out.items=%d in.items=%d opt.items=%d net_advs=%d",
			changed ? "" : "UN",
			redist_out_tree.items, redist_in_tree.items, redist_opt_tree.items, tunXin6_net_adv_list.items);

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

			dbgf_sys(DBGT_INFO, "%s route=%s table=%d protocol=%s",	nh->nlmsg_type==RTM_NEWROUTE?"ADD":"DEL",
				netAsStr(&net), rtm->rtm_table, rtredist_rt_dict[rtm->rtm_protocol].sys2Name);

			struct redist_in_node new = {.k = {.table = rtm->rtm_table, .inType = rtm->rtm_protocol, .net = net}};
			struct redist_in_node *rin = avl_find_item(&redist_in_tree, &new.k);
			assertion(-501527, IMPLIES(nh->nlmsg_type==RTM_DELROUTE, rin && rin->cnt>0));

			if (rin) {
				
				rin->cnt += (nh->nlmsg_type==RTM_NEWROUTE ? 1 : -1);

			} else {
				rin = debugMalloc(sizeof(new), -300552);
				*rin = new;
				rin->cnt = 1;
				avl_insert(&redist_in_tree, rin, -300553);
			}
			redist_table_routes((void*)1);
		}
                rtap = RTA_NEXT(rtap, rtl);
        }
}


static void recv_rtevent_netlink_sk(int sk)
{
        TRACE_FUNCTION_CALL;
	char buf[4096]; //test this with a very small value !!
	struct sockaddr_nl sa;
        struct iovec iov = {.iov_base = buf, .iov_len = sizeof (buf)};
	assertion(-501528, (sk==rtevent_sk));

        dbgf_all(DBGT_INFO, "detected changed routes! Going to check...");

        struct msghdr msg; // = {(void *) & sa, sizeof (sa), &iov, 1, NULL, 0, 0};
        memset( &msg, 0, sizeof( struct msghdr));
        msg.msg_name = (void *)&sa;
        msg.msg_namelen = sizeof(sa); /* Length of address data.  */
        msg.msg_iov = &iov; /* Vector of data to send/receive into.  */
        msg.msg_iovlen = 1; /* Number of elements in the vector.  */

	rtnl_rcv( sk, 0, 0, IP_ROUTE_GET, NO, get_route_list_nlhdr, NULL );
}

static int open_rtevent_netlink_sk(void)
{
	struct sockaddr_nl sa;
	int32_t unix_opts;
	memset (&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups |= RTMGRP_IPV4_ROUTE; //| RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_MROUTE | RTMGRP_IPV4_RULE;
        sa.nl_groups |= RTMGRP_IPV6_ROUTE; //| RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_MROUTE | RTMGRP_IPV6_IFINFO | RTMGRP_IPV6_PREFIX;
//	sa.nl_groups |= RTMGRP_LINK; // (this can result in select storms with buggy wlan devices


	if ( ( rtevent_sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) ) < 0 ) {
		dbgf_sys(DBGT_ERR, "can't create af_netlink socket for reacting on if route events: %s",
		     strerror(errno) );
		rtevent_sk = 0;
		return -1;
	}


	unix_opts = fcntl( rtevent_sk, F_GETFL, 0 );
	fcntl( rtevent_sk, F_SETFL, unix_opts | O_NONBLOCK );

	if ( ( bind( rtevent_sk, (struct sockaddr*)&sa, sizeof(sa) ) ) < 0 ) {
		dbgf_sys(DBGT_ERR, "can't bind af_netlink socket for reacting on if up/down events: %s",
		     strerror(errno) );
		rtevent_sk = 0;
		return -1;
        }


	return rtevent_sk;
}

static void close_rtevent_netlink_sk(void)
{

	if ( rtevent_sk > 0 )
		close( rtevent_sk );

	rtevent_sk = 0;
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

		kernel_get_route(NO, AF_INET, 0, get_route_list_nlhdr);
		kernel_get_route(NO, AF_INET6, 0, get_route_list_nlhdr);

/*
		struct redist_in_node *rin;
		struct avl_node *an=NULL;
		while ((rin=avl_iterate_item(&redist_in_tree, &an))) {
			dbgf_track(DBGT_INFO, "current routes: net=%s table=%d cnt=%d",
				netAsStr(&rin->k.net), rin->k.table, rin->cnt);
		}
*/

		set_tunXin6_net_adv_list(ADD, &tunXin6_net_adv_list);

		open_rtevent_netlink_sk();
		set_fd_hook( rtevent_sk, recv_rtevent_netlink_sk, ADD);

		initialized = YES;
	}

	if (cmd == OPT_SET_POST && initialized && changed) {

		dbgf_track(DBGT_INFO, "Updating...");
		redist_table_routes(NULL);

		changed = NO;
	}

	if ((cmd == OPT_UNREGISTER || (cmd == OPT_SET_POST && !redist_opt_tree.items)) && initialized ) {

		dbgf_track(DBGT_INFO, "Cleaning up...");

		set_tunXin6_net_adv_list(DEL, &tunXin6_net_adv_list);
		set_fd_hook(rtevent_sk, recv_rtevent_netlink_sk, DEL);
		close_rtevent_netlink_sk();

		while (redist_in_tree.items)
			debugFree(avl_remove_first_item(&redist_in_tree, -300487), -300488);

		while (redist_out_tree.items) {
			debugFree(avl_remove_first_item(&redist_out_tree, -300513), -300514);
			my_description_changed = YES;
		}

		while (tunXin6_net_adv_list.items)
			debugFree(list_del_head(&tunXin6_net_adv_list), -300515);
		

		initialized = NO;
		changed = NO;
	}

        return SUCCESS;
}


static struct opt_type rtredist_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

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


