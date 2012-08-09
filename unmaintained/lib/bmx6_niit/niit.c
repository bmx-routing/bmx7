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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <sys/ioctl.h>
//#include <net/if.h>



#include "bmx.h"
#include "msg.h"
#include "ip.h"
#include "plugin.h"
#include "hna.h"
#include "niit.h"
#include "tools.h"
#include "metrics.h"
#include "schedule.h"

#define CODE_CATEGORY_NAME "niit"

static struct net_key niit4_address;

static int niit4to6_idx = 0;
static int niit6to4_idx = 0;
static IPX_T niitPrefix96 = DEF_NIIT_PREFIX;




STATIC_FUNC
void niit_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        if (on != self)
                return;

        dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

        assertion(-501245, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501248, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {
                process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_DEL, BMX_DSC_TLV_UHNA6, NULL, NULL);
        }

        if (cb_id == PLUGIN_CB_DESCRIPTION_CREATED) {
                process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_ADD, BMX_DSC_TLV_UHNA6, NULL, NULL);
        }
}



STATIC_FUNC
void niit_dev_event_hook(int32_t cb_id, void* unused)
{
        TRACE_FUNCTION_CALL;
        struct avl_node *an = NULL;
        struct if_link_node *iln = NULL;
        struct if_link_node *iln_4to6 = NULL;
        struct if_link_node *iln_6to4 = NULL;
        struct orig_node *on;
        IDM_T has_niit4to6_address = 0;

        if (!niit4_address.mask || AF_CFG == AF_INET)
                return;

        while ((iln = avl_iterate_item(&if_link_tree, &an))) {

                if (!(iln->flags & IFF_UP))
                        continue;

                if (!strcmp(iln->name.str, DEF_NIIT_6TO4_DEV)) {
                        dbgf_track(DBGT_INFO, "%s UP", DEF_NIIT_6TO4_DEV);
                        iln_6to4 = iln;
                }

                if (!strcmp(iln->name.str, DEF_NIIT_4TO6_DEV)) {
                        dbgf_track(DBGT_INFO, "%s UP", DEF_NIIT_4TO6_DEV);
                        iln_4to6 = iln;
                }

                if (avl_find_item(&iln->if_addr_tree, &niit4_address.ip)) {
                        dbgf_track(DBGT_INFO, "Found niit address on interface %s", iln->name.str);
                        has_niit4to6_address = 1;
                }

                if (iln_4to6 && iln_6to4 && has_niit4to6_address)
                        break;
        }

        if (!has_niit4to6_address) {
                dbgf_track(DBGT_WARN, "%s address %s does not exist on the system",
                        ARG_TUN4_ADDRESS, ipXAsStr(AF_INET, &niit4_address.ip));
        }

        if (!iln_4to6) {
                dbgf_track(DBGT_WARN, "%s interface not found or down", DEF_NIIT_4TO6_DEV);
        }

        if (!iln_6to4) {
                dbgf_track(DBGT_WARN, "%s interface not found or down", DEF_NIIT_6TO4_DEV);
        }

        int niit4to6_old_idx = niit4to6_idx;
        int niit4to6_new_idx = (iln_4to6 && has_niit4to6_address) ? iln_4to6->index : 0;
        int niit6to4_old_idx = niit6to4_idx;
        int niit6to4_new_idx = iln_6to4 ? iln_6to4->index : 0;

        if (niit4to6_idx != niit4to6_new_idx) {

                dbgf_track(DBGT_INFO, "niit4to6_dev_idx=%d niit4to6_new_idx=%d", niit4to6_idx, niit4to6_new_idx);

                for (an = NULL; (on = avl_iterate_item(&orig_tree, &an));) {

                        if (on == self)
                                continue;

                        if ((niit4to6_idx = niit4to6_old_idx))
                                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT4TO6_DEL, BMX_DSC_TLV_UHNA6, NULL, NULL);

                        if ((niit4to6_idx = niit4to6_new_idx))
                                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT4TO6_ADD, BMX_DSC_TLV_UHNA6, NULL, NULL);
                }

                niit4to6_idx = niit4to6_new_idx;
        }

        if (niit6to4_idx != niit6to4_new_idx) {

                dbgf_track(DBGT_INFO, "niit6to4_dev_idx=%d niit6to4_new_idx=%d", niit6to4_idx, niit6to4_new_idx);

                if (niit6to4_old_idx)
                        process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_DEL, BMX_DSC_TLV_UHNA6, NULL, NULL);

                niit6to4_idx = niit6to4_new_idx;

                if (niit6to4_new_idx)
                        process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_ADD, BMX_DSC_TLV_UHNA6, NULL, NULL);

        }
}



STATIC_FUNC
IDM_T configure_niit4to6(IDM_T del, struct net_key *key)
{
        TRACE_FUNCTION_CALL;

        if (!niit4to6_idx || !niit4_address.mask || AF_CFG != AF_INET6 || key->mask < 96 ||
                !is_ip_net_equal(&key->ip, &niitPrefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_all(DBGT_INFO, "del=%d %s", del, netAsStr(key));

        IPX_T niit_glip4 = ZERO_IP;
        niit_glip4.s6_addr32[3] = key->ip.s6_addr32[3];
        struct net_key *niit4 = setNet(NULL, AF_INET, (key->mask - 96), &niit_glip4);

        // update network routes:
        if (del)
                return iproute(IP_ROUTE_TUNS, DEL, NO, niit4, RT_TABLE_TUN, 0, NULL, 0, NULL, NULL, DEF_IP_METRIC);

        else
                return iproute(IP_ROUTE_TUNS, ADD, NO, niit4, RT_TABLE_TUN, 0, NULL, niit4to6_idx, NULL, &niit4_address.ip, DEF_IP_METRIC);


        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_4TO6_DEV);
        return FAILURE;
}

STATIC_FUNC
IDM_T configure_niit6to4(IDM_T del, struct net_key *key)
{
        TRACE_FUNCTION_CALL;

        if (!niit6to4_idx || !niit4_address.mask || AF_CFG != AF_INET6 || key->mask < 96 ||
                !is_ip_net_equal(&key->ip, &niitPrefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_track(DBGT_INFO, "del=%d %s", del, netAsStr(key));

        assertion(-501329, (key->af == AF_INET6));

        // update network routes:
        if (del)
                return iproute(IP_ROUTE_TUNS, DEL, NO, key, RT_TABLE_TUN, 0, NULL, 0, NULL, NULL, DEF_IP_METRIC);

        else
                return iproute(IP_ROUTE_TUNS, ADD, NO, key, RT_TABLE_TUN, 0, NULL, niit6to4_idx, NULL, NULL, DEF_IP_METRIC);


        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_6TO4_DEV);
        return FAILURE;
}



STATIC_FUNC
struct net_key netX4ToNiit6(struct net_key *net)
{
        struct net_key niit;
        assertion(-501330, (net->af == AF_INET));
        setNet(&niit, AF_INET6, net->mask + 96, &niitPrefix96);
        niit.ip.s6_addr32[3] = net->ip.s6_addr32[3];
        return niit;
}


STATIC_FUNC
int32_t opt_niit4_address(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

        struct net_key net = ZERO_NET_KEY;
        net.af = AF_INET;

        if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                if (AF_CFG != AF_INET6) {

                        return FAILURE;

                } else if (patch->diff == DEL) {

                        net = ZERO_NET_KEY;

                } else if (str2netw(patch->val, &net.ip, cn, &net.mask, &net.af, YES) == FAILURE || !is_ip_valid(&net.ip, net.af)) {

                        return FAILURE;

                } else if (net.mask < HNA4_PREFIXLEN_MIN) {

                        return FAILURE;

                } else {

                        struct net_key find = net.af == AF_INET ? netX4ToNiit6(&net) : net;
                        struct hna_node *hna;

                        if ((hna = find_overlapping_hna(&find.ip, find.mask, self))) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s already used by orig=%s hna=%s",
                                        opt->name, netAsStr(&find), globalIdAsString(&hna->on->global_id), netAsStr(&hna->key));

                                return FAILURE;
                        }
                }
        }

        if (cmd == OPT_APPLY) {

                assertion(-501396, (net.af == AF_INET));

                niit4_address = net;

                niit_dev_event_hook(PLUGIN_CB_SYS_DEV_EVENT, NULL);

                my_description_changed = YES;
        }

        if(cmd == OPT_REGISTER) {
                niit4_address = ZERO_NET_KEY;
        }

        return SUCCESS;
}










STATIC_FUNC
struct opt_type niit_options[]= {
//     		ord parent long_name   shrt Attributes				*ival		min		max		default		*function

	{ODI,0,ARG_NIIT4_ADDRESS,        0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_niit4_address,
			ARG_PREFIX_FORM,"specify default niit IPv4 tunnel address (IP SHOULD be announced and assigned to niit4to6 interface!)"},

};









STATIC_FUNC
void niit_cleanup( void )
{
        TRACE_FUNCTION_CALL;
        //set_route_change_hooks(hna_route_change_hook, DEL);
}


STATIC_FUNC
int32_t niit_init( void )
{
        TRACE_FUNCTION_CALL;

        hna_configure_niit4to6 = configure_niit4to6;
        hna_configure_niit6to4 = configure_niit6to4;

        register_options_array(niit_options, sizeof ( niit_options), CODE_CATEGORY_NAME);

        //set_route_change_hooks(hna_route_change_hook, ADD);


        return SUCCESS;
}














struct plugin *niit_get_plugin( void ) {

	static struct plugin niit_plugin;
	memset( &niit_plugin, 0, sizeof ( struct plugin ) );

	niit_plugin.plugin_name = CODE_CATEGORY_NAME;
	niit_plugin.plugin_size = sizeof ( struct plugin );
        niit_plugin.plugin_code_version = CODE_VERSION;
        niit_plugin.cb_init = niit_init;
	niit_plugin.cb_cleanup = niit_cleanup;
        niit_plugin.cb_plugin_handler[PLUGIN_CB_SYS_DEV_EVENT] = niit_dev_event_hook;
        niit_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_CREATED] = (void (*) (int32_t, void*)) niit_description_event_hook;
        niit_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_DESTROY] = (void (*) (int32_t, void*)) niit_description_event_hook;

        return &niit_plugin;
}
