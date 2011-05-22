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



#include "bmx.h"
#include "msg.h"
#include "ip.h"
#include "plugin.h"
#include "hna.h"
#include "tools.h"

#define CODE_CATEGORY_NAME "hna"

static AVL_TREE(global_uhna_tree, struct uhna_node, key );
static AVL_TREE(local_uhna_tree, struct uhna_node, key );

static IPX_T niit_address;

static int niit4to6_dev_idx = 0;
static int niit6to4_dev_idx = 0;
static IPX_T niit_prefix96 = DEF_NIIT_PREFIX;


STATIC_FUNC
void niit_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        if (on != &self)
                return;

        dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

        assertion(-501245, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501246, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY)
                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT6TO4_DEL, BMX_DSC_TLV_UHNA6, NULL);
        
        if (cb_id == PLUGIN_CB_DESCRIPTION_CREATED)
                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT6TO4_ADD, BMX_DSC_TLV_UHNA6, NULL);
        
}



STATIC_FUNC
void niit_dev_event_hook(int32_t cb_id, void* unused)
{
        struct avl_node *an = NULL;
        struct if_link_node *iln = NULL;
        struct if_link_node *iln_4to6 = NULL;
        struct if_link_node *iln_6to4 = NULL;
        struct orig_node *on;
        IDM_T has_niit4to6_address = 0;

        if (!niit_enabled || af_cfg != AF_INET6)
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

                if (avl_find_item(&iln->if_addr_tree, &niit_address)) {
                        dbgf_track(DBGT_INFO, "Found niit address on interface %s", iln->name.str);
                        has_niit4to6_address = 1;
                }

                if (iln_4to6 && iln_6to4 && has_niit4to6_address)
                        break;
        }

        if (!has_niit4to6_address) {
                dbgf_track(DBGT_WARN, "%s address %s does not exist on the system",
                        ARG_NIIT, ipXAsStr(AF_INET, &niit_address));
        }

        if (!iln_4to6) {
                dbgf_track(DBGT_WARN, "%s interface not found or down", DEF_NIIT_4TO6_DEV);
        }

        if (!iln_6to4) {
                dbgf_track(DBGT_WARN, "%s interface not found or down", DEF_NIIT_6TO4_DEV);
        }

        int niit4to6_old_idx = niit4to6_dev_idx;
        int niit4to6_new_idx = (iln_4to6 && has_niit4to6_address) ? iln_4to6->index : 0;
        int niit6to4_old_idx = niit6to4_dev_idx;
        int niit6to4_new_idx = iln_6to4 ? iln_6to4->index : 0;

        if (niit4to6_dev_idx != niit4to6_new_idx) {

                dbgf_track(DBGT_INFO, "niit4to6_dev_idx=%d niit4to6_new_idx=%d", niit4to6_dev_idx, niit4to6_new_idx);

                for (an = NULL; (on = avl_iterate_item(&orig_tree, &an));) {

                        if (on == &self)
                                continue;

                        if ((niit4to6_dev_idx = niit4to6_old_idx))
                                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT4TO6_DEL, BMX_DSC_TLV_UHNA6, NULL);

                        if ((niit4to6_dev_idx = niit4to6_new_idx))
                                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT4TO6_ADD, BMX_DSC_TLV_UHNA6, NULL);
                }

                niit4to6_dev_idx = niit4to6_new_idx;
        }

        if (niit6to4_dev_idx != niit6to4_new_idx) {

                dbgf_track(DBGT_INFO, "niit6to4_dev_idx=%d niit6to4_new_idx=%d", niit6to4_dev_idx, niit6to4_new_idx);

                if (niit6to4_old_idx)
                        process_description_tlvs(NULL, &self, self.desc, TLV_OP_CUSTOM_NIIT6TO4_DEL, BMX_DSC_TLV_UHNA6, NULL);

                niit6to4_dev_idx = niit6to4_new_idx;

                if (niit6to4_new_idx)
                        process_description_tlvs(NULL, &self, self.desc, TLV_OP_CUSTOM_NIIT6TO4_ADD, BMX_DSC_TLV_UHNA6, NULL);

        }

}

STATIC_FUNC
int32_t opt_niit(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

        IPX_T vis_ip = ZERO_IP;
        uint8_t family = AF_INET;
        IDM_T enabled = NO;

        if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                if ( patch->p_diff == DEL ) {

                        vis_ip = ZERO_IP;

                } else if ( str2netw( patch->p_val, &vis_ip, '/', cn, NULL, &family ) == FAILURE  ) {

                        return FAILURE;

                } else if ( family != AF_INET ) {

                        return FAILURE;
                } else {

                        enabled = YES;

                }
        }

        if (cmd == OPT_APPLY) {
                niit_enabled = enabled;
                niit_address = vis_ip;
        }

        return SUCCESS;
}

STATIC_FUNC
IDM_T configure_niit4to6(IDM_T del, struct uhna_key *key)
{

        if (!niit4to6_dev_idx || !niit_enabled || key->family != AF_INET6 || key->prefixlen < 96 ||
                !is_ip_net_equal(&key->glip, &niit_prefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_all(DBGT_INFO, "del=%d %s/%d", del, ipXAsStr(AF_INET6, &key->glip), key->prefixlen);

        IPX_T niit_glip4 = ZERO_IP;
        niit_glip4.s6_addr32[3] = key->glip.s6_addr32[3];

        // update network routes:
        if (del) {

                return ip(AF_INET, IP_ROUTE_TUNS, DEL, NO, &niit_glip4, (key->prefixlen - 96), RT_TABLE_TUNS, 0,
                        NULL, 0, NULL, NULL, ntohl(key->metric_nl));

        } else {

                return ip(AF_INET, IP_ROUTE_TUNS, ADD, NO, &niit_glip4, (key->prefixlen - 96), RT_TABLE_TUNS, 0,
                        NULL, niit4to6_dev_idx, NULL, &niit_address, ntohl(key->metric_nl));

        }

        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_4TO6_DEV);
        return FAILURE;
}

STATIC_FUNC
IDM_T configure_niit6to4(IDM_T del, struct uhna_key *key)
{

        if (!niit6to4_dev_idx || !niit_enabled || key->family != AF_INET6 || key->prefixlen < 96 ||
                !is_ip_net_equal(&key->glip, &niit_prefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_track(DBGT_INFO, "del=%d %s/%d", del, ipXAsStr(AF_INET6, &key->glip), key->prefixlen);

        // update network routes:
        if (del) {

                return ip(AF_INET6, IP_ROUTE_TUNS, DEL, NO, &key->glip, key->prefixlen, RT_TABLE_TUNS, 0,
                        NULL, 0, NULL, NULL, ntohl(key->metric_nl));

        } else {

                return ip(AF_INET6, IP_ROUTE_TUNS, ADD, NO, &key->glip, key->prefixlen, RT_TABLE_TUNS, 0,
                        NULL, niit6to4_dev_idx, NULL, &niit_address, ntohl(key->metric_nl));

        }

        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_6TO4_DEV);
        return FAILURE;
}



STATIC_FUNC
IDM_T configure_route(IDM_T del, struct orig_node *on, struct uhna_key *key)
{

        IDM_T primary = is_ip_equal(&key->glip, &on->primary_ip);
        uint8_t cmd = primary ? IP_ROUTE_HOST : IP_ROUTE_HNA;
        int32_t table_macro = primary ? RT_TABLE_HOSTS : RT_TABLE_NETS;

        // update network routes:
        if (del) {

                return ip(key->family, cmd, DEL, NO, &key->glip, key->prefixlen, table_macro, 0,
                        NULL, 0, NULL, NULL, ntohl(key->metric_nl));

        } else {

                struct link_dev_node *lndev = on->curr_rt_lndev;

                assertion(-500820, (lndev));
                ASSERTION(-500239, (avl_find(&link_dev_tree, &(lndev->key))));
                assertion(-500579, (lndev->key.dev->if_llocal_addr));

                return ip(key->family, cmd, ADD, NO, &key->glip, key->prefixlen, table_macro, 0,
                        NULL, lndev->key.dev->if_llocal_addr->ifa.ifa_index,
                        &(lndev->key.link->link_ip), &(self.primary_ip), ntohl(key->metric_nl));

        }
}

STATIC_FUNC
void set_uhna_key(struct uhna_key *key, uint8_t family, uint8_t prefixlen, IPX_T *glip, uint32_t metric)
{
        memset( key, 0, sizeof(struct uhna_key));
        key->family = family;
        key->prefixlen = prefixlen;
        key->metric_nl = htonl(metric);
        key->glip = *glip;

}

STATIC_FUNC
void set_uhna_to_key(struct uhna_key *key, struct description_msg_hna4 *uhna4, struct description_msg_hna6 *uhna6)
{
        if (uhna4) {

                IPX_T ipX;
                ip42X(&ipX, uhna4->ip4);

                set_uhna_key(key, AF_INET, uhna4->prefixlen, &ipX, ntohl(uhna4->metric));

        } else {

                set_uhna_key(key, AF_INET6, uhna6->prefixlen, &uhna6->ip6, ntohl(uhna6->metric));

        }
}


STATIC_FUNC
int _create_tlv_hna(int family, uint8_t* data, uint16_t max_size, uint16_t pos,
        IPX_T *ip, uint32_t metric, uint16_t prefixlen)
{
        int i;
        uint16_t msg_size = family == AF_INET ?
                sizeof (struct description_msg_hna4) : sizeof (struct description_msg_hna6);


        if ((pos + msg_size) > max_size) {

                dbgf_sys(DBGT_ERR, "unable to announce %s/%d metric %d due to limiting --%s=%d",
                        ipXAsStr(family, ip), prefixlen, ntohl(metric), ARG_UDPD_SIZE, max_size);

                return pos;
        }

        dbgf_all(DBGT_INFO, "announce %s/%d metric %d ", ipXAsStr(family, ip), prefixlen, ntohl(metric));


        assertion(-500610, (!(family == AF_INET6 &&
                is_ip_net_equal(ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))));
        // this should be catched during configuration!!


        if (family == AF_INET) {
                struct description_msg_hna4 * msg4 = ((struct description_msg_hna4 *) data);

                struct description_msg_hna4 hna4;
                memset( &hna4, 0, sizeof(hna4));
                hna4.ip4 = ipXto4(*ip);
                hna4.metric = metric;
                hna4.prefixlen = prefixlen;

                for (i = 0; i < pos / msg_size; i++) {

                        if (!memcmp(&(msg4[i]), &hna4, sizeof (struct description_msg_hna4)))
                                return pos;
                }

                msg4[i] = hna4;

        } else {
                struct description_msg_hna6 * msg6 = ((struct description_msg_hna6 *) data);

                struct description_msg_hna6 hna6;
                memset( &hna6, 0, sizeof(hna6));
                hna6.ip6 = *ip;
                hna6.metric = metric;
                hna6.prefixlen = prefixlen;

                for (i = 0; i < pos / msg_size; i++) {

                        if (!memcmp(&(msg6[i]), &hna6, sizeof (struct description_msg_hna6)))
                                return pos;
                }

                msg6[i] = hna6;

        }

        dbgf_track(DBGT_INFO, "%s %s/%d metric %d", family2Str(family), ipXAsStr(family, ip), prefixlen, metric);


        return (pos + msg_size);
}

STATIC_FUNC
int create_description_tlv_hna(struct tx_frame_iterator *it)
{
        assertion(-500765, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));
        assertion(-501106, (af_cfg == AF_INET || af_cfg == AF_INET6));

        uint8_t *data = tx_iterator_cache_msg_ptr(it);
        uint16_t max_size = tx_iterator_cache_data_space(it);
        uint8_t family = it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6;
        uint8_t max_prefixlen = ort_dat[ (AFINET2BMX(family)) ].max_prefixlen;

        struct avl_node *an;
        struct uhna_node *un;
        struct dev_node *dev;
        int pos = 0;

        if (af_cfg != family || !is_ip_set(&self.primary_ip))
                return TLV_TX_DATA_IGNORED;

        pos = _create_tlv_hna(family, data, max_size, pos, &self.primary_ip, 0, max_prefixlen);

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                if (!dev->active || !dev->announce)
                        continue;

                pos = _create_tlv_hna(family, data, max_size, pos, &dev->if_global_addr->ip_addr, 0, max_prefixlen);
        }

        for (an = NULL; (un = avl_iterate_item(&local_uhna_tree, &an));) {

                if (un->key.family != family)
                        continue;

                pos = _create_tlv_hna(family, data, max_size, pos, &un->key.glip, un->key.metric_nl, un->key.prefixlen);
        }

        return pos;
}



STATIC_FUNC
void configure_uhna ( IDM_T del, struct uhna_key* key, struct orig_node *on ) {

        struct uhna_node *un = avl_find_item( &global_uhna_tree, key );

        assertion(-500589, (on));
        assertion(-500236, ((del && un) != (!del && !un)));

        // update uhna_tree:
        if ( del ) {

                assertion(-500234, (on == un->on));
                avl_remove(&global_uhna_tree, &un->key, -300212);
                ASSERTION( -500233, (!avl_find( &global_uhna_tree, key)) ); // there should be only one element with this key

                if (on == &self)
                        avl_remove(&local_uhna_tree, &un->key, -300213);

        } else {

                un = debugMalloc( sizeof (struct uhna_node), -300090 );
                un->key = *key;
                un->on = on;
                avl_insert(&global_uhna_tree, un, -300149);

                if (on == &self)
                        avl_insert(&local_uhna_tree, un, -300150);

        }


        if (on == &self) {

                // update throw routes:
                if (policy_routing == POLICY_RT_ENABLED && ip_throw_rules_cfg) {
                        ip(key->family, IP_THROW_MY_HNA, del, NO, &key->glip, key->prefixlen, RT_TABLE_HOSTS, 0, 0, 0, 0, 0, 0);
                        ip(key->family, IP_THROW_MY_HNA, del, NO, &key->glip, key->prefixlen, RT_TABLE_NETS, 0, 0, 0, 0, 0, 0);
                        ip(key->family, IP_THROW_MY_HNA, del, NO, &key->glip, key->prefixlen, RT_TABLE_TUNS, 0, 0, 0, 0, 0, 0);
                }

                my_description_changed = YES;

        } else if (on->curr_rt_lndev) {

                configure_route(del, on, key);
                configure_niit4to6(del, key);
        }


        if (del)
                debugFree(un, -300089);

}



STATIC_FUNC
int process_description_tlv_hna(struct rx_frame_iterator *it)
{
        ASSERTION(-500357, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));
        assertion(-500588, (it->on));
        assertion(-501107, (af_cfg == AF_INET || af_cfg == AF_INET6));

        struct orig_node *on = it->on;
        uint8_t op = it->op;
        uint8_t family = (it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6);

        if (af_cfg != family) {
                dbgf_sys(DBGT_ERR, "invalid family %s", family2Str(family));
                return TLV_RX_DATA_BLOCKED;
        }

        uint16_t msg_size = it->handls[it->frame_type].min_msg_size;
        uint16_t pos;

        for (pos = 0; pos < it->frame_msgs_length; pos += msg_size) {

                struct uhna_key key;

                if (it->frame_type == BMX_DSC_TLV_UHNA4)
                        set_uhna_to_key(&key, (struct description_msg_hna4 *) (it->frame_data + pos), NULL);

                else
                        set_uhna_to_key(&key, NULL, (struct description_msg_hna6 *) (it->frame_data + pos));



                dbgf_all(DBGT_INFO, "%s %s %s=%s/%d %s=%d",
                        tlv_op_str(op), family2Str(key.family), ARG_UHNA,
                        ipXAsStr(key.family, &key.glip), key.prefixlen, ARG_UHNA_METRIC, ntohl(key.metric_nl));

                if (op == TLV_OP_DEL) {

                        configure_uhna(DEL, &key, on);

                        if (pos == 0 && key.family == family) {
                                on->primary_ip = ZERO_IP;
                                ip2Str(family, &ZERO_IP, on->primary_ip_str);
                        }

                } else if (op == TLV_OP_TEST) {

                        struct uhna_node *un = NULL;

                        if (!is_ip_set(&key.glip) || is_ip_forbidden( &key.glip, family ) ||
                                (un = avl_find_item(&global_uhna_tree, &key))) {

                                dbgf_sys(DBGT_ERR,
                                        "global_id=%s %s=%s/%d %s=%d blocked by global_id=%s ",
                                        globalIdAsString(&on->global_id),
                                        ARG_UHNA, ipXAsStr(key.family, &key.glip), key.prefixlen,
                                        ARG_UHNA_METRIC, ntohl(key.metric_nl),
                                        un ? globalIdAsString(&un->on->global_id) : "???");

                                return TLV_RX_DATA_BLOCKED;
                        }

                        if (is_ip_net_equal(&key.glip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)) {

                                dbgf_sys(DBGT_ERR, "NO link-local addresses %s", ipXAsStr(key.family, &key.glip));

                                return TLV_RX_DATA_BLOCKED;
                        }


                } else if (op == TLV_OP_ADD) {

                        //TODO: return with TLVS_BLOCKED because this happens when node announces the same key twice !!!
                        ASSERTION( -500359, (!avl_find(&global_uhna_tree, &key)));

                        if (pos == 0 && key.family == family) {
                                on->primary_ip = key.glip;
                                ip2Str(key.family, &key.glip, on->primary_ip_str);
                        }

                        configure_uhna(ADD, &key, on);


                } else if (op >= TLV_OP_CUSTOM_MIN) {

                        dbgf_all(DBGT_INFO, "configure_niit... op=%d  global_id=%s blocked=%d",
                                op, globalIdAsString(&on->global_id), on->blocked);

                        if (!on->blocked) {
                                ASSERTION(-501141, (avl_find(&global_uhna_tree, &key)));

                                if (op == TLV_OP_CUSTOM_NIIT6TO4_ADD) {
                                        configure_niit6to4(ADD, &key);
                                } else if (op == TLV_OP_CUSTOM_NIIT6TO4_DEL) {
                                        configure_niit6to4(DEL, &key);
                                } else if (op == TLV_OP_CUSTOM_NIIT4TO6_ADD) {
                                        configure_niit4to6(ADD, &key);
                                } else if (op == TLV_OP_CUSTOM_NIIT4TO6_DEL) {
                                        configure_niit4to6(DEL, &key);
                                } else if (op == TLV_OP_CUSTOM_HNA_ROUTE_DEL) {
                                        configure_niit4to6(DEL, &key);
                                        configure_route(DEL, on, &key);
                                } else if (op == TLV_OP_CUSTOM_HNA_ROUTE_ADD) {
                                        configure_route(ADD, on, &key);
                                        configure_niit4to6(ADD, &key);
                                } else {
                                        assertion(-501142, (NO));
                                }
                        }

                } else {
                        assertion( -500369, (NO));
                }
        }

        dbgf((it->frame_msgs_length == pos) ? DBGL_ALL : DBGL_SYS, (it->frame_msgs_length == pos) ? DBGT_INFO : DBGT_ERR,
                "processed %d bytes frame_msgs_len=%d msg_size=%d", pos, it->frame_msgs_length, msg_size);

        return pos;
}





STATIC_FUNC
int32_t opt_uhna(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        IPX_T ipX;
	uint8_t mask;
        uint32_t metric = 0;
        struct uhna_key key;
	char new[IPXNET_STR_LEN];

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                assertion(-501109, (af_cfg == AF_INET || af_cfg == AF_INET6));

                uint8_t family = 0;

		dbgf_all(DBGT_INFO, "diff=%d cmd =%s  save=%d  opt=%s  patch=%s",
		        patch->p_diff, opt_cmd2str[cmd], _save, opt->long_name, patch->p_val);


                if (strchr(patch->p_val, '/')) {

                        if (str2netw(patch->p_val, &ipX, '/', cn, &mask, &family) == FAILURE)
                                family = 0;

			// the unnamed UHNA
                        dbgf_all(DBGT_INFO, "unnamed %s %s diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                                ARG_UHNA, family2Str(family), patch->p_diff, opt_cmd2str[cmd], _save, opt->long_name, patch->p_val);

                        if ( family != AF_INET && family != AF_INET6)
                                return FAILURE;

                        if (af_cfg && af_cfg != family)
                                return FAILURE;
                        else
                                af_cfg = family;

                        if (is_ip_forbidden(&ipX, family) || ip_netmask_validate(&ipX, mask, family, NO) == FAILURE) {
                                dbg_cn(cn, DBGL_SYS, DBGT_ERR,
                                        "invalid prefix %s/%d", ipXAsStr(family, &ipX), mask);
                                return FAILURE;
                        }

                        sprintf(new, "%s/%d", ipXAsStr(family, &ipX), mask);

			set_opt_parent_val( patch, new );

			if ( cmd == OPT_ADJUST )
				return SUCCESS;

		} else {
                        return FAILURE;

                }


                set_uhna_key(&key, family, mask, &ipX, metric);

                struct uhna_node *un;

                if (patch->p_diff != DEL && (un = (avl_find_item(&global_uhna_tree, &key)))) {

			dbg_cn( cn, DBGL_CHANGES, DBGT_ERR,
                                "UHNA %s/%d metric %d already blocked by global_id=%s !",
                                ipXAsStr(key.family, &key.glip), mask, metric,
                                (un->on == &self ? "MYSELF" : globalIdAsString(&un->on->global_id)));

                        return FAILURE;
		}

		if ( cmd == OPT_APPLY )
                        configure_uhna((patch->p_diff == DEL ? DEL : ADD), &key, &self);



	} else if ( cmd == OPT_UNREGISTER ) {

                struct uhna_node * un;

                while ((un = avl_first_item(&global_uhna_tree)))
                        configure_uhna(DEL, &un->key, &self);

	}

	return SUCCESS;

}





STATIC_FUNC
struct opt_type hna_options[]= {
//     		ord parent long_name   shrt Attributes				*ival		min		max		default		*function

	{ODI,0,ARG_UHNA,	 	'a',5,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_PREFIX_FORM,"specify host-network announcement (HNA) for defined ip range"}
        ,
/*
        ,
	{ODI,ARG_UHNA,ARG_UHNA_NETWORK,	'n',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_NETW_FORM, 	"specify network of announcement"}
        ,
	{ODI,ARG_UHNA,ARG_UHNA_PREFIXLEN,'p',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_MASK_FORM, 	"specify network prefix of announcement"}
        ,
	{ODI,ARG_UHNA,ARG_UHNA_METRIC,   'm',5,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		MIN_UHNA_METRIC,MAX_UHNA_METRIC,DEF_UHNA_METRIC,0,opt_uhna,
			ARG_VALUE_FORM, "specify hna-metric of announcement (0 means highest preference)"}
*/
	{ODI,0,ARG_NIIT,        	0,  5,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_niit,
			ARG_ADDR_FORM,HLP_NIIT}

};


STATIC_FUNC
void hna_route_change_hook(uint8_t del, struct orig_node *on)
{
        assertion(-501110, (af_cfg == AF_INET || af_cfg == AF_INET6));

        dbgf_all(DBGT_INFO, "global_id=%s", globalIdAsString(&on->global_id));

        if (!is_ip_set(&on->primary_ip))
                return;

        process_description_tlvs(NULL, on, on->desc,
                del ? TLV_OP_CUSTOM_HNA_ROUTE_DEL : TLV_OP_CUSTOM_HNA_ROUTE_ADD,
                af_cfg == AF_INET ? BMX_DSC_TLV_UHNA4 : BMX_DSC_TLV_UHNA6, NULL);

}









STATIC_FUNC
void hna_cleanup( void )
{
        set_route_change_hooks(hna_route_change_hook, DEL);
}


STATIC_FUNC
int32_t hna_init( void )
{
        struct frame_handl tlv_handl;
        
        static const struct field_format hna4_format[] = DESCRIPTION_MSG_HNA4_FORMAT;
        static const struct field_format hna6_format[] = DESCRIPTION_MSG_HNA6_FORMAT;


        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_hna4);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.name = "DESC_EXT_UHNA4";
        tlv_handl.tx_frame_handler = create_description_tlv_hna;
        tlv_handl.rx_frame_handler = process_description_tlv_hna;
        tlv_handl.msg_format = hna4_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_UHNA4, &tlv_handl);


        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_hna6);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.name = "DESC_EXT_UHNA6";
        tlv_handl.tx_frame_handler = create_description_tlv_hna;
        tlv_handl.rx_frame_handler = process_description_tlv_hna;
        tlv_handl.msg_format = hna6_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_UHNA6, &tlv_handl);

        set_route_change_hooks(hna_route_change_hook, ADD);

        register_options_array(hna_options, sizeof ( hna_options), CODE_CATEGORY_NAME);

        return SUCCESS;
}


struct plugin *hna_get_plugin( void ) {

	static struct plugin hna_plugin;
	memset( &hna_plugin, 0, sizeof ( struct plugin ) );

	hna_plugin.plugin_name = CODE_CATEGORY_NAME;
	hna_plugin.plugin_size = sizeof ( struct plugin );
        hna_plugin.plugin_code_version = CODE_VERSION;
        hna_plugin.cb_init = hna_init;
	hna_plugin.cb_cleanup = hna_cleanup;
        hna_plugin.cb_plugin_handler[PLUGIN_CB_SYS_DEV_EVENT] = niit_dev_event_hook;
        hna_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_CREATED] = (void (*) (int32_t, void*)) niit_description_event_hook;
        hna_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_DESTROY] = (void (*) (int32_t, void*)) niit_description_event_hook;

        return &hna_plugin;
}


