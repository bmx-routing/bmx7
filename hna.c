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
#include "tools.h"
#include "metrics.h"

#define CODE_CATEGORY_NAME "hna"

static AVL_TREE(global_uhna_tree, struct hna_node, key );
static AVL_TREE(local_uhna_tree, struct hna_node, key );

static AVL_TREE(tunnel_in_tree, struct tun_in_node, srcTunIp);
static AVL_TREE(network_tree, struct tun_search_node, networkName);


static IPX_T niit_address;

static int niit4to6_dev_idx = 0;
static int niit6to4_dev_idx = 0;
static IPX_T niit_prefix96 = DEF_NIIT_PREFIX;

//static int32_t tun_orig_registry = FAILURE;
//static int32_t gw_orig_registry = FAILURE;

static IFNAME_T tun_name_prefix = {{DEF_TUN_NAME_PREFIX}};


STATIC_FUNC
void hna_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        if (on != self)
                return;

        dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

        assertion(-501245, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501246, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {
                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT6TO4_DEL, BMX_DSC_TLV_UHNA6, NULL);
        }

        if (cb_id == PLUGIN_CB_DESCRIPTION_CREATED) {
                process_description_tlvs(NULL, on, on->desc, TLV_OP_CUSTOM_NIIT6TO4_ADD, BMX_DSC_TLV_UHNA6, NULL);
        }
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

        if (!niit_enabled || af_cfg() == AF_INET)
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

                        if (on == self)
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
                        process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_DEL, BMX_DSC_TLV_UHNA6, NULL);

                niit6to4_dev_idx = niit6to4_new_idx;

                if (niit6to4_new_idx)
                        process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_ADD, BMX_DSC_TLV_UHNA6, NULL);

        }

}

STATIC_FUNC
int32_t opt_niit(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

        IPX_T ipX = ZERO_IP;
        uint8_t family = AF_INET;
        IDM_T enabled = NO;

        if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                if ( patch->diff == DEL ) {

                        ipX = ZERO_IP;

                } else if ( str2netw( patch->val, &ipX, cn, NULL, &family ) == FAILURE  ) {

                        return FAILURE;

                } else if ( family != AF_INET ) {

                        return FAILURE;
                } else {

                        enabled = YES;

                }
        }

        if (cmd == OPT_APPLY) {
                niit_enabled = enabled;
                niit_address = ipX;

                niit_dev_event_hook(PLUGIN_CB_SYS_DEV_EVENT, NULL);

                my_description_changed = YES;

        }

        return SUCCESS;
}

STATIC_FUNC
IDM_T configure_niit4to6(IDM_T del, struct net_key *key)
{

        if (!niit4to6_dev_idx || !niit_enabled || af_cfg() != AF_INET6 || key->prefixlen < 96 ||
                !is_ip_net_equal(&key->net, &niit_prefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_all(DBGT_INFO, "del=%d %s/%d", del, ipXAsStr(AF_INET6, &key->net), key->prefixlen);

        IPX_T niit_glip4 = ZERO_IP;
        niit_glip4.s6_addr32[3] = key->net.s6_addr32[3];

        // update network routes:
        if (del) {

                return ip(AF_INET, IP_ROUTE_TUNS, DEL, NO, &niit_glip4, (key->prefixlen - 96), RT_TABLE_TUNS, 0,
                        NULL, 0, NULL, NULL, DEF_IP_METRIC);

        } else {

                return ip(AF_INET, IP_ROUTE_TUNS, ADD, NO, &niit_glip4, (key->prefixlen - 96), RT_TABLE_TUNS, 0,
                        NULL, niit4to6_dev_idx, NULL, &niit_address, DEF_IP_METRIC);

        }

        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_4TO6_DEV);
        return FAILURE;
}

STATIC_FUNC
IDM_T configure_niit6to4(IDM_T del, struct net_key *key)
{

        if (!niit6to4_dev_idx || !niit_enabled || af_cfg() != AF_INET6 || key->prefixlen < 96 ||
                !is_ip_net_equal(&key->net, &niit_prefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_track(DBGT_INFO, "del=%d %s/%d", del, ipXAsStr(AF_INET6, &key->net), key->prefixlen);

        // update network routes:
        if (del) {

                return ip(AF_INET6, IP_ROUTE_TUNS, DEL, NO, &key->net, key->prefixlen, RT_TABLE_TUNS, 0,
                        NULL, 0, NULL, NULL, DEF_IP_METRIC);

        } else {

                return ip(AF_INET6, IP_ROUTE_TUNS, ADD, NO, &key->net, key->prefixlen, RT_TABLE_TUNS, 0,
                        NULL, niit6to4_dev_idx, NULL, &niit_address, DEF_IP_METRIC);

        }

        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_6TO4_DEV);
        return FAILURE;
}



STATIC_FUNC
IDM_T configure_route(IDM_T del, struct orig_node *on, struct net_key *key)
{

        IDM_T primary = is_ip_equal(&key->net, &on->primary_ip);
        uint8_t cmd = primary ? IP_ROUTE_HOST : IP_ROUTE_HNA;
        int32_t table_macro = primary ? RT_TABLE_HOSTS : RT_TABLE_NETS;

        // update network routes:
        if (del) {

                return ip(af_cfg(), cmd, DEL, NO, &key->net, key->prefixlen, table_macro, 0,
                        NULL, 0, NULL, NULL, DEF_IP_METRIC);

        } else {

                struct link_dev_node *lndev = on->curr_rt_lndev;

                assertion(-500820, (lndev));
                ASSERTION(-500239, (avl_find(&link_dev_tree, &(lndev->key))));
                assertion(-500579, (lndev->key.dev->if_llocal_addr));

                return ip(af_cfg(), cmd, ADD, NO, &key->net, key->prefixlen, table_macro, 0,
                        NULL, lndev->key.dev->if_llocal_addr->ifa.ifa_index,
                        &(lndev->key.link->link_ip), &(self->primary_ip), DEF_IP_METRIC);

        }
}

STATIC_FUNC
void set_net_key(struct net_key *key, uint8_t prefixlen, IPX_T *glip)
{
        memset( key, 0, sizeof(struct net_key));
        key->prefixlen = prefixlen;
        key->net = *glip;

}

STATIC_FUNC
void set_hna_to_key(struct net_key *key, struct description_msg_hna4 *uhna4, struct description_msg_hna6 *uhna6)
{
        if (uhna4) {

                IPX_T ipX;
                ip4ToX(&ipX, uhna4->ip4);

                set_net_key(key, uhna4->prefixlen, &ipX);

        } else {

                set_net_key(key, uhna6->prefixlen, &uhna6->ip6);

        }
}


STATIC_FUNC
int _create_tlv_hna(int family, uint8_t* data, uint16_t max_size, uint16_t pos,
        IPX_T *ip, uint16_t prefixlen)
{
        int i;
        uint16_t msg_size = family == AF_INET ?
                sizeof (struct description_msg_hna4) : sizeof (struct description_msg_hna6);


        if ((pos + msg_size) > max_size) {

                dbgf_sys(DBGT_ERR, "unable to announce %s/%d due to limiting --%s=%d",
                        ipXAsStr(family, ip), prefixlen, ARG_UDPD_SIZE, max_size);

                return pos;
        }

        dbgf_all(DBGT_INFO, "announce %s/%d", ipXAsStr(family, ip), prefixlen);


        assertion(-500610, (!(family == AF_INET6 &&
                is_ip_net_equal(ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))));
        // this should be catched during configuration!!


        if (family == AF_INET) {
                struct description_msg_hna4 * msg4 = ((struct description_msg_hna4 *) data);

                struct description_msg_hna4 hna4;
                memset( &hna4, 0, sizeof(hna4));
                hna4.ip4 = ipXto4(*ip);
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
                hna6.prefixlen = prefixlen;

                for (i = 0; i < pos / msg_size; i++) {

                        if (!memcmp(&(msg6[i]), &hna6, sizeof (struct description_msg_hna6)))
                                return pos;
                }

                msg6[i] = hna6;

        }

        dbgf_track(DBGT_INFO, "%s %s/%d", family2Str(family), ipXAsStr(family, ip), prefixlen);


        return (pos + msg_size);
}

STATIC_FUNC
int create_description_tlv_hna(struct tx_frame_iterator *it)
{
        assertion(-500765, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));

        uint8_t *data = tx_iterator_cache_msg_ptr(it);
        uint16_t max_size = tx_iterator_cache_data_space(it);
        uint8_t family = it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6;
        uint8_t max_prefixlen = ort_dat[ (AFINET2BMX(family)) ].max_prefixlen;

        struct avl_node *an;
        struct hna_node *un;
        struct dev_node *dev;
        int pos = 0;

        if (af_cfg() != family || !is_ip_set(&self->primary_ip))
                return TLV_TX_DATA_IGNORED;

        pos = _create_tlv_hna(family, data, max_size, pos, &self->primary_ip, max_prefixlen);

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                if (!dev->active || !dev->announce)
                        continue;

                pos = _create_tlv_hna(family, data, max_size, pos, &dev->if_global_addr->ip_addr, max_prefixlen);
        }

        for (an = NULL; (un = avl_iterate_item(&local_uhna_tree, &an));)
                pos = _create_tlv_hna(family, data, max_size, pos, &un->key.net, un->key.prefixlen);


        return pos;
}





STATIC_FUNC
void configure_hna ( IDM_T del, struct net_key* key, struct orig_node *on ) {

        struct hna_node *un = avl_find_item( &global_uhna_tree, key );

        assertion(-500589, (on));
        assertion(-500236, ((del && un) != (!del && !un)));

        // update uhna_tree:
        if ( del ) {

                assertion(-500234, (on == un->on));
                avl_remove(&global_uhna_tree, &un->key, -300212);
                ASSERTION( -500233, (!avl_find( &global_uhna_tree, key)) ); // there should be only one element with this key

                if (on == self)
                        avl_remove(&local_uhna_tree, &un->key, -300213);

        } else {

                un = debugMalloc( sizeof (struct hna_node), -300090 );
                un->key = *key;
                un->on = on;
                avl_insert(&global_uhna_tree, un, -300149);

                if (on == self)
                        avl_insert(&local_uhna_tree, un, -300150);

        }


        if (on == self) {

                // update throw routes:
                if (policy_routing == POLICY_RT_ENABLED && ip_throw_rules_cfg) {
                        ip(af_cfg(), IP_THROW_MY_HNA, del, NO, &key->net, key->prefixlen, RT_TABLE_HOSTS, 0, 0, 0, 0, 0, 0);
                        ip(af_cfg(), IP_THROW_MY_HNA, del, NO, &key->net, key->prefixlen, RT_TABLE_NETS, 0, 0, 0, 0, 0, 0);
                        ip(af_cfg(), IP_THROW_MY_HNA, del, NO, &key->net, key->prefixlen, RT_TABLE_TUNS, 0, 0, 0, 0, 0, 0);
                }

        } else if (on->curr_rt_lndev) {

                configure_route(del, on, key);
                configure_niit4to6(del, key);
        }


        if (del)
                debugFree(un, -300089);

}


STATIC_FUNC
struct hna_node * find_overlapping_hna( IPX_T *ipX, uint8_t prefixlen )
{
        struct hna_node *un;
        struct avl_node *it = NULL;

        while ((un = avl_iterate_item(&global_uhna_tree, &it))) {

                if (is_ip_net_equal(ipX, &un->key.net, MIN(prefixlen, un->key.prefixlen), af_cfg()))
                        return un;

        }
        return NULL;
}

STATIC_FUNC
int process_description_tlv_hna(struct rx_frame_iterator *it)
{
        ASSERTION(-500357, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));
        assertion(-500588, (it->on));

        struct orig_node *on = it->on;
        uint8_t op = it->op;
        uint8_t family = (it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6);

        if (af_cfg() != family) {
                dbgf_sys(DBGT_ERR, "invalid family %s", family2Str(family));
                return TLV_RX_DATA_BLOCKED;
        }

        uint16_t msg_size = it->handls[it->frame_type].min_msg_size;
        uint16_t pos;

        for (pos = 0; pos < it->frame_msgs_length; pos += msg_size) {

                struct net_key key;

                if (it->frame_type == BMX_DSC_TLV_UHNA4)
                        set_hna_to_key(&key, (struct description_msg_hna4 *) (it->frame_data + pos), NULL);
                else
                        set_hna_to_key(&key, NULL, (struct description_msg_hna6 *) (it->frame_data + pos));


                dbgf_track(DBGT_INFO, "%s %s %s %s=%s/%d",
                        tlv_op_str(op), family2Str(family), globalIdAsString(&on->global_id), ARG_UHNA,
                        ipXAsStr(family, &key.net), key.prefixlen);

                if (op == TLV_OP_DEL) {

                        configure_hna(DEL, &key, on);

                        if (pos == 0) {
                                on->primary_ip = ZERO_IP;
                                ipXToStr(family, &ZERO_IP, on->primary_ip_str);
                        }

                } else if (op == TLV_OP_TEST) {

                        struct hna_node *un = NULL;

                        if (is_ip_invalid(&key.net, family) || (un = find_overlapping_hna(&key.net, key.prefixlen)) ||
                                is_ip_net_equal(&key.net, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)) {

                                dbgf_sys(DBGT_ERR, "global_id=%s %s=%s/%d blocked (by global_id=%s)",
                                        globalIdAsString(&on->global_id),
                                        ARG_UHNA, ipXAsStr(family, &key.net), key.prefixlen,
                                        un ? globalIdAsString(&un->on->global_id) : "???");

                                return TLV_RX_DATA_BLOCKED;
                        }


                        // check if node announces the same key twice:
                        assertion(-500000, (it->misc_ptr));

                        uint32_t i;
                        struct net_key *k = (struct net_key*) *(it->misc_ptr);
                        for (i = 0; i < it->misc_uint; i++) {
                                if (!memcmp(&k[i], &key, sizeof (key)))
                                        return TLV_RX_DATA_BLOCKED;
                        }

                        *it->misc_ptr = debugRealloc(*it->misc_ptr, (i + 1) * sizeof (key), -300398);

                        memcpy(&(((struct net_key*) *(it->misc_ptr))[i]), &key, sizeof(key));
                        it->misc_uint = i + 1;



                } else if (op == TLV_OP_ADD) {

                        ASSERTION( -500359, (!avl_find(&global_uhna_tree, &key)));

                        if (pos == 0) {
                                on->primary_ip = key.net;
                                ipFToStr( &key.net, on->primary_ip_str);
                        }

                        configure_hna(ADD, &key, on);


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
	char new[IPXNET_STR_LEN];

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                uint8_t family = 0;
                struct net_key key;
                struct hna_node *un;

                dbgf_all(DBGT_INFO, "af_cfg=%s diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        family2Str(af_cfg()), patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (str2netw(patch->val, &ipX, cn, &mask, &family) == FAILURE || family != af_cfg()) {

                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid prefix: %s", patch->val);
                        return FAILURE;
                }

                sprintf(new, "%s/%d", ipXAsStr(family, &ipX), mask);

                set_opt_parent_val(patch, new);

                if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

                        
                        set_net_key(&key, mask, &ipX);


                        if (patch->diff != DEL && (un = find_overlapping_hna(&key.net, key.prefixlen))) {

                                dbg_cn(cn, DBGL_CHANGES, DBGT_ERR,
                                        "UHNA %s/%d already blocked by global_id=%s !",
                                        ipFAsStr(&key.net), mask,
                                        (un->on == self ? "MYSELF" : globalIdAsString(&un->on->global_id)));

                                return FAILURE;
                        }
                }

                if (cmd == OPT_APPLY) {
                        configure_hna((patch->diff == DEL ? DEL : ADD), &key, self);
                        my_description_changed = YES;
                }


	} else if ( cmd == OPT_UNREGISTER ) {

                struct hna_node * un;

                while ((un = avl_first_item(&global_uhna_tree)))
                        configure_hna(DEL, &un->key, self);
	}

	return SUCCESS;
}











STATIC_FUNC
void configure_tun_in(uint8_t del, struct orig_node *on, struct tun_in_node *tun)
{

        assertion(-501292, (is_ip_set(&tun->srcTunIp)));
        assertion(-500000, on && is_ip_set(&on->primary_ip));
        assertion(-501294, IMPLIES(tun->up, tun->name.str[0]));
        assertion(-501295, IMPLIES(tun->up, del));

        if (del) {

                if (!tun->up)
                        return;

                iptunnel(DEL, tun->name.str, 0, NULL, NULL);
                tun->up = 0;

        } else {


                IPX_T *local = (on == self) ? &on->primary_ip : &tun->srcTunIp;
                IPX_T *remote = (on == self) ? &tun->srcTunIp : &on->primary_ip;


                if (tun->name_auto) {

                        static uint16_t tun_idx = 0;
                        struct if_link_node *iln = NULL;

                        do {
                                memset(&tun->name, 0, sizeof (tun->name));
                                snprintf(tun->name.str, IFNAMSIZ - 1, "%s_%s%.4X",
                                        tun_name_prefix.str, (on == self ? "in" : "out"), tun_idx++);

                                struct avl_node *an = NULL;
                                iln = NULL;
                                //check if tun->name is already used:
                                while ((iln = avl_iterate_item(&if_link_tree, &an)) && strcmp(iln->name.str, tun->name.str));

                        } while (iln);

                }

                assertion(-501292, (strlen(tun->name.str)));

                if (iptunnel(ADD, tun->name.str, IPPROTO_IP, local, remote) == SUCCESS)
                        tun->up = 1;
        }
}


STATIC_FUNC
int process_description_tlv_tun_adv(struct rx_frame_iterator *it)
{
        struct orig_node *on = it->on;
        uint8_t op = it->op;
        uint16_t msg_size = it->handls[it->frame_type].min_msg_size;
        uint16_t msgs = it->frame_msgs_length / msg_size;
        uint16_t m;
        struct description_msg_tun_adv *adv = (((struct description_msg_tun_adv *) (it->frame_data)));

        if (af_cfg() != AF_INET6)
                return TLV_RX_DATA_IGNORED;

        for (m = 0; m < msgs; m++) {


                if (op == TLV_OP_DEL) {


                } else if (op == TLV_OP_TEST) {

                        if (is_ip_invalid(&adv->srcTunIp, AF_INET6) || find_overlapping_hna(&adv->srcTunIp, 128) ||
                                is_ip_net_equal(&adv->srcTunIp, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))
                                return TLV_RX_DATA_BLOCKED;



                } else if (op == TLV_OP_ADD) {


                }

                adv++;
        }

        return it->frame_msgs_length;
}




STATIC_FUNC
int create_description_tlv_tun_adv(struct tx_frame_iterator *it)
{
        struct description_msg_tun_adv *msg = ((struct description_msg_tun_adv *) tx_iterator_cache_msg_ptr(it));
        uint16_t m = 0, max = tx_iterator_cache_data_space(it) / sizeof (struct description_msg_tun_adv);
        struct opt_type *o = get_option(NULL, NO, ARG_TUN_ADV);
        struct opt_parent *p = NULL;
        struct opt_child *c = NULL;
        struct tun_in_node *tun;
        struct avl_node *an = NULL;

        if (af_cfg() != AF_INET6)
                return TLV_TX_DATA_IGNORED;

        while ((tun = avl_iterate_item(&tunnel_in_tree, &an)))
                configure_tun_in(DEL, self, tun);

        while ((p = list_iterate(&o->d.parents_instance_list, p)) && m <= max) {

                struct description_msg_tun_adv gw;
                memset(&gw, 0, sizeof (gw));

                while ((c = list_iterate(&p->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC)) {
                                str2netw(c->val, &gw.srcTunIp, NULL, NULL, NULL);
                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_BW)) {
                                UMETRIC_T um = strtoul(c->val, NULL, 10);
                                gw.bandwidth = umetric_to_fmu8(&um);
                        }
                }

                if (!is_ip_set(&gw.srcTunIp) && (tun = avl_first_item(&tunnel_in_tree)))
                        gw.srcTunIp = tun->srcTunIp;

                str2netw(p->val, &gw.network, NULL, &gw.prefixlen, NULL);

                if ((tun = avl_find_item(&tunnel_in_tree, &gw.srcTunIp)) && !tun->up)
                        configure_tun_in(ADD, self, tun);

                if (tun && tun->up) {
                        dbgf_track(DBGT_INFO, "src=%s dst=%s", ip6AsStr(&gw.srcTunIp), ip6AsStr(&gw.network));
                        msg[m++] = gw;
                } else {
                        continue;
                }
        }

        if (m)
                return m * sizeof (struct description_msg_tun_adv);
        else
                return TLV_TX_DATA_IGNORED;
}



STATIC_FUNC
int32_t opt_gw_in(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK) {

                uint8_t family = 0;
                uint8_t mask;
                IPX_T dst;

                dbgf_all(DBGT_INFO, "af_cfg=%s diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        family2Str(af_cfg()), patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (str2netw(patch->val, &dst, cn, &mask, &family) == FAILURE) {
                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s", ARG_TUN_ADV, patch->val);
                        return FAILURE;
                }

                if(cmd == OPT_ADJUST) {
                        char adjusted_dst[IPXNET_STR_LEN];
                        sprintf(adjusted_dst, "%s/%d", ipXAsStr(family, &dst), mask);
                        set_opt_parent_val(patch, adjusted_dst);
                }


                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_ADV_BW) && c->val) {

                                char *endptr;
                                unsigned long long ull = strtoul(c->val, &endptr, 10);

                                if (ull > UMETRIC_MAX || ull < UMETRIC_FM8_MIN || *endptr != '\0')
                                        return FAILURE;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC) && c->val) {

                                IPX_T src;
                                uint8_t family = 0;

                                if (str2netw(c->val, &src, cn, NULL, &family) == FAILURE || family != AF_INET6) {
                                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s", ARG_TUN_ADV_SRC, c->val);
                                        return FAILURE;
                                }

                                if (cmd == OPT_ADJUST) {
                                        char adjusted_src[IPXNET_STR_LEN];
                                        sprintf(adjusted_src, "%s", ipXAsStr(AF_INET6, &src));
                                        set_opt_child_val(c, adjusted_src);
                                }
                        }
                }
	}


        if (cmd == OPT_APPLY) {
                my_description_changed = YES;
        }

	return SUCCESS;
}

STATIC_FUNC
void configure_tun_out(IDM_T del, struct tun_search_node *net, struct ctrl_node *cn)
{
        dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "%s %s: %s/%d %s",
                del ? "DEL" : "ADD", net->networkName, ipXAsStr(net->family, &net->network), net->prefixlen,
                globalIdAsString(&net->global_id));
}

STATIC_FUNC
int32_t opt_gw_out(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        struct tun_search_node *net = NULL;

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

                struct opt_child *c = NULL;
                char name[NETWORK_NAME_LEN] = {0};

                dbgf_all(DBGT_INFO, "af_cfg=%s diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        family2Str(af_cfg()), patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (strlen(patch->val) >= NETWORK_NAME_LEN || validate_name_string(patch->val, strlen(patch->val) + 1) != SUCCESS)
                        return FAILURE;

                strcpy(name, patch->val);

                if (cmd == OPT_APPLY) {
                        net = avl_find_item(&network_tree, name);
                        
                        if (net && net->tun_adv) {
                                configure_tun_out(DEL, net, cn);
                        }
                        
                        if (patch->diff != DEL && !net) {
                                net = debugMalloc(sizeof (struct tun_search_node), -300400);
                                memset(net, 0, sizeof (struct tun_search_node));
                                strcpy(net->networkName, name);
                                avl_insert(&network_tree, net, -300401);
                        }
                }


                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_SEARCH_NETWORK)) {

                                if (c->val) {
                                        uint8_t family = 0;
                                        uint8_t mask;
                                        IPX_T dst;
                                        char adjusted_dst[IPXNET_STR_LEN];
                                        
                                        if (str2netw(c->val, &dst, cn, &mask, &family) == FAILURE)
                                                return FAILURE;


                                        sprintf(adjusted_dst, "%s/%d", ipXAsStr(family, &dst), mask);
                                        set_opt_child_val(c, adjusted_dst);

                                        if (cmd == OPT_APPLY && net) {
                                                net->network = dst;
                                                net->prefixlen = mask;
                                                net->family = family;
                                        }

                                } else if (cmd == OPT_APPLY && net) {
                                        net->network = ZERO_IP;
                                        net->prefixlen = 0;
                                        net->family = 0;
                                }


                        } else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_HOSTNAME) ) {

                                if (c->val) {

                                        if (strlen(c->val) > GLOBAL_ID_NAME_LEN ||
                                                validate_name_string(c->val, strlen(c->val) + 1) != SUCCESS)
                                                return FAILURE;

                                        if (cmd == OPT_APPLY && net) {
                                                memset(net->global_id.name, 0, sizeof (net->global_id.name));
                                                sprintf(net->global_id.name, c->val);
                                        }
                                        
                                } else if ( cmd == OPT_APPLY && net ) {
                                        memset(net->global_id.name, 0, sizeof (net->global_id.name));
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_PKID)) {

                                if (c->val) {

                                        uint8_t pkid[GLOBAL_ID_PKID_LEN] = {0};

                                        if (hexStrToMem(c->val, pkid, GLOBAL_ID_PKID_LEN) == FAILURE)
                                                        return FAILURE;


                                        set_opt_child_val(c, memAsHexString(pkid, GLOBAL_ID_PKID_LEN));

                                        if (cmd == OPT_APPLY && net)
                                                memcpy(&net->global_id.pkid, pkid, GLOBAL_ID_PKID_LEN);

                                } else if (cmd == OPT_APPLY && net) {
                                        memset(&net->global_id.pkid, 0, GLOBAL_ID_PKID_LEN);
                                }
                        }
                }
        }



        if (cmd == OPT_APPLY && net) {

                if (patch->diff == DEL) {
                        avl_remove(&network_tree, &net->networkName, -300402);
                        debugFree(net, -300403);
                } else {
                        configure_tun_out(ADD, net, cn);
                }
        }

        if (  cmd == OPT_UNREGISTER ) {

                while ((net = avl_first_item(&network_tree))) {

                        configure_tun_out(DEL, net, cn);
                        avl_remove(&network_tree, &net->networkName, -300404);
                        debugFree(net, -300405);
                }
        }




        return SUCCESS;
}




STATIC_FUNC
int32_t opt_tun_in(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        IPX_T src;
        struct tun_in_node *tun;
        struct opt_child *c = NULL;

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                uint8_t family = 0;
                struct hna_node *un = NULL;;
                char adjusted_src[IPXNET_STR_LEN];

                
                dbgf_track(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (str2netw(patch->val, &src, cn, NULL, &family) == FAILURE || family != AF_INET6 ||
                        ((un = find_overlapping_hna(&src, 128)) && un->on != self)) {

                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid prefix: %s or blocked by %s",
                                patch->val, un ? globalIdAsString(&un->on->global_id) : "");
                        
                        return FAILURE;
                }

                sprintf(adjusted_src, "%s", ipXAsStr(family, &src));
                set_opt_parent_val(patch, adjusted_src);

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_SRC_NAME) && c->val && (
                                strlen(c->val) >= sizeof (tun->name) ||
                                validate_name_string(c->val, strlen(c->val) + 1) != SUCCESS ||
                                strncmp(tun_name_prefix.str, c->val, strlen(tun_name_prefix.str)))) {
                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
                                        c->val, tun_name_prefix.str);
                                return FAILURE;
                        }
                }
        }

        if (cmd == OPT_APPLY) {

                if ((tun = avl_find_item(&tunnel_in_tree, &src)))
                        configure_tun_in(DEL, self, tun);

                if (patch->diff == DEL) {
                        avl_remove(&tunnel_in_tree, &tun->srcTunIp, -300391);
                        debugFree(tun, -300392);
                } else {
                        if(!tun) {
                                tun = debugMalloc(sizeof (struct tun_in_node), -300389);
                                memset(tun, 0, sizeof (struct tun_in_node));
                                tun->srcTunIp = src;
                                tun->name_auto = 1;
                                avl_insert(&tunnel_in_tree, tun, -300390);
                        }

                        while ((c = list_iterate(&patch->childs_instance_list, c))) {

                                if (!strcmp(c->opt->name, ARG_TUN_SRC_NAME)) {

                                        memset(&tun->name, 0, sizeof (tun->name));
                                        
                                        if (c->val) {
                                                strcpy(tun->name.str, c->val);
                                                tun->name_auto = 0;
                                        } else
                                                tun->name_auto = 1;
                                }
                        }
                }

                my_description_changed = YES;
        }

        if (  cmd == OPT_UNREGISTER ) {

                while ((tun = avl_first_item(&tunnel_in_tree))) {
                        configure_tun_in(DEL, self, tun);
                        avl_remove(&tunnel_in_tree, &tun->srcTunIp, -300393);
                        debugFree(tun, -300394);
                }
        }

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_tun_name(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        if (cmd == OPT_CHECK) {

                struct tun_in_node *tun;
                struct avl_node *it = NULL;

                if (strlen(patch->val) > MAX_TUN_NAME_PREFIX_LEN ||
                        validate_name_string(patch->val, strlen(patch->val) + 1))
                        return FAILURE;

                while((tun = avl_iterate_item(&tunnel_in_tree, &it))) {
                        if (!tun->name_auto && strncmp(patch->val, tun->name.str, strlen(patch->val)))
                                return FAILURE;
                }

                sprintf(tun_name_prefix.str, patch->val); //MUST be configured before opt_tunnel_in is checked

        } else if (cmd == OPT_POST && initializing) {

                struct avl_node *an = NULL;
                struct if_link_node *iln = NULL;

                while ((iln = avl_iterate_item(&if_link_tree, &an))) {

                        if (!strncmp(tun_name_prefix.str, iln->name.str, strlen(tun_name_prefix.str))) {
                                dbgf_sys(DBGT_WARN, "removing orphan tunnel dev=%s", iln->name.str);
                                iptunnel(DEL, iln->name.str, 0, NULL, NULL);
                        }
                }
        }


        return SUCCESS;
}


static int32_t tun_in_status_creator(struct status_handl *handl, void* data)
{
        struct avl_node *it = NULL;
        struct tun_in_node *tun;
        uint32_t status_size = tunnel_in_tree.items * sizeof (struct tun_in_node);
        uint32_t i = 0;
        struct tun_in_node *status = ((struct tun_in_node*) (handl->data = debugRealloc(handl->data, status_size, -300395)));

        while ((tun = avl_iterate_item(&tunnel_in_tree, &it)))
                status[i++] = *tun;

        return status_size;
}

/*
static int32_t tun_out_status_creator(struct status_handl *handl, void* data)
{
        struct avl_node *it = NULL;
        struct orig_node *on = NULL;
        uint32_t status_size = out_tunnels * sizeof (struct tun_node);
        int32_t i = 0;
        struct tun_node *status = ((struct tun_node*) (handl->data = debugRealloc(handl->data, status_size, -300396)));
        
        while ((on = avl_iterate_item(&orig_tree, &it))) {

                struct orig_tuns **tun = (struct orig_tuns **) (get_plugin_data(on, PLUGIN_DATA_ORIG, tun_orig_registry));

                if (tun && *tun) {
                        assertion(-501280, ((i + (*tun)->msgs) <= out_tunnels));
                        memcpy(&status[i], (*tun)->tun, (*tun)->msgs * sizeof (struct tun_node));
                        i += (*tun)->msgs;
                }
        }

        return status_size;
}
*/


STATIC_FUNC
struct opt_type hna_options[]= {
//     		ord parent long_name   shrt Attributes				*ival		min		max		default		*function

	{ODI,0,ARG_UHNA,	 	'a',5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_PREFIX_FORM,"specify host-network announcement (HNA) for defined ip range"}
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
        ,
	{ODI,0,ARG_NIIT,        	0,  5,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_niit,
			ARG_ADDR_FORM,HLP_NIIT}
        ,



	{ODI,0,ARG_TUN_NAME_PREFIX,    	0,  5,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_name,
			ARG_NAME_FORM, "specify first letters of local tunnel-interface names"}
        ,
	{ODI,0,ARG_TUN_SRC,	 	0,5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_in,
			ARG_ADDR_FORM,  "configure one-way IPv6 tunnel by specifying to-be-used src address"},
	{ODI,ARG_TUN_SRC,ARG_TUN_SRC_NAME,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,	        0,              0,0,            opt_tun_in,
			ARG_NAME_FORM,	"specify name of tunnel interface"}
        ,
	{ODI,0,ARG_TUNS,	        0,5,2,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show announced gateways and tunnels"}
        ,

        {ODI,0,ARG_TUN_ADV,	 	0,5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_gw_in,
			ARG_PREFIX_FORM,"announce gateway tunnel to network"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC,     0,5,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,              0,              0,0,            opt_gw_in,
			ARG_ADDR_FORM,	"specify incoming tunnel (by announcing to-be-used src address)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_BW,      0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,	        0,              0,0,            opt_gw_in,
			ARG_VALUE_FORM,	"announce bandwidth as bits/sec"}
        ,
	{ODI,0,ARG_TUN_SEARCH,	 	0,5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_gw_out,
		        ARG_NAME_FORM,"specify arbitrary but unique name for network which should be reached via tunnel depending on sub criterias"},
	{ODI,ARG_TUN_SEARCH,ARG_TUN_SEARCH_NETWORK,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,              0,              0,0,            opt_gw_out,
			ARG_PREFIX_FORM, "specify network to be reached via tunnel"},
	{ODI,ARG_TUN_SEARCH,ARG_TUN_SEARCH_IPMETRIC,0,5,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,              MAX_TUN_SEARCH_IPMETRIC,0,0,        opt_gw_out,
			ARG_VALUE_FORM, "specify ip metric for local routing table entries"},
	{ODI,ARG_TUN_SEARCH,ARG_TUN_SEARCH_HOSTNAME,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,              0,              0,0,            opt_gw_out,
			ARG_NAME_FORM, "specify hotname of remote tunnel endpoint"},
	{ODI,ARG_TUN_SEARCH,ARG_TUN_SEARCH_PKID,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,              0,              0,0,            opt_gw_out,
			ARG_SHA2_FORM, "specify pkid of remote tunnel endpoint"}
        ,

};


STATIC_FUNC
void hna_route_change_hook(uint8_t del, struct orig_node *on)
{

        dbgf_all(DBGT_INFO, "global_id=%s", globalIdAsString(&on->global_id));

        if (!is_ip_set(&on->primary_ip))
                return;

        process_description_tlvs(NULL, on, on->desc,
                del ? TLV_OP_CUSTOM_HNA_ROUTE_DEL : TLV_OP_CUSTOM_HNA_ROUTE_ADD,
                af_cfg() == AF_INET ? BMX_DSC_TLV_UHNA4 : BMX_DSC_TLV_UHNA6, NULL);

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
        static const struct field_format tun_adv_format[] = DESCRIPTION_MSG_TUN_ADV_FORMAT;

        static const struct field_format tunnel_status_format[] = TUNNEL_NODE_FORMAT;


        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_hna4);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.name = "HNA4_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_hna;
        tlv_handl.rx_frame_handler = process_description_tlv_hna;
        tlv_handl.msg_format = hna4_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_UHNA4, &tlv_handl);

        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_hna6);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.name = "HNA6_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_hna;
        tlv_handl.rx_frame_handler = process_description_tlv_hna;
        tlv_handl.msg_format = hna6_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_UHNA6, &tlv_handl);

        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.name = "TUN_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tun_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tun_adv;
        tlv_handl.msg_format = tun_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN_ADV, &tlv_handl);


        register_options_array(hna_options, sizeof ( hna_options), CODE_CATEGORY_NAME);

        set_route_change_hooks(hna_route_change_hook, ADD);

//        tun_orig_registry = get_plugin_data_registry(PLUGIN_DATA_ORIG);
//        gw_orig_registry = get_plugin_data_registry(PLUGIN_DATA_ORIG);

        register_status_handl(sizeof (struct tun_in_node), 1, tunnel_status_format, ARG_TUNS, tun_in_status_creator);

//        register_status_handl(sizeof (struct tun_node), tunnel_status_format, ARG_TUNS_OUT, tun_out_status_creator);


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
        hna_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_CREATED] = (void (*) (int32_t, void*)) hna_description_event_hook;
        hna_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_DESTROY] = (void (*) (int32_t, void*)) hna_description_event_hook;

        return &hna_plugin;
}


