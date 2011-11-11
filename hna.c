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
#include "schedule.h"

#define CODE_CATEGORY_NAME "hna"

static AVL_TREE(global_uhna_tree, struct hna_node, key );
static AVL_TREE(local_uhna_tree, struct hna_node, key );

static AVL_TREE(tunnel_in_tree, struct tunnel_node_in, remoteIp);

static AVL_TREE(tun_search_name_tree, struct tun_search_node, key.netName);
static AVL_TREE(tun_search_net_tree, struct tun_search_node, key);
static AVL_TREE(tun_net_tree, struct tun_net_node, key);
//static AVL_TREE(tun_adv_tree, struct tun_adv_node, key); // combined with tunnel_node/tunnel_out_tree
static AVL_TREE(tunnel_out_tree, struct tunnel_node_out, key);

static const struct net_key ZERO_NET_KEY = {.prefixlen = 0};

static struct net_key tun4_address;
static struct net_key tun6_address;

static int niit4to6_dev_idx = 0;
static int niit6to4_dev_idx = 0;
static IPX_T niitPrefix96 = DEF_NIIT_PREFIX;

//static int32_t tun_orig_registry = FAILURE;
//static int32_t gw_orig_registry = FAILURE;

static IFNAME_T tun_name_prefix = {{DEF_TUN_NAME_PREFIX}};


STATIC_FUNC
void hna_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;
        
        if (on != self)
                return;

        dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

        assertion(-501245, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501248, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {
                process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_DEL, BMX_DSC_TLV_UHNA6, NULL);
        }

        if (cb_id == PLUGIN_CB_DESCRIPTION_CREATED) {
                process_description_tlvs(NULL, self, self->desc, TLV_OP_CUSTOM_NIIT6TO4_ADD, BMX_DSC_TLV_UHNA6, NULL);
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

        if (!tun4_address.prefixlen || af_cfg() == AF_INET)
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

                if (avl_find_item(&iln->if_addr_tree, &tun4_address.net)) {
                        dbgf_track(DBGT_INFO, "Found niit address on interface %s", iln->name.str);
                        has_niit4to6_address = 1;
                }

                if (iln_4to6 && iln_6to4 && has_niit4to6_address)
                        break;
        }

        if (!has_niit4to6_address) {
                dbgf_track(DBGT_WARN, "%s address %s does not exist on the system",
                        ARG_TUN4_ADDRESS, ipXAsStr(AF_INET, &tun4_address.net));
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
void hna_dev_event_hook(int32_t cb_id, void* unused)
{
        TRACE_FUNCTION_CALL;

        niit_dev_event_hook(cb_id, unused);


        struct tunnel_node_in *tun;
        struct avl_node *an = NULL;
        while ((tun = avl_iterate_item(&tunnel_in_tree, &an))) {

                if (tun->upIfIdx && is_ip_local(&tun->remoteIp)) {
                        dbgf_sys(DBGT_WARN, "ERROR:..");
                        my_description_changed = YES;
                }
        }

}


STATIC_FUNC
IDM_T configure_niit4to6(IDM_T del, struct net_key *key)
{
        TRACE_FUNCTION_CALL;

        if (!niit4to6_dev_idx || !tun4_address.prefixlen || af_cfg() != AF_INET6 || key->prefixlen < 96 ||
                !is_ip_net_equal(&key->net, &niitPrefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_all(DBGT_INFO, "del=%d %s/%d", del, ipXAsStr(AF_INET6, &key->net), key->prefixlen);

        IPX_T niit_glip4 = ZERO_IP;
        niit_glip4.s6_addr32[3] = key->net.s6_addr32[3];

        // update network routes:
        if (del) {

                return ip(AF_INET, IP_ROUTE_TUNS, DEL, NO, &niit_glip4, (key->prefixlen - 96), RT_TABLE_TUN, 0,
                        NULL, 0, NULL, NULL, DEF_IP_METRIC);

        } else {

                return ip(AF_INET, IP_ROUTE_TUNS, ADD, NO, &niit_glip4, (key->prefixlen - 96), RT_TABLE_TUN, 0,
                        NULL, niit4to6_dev_idx, NULL, &tun4_address.net, DEF_IP_METRIC);

        }

        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_4TO6_DEV);
        return FAILURE;
}

STATIC_FUNC
IDM_T configure_niit6to4(IDM_T del, struct net_key *key)
{
        TRACE_FUNCTION_CALL;

        if (!niit6to4_dev_idx || !tun4_address.prefixlen || af_cfg() != AF_INET6 || key->prefixlen < 96 ||
                !is_ip_net_equal(&key->net, &niitPrefix96, 96, AF_INET6))
                return SUCCESS;

        dbgf_track(DBGT_INFO, "del=%d %s/%d", del, ipXAsStr(AF_INET6, &key->net), key->prefixlen);

        // update network routes:
        if (del) {

                return ip(AF_INET6, IP_ROUTE_TUNS, DEL, NO, &key->net, key->prefixlen, RT_TABLE_TUN, 0,
                        NULL, 0, NULL, NULL, DEF_IP_METRIC);

        } else {

                return ip(AF_INET6, IP_ROUTE_TUNS, ADD, NO, &key->net, key->prefixlen, RT_TABLE_TUN, 0,
                        NULL, niit6to4_dev_idx, NULL, NULL, DEF_IP_METRIC);

        }

        dbgf_sys(DBGT_ERR, "niit tunnel interface %s ERROR", DEF_NIIT_6TO4_DEV);
        return FAILURE;
}

STATIC_FUNC
void set_net_key(struct net_key *key, uint8_t prefixlen, IPX_T *glip)
{
        memset( key, 0, sizeof(struct net_key));
        key->prefixlen = prefixlen;
        key->net = *glip;
}


STATIC_FUNC
struct net_key netX4ToNiit6(struct net_key *net)
{
        struct net_key niit;

        set_net_key(&niit, net->prefixlen + 96, &niitPrefix96);
        niit.net.s6_addr32[3] = net->net.s6_addr32[3];
        return niit;
}


STATIC_FUNC
IDM_T configure_route(IDM_T del, struct orig_node *on, struct net_key *key)
{

        // update network routes:
        if (del) {

                return ip(af_cfg(), IP_ROUTE_HNA, DEL, NO, &key->net, key->prefixlen, RT_TABLE_HNA, 0,
                        NULL, 0, NULL, NULL, DEF_IP_METRIC);

        } else {

                struct link_dev_node *lndev = on->curr_rt_lndev;

                assertion(-500820, (lndev));
                ASSERTION(-500239, (avl_find(&link_dev_tree, &(lndev->key))));
                assertion(-500579, (lndev->key.dev->if_llocal_addr));

                return ip(af_cfg(), IP_ROUTE_HNA, ADD, NO, &key->net, key->prefixlen, RT_TABLE_HNA, 0,
                        NULL, lndev->key.dev->if_llocal_addr->ifa.ifa_index,
                        &(lndev->key.link->link_ip), &(self->primary_ip), DEF_IP_METRIC);

        }
}


STATIC_FUNC
void set_hna_to_key(struct net_key *key, struct description_msg_hna4 *uhna4, struct description_msg_hna6 *uhna6)
{
        if (uhna4) {

                IPX_T ipX = ip4ToX(uhna4->ip4);

                set_net_key(key, uhna4->prefixlen, &ipX);
                ip_netmask_validate(&key->net, key->prefixlen, AF_INET, YES);

        } else {

                set_net_key(key, uhna6->prefixlen, &uhna6->ip6);
                ip_netmask_validate(&key->net, key->prefixlen, AF_INET6, YES);
        }
}


STATIC_FUNC
int _create_tlv_hna(int family, uint8_t* data, uint16_t max_size, uint16_t pos, IPX_T *ip, uint16_t prefixlen)
{
        TRACE_FUNCTION_CALL;
        int i;
        uint16_t msg_size = family == AF_INET ? sizeof (struct description_msg_hna4) : sizeof (struct description_msg_hna6);


        if ((pos + msg_size) > max_size) {

                dbgf_sys(DBGT_ERR, "unable to announce %s/%d due to limiting --%s=%d",
                        ipXAsStr(family, ip), prefixlen, ARG_UDPD_SIZE, max_size);

                return pos;
        }

        dbgf_all(DBGT_INFO, "announce %s/%d", ipXAsStr(family, ip), prefixlen);


        assertion(-500610, (!(family == AF_INET6 && is_ip_net_equal(ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))));
        // this should be catched during configuration!!


        if (family == AF_INET) {
                struct description_msg_hna4 *msg4 = ((struct description_msg_hna4 *) data);

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
                struct description_msg_hna6 *msg6 = ((struct description_msg_hna6 *) data);

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
        TRACE_FUNCTION_CALL;
        assertion(-500765, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));

        uint8_t *data = tx_iterator_cache_msg_ptr(it);
        uint16_t max_size = tx_iterator_cache_data_space(it);
        uint8_t family = it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6;
        uint8_t max_prefixlen = ort_dat[ (AFINET2BMX(family)) ].max_prefixlen;

        int pos = 0;
        struct avl_node *an;
        struct tun_search_node *tsn;
        struct dev_node *dev;
        struct hna_node *un;

        if (!is_ip_set(&self->primary_ip))
                return TLV_TX_DATA_IGNORED;

        pos = _create_tlv_hna(family, data, max_size, pos, &self->primary_ip, max_prefixlen);

        if (tun4_address.prefixlen) {
                struct net_key niit6_address = netX4ToNiit6(&tun4_address);
                pos = _create_tlv_hna(AF_INET6, data, max_size, pos, &niit6_address.net, niit6_address.prefixlen);
        }

        if (tun6_address.prefixlen)
                pos = _create_tlv_hna(AF_INET6, data, max_size, pos, &tun6_address.net, tun6_address.prefixlen);
        

        for (an = NULL; (tsn = avl_iterate_item(&tun_search_name_tree, &an));) {
                if (tsn->srcPrefix.prefixlen) {
                        struct net_key src = (tsn->key.family == AF_INET) ? netX4ToNiit6(&tsn->srcPrefix) : tsn->srcPrefix;
                        pos = _create_tlv_hna(AF_INET6, data, max_size, pos, &src.net, src.prefixlen);
                }
        }

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                if (dev->active && dev->announce)
                        pos = _create_tlv_hna(family, data, max_size, pos, &dev->if_global_addr->ip_addr, max_prefixlen);
        }

        for (an = NULL; (un = avl_iterate_item(&local_uhna_tree, &an));)
                pos = _create_tlv_hna(family, data, max_size, pos, &un->key.net, un->key.prefixlen);


        return pos;
}




STATIC_FUNC
void configure_hna(IDM_T del, struct net_key* key, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;
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
                        ip(af_cfg(), IP_THROW_MY_HNA, del, NO, &key->net, key->prefixlen, RT_TABLE_HNA, 0, 0, 0, 0, 0, 0);
                        ip(af_cfg(), IP_THROW_MY_HNA, del, NO, &key->net, key->prefixlen, RT_TABLE_TUN, 0, 0, 0, 0, 0, 0);
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
        TRACE_FUNCTION_CALL;
        ASSERTION(-500357, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));
        assertion(-500588, (it->on));

        struct orig_node *on = it->on;
        uint8_t op = it->op;
        uint8_t family = (it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6);

        if (af_cfg() != family) {
                dbgf_sys(DBGT_ERR, "invalid family %s", family2Str(family));
                return TLV_RX_DATA_BLOCKED;
        }

        uint16_t msg_size = it->handl->min_msg_size;
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

                        if (!is_ip_valid(&key.net, family) || (un = find_overlapping_hna(&key.net, key.prefixlen)) ||
                                is_ip_net_equal(&key.net, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)) {

                                dbgf_sys(DBGT_ERR, "global_id=%s %s=%s/%d blocked (by global_id=%s)",
                                        globalIdAsString(&on->global_id),
                                        ARG_UHNA, ipXAsStr(family, &key.net), key.prefixlen,
                                        un ? globalIdAsString(&un->on->global_id) : "???");

                                return TLV_RX_DATA_BLOCKED;
                        }


                        // check if node announces the same key twice:
                        assertion(-501294, (it->misc_ptr));

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
                                //ASSERTION(-501314, (avl_find(&global_uhna_tree, &key)));

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
                                        assertion(-501315, (NO));
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
        TRACE_FUNCTION_CALL;
        IPX_T ipX;
	uint8_t mask;
	char new[IPXNET_STR_LEN];

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                uint8_t family = af_cfg();
                struct net_key key = ZERO_NET_KEY;
                struct hna_node *un;

                dbgf_all(DBGT_INFO, "af_cfg=%s diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        family2Str(af_cfg()), patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (str2netw(patch->val, &ipX, cn, &mask, &family, NO) == FAILURE || !is_ip_valid(&ipX, family)) {
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
IDM_T configure_tunnel_in(uint8_t del, struct tunnel_node_in *tun)
{
        TRACE_FUNCTION_CALL;
        assertion(-501292, (is_ip_set(&tun->remoteIp)));
        assertion(-501295, IMPLIES(!del, (is_ip_set(&self->primary_ip))));
        assertion(-501311, IMPLIES(tun->upIfIdx, tun->name.str[0]));
        assertion(-501295, IMPLIES(tun->upIfIdx, del));

        if (del && tun->upIfIdx) {

                iptunnel(DEL, tun->name.str, 0, NULL, NULL);
                tun->upIfIdx = 0;
                tun->tun6Id = -1;
/*
                tun->src4Ip = ZERO_IP;
                tun->src6Ip = ZERO_IP;
*/


        } else if (!del && !tun->upIfIdx) {

                IPX_T *local = &self->primary_ip;
                IPX_T *remote = &tun->remoteIp;

                if (tun->name_auto) {

                        static uint16_t tun_idx = 0;
                        struct if_link_node *iln = NULL;

                        do {
                                memset(&tun->name, 0, sizeof (tun->name));
                                snprintf(tun->name.str, IFNAMSIZ - 1, "%s_%s%.4X", tun_name_prefix.str, "in", tun_idx++);

                                struct avl_node *an = NULL;
                                iln = NULL;
                                //check if tun->name is already used:
                                while ((iln = avl_iterate_item(&if_link_tree, &an)) && strcmp(iln->name.str, tun->name.str));

                        } while (iln);

                }

                assertion(-501312, (strlen(tun->name.str)));

                if (iptunnel(ADD, tun->name.str, IPPROTO_IP, local, remote) == SUCCESS)
                        tun->upIfIdx = get_if_index(&tun->name);

        }

        return (XOR(del, tun->upIfIdx)) ? SUCCESS : FAILURE;
}

STATIC_FUNC
IDM_T configure_tunnel_out(uint8_t del, struct orig_node *on, struct tunnel_node_out *tun)
{
        TRACE_FUNCTION_CALL;
        assertion(-501292, (is_ip_set(&tun->localIp)));
        assertion(-501235, (on));
        assertion(-501321, (on != self));
        assertion(-501295, IMPLIES(!del, (is_ip_set(&on->primary_ip))));
        assertion(-501311, IMPLIES(tun->upIfIdx, tun->name.str[0]));
        assertion(-501295, IMPLIES(tun->upIfIdx, del));

        if (del && tun->upIfIdx) {

                iptunnel(DEL, tun->name.str, 0, NULL, NULL);
                tun->upIfIdx = 0;
                tun->src4Ip = ZERO_IP;
                tun->src6Ip = ZERO_IP;


        } else if (!del && !tun->upIfIdx) {


                IPX_T *local = &tun->localIp;
                IPX_T *remote = &on->primary_ip;

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

                assertion(-501312, (strlen(tun->name.str)));

                if (iptunnel(ADD, tun->name.str, IPPROTO_IP, local, remote) == SUCCESS)
                        tun->upIfIdx = get_if_index(&tun->name);

        }

        return (XOR(del, tun->upIfIdx)) ? SUCCESS : FAILURE;
}


STATIC_FUNC
void unlink_tun_net(struct tun_net_node *tnn, struct tun_search_node *tsn, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *itnn = NULL;
        struct tun_net_node *ttnn;

        while ((ttnn = tnn ? tnn : avl_iterate_item(&tun_net_tree, &itnn))) {

                assertion(-501296, ttnn->key.tun);

                dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "%s: %s/%d %s", tsn ? tsn->key.netName : DBG_NIL,
                        ipXAsStr(ttnn->family, &ttnn->key.network.net), ttnn->key.network.prefixlen,
                        globalIdAsString(&ttnn->key.tun->key.on->global_id));

                struct tun_search_node *ttsn;
                struct avl_node *itsn = NULL;
                struct tunnel_node_out *tun = ttnn->key.tun;

                while ((ttsn = avl_iterate_item(&ttnn->tun_search_tree, &itsn))) {

                        if (!tsn || tsn == ttsn) {

                                assertion(-501298, (ttsn->tun_net == ttnn));
                                assertion(-501299, (tun && tun->upIfIdx && tun->tun_net_tree.items));

                                ip(ttsn->key.family, IP_ROUTE_TUNS, DEL, NO, &ttsn->key.network.net, ttsn->key.network.prefixlen,
                                        RT_TABLE_TUN, 0, NULL, tun->upIfIdx, NULL, NULL, ttsn->ipmetric);

                                ttsn->tun_net = NULL;

                                avl_remove(&ttnn->tun_search_tree, ttsn->key.netName, -300408);

                                itsn = NULL;
                        }
                }


                struct avl_node *itused = NULL;
                struct tun_net_node *used;
                while ((used = avl_iterate_item(&tun->tun_net_tree, &itused)) && !used->tun_search_tree.items);

                assertion(-501236, IMPLIES(used, tun->upIfIdx));

                if (!used)
                        configure_tunnel_out(DEL, tun->key.on, tun);

                if (tnn)
                        break;
        }

}

STATIC_FUNC
struct tun_search_node* get_active_tun(struct tun_search_node *tsn)
{
        struct tun_search_node *other, *best = NULL;
        struct tun_search_key key;
        memset(&key, 0, sizeof (key));
        key.family = tsn->key.family;
        key.network = tsn->key.network;

        while ((other = avl_next_item(&tun_search_net_tree, &key))) {

                if (memcmp(&other->key, &tsn->key, sizeof (struct tun_search_key)))
                        return NULL;

                if (other->ipmetric != tsn->ipmetric || !other->tun_net)
                        continue;

                if (!best || best->tun_net->e2eMetric < other->tun_net->e2eMetric)
                        best = other;

        }
        
        return best;
}


STATIC_FUNC
void set_tun_net(struct tun_search_node *sn)
{
        TRACE_FUNCTION_CALL;
        struct tun_search_node *tsn = NULL;
        struct tun_net_node *tnn = NULL;
        struct avl_node *atsn = NULL, *itnn = NULL;


        task_remove((void(*)(void*))set_tun_net, NULL);
        if (tun_search_name_tree.items)
                task_register(5000, (void(*)(void*))set_tun_net, NULL, -300420);

        dbgf_all(DBGT_INFO, "netName=%s: tunnel_tree_out.items=%d net_tree.items=%d search_tree.items=%d ",
                sn ? sn->key.netName : DBG_NIL, tunnel_out_tree.items, tun_net_tree.items, tun_search_name_tree.items);

        while (IMPLIES(sn, !tsn) && (tsn = sn ? sn : avl_iterate_item(&tun_search_name_tree, &atsn))) {

                struct tun_net_node *best_tnn = NULL;
                struct net_key srcPrefix = tsn->srcPrefix.prefixlen ?
                        tsn->srcPrefix : (tsn->key.family == AF_INET ? tun4_address : tun6_address);

                dbgf_all(DBGT_INFO, "searching %s=%s: %s=%s %s=%d %s=%s/%d %s=%s/%d ",
                        ARG_TUN_SEARCH_NAME, tsn->key.netName,
                        ARG_TUN_SEARCH_HOSTNAME, globalIdAsString(&tsn->global_id),
                        ARG_TUN_SEARCH_TYPE, tsn->srcType,
                        ARG_TUN_SEARCH_NETWORK, ipXAsStr(tsn->key.family, &tsn->key.network.net), tsn->key.network.prefixlen,
                        ARG_TUN_SEARCH_IP, ipXAsStr(tsn->key.family, &srcPrefix.net), srcPrefix.prefixlen
                        );

                while ((tnn = avl_iterate_item(&tun_net_tree, &itnn))) {

                        struct orig_node *on = tnn->key.tun->key.on;
                        GLOBAL_ID_T *tnn_gid = &on->global_id, *tsn_gid = &tsn->global_id;
                        UMETRIC_T linkQuality = UMETRIC_MAX;
                        UMETRIC_T linkMax = fmetric_to_umetric(fmetric_u8_to_fmu16(tnn->bandwidth));
                        UMETRIC_T pathMetric = on->curr_rt_local ? (on->curr_rt_local->mr.umetric) : 0;
                        uint8_t family = tnn->family;
                        struct net_key ingressPrefix = (family == AF_INET) ? tnn->key.tun->ingress4Prefix : tnn->key.tun->ingress6Prefix;

                        dbgf_all(DBGT_INFO, "checking network=%s/%d bw_fmu8=%d, ingress=%s/%d localIp=%s tun6Id=%d tun=%p from orig=%s",
                                ipXAsStr(family, &tnn->key.network.net), tnn->key.network.prefixlen, tnn->bandwidth.val.u8,
                                ipXAsStr(family, &ingressPrefix.net), ingressPrefix.prefixlen,
                                ip6AsStr(&tnn->key.tun->localIp), tnn->key.tun->key.tun6Id, (void*)(tnn->key.tun),
                                globalIdAsString(&on->global_id));

                        if (!(
                                tsn->key.family == family &&
                                tsn->key.network.prefixlen >= tnn->key.network.prefixlen &&
                                is_ip_net_equal(&tsn->key.network.net, &tnn->key.network.net, tnn->key.network.prefixlen, family) &&
                                IMPLIES(strlen(tsn_gid->name), !strcmp(tsn_gid->name, tnn_gid->name)) &&
                                IMPLIES(!is_zero(&tsn_gid->pkid, GLOBAL_ID_PKID_LEN), !memcmp(&tsn_gid->pkid, &tnn_gid->pkid, GLOBAL_ID_PKID_LEN))
                                ))
                                continue;

                                dbgf_all(DBGT_INFO, "acceptable A");

                        if (tsn->srcType == TUN_SRC_TYPE_UNDEF || tsn->srcType == TUN_SRC_TYPE_STATIC) {
                                
                                dbgf_all(DBGT_INFO, "acceptable B");

                                if (!srcPrefix.prefixlen || srcPrefix.prefixlen < ingressPrefix.prefixlen ||
                                        !is_ip_net_equal(&srcPrefix.net, &ingressPrefix.net, MIN(srcPrefix.prefixlen, ingressPrefix.prefixlen), family))
                                        continue;

                                dbgf_all(DBGT_INFO, "acceptable C");


                        } else {

                                continue;
                        }


                        if (linkMax <= UMETRIC_MIN__NOT_ROUTABLE || pathMetric <= UMETRIC_MIN__NOT_ROUTABLE)
                                continue;

                        tnn->e2eMetric = apply_metric_algo(&linkQuality, &linkMax, &pathMetric, on->path_metricalgo);

                        if (!best_tnn ||
                                (tnn->e2eMetric > best_tnn->e2eMetric) ||
                                (tnn->e2eMetric == best_tnn->e2eMetric && tnn->key.network.prefixlen > best_tnn->key.network.prefixlen) ||
                                (tnn->e2eMetric == best_tnn->e2eMetric && tnn->key.network.prefixlen == best_tnn->key.network.prefixlen && tnn == tsn->tun_net)
                                )
                                best_tnn = tnn;

                        dbgf_all(DBGT_INFO, "acceptable e2eMetric=%s, %s",
                                umetric_to_human(tnn->e2eMetric), best_tnn == tnn ? "NEW BEST" : "NOT best");


                }

                if (best_tnn != tsn->tun_net) {

                        if(tsn->tun_net)
                                unlink_tun_net(tsn->tun_net, tsn, NULL);

                        struct tun_search_node *alternative = get_active_tun(tsn);

                        if (alternative && alternative->tun_net->e2eMetric < best_tnn->e2eMetric) {

                                unlink_tun_net(alternative->tun_net, alternative, NULL);

                        } else if (best_tnn && best_tnn->e2eMetric > UMETRIC_MIN__NOT_ROUTABLE && !alternative) {

                                struct tunnel_node_out *tun = best_tnn->key.tun;

                                if (!tun->upIfIdx && configure_tunnel_out(ADD, tun->key.on, tun) == SUCCESS){
                                        ipaddr(ADD, tun->upIfIdx, AF_INET6, &tun->localIp, 128, YES /*deprecated*/);
					change_mtu(tun->name.str, tsn->mtu);
					dbgf_track(DBGT_INFO, "Set MTU from %s as %d",tun->name.str, tsn->mtu);
				}

                                if (tun->upIfIdx) {
                                        if (tsn->key.family == AF_INET && !is_ip_set(&tun->src4Ip)) {

                                                tun->src4Ip = tsn->srcPrefix.prefixlen ? tsn->srcPrefix.net : tun4_address.net;
                                                ipaddr(ADD, tun->upIfIdx, AF_INET, &tun->src4Ip, 32, NO /*deprecated*/);

                                        } else if (tsn->key.family == AF_INET6 && !is_ip_set(&tun->src6Ip)) {

                                                tun->src6Ip = tsn->srcPrefix.prefixlen ? tsn->srcPrefix.net : tun6_address.net;
                                                ipaddr(ADD, tun->upIfIdx, AF_INET6, &tun->src6Ip, 128, NO /*deprecated*/);
                                        }

                                        ip(tsn->key.family, IP_ROUTE_TUNS, ADD, NO, &tsn->key.network.net, tsn->key.network.prefixlen,
                                                RT_TABLE_TUN, 0, NULL, tun->upIfIdx, NULL, NULL, tsn->ipmetric);


                                        tsn->tun_net = best_tnn;
                                        avl_insert(&best_tnn->tun_search_tree, tsn, -300415);
                                }
                        }
                }
        }
}


STATIC_FUNC
int create_description_tlv_tun6_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        uint16_t m = 0;
        struct tunnel_node_in *tun;
        struct avl_node *an = NULL;
        struct description_msg_tun6_adv *adv = (struct description_msg_tun6_adv *) tx_iterator_cache_msg_ptr(it);

        while ((tun = avl_iterate_item(&tunnel_in_tree, &an)) && m < tx_iterator_cache_msg_space(it)) {

                struct hna_node *hna;

                configure_tunnel_in(DEL, tun);

                if (is_ip_local(&tun->remoteIp) ||
                        (tun->ingress6Prefix.prefixlen && (hna = find_overlapping_hna(&tun->ingress6Prefix.net, tun->ingress6Prefix.prefixlen)) && hna->on == self) ||
//                      (tun->src4Prefix.prefixlen && (hna = find_overlapping_hna(&tun->src4Prefix.net, tun->src4Prefix.prefixlen)) && hna->on == self) ||
                        configure_tunnel_in(ADD, tun) == FAILURE) {
                        dbgf_sys(DBGT_WARN, "FAILED advertising tun localIp=%s", ip6AsStr(&tun->remoteIp));
                        continue;
                }

                assertion(-501237, (tun->upIfIdx && tun->tun6Id == -1));

                tun->tun6Id = m;
                adv[m].localIp = tun->remoteIp;
                m++;
        }

        return m * sizeof ( struct description_msg_tun6_adv);
}

STATIC_FUNC
struct tun_adv_key set_tun_adv_key(struct orig_node *on, int16_t tun6Id)
{
        struct tun_adv_key key;
        memset(&key, 0, sizeof (key));
        key.on = on;
        key.tun6Id = tun6Id;
        return key;
}

STATIC_FUNC
int process_description_tlv_tun6_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        int16_t m;
        IDM_T used = NO;

        for (m = 0; m < it->frame_msgs_fixed; m++) {

                struct description_msg_tun6_adv *adv = &(((struct description_msg_tun6_adv *) (it->frame_data))[m]);
                struct tun_adv_key key = set_tun_adv_key(it->on, m);

                dbgf_all(DBGT_INFO, "op=%s tunnel_out.items=%d tun_net.items=%d msg=%d/%d localIp=%s orig=%s (%p) key=%s",
                        tlv_op_str(it->op), tunnel_out_tree.items, tun_net_tree.items, m, it->frame_msgs_fixed,
                        ip6AsStr(&adv->localIp), globalIdAsString(&it->on->global_id), (void*) (it->on), memAsHexString(&key, sizeof (key)));


                if (it->op == TLV_OP_DEL) {

                        struct tunnel_node_out *tun = avl_find_item(&tunnel_out_tree, &key);
                        struct tunnel_node_out *rtun;
                        struct tun_net_node *tnn;
                        struct tun_net_node *rtnn;


                        assertion(-501247, (tun));

                        dbgf_all(DBGT_INFO, "should A remove tunnel_node localIp=%s tun6Id=%d orig=%s key=%s (tunnel_out.items=%d, tun->net.items=%d)",
                                ip6AsStr(&tun->localIp), tun->key.tun6Id, globalIdAsString(&tun->key.on->global_id), memAsHexString(&tun->key, sizeof (key)), tunnel_out_tree.items, tun->tun_net_tree.items);

                        used |= (tun->upIfIdx) ? YES : NO;

                        while ((tnn = avl_first_item(&tun->tun_net_tree))) {

                                unlink_tun_net(tnn, NULL, NULL);

                                rtnn = avl_remove(&tun_net_tree, &tnn->key, -300421);
                                assertion(-501251, (rtnn == tnn));

                                rtnn = avl_remove(&tun->tun_net_tree, &tnn->key, -300423);
                                assertion(-501252, (rtnn == tnn));
                                debugFree(tnn, -300424);
                        }

                        assertion(-501249, (!tun->tun_net_tree.items));

                        checkIntegrity();

                        rtun = avl_remove(&tunnel_out_tree, &key, -300410);
                        assertion(-501253, (rtun == tun));
                        debugFree(tun, -300425);

                } else if (it->op == TLV_OP_TEST) {

                        if (avl_find(&tunnel_in_tree, &adv->localIp) ||
                                !is_ip_valid(&adv->localIp, AF_INET6) || find_overlapping_hna(&adv->localIp, 128) ||
                                is_ip_net_equal(&adv->localIp, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))
                                return TLV_RX_DATA_BLOCKED;

                } else if (it->op == TLV_OP_ADD) {

                        struct tunnel_node_out *tun = debugMalloc(sizeof (struct tunnel_node_out), -300426);
                        memset(tun, 0, sizeof (struct tunnel_node_out));
                        tun->key = key;
                        tun->localIp = adv->localIp;
                        tun->name_auto = 1;
                        AVL_INIT_TREE(tun->tun_net_tree, struct tun_net_node, key);
                        avl_insert(&tunnel_out_tree, tun, -300427);
                }
        }

        if (used)
                set_tun_net(NULL);


        return it->frame_msgs_length;
}


STATIC_FUNC
int create_description_tlv_tunXin6_ingress_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tunnel_node_in *tun;
        struct avl_node *an = NULL;
        uint8_t isSrc4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_INGRESS_ADV);
        uint16_t pos = 0;
        uint16_t msg_size = isSrc4in6 ? sizeof (struct description_msg_tun4in6_ingress_adv) : sizeof (struct description_msg_tun6in6_ingress_adv);

        while ((tun = avl_iterate_item(&tunnel_in_tree, &an))) {

                if (tun->tun6Id >= 0 && (isSrc4in6 ? tun->ingress4Prefix.prefixlen : tun->ingress6Prefix.prefixlen)) {

                        if (pos + msg_size > tx_iterator_cache_data_space(it)) {
                                memset(tx_iterator_cache_msg_ptr(it), 0, pos);
                                return TLV_TX_DATA_FULL;
                        }

                        struct description_msg_tun6in6_ingress_adv *adv =
                                (struct description_msg_tun6in6_ingress_adv *) (tx_iterator_cache_msg_ptr(it) + pos);

                        adv->tun6Id = tun->tun6Id;
                        adv->ingressPrefixLen = isSrc4in6 ? tun->ingress4Prefix.prefixlen: tun->ingress6Prefix.prefixlen;

                        if (isSrc4in6)
                                *((IP4_T*) & adv->ingressPrefix) = ipXto4(tun->ingress4Prefix.net);
                        else
                                adv->ingressPrefix = tun->ingress6Prefix.net;

                        pos += msg_size;
                }
        }
        return pos;
}


STATIC_FUNC
int process_description_tlv_tunXin6_ingress_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        uint8_t isSrc4 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_INGRESS_ADV);
        uint16_t pos;

        for (pos = 0; pos < it->frame_data_length; pos += it->handl->min_msg_size) {

                struct description_msg_tun6in6_ingress_adv *adv = (struct description_msg_tun6in6_ingress_adv *) (it->frame_data + pos);
                struct tun_adv_key key = set_tun_adv_key(it->on, adv->tun6Id);
                struct tunnel_node_out *tun = avl_find_item(&tunnel_out_tree, &key);
                IPX_T prefix = isSrc4 ? ip4ToX(*((IP4_T*)&adv->ingressPrefix)) : adv->ingressPrefix;

                if (it->op == TLV_OP_DEL) {

                        assertion(-501238, (!tun));

                } else if (it->op == TLV_OP_TEST) {

                        assertion(-501265, (!tun));

                        if (ip_netmask_validate(&prefix, adv->ingressPrefixLen, isSrc4 ? AF_INET : AF_INET6, NO) == FAILURE)
                                return TLV_RX_DATA_FAILURE;

                } else if (it->op == TLV_OP_ADD) {

                        if (tun) {
                                if (isSrc4) {
                                        tun->ingress4Prefix.prefixlen = adv->ingressPrefixLen;
                                        tun->ingress4Prefix.net = prefix;
                                } else {
                                        tun->ingress6Prefix.prefixlen = adv->ingressPrefixLen;
                                        tun->ingress6Prefix.net = prefix;
                                }
                        }
                }
        }
        return it->frame_msgs_length;
}

STATIC_FUNC
int create_description_tlv_tunXin6_src_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        return TLV_TX_DATA_IGNORED;
}


STATIC_FUNC
int process_description_tlv_tunXin6_src_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        return it->frame_msgs_length;
}


STATIC_FUNC
int create_description_tlv_tunXin6_net_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        IDM_T is4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET_ADV) ? YES : NO;
        uint16_t m = 0;
        struct opt_type *o = get_option(NULL, NO, ARG_TUN_NET);
        struct opt_parent *p = NULL;

        while ((p = list_iterate(&o->d.parents_instance_list, p)) && m <= tx_iterator_cache_msg_space(it)) {

                struct opt_child *c = NULL;
                struct tunnel_node_in *tun = NULL;
                struct avl_node *an = NULL;
                struct description_msg_tun6in6_net_adv adv;
                uint8_t family = 0;
                UMETRIC_T um = 0;
                memset(&adv, 0, sizeof (adv));
                IPX_T remoteIp = ZERO_IP;

                str2netw(p->val, &adv.network, NULL, &adv.networkLen, &family, NO);

                dbgf_all(DBGT_INFO, "is4in6=%d family=%d dst=%s/%d", is4in6, family, ip6AsStr(&adv.network), adv.networkLen);

                if (family != (is4in6 ? AF_INET : AF_INET6))
                        continue;

                while ((c = list_iterate(&p->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_NET_BW)) {
                                um = strtoull(c->val, NULL, 10);
                                adv.bandwidth = umetric_to_fmu8(&um);
                        } else if (!strcmp(c->opt->name, ARG_TUN_NET_LOCAL)) {
                                str2netw(c->val, &remoteIp, NULL, NULL, NULL, YES);
                        }
                }

                if (um <= UMETRIC_MIN__NOT_ROUTABLE)
                        continue;

                if (is_ip_set(&remoteIp)) {
                        tun = avl_find_item(&tunnel_in_tree, &remoteIp);
                } else {
                        while ((tun = avl_iterate_item(&tunnel_in_tree, &an)) && tun->tun6Id < 0);
                }

                if (tun && tun->upIfIdx && tun->tun6Id >= 0)
                        adv.tun6Id = tun->tun6Id;
                else
                        continue;

                dbgf_track(DBGT_INFO, "src=%s dst=%s", ip6AsStr(&tun->remoteIp), ip6AsStr(&adv.network));

                if ( is4in6 ) {
                        struct description_msg_tun4in6_net_adv *msg4 =
                                &(((struct description_msg_tun4in6_net_adv *) tx_iterator_cache_msg_ptr(it))[m]);

                        msg4->network = ipXto4(adv.network);
                        msg4->networkLen = adv.networkLen;
                        msg4->bandwidth = adv.bandwidth;
                        msg4->tun6Id = adv.tun6Id;

                } else {
                        ((struct description_msg_tun6in6_net_adv *) tx_iterator_cache_msg_ptr(it))[m] = adv;
                }

                m++;
        }

        return m * (is4in6 ? sizeof (struct description_msg_tun4in6_net_adv) : sizeof (struct description_msg_tun6in6_net_adv));
}

STATIC_FUNC
int process_description_tlv_tunXin6_net_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        IDM_T is4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET_ADV ? YES : NO);
        uint8_t family = is4in6 ? AF_INET : AF_INET6;
        uint16_t msg_size = it->handl->min_msg_size;
        uint16_t pos;
        uint8_t used = NO;

        for (pos = 0; pos < it->frame_msgs_length; pos += msg_size) {

                struct description_msg_tun6in6_net_adv *adv = (((struct description_msg_tun6in6_net_adv *) (it->frame_data + pos)));
                struct net_key net = ZERO_NET_KEY;
                net.net = is4in6 ? ip4ToX(*((IP4_T*) & adv->network)) : adv->network;
                net.prefixlen = adv->networkLen;

                if (it->op == TLV_OP_DEL) {

                } else if (it->op == TLV_OP_TEST) {

                        if (ip_netmask_validate(&net.net, net.prefixlen, family, NO) == FAILURE) {
                                dbgf_sys(DBGT_ERR, "network=%s/%d", ipXAsStr(family, &net.net), net.prefixlen);
                                return TLV_RX_DATA_FAILURE;
                        }

                } else if (it->op == TLV_OP_ADD) {

                        struct tun_adv_key key = set_tun_adv_key(it->on, adv->tun6Id);
                        struct tunnel_node_out *tun = avl_find_item(&tunnel_out_tree, &key);

                        if (tun) {

                                struct tun_net_node *tnn = debugMalloc(sizeof (struct tun_net_node), -300418);
                                memset(tnn, 0, sizeof (struct tun_net_node));
                                tnn->key.tun = tun;
                                tnn->key.network = net;
                                tnn->family = family;
                                tnn->bandwidth = adv->bandwidth;

                                AVL_INIT_TREE(tnn->tun_search_tree, struct tun_search_node, key.netName);

                                avl_insert(&tun_net_tree, tnn, -300419);
                                avl_insert(&tun->tun_net_tree, tnn, -300419);

                                used = 1;

                        } else {
                                dbgf_sys(DBGT_WARN, "no matching tunnel_node found for orig=%s tun6Id=%d",
                                        globalIdAsString(&key.on->global_id), key.tun6Id);
                        }
                }
        }

        if (used)
                set_tun_net(NULL);

        return it->frame_msgs_length;
}





struct tun_out_status {
        GLOBAL_ID_T *globalId;
        IPX_T *local;
        IPX_T *remote;
        char network[IPX_PREFIX_STR_LEN];
        UMETRIC_T bw_val;
        UMETRIC_T *bandwidth;
        UMETRIC_T *metric;
        UMETRIC_T *e2EMetric;
        char *tunName;
//        uint16_t up;
        char* searchName;
        char searchNetwork[IPX_PREFIX_STR_LEN];
        GLOBAL_ID_T *searchId;
        uint32_t ipMetric;
};

static const struct field_format tun_out_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, globalId,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, local,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, remote,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, network,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, bw_val,        1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, bandwidth,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, metric,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, e2EMetric,     1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunName,       1, FIELD_RELEVANCE_HIGH),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, up,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, searchName,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, searchNetwork, 1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, searchId,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, ipMetric,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_END
};

static int32_t tun_out_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *itnn, *itsn;
        int32_t status_size = tun_search_name_tree.items * sizeof (struct tun_out_status);
        struct tun_net_node *tnn;
        struct tun_search_node *tsn;
        struct tun_out_status *status;

        for (itnn = NULL; (tnn = avl_iterate_item(&tun_net_tree, &itnn));)
                status_size += (tnn->tun_search_tree.items ? 0 : sizeof (struct tun_out_status));

        status = (struct tun_out_status *) (handl->data = debugRealloc(handl->data, status_size, -300428));
        memset(status, 0, status_size);

        for (itnn = NULL; (tnn = avl_iterate_item(&tun_net_tree, &itnn));) {

                itsn = NULL;
                tsn = avl_iterate_item(&tnn->tun_search_tree, &itsn);

                do {
                        struct tunnel_node_out *tun = tnn->key.tun;

                        status->globalId = &tun->key.on->global_id;
                        status->local = &tun->localIp;
                        status->remote = &tun->key.on->primary_ip;
                        sprintf(status->network, "%s/%d", ipXAsStr(tnn->family, &tnn->key.network.net), tnn->key.network.prefixlen);
                        status->bw_val = fmetric_to_umetric(fmetric_u8_to_fmu16(tnn->bandwidth));
                        status->bandwidth = status->bw_val ? &status->bw_val : NULL;
                        status->metric = tun->key.on->curr_rt_local ? &tun->key.on->curr_rt_local->mr.umetric : NULL;
                        status->e2EMetric = tnn->e2eMetric ? &tnn->e2eMetric : NULL;
                        status->tunName = strlen(tun->name.str) ? tun->name.str : DBG_NIL;
  //                      status->up = tun->upIfIdx;

                        if (tsn) {
                                status->searchName = tsn->key.netName;
                                sprintf(status->searchNetwork, "%s/%d",
                                        ipXAsStr(tsn->key.family, &tsn->key.network.net), tsn->key.network.prefixlen);
                                status->searchId = &tsn->global_id;
                                status->ipMetric = tsn->ipmetric;

                                tsn->shown = YES;

                        } else {

                                status->searchName = DBG_NIL;
                                strcpy(status->searchNetwork, DBG_NIL);
                        }

                        status++;

                } while ((tsn = avl_iterate_item(&tnn->tun_search_tree, &itsn)));

        }

        for (itsn = NULL; (tsn = avl_iterate_item(&tun_search_name_tree, &itsn));) {

                if (!tsn->shown) {
                        strcpy(status->network, DBG_NIL);
                        status->tunName = DBG_NIL;
                        status->searchName = tsn->key.netName;
                        if (tsn->key.family) {
                                sprintf(status->searchNetwork, "%s/%d",
                                        ipXAsStr(tsn->key.family, &tsn->key.network.net), tsn->key.network.prefixlen);
                        } else {
                                sprintf(status->searchNetwork, DBG_NIL);
                        }
                        status++;
                }
                tsn->shown = NO;
        }

        assertion(-501322, (handl->data + status_size == (uint8_t*) status));

        return status_size;
}





STATIC_FUNC
int32_t opt_tun_net(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK) {

                uint8_t adv_family = 0;
                uint8_t mask;
                IPX_T dst;

                dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (af_cfg() != AF_INET6)
                        return FAILURE;

                if (str2netw(patch->val, &dst, cn, &mask, &adv_family, NO) == FAILURE) {
                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s", ARG_TUN_NET, patch->val);
                        return FAILURE;
                }

                if(cmd == OPT_ADJUST) {
                        char adjusted_dst[IPXNET_STR_LEN];
                        sprintf(adjusted_dst, "%s/%d", ipXAsStr(adv_family, &dst), mask);
                        set_opt_parent_val(patch, adjusted_dst);
                }


                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_NET_BW) && c->val) {

                                char *endptr;
                                unsigned long long ull = strtoul(c->val, &endptr, 10);

                                if (ull > UMETRIC_MAX || ull < UMETRIC_FM8_MIN || *endptr != '\0')
                                        return FAILURE;

                        } else if (!strcmp(c->opt->name, ARG_TUN_NET_LOCAL) && c->val) {

                                IPX_T src;
                                uint8_t src_family = AF_INET6;
                                char adjusted_src[IPXNET_STR_LEN];

                                if (str2netw(c->val, &src, cn, NULL, &src_family, YES) == FAILURE || !is_ip_valid(&src, AF_INET6)) {
                                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s", ARG_TUN_NET_LOCAL, c->val);
                                        return FAILURE;
                                }

                                if (avl_find(&tunnel_in_tree, &src)) {
                                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s already used as local address",
                                                ARG_TUN_NET_LOCAL, ip6AsStr(&src));
                                        return FAILURE;
                                }

                                sprintf(adjusted_src, "%s", ip6AsStr(&src));
                                set_opt_child_val(c, adjusted_src);
                        }
                }
	}


        if (cmd == OPT_APPLY) {
                my_description_changed = YES;
        }

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_tun_search(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        struct tun_search_node *tsn = NULL;

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

                struct opt_child *c = NULL;
                char name[NETWORK_NAME_LEN] = {0};

                dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (af_cfg() != AF_INET6)
                        return FAILURE;

                if (strlen(patch->val) >= NETWORK_NAME_LEN || validate_name_string(patch->val, strlen(patch->val) + 1) != SUCCESS)
                        return FAILURE;

                strcpy(name, patch->val);

                tsn = avl_find_item(&tun_search_name_tree, name);
                uint8_t family = tsn ? tsn->key.family : 0; // family of ARG_TUN_SEARCH_NETWORK and ARG_TUN_SEARCH_SRC must be the same!!!

                if (cmd == OPT_APPLY) {
                        
                        unlink_tun_net(NULL, NULL, NULL);
                        
                        if (patch->diff != DEL && !tsn) {
                                tsn = debugMalloc(sizeof (struct tun_search_node), -300400);
                                memset(tsn, 0, sizeof (struct tun_search_node));
                                strcpy(tsn->key.netName, name);
                                avl_insert(&tun_search_name_tree, tsn, -300401);
                                avl_insert(&tun_search_net_tree, tsn, -300401);
                                tsn->mtu = DEF_TUN_SEARCH_MTU;
                        }

                }


                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_SEARCH_NETWORK)) {

                                if (c->val) {
                                        uint8_t mask;
                                        IPX_T dst;
                                        char adjusted_dst[IPXNET_STR_LEN];

                                        if (str2netw(c->val, &dst, cn, &mask, &family, NO) == FAILURE)
                                                return FAILURE;

                                        sprintf(adjusted_dst, "%s/%d", ipXAsStr(family, &dst), mask);
                                        set_opt_child_val(c, adjusted_dst);

                                        if (cmd == OPT_APPLY && tsn) {
                                                avl_remove(&tun_search_net_tree, &tsn->key, -300000);
                                                tsn->key.network.net = dst;
                                                tsn->key.network.prefixlen = mask;
                                                tsn->key.family = family;
                                                avl_insert(&tun_search_net_tree, &tsn, -300000);
                                        }

                                } else if (cmd == OPT_APPLY && tsn) {
                                        avl_remove(&tun_search_net_tree, &tsn->key, -300000);
                                        tsn->key.network.net = ZERO_IP;
                                        tsn->key.network.prefixlen = 0;
                                        avl_insert(&tun_search_net_tree, &tsn, -300000);
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_IPMETRIC)) {

                                if (cmd == OPT_APPLY && tsn)
                                        tsn->ipmetric = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_TYPE)) {

                                if (cmd == OPT_APPLY && tsn)
                                        tsn->srcType = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_IP)) {

                                if (c->val) {
                                        struct net_key ip = ZERO_NET_KEY;
                                        char adjusted_src[IPXNET_STR_LEN];
                                        struct hna_node *hna;

                                        if (str2netw(c->val, &ip.net, cn, &ip.prefixlen, &family, YES) == FAILURE)
                                                return FAILURE;

                                        sprintf(adjusted_src, "%s/%d", ipXAsStr(family, &ip.net), ip.prefixlen);
                                        set_opt_child_val(c, adjusted_src);

                                        struct net_key find = (family == AF_INET) ? netX4ToNiit6(&ip) : ip;

                                        if ((hna = find_overlapping_hna(&find.net, find.prefixlen)) && hna->on != self) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s /%s=%s/%d already used by orig=%s hna=%s/%d",
                                                        ARG_TUN_SEARCH_NAME, name, ARG_TUN_SEARCH_IP, ip6AsStr(&find.net), find.prefixlen,
                                                        globalIdAsString(&hna->on->global_id), ip6AsStr(&hna->key.net), hna->key.prefixlen);

                                                return FAILURE;
                                        }

                                        if (cmd == OPT_APPLY && tsn) {
                                                tsn->srcPrefix = ip;
                                                tsn->key.family = family;
                                        }

                                } else if (cmd == OPT_APPLY && tsn) {
                                        tsn->srcPrefix.net = ZERO_IP;
                                        tsn->srcPrefix.prefixlen = 0;
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_HOSTNAME) ) {

                                if (c->val) {

                                        if (strlen(c->val) > GLOBAL_ID_NAME_LEN ||
                                                validate_name_string(c->val, strlen(c->val) + 1) != SUCCESS)
                                                return FAILURE;

                                        if (cmd == OPT_APPLY && tsn) {
                                                memset(tsn->global_id.name, 0, sizeof (tsn->global_id.name));
                                                sprintf(tsn->global_id.name, c->val);
                                        }
                                        
                                } else if ( cmd == OPT_APPLY && tsn ) {
                                        memset(tsn->global_id.name, 0, sizeof (tsn->global_id.name));
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_PKID)) {

                                if (c->val) {

                                        uint8_t pkid[GLOBAL_ID_PKID_LEN] = {0};

                                        if (hexStrToMem(c->val, pkid, GLOBAL_ID_PKID_LEN) == FAILURE)
                                                        return FAILURE;


                                        set_opt_child_val(c, memAsHexString(pkid, GLOBAL_ID_PKID_LEN));

                                        if (cmd == OPT_APPLY && tsn)
                                                memcpy(&tsn->global_id.pkid, pkid, GLOBAL_ID_PKID_LEN);

                                } else if (cmd == OPT_APPLY && tsn) {
                                        memset(&tsn->global_id.pkid, 0, GLOBAL_ID_PKID_LEN);
                                }

                        }  else if (!strcmp(c->opt->name, ARG_TUN_SEARCH_MTU)) {
				if (c->val) {
					uint16_t mtuVal = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_SEARCH_MTU;
				        if (cmd == OPT_APPLY && tsn)
				                tsn->mtu = mtuVal;
				}

                        }
                }
        }



        if (cmd == OPT_APPLY) {

                if (tsn) {

                        if (patch->diff == DEL) {
                                avl_remove(&tun_search_name_tree, &tsn->key.netName, -300402);
                                avl_remove(&tun_search_net_tree, &tsn->key, -300000);
                                debugFree(tsn, -300403);
                        }
                }

                set_tun_net(NULL);
                my_description_changed = YES;
        }


        if (  cmd == OPT_UNREGISTER ) {

                while ((tsn = avl_first_item(&tun_search_name_tree))) {

                        assertion(-501242, (!tsn->tun_net));

                        avl_remove(&tun_search_name_tree, &tsn->key.netName, -300404);
                        avl_remove(&tun_search_net_tree, &tsn->key, -300432);
                        debugFree(tsn, -300405);
                }
        }


        assertion(-501323, (tun_search_name_tree.items == tun_search_net_tree.items));

        return SUCCESS;
}




STATIC_FUNC
int32_t opt_tun_adv(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        struct tunnel_node_in *tun = NULL;

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                struct opt_child *c = NULL;

                if (af_cfg() != AF_INET6)
                        return FAILURE;


                {
                        IPX_T ip_remote;
                        uint8_t af_remote = AF_INET6;
                        struct hna_node *un_remote = NULL;
                        ;
                        char adjusted_remote[IPXNET_STR_LEN];


                        dbgf_track(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                                patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                        if (str2netw(patch->val, &ip_remote, cn, NULL, &af_remote, YES) == FAILURE || !is_ip_valid(&ip_remote, af_remote) ||
                                ((un_remote = find_overlapping_hna(&ip_remote, 128)) && un_remote->on != self)) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid prefix: %s or blocked by %s",
                                        patch->val, un_remote ? globalIdAsString(&un_remote->on->global_id) : DBG_NIL);

                                return FAILURE;
                        }

                        sprintf(adjusted_remote, "%s", ip6AsStr(&ip_remote));
                        set_opt_parent_val(patch, adjusted_remote);


                        if (cmd == OPT_APPLY) {

                                if ((tun = avl_find_item(&tunnel_in_tree, &ip_remote)))
                                        configure_tunnel_in(DEL, tun);

                                if (patch->diff == DEL) {
                                        avl_remove(&tunnel_in_tree, &ip_remote, -300391);
                                        debugFree(tun, -300392);
                                        tun = NULL;
                                } else {
                                        if (!tun) {
                                                tun = debugMalloc(sizeof (struct tunnel_node_in), -300389);
                                                memset(tun, 0, sizeof (struct tunnel_node_in));
                                                tun->tun6Id = -1;
                                                tun->remoteIp = ip_remote;
                                                tun->name_auto = 1;
                                                avl_insert(&tunnel_in_tree, tun, -300390);
                                        }
                                }
                        }
                }


                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_ADV_NAME) ) {
                                if (c->val) {
                                        if (strlen(c->val) >= sizeof (IFNAME_T) ||
                                                validate_name_string(c->val, strlen(c->val) + 1) != SUCCESS ||
                                                strncmp(tun_name_prefix.str, c->val, strlen(tun_name_prefix.str))) {
                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
                                                        c->val, tun_name_prefix.str);
                                                return FAILURE;
                                        }
                                        if (cmd == OPT_APPLY && tun) {
                                                strcpy(tun->name.str, c->val);
                                                tun->name_auto = 0;
                                        }
                                } else {
                                        if (cmd == OPT_APPLY && tun) {
                                                memset(&tun->name, 0, sizeof (tun->name));
                                                tun->name_auto = 1;
                                        }
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC4_TYPE)) {

                                if (cmd == OPT_APPLY && tun)
                                        tun->src4Type = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_INGRESS4)) {
                                IPX_T prefix4;
                                uint8_t af_prefix4 = AF_INET;
                                uint8_t prefix4len;

                                if (c->val) {
                                        if (str2netw(c->val, &prefix4, cn, &prefix4len, &af_prefix4, NO) == FAILURE ||
                                                !is_ip_valid(&prefix4, af_prefix4)) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s", ARG_TUN_ADV_INGRESS4, patch->val, c->val);
                                                return FAILURE;
                                        }

                                        if (cmd == OPT_APPLY && tun) {
                                                tun->ingress4Prefix.net = prefix4;
                                                tun->ingress4Prefix.prefixlen = prefix4len;
                                        }
                                } else {
                                        if (cmd == OPT_APPLY && tun) {
                                                tun->ingress4Prefix.net = ZERO_IP;
                                                tun->ingress4Prefix.prefixlen = 0;
                                        }
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC4_MIN)) {

                                if (cmd == OPT_APPLY && tun)
                                        tun->src4PrefixMin = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC6_TYPE)) {

                                if (cmd == OPT_APPLY && tun)
                                        tun->src6Type = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_INGRESS6)) {
                                IPX_T prefix6;
                                uint8_t af_prefix6 = AF_INET6;
                                uint8_t prefix6len;
                                char adjusted_prefix6[IPXNET_STR_LEN];

                                if (c->val) {
                                        if (str2netw(c->val, &prefix6, cn, &prefix6len, &af_prefix6, NO) == FAILURE ||
                                                !is_ip_valid(&prefix6, af_prefix6)) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s", ARG_TUN_ADV_INGRESS6, patch->val, c->val);
                                                return FAILURE;
                                        }

                                        sprintf(adjusted_prefix6, "%s", ip6AsStr(&prefix6));
                                        set_opt_child_val(c, adjusted_prefix6);

                                        if (cmd == OPT_APPLY && tun) {
                                                tun->ingress6Prefix.net = prefix6;
                                                tun->ingress6Prefix.prefixlen = prefix6len;
                                        }
                                } else {
                                        if (cmd == OPT_APPLY && tun) {
                                                tun->ingress6Prefix.net = ZERO_IP;
                                                tun->ingress6Prefix.prefixlen = 0;
                                        }
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC6_MIN)) {

                                if (cmd == OPT_APPLY && tun)
                                        tun->src6PrefixMin = c->val ? strtol(c->val, NULL, 10) : 0;

                        }

                }
        }


        if (cmd == OPT_APPLY)
                my_description_changed = YES;


        if (cmd == OPT_UNREGISTER) {

                while ((tun = avl_first_item(&tunnel_in_tree))) {
                        configure_tunnel_in(DEL, tun);
                        avl_remove(&tunnel_in_tree, &tun->remoteIp, -300393);
                        debugFree(tun, -300394);
                }
        }

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_tun_name(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        if (cmd == OPT_CHECK) {

                struct tunnel_node_in *tun;
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



STATIC_FUNC
int32_t opt_tun_address(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

        struct net_key net = ZERO_NET_KEY;
        uint8_t isTun4 = !strcmp(opt->name, ARG_TUN4_ADDRESS);
        uint8_t family = isTun4 ? AF_INET : AF_INET6;

        if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                if (af_cfg() != AF_INET6) {

                        return FAILURE;

                } else if (patch->diff == DEL) {

                        net = ZERO_NET_KEY;

                } else if (str2netw(patch->val, &net.net, cn, &net.prefixlen, &family, YES) == FAILURE || !is_ip_valid(&net.net, family)) {

                        return FAILURE;

                } else if (net.prefixlen < (isTun4 ? HNA4_PREFIXLEN_MIN : HNA6_PREFIXLEN_MIN)) {

                        return FAILURE;

                } else {

                        struct net_key find = isTun4 ? netX4ToNiit6(&net) : net;
                        struct hna_node *hna = find_overlapping_hna(&find.net, find.prefixlen);

                        if (hna && hna->on != self) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s/%d already used by orig=%s hna=%s/%d",
                                        opt->name, ip6AsStr(&find.net), find.prefixlen,
                                        globalIdAsString(&hna->on->global_id), ip6AsStr(&hna->key.net), hna->key.prefixlen);

                                return FAILURE;
                        }
                }
        }

        if (cmd == OPT_APPLY) {

                if (isTun4) {

                        tun4_address = net;

                        niit_dev_event_hook(PLUGIN_CB_SYS_DEV_EVENT, NULL);

                } else {

                        tun6_address = net;
                }

                my_description_changed = YES;
                unlink_tun_net(NULL, NULL, NULL);
                set_tun_net(NULL);
        }

        if(cmd == OPT_REGISTER) {
                memset(&tun4_address, 0, sizeof (tun4_address));
                memset(&tun6_address, 0, sizeof (tun6_address));
        }

        return SUCCESS;
}


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
	{ODI,0,ARG_TUN4_ADDRESS,        0,  5,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_address,
			ARG_PREFIX_FORM,HLP_TUN4_ADDRESS},
	{ODI,0,ARG_TUN6_ADDRESS,        0,  5,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_address,
			ARG_PREFIX_FORM,HLP_TUN6_ADDRESS}
        ,



	{ODI,0,ARG_TUN_NAME_PREFIX,    	0,5,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_name,
			ARG_NAME_FORM, "specify first letters of local tunnel-interface names"}
        ,
	{ODI,0,ARG_TUN_ADV, 	        0,5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_adv,
			ARG_ADDR_FORM,  "configure one-way IPv6 tunnel by specifying tunnel-src (remote) address"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_NAME,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,	        0,              0,0,            opt_tun_adv,
			ARG_NAME_FORM,	"specify name of tunnel interface"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_INGRESS4,  0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_adv,
			ARG_PREFIX_FORM,"specify IPv4 source prefix (ingress filter)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_INGRESS6,  0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_adv,
			ARG_PREFIX_FORM,"specify IPv6 source prefix (ingress filter)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC4_TYPE,0,5,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,    opt_tun_adv,
			ARG_VALUE_FORM, "specify IPv4 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC4_MIN,0,5,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        32,             0,0,            opt_tun_adv,
			ARG_VALUE_FORM, "specify IPv4 source prefix len usable for address auto configuration (0 = NO autoconfig)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC6_TYPE,0,5,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,    opt_tun_adv,
			ARG_VALUE_FORM, "specify IPv6 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC6_MIN,0,5,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        128,            0,0,            opt_tun_adv,
			ARG_VALUE_FORM, "specify IPv6 source prefix len usable for address auto configuration (0 = NO autoconfig)"}
        ,
        {ODI,0,ARG_TUN_NET,	 	0,5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,	        opt_tun_net,
			ARG_PREFIX_FORM,"specify network reachable via this tunnel"},
	{ODI,ARG_TUN_NET,ARG_TUN_NET_LOCAL,0,5,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY, 0,		0,              0,              0,0,            opt_tun_net,
			ARG_ADDR_FORM,	"specify to be used incoming tunnel interface by giving related tunnel-src address"},
	{ODI,ARG_TUN_NET,ARG_TUN_NET_BW, 'b',5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,		0,	        0,              0,0,            opt_tun_net,
			ARG_VALUE_FORM,	"specify bandwidth to network as bits/sec"}
        ,
	{ODI,0,ARG_TUN_SEARCH_NAME, 	0,5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_search,
		        ARG_NAME_FORM,  "specify arbitrary but unique name for network which should be reached via tunnel depending on sub criterias"},
	{ODI,ARG_TUN_SEARCH_NAME,ARG_TUN_SEARCH_NETWORK,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	0,              0,              0,0,            opt_tun_search,
			ARG_PREFIX_FORM, "specify network to be reached via tunnel"},
	{ODI,ARG_TUN_SEARCH_NAME,ARG_TUN_SEARCH_IP,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	0,              0,              0,0,            opt_tun_search,
			ARG_PREFIX_FORM,"specify IP address and prefixlen of tunnel"},
	{ODI,ARG_TUN_SEARCH_NAME,ARG_TUN_SEARCH_TYPE,0,5,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,opt_tun_search,
			ARG_VALUE_FORM, "specify tunnel ip allocation mechanism (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_SEARCH_NAME,ARG_TUN_SEARCH_HOSTNAME,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	0,              0,              0,0,            opt_tun_search,
			ARG_NAME_FORM,  "specify hotname of remote tunnel endpoint"},
	{ODI,ARG_TUN_SEARCH_NAME,ARG_TUN_SEARCH_PKID,0,5,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	0,              0,              0,0,            opt_tun_search,
			ARG_SHA2_FORM, "specify pkid of remote tunnel endpoint"},
	{ODI,ARG_TUN_SEARCH_NAME,ARG_TUN_SEARCH_IPMETRIC,0,5,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	0,      MAX_TUN_SEARCH_IPMETRIC,0,0,            opt_tun_search,
			ARG_VALUE_FORM, "specify ip metric for local routing table entries"},
	{ODI,ARG_TUN_SEARCH_NAME,ARG_TUN_SEARCH_MTU,0,5,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	MIN_TUN_SEARCH_MTU,MAX_TUN_SEARCH_MTU,DEF_TUN_SEARCH_MTU,0,opt_tun_search,
			ARG_VALUE_FORM, "specify MTU of outgoing tunnel"}
        ,
	{ODI,0,ARG_TUNS,	        0,5,2,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show announced and used tunnels and related networks"}

};


STATIC_FUNC
void hna_route_change_hook(uint8_t del, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

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
        TRACE_FUNCTION_CALL;
        task_remove((void(*)(void*))set_tun_net, NULL);
        set_route_change_hooks(hna_route_change_hook, DEL);
}


STATIC_FUNC
int32_t hna_init( void )
{
        TRACE_FUNCTION_CALL;

        assertion(-501254, is_zero((void*)&ZERO_NET_KEY, sizeof(ZERO_NET_KEY)));

        struct frame_handl tlv_handl;
        
        static const struct field_format hna4_format[] = DESCRIPTION_MSG_HNA4_FORMAT;
        static const struct field_format hna6_format[] = DESCRIPTION_MSG_HNA6_FORMAT;
        static const struct field_format tun6_adv_format[] = DESCRIPTION_MSG_TUN6_ADV_FORMAT;
        static const struct field_format tun4in6_ingress_adv_format[] = DESCRIPTION_MSG_TUN4IN6_INGRESS_ADV_FORMAT;
        static const struct field_format tun6in6_ingress_adv_format[] = DESCRIPTION_MSG_TUN6IN6_INGRESS_ADV_FORMAT;
        static const struct field_format tun4in6_src_adv_format[] = DESCRIPTION_MSG_TUN4IN6_SRC_ADV_FORMAT;
        static const struct field_format tun6in6_src_adv_format[] = DESCRIPTION_MSG_TUN6IN6_SRC_ADV_FORMAT;
        static const struct field_format tun4in6_adv_format[] = DESCRIPTION_MSG_TUN4IN6_NET_ADV_FORMAT;
        static const struct field_format tun6in6_adv_format[] = DESCRIPTION_MSG_TUN6IN6_NET_ADV_FORMAT;


        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_hna4);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET;
        tlv_handl.name = "HNA4_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_hna;
        tlv_handl.rx_frame_handler = process_description_tlv_hna;
        tlv_handl.msg_format = hna4_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_UHNA4, &tlv_handl);

        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_hna6);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "HNA6_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_hna;
        tlv_handl.rx_frame_handler = process_description_tlv_hna;
        tlv_handl.msg_format = hna6_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_UHNA6, &tlv_handl);




        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun6_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "TUN6_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tun6_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tun6_adv;
        tlv_handl.msg_format = tun6_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN6_ADV, &tlv_handl);


        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun4in6_ingress_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "TUN4IN6_INGRESS_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tunXin6_ingress_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tunXin6_ingress_adv;
        tlv_handl.msg_format = tun4in6_ingress_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN4IN6_INGRESS_ADV, &tlv_handl);

        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun6in6_ingress_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "TUN6IN6_INGRESS_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tunXin6_ingress_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tunXin6_ingress_adv;
        tlv_handl.msg_format = tun6in6_ingress_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN6IN6_INGRESS_ADV, &tlv_handl);


        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun4in6_src_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "TUN4IN6_SRC_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tunXin6_src_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tunXin6_src_adv;
        tlv_handl.msg_format = tun4in6_src_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN4IN6_SRC_ADV, &tlv_handl);

        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun6in6_src_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "TUN6IN6_SRC_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tunXin6_src_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tunXin6_src_adv;
        tlv_handl.msg_format = tun6in6_src_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN6IN6_SRC_ADV, &tlv_handl);


        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun4in6_net_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "TUN4IN6_NET_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tunXin6_net_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tunXin6_net_adv;
        tlv_handl.msg_format = tun4in6_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN4IN6_NET_ADV, &tlv_handl);

        memset(&tlv_handl, 0, sizeof (tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_tun6in6_net_adv);
        tlv_handl.fixed_msg_size = 1;
        tlv_handl.is_relevant = 1;
        tlv_handl.family = AF_INET6;
        tlv_handl.name = "TUN6IN6_NET_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_tlv_tunXin6_net_adv;
        tlv_handl.rx_frame_handler = process_description_tlv_tunXin6_net_adv;
        tlv_handl.msg_format = tun6in6_adv_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_TUN6IN6_NET_ADV, &tlv_handl);

        register_options_array(hna_options, sizeof ( hna_options), CODE_CATEGORY_NAME);

        set_route_change_hooks(hna_route_change_hook, ADD);

        register_status_handl(sizeof (struct tun_out_status), 1, tun_out_status_format, ARG_TUNS, tun_out_status_creator);


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
        hna_plugin.cb_plugin_handler[PLUGIN_CB_SYS_DEV_EVENT] = hna_dev_event_hook;
        hna_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_CREATED] = (void (*) (int32_t, void*)) hna_description_event_hook;
        hna_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_DESTROY] = (void (*) (int32_t, void*)) hna_description_event_hook;

        return &hna_plugin;
}


