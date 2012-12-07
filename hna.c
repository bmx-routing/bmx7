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
#include <endian.h>

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

static AVL_TREE(tun_in_tree, struct tun_in_node, nameKey);             // configured tun_in tunnels

static AVL_TREE(tun_search_tree, struct tun_search_node, nameKey); // configured tun_out names searches
//static AVL_TREE(tun_search_net_tree, struct tun_search_node, tunSearchKey); //REMOVE // configured tun_out networks searches

static AVL_TREE(tun_bit_tree, struct tun_bit_node, tunBitKey);          // identified matching bits (peaces) of tun_search and tun_net trees

static AVL_TREE(tun_net_tree, struct tun_net_node, tunNetKey);          // rcvd tun_out network advs
static AVL_TREE(tun_out_tree, struct tun_out_node, tunOutKey);          // rcvd tun_out advs

LIST_SIMPEL(tunXin6_net_adv_list_list, struct tunXin6_net_adv_list_node, list, list);

static const struct tun_net_key ZERO_TUN_NET_KEY = {.tun = NULL};

struct net_key tun4_address;
struct net_key tun6_address;

IDM_T (*hna_configure_niit4to6) (IDM_T del, struct net_key *key) = NULL;
IDM_T (*hna_configure_niit6to4) (IDM_T del, struct net_key *key) = NULL;



static IFNAME_T tun_name_prefix = {{DEF_TUN_NAME_PREFIX}};

static int32_t tun_out_mtu = DEF_TUN_OUT_MTU;


char* bmx6RouteBits2String(uint32_t bmx6_route_bits)
{
	static char r[BMX6_ROUTE_MAX+1];

	//memset(r, ' ', sizeof(r));
	//r[BMX6_ROUTE_MAX] = 0;

	uint8_t t, p=0;
	for (t = 0; t < BMX6_ROUTE_MAX; t++) {
		if (bit_get((uint8_t*) &bmx6_route_bits, sizeof (bmx6_route_bits) * 8, t))
			r[p++] = bmx6_rt_dict[t].bmx2Char;
	}
        if(p)
                r[p] = 0;
        else
                sprintf(r, "---");

	return r;
}

void set_tunXin6_net_adv_list(uint8_t del, struct list_head *adv_list)
{
        struct list_node *list_pos, *tmp_pos, *prev_pos = (struct list_node *)&tunXin6_net_adv_list_list;
	struct tunXin6_net_adv_list_node *n;

        list_for_each_safe(list_pos, tmp_pos,  &tunXin6_net_adv_list_list)
        {
                n = list_entry(list_pos, struct tunXin6_net_adv_list_node, list);

                if (adv_list == n->adv_list) {

			if ( del ) {
                                list_del_next(( &tunXin6_net_adv_list_list), prev_pos);
				debugFree( n, -300516 );
                                return;
			} else {
                                cleanup_all(-501440);
			}

		} else {
			prev_pos = &n->list;
		}
	}

        assertion(-501441, (!del));

        n = debugMalloc(sizeof ( struct tunXin6_net_adv_list_node), -300517);
        memset(n, 0, sizeof ( struct tunXin6_net_adv_list_node));

        n->adv_list = adv_list;
        list_add_tail((&tunXin6_net_adv_list_list), &n->list);
}


STATIC_FUNC
void hna_dev_event_hook(int32_t cb_id, void* unused)
{
        TRACE_FUNCTION_CALL;

        struct tun_in_node *tun;
        struct avl_node *an = NULL;
        while ((tun = avl_iterate_item(&tun_in_tree, &an))) {

                if (tun->upIfIdx && is_ip_local(&tun->remote)) {
                        dbgf_sys(DBGT_WARN, "ERROR:..");
                        my_description_changed = YES;
                }
        }

}




STATIC_FUNC
IDM_T configure_route(IDM_T del, struct orig_node *on, struct net_key *key)
{

        assertion(-501331, (key->af == AF_CFG));

        // update network routes:
        if (del) {

                return iproute(IP_ROUTE_HNA, DEL, NO, key, RT_TABLE_HNA, 0, 0, NULL, NULL, DEF_IP_METRIC, NULL);

        } else {

                struct link_dev_node *lndev = on->curr_rt_lndev;

                assertion(-500820, (lndev));
                ASSERTION(-500239, (avl_find(&link_dev_tree, &(lndev->key))));
                assertion(-500579, (lndev->key.dev->if_llocal_addr));

                return iproute(IP_ROUTE_HNA, ADD, NO, key, RT_TABLE_HNA, 0,
                        lndev->key.dev->if_llocal_addr->ifa.ifa_index, &(lndev->key.link->link_ip),
                        (key->af == AF_INET ? (&(self->primary_ip)) : NULL), DEF_IP_METRIC, NULL);

        }
}


STATIC_FUNC
uint8_t set_hna_to_key(struct net_key *key, struct description_msg_hna4 *uhna4, struct description_msg_hna6 *uhna6)
{
        uint8_t flags;

        if (uhna4) {
                IPX_T ipX = ip4ToX(uhna4->ip4);
                setNet(key, AF_INET, uhna4->prefixlen, &ipX);
                flags = uhna4->flags;

        } else {
                setNet(key, AF_INET6, uhna6->prefixlen, &uhna6->ip6);
                flags = uhna6->flags;
        }

        ip_netmask_validate(&key->ip, key->mask, key->af, YES);

        return flags;
}


STATIC_FUNC
int _create_tlv_hna(uint8_t* data, uint16_t max_size, uint16_t pos, struct net_key *net, uint8_t flags)
{
        TRACE_FUNCTION_CALL;
        int i;
        uint16_t msg_size = net->af == AF_INET ? sizeof (struct description_msg_hna4) : sizeof (struct description_msg_hna6);


        if ((pos + msg_size) > max_size) {
                dbgf_sys(DBGT_ERR, "unable to announce %s! Exceeded %s=%d", netAsStr(net), ARG_UDPD_SIZE, max_size);
                return pos;
        }

        dbgf_track(DBGT_INFO, "%s", netAsStr(net));

        assertion(-500610, (!(net->af == AF_INET6 && is_ip_net_equal(&net->ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))));
        // this should be catched during configuration!!


        if (net->af == AF_INET) {
                struct description_msg_hna4 *msg4 = ((struct description_msg_hna4 *) data);

                struct description_msg_hna4 hna4;
                memset( &hna4, 0, sizeof(hna4));
                hna4.ip4 = ipXto4(net->ip);
                hna4.prefixlen = net->mask;
                hna4.flags = flags;

                for (i = 0; i < pos / msg_size; i++) {

                        if (!memcmp(&(msg4[i]), &hna4, sizeof (struct description_msg_hna4)))
                                return pos;
                }

                msg4[i] = hna4;

        } else {
                struct description_msg_hna6 *msg6 = ((struct description_msg_hna6 *) data);

                struct description_msg_hna6 hna6;
                memset( &hna6, 0, sizeof(hna6));
                hna6.ip6 = net->ip;
                hna6.prefixlen = net->mask;
                hna6.flags = flags;

                for (i = 0; i < pos / msg_size; i++) {

                        if (!memcmp(&(msg6[i]), &hna6, sizeof (struct description_msg_hna6)))
                                return pos;
                }

                msg6[i] = hna6;
        }

        return (pos + msg_size);
}


STATIC_FUNC
IDM_T configure_tunnel_in(uint8_t del, struct tun_in_node *tin)
{
        TRACE_FUNCTION_CALL;
        assertion(-501292, (is_ip_set(&tin->remote)));
        assertion(-501341, IMPLIES(!del, (is_ip_set(&self->primary_ip))));
        assertion(-501311, IMPLIES(tin->upIfIdx, tin->nameKey.str[0]));
        assertion(-501342, IMPLIES(tin->upIfIdx, del));
        assertion(-501368, IMPLIES(del,((tin->tun6Id >= 0) == (tin->upIfIdx > 0))));
        assertion(-501369, IMPLIES(!del,((tin->tun6Id >= 0) && (tin->upIfIdx == 0))));

        if (del && tin->upIfIdx) {

                kernel_set_tun(DEL, tin->nameKey.str, 0, NULL, NULL);
                tin->upIfIdx = 0;
                tin->tun6Id = -1;

/*
                tun->src4Ip = ZERO_IP;
                tun->src6Ip = ZERO_IP;
*/


        } else if (!del && !tin->upIfIdx) {

                if (is_ip_local(&tin->remote) ||
                        (tin->ingress6Prefix.mask && find_overlapping_hna(&tin->ingress6Prefix.ip, tin->ingress6Prefix.mask, self))) {

                        dbgf_sys(DBGT_WARN, "FAILED creating tun remoteIp=%s", ip6AsStr(&tin->remote));
                        return FAILURE;
                }


                IPX_T *local = &self->primary_ip;
                IPX_T *remote = &tin->remote;

                if (tin->name_auto) {

                        static uint16_t tun_idx = 0;
                        struct if_link_node *iln = NULL;

                        do {
                                memset(&tin->nameKey, 0, sizeof (tin->nameKey));
                                snprintf(tin->nameKey.str, IFNAMSIZ - 1, "%s_%s%.4X", tun_name_prefix.str, "in", tun_idx++);

                                struct avl_node *an = NULL;
                                iln = NULL;
                                //check if tun->name is already used:
                                while ((iln = avl_iterate_item(&if_link_tree, &an)) && strcmp(iln->name.str, tin->nameKey.str));

                        } while (iln);

                }

                assertion(-501312, (strlen(tin->nameKey.str)));

                if (kernel_set_tun(ADD, tin->nameKey.str, IPPROTO_IP, local, remote) == SUCCESS) {

                        tin->upIfIdx = get_if_index(&tin->nameKey);

                        if (tun4_address.mask)
                                kernel_set_addr(ADD, tin->upIfIdx, AF_INET, &tun4_address.ip, 32, NO /*deprecated*/);

                        if (tun6_address.mask)
                                kernel_set_addr(ADD, tin->upIfIdx, AF_INET6, &tun6_address.ip, 128, NO /*deprecated*/);
                }

        }

        return (XOR(del, tin->upIfIdx)) ? SUCCESS : FAILURE;
}


STATIC_FUNC
int create_description_tlv_hna(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        assertion(-500765, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));

        uint8_t *data = tx_iterator_cache_msg_ptr(it);
        uint16_t max_size = tx_iterator_cache_data_space_max(it);
        uint8_t family = it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6;
        uint8_t max_plen = (family == AF_INET ? 32 : 128);

        int pos = 0;
        struct avl_node *an;
        struct dev_node *dev;
        struct hna_node *un;

        if (!is_ip_set(&self->primary_ip))
                return TLV_TX_DATA_IGNORED;

        pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, family, max_plen, &self->primary_ip), 0);

/*
        if (tun4_address.mask) {
                struct net_key niit6_address = netX4ToNiit6(&tun4_address);
                pos = _create_tlv_hna(data, max_size, pos, &niit6_address, 0);
        }

        if (tun6_address.mask)
                pos = _create_tlv_hna(data, max_size, pos, &tun6_address, 0);
        

        struct tun_search_node *tsn;
        for (an = NULL; (tsn = avl_iterate_item(&tun_search_name_tree, &an));) {
                if (tsn->srcPrefix.mask) {
                        struct net_key src = (tsn->srcPrefix.af == AF_INET) ? netX4ToNiit6(&tsn->srcPrefix) : tsn->srcPrefix;
                        pos = _create_tlv_hna(data, max_size, pos, &src, 0);
                }
        }
*/


        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                if (dev->active && dev->announce)
                        pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, family, max_plen, &dev->if_global_addr->ip_addr), 0);
        }


        if (family == AF_INET6) {

                struct tun_in_node *tin;
                struct net_key autoRemotePrefix = bmx6AutoEUI64Ip6(primary_phy, &remote_prefix_cfg);

                if (default_tun_in.tun6Id >= 0)
                        configure_tunnel_in(DEL, &default_tun_in);

                for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));)
                        configure_tunnel_in(DEL, tin);

                if (!tun_in_tree.items) {

                        if (autoRemotePrefix.mask && (tun4_address.mask || tun6_address.mask)) {
                                memset(&default_tun_in, 0, sizeof (default_tun_in));
                                default_tun_in.remote = autoRemotePrefix.ip;
                                default_tun_in.name_auto = 1;
                                default_tun_in.tun6Id = 0;
                                configure_tunnel_in(ADD, &default_tun_in);
                                pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, AF_INET6, 128, &default_tun_in.remote), DESC_MSG_HNA_FLAG_NO_ROUTE);
                        }

                } else {

                        int16_t m = 0;
                        for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));) {

                                if (!tin->remote_manual) {
                                        tin->remote = autoRemotePrefix.ip;
                                        tin->remote.s6_addr[7] = m;
                                }

                                tin->tun6Id = m++;
                                configure_tunnel_in(ADD, tin);
                                assertion(-501237, (tin->upIfIdx && tin->tun6Id == -1));
                                pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, AF_INET6, 128, &tin->remote), DESC_MSG_HNA_FLAG_NO_ROUTE);
                        }
                }
        }


        for (an = NULL; (un = avl_iterate_item(&local_uhna_tree, &an));)
                pos = _create_tlv_hna(data, max_size, pos, &un->key, 0);


        return pos;
}




STATIC_FUNC
void configure_hna(IDM_T del, struct net_key* key, struct orig_node *on, uint8_t flags)
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
                un->flags = flags;
                avl_insert(&global_uhna_tree, un, -300149);

                if (on == self)
                        avl_insert(&local_uhna_tree, un, -300150);

        }


        if (on == self) {

                // update throw routes:
                if (policy_routing == POLICY_RT_ENABLED && ip_throw_rules_cfg) {
                        assertion(-501333, (key->af == AF_CFG));
                        iproute(IP_THROW_MY_HNA, del, NO, key, RT_TABLE_HNA, 0, 0, 0, 0, 0, NULL);
                        iproute(IP_THROW_MY_HNA, del, NO, key, RT_TABLE_TUN, 0, 0, 0, 0, 0, NULL);
                }

        } else if (on->curr_rt_lndev && !(flags & DESC_MSG_HNA_FLAG_NO_ROUTE)) {

                configure_route(del, on, key);
                if (hna_configure_niit4to6)
                        (*hna_configure_niit4to6)(del, key);
        }


        if (del)
                debugFree(un, -300089);

}


STATIC_FUNC
struct hna_node * find_orig_hna(struct orig_node *on)
{
        struct hna_node *un;
        struct avl_node *it = NULL;

        while ((un = avl_iterate_item(&global_uhna_tree, &it)) && un->on != on);

        return un;
}


struct hna_node * find_overlapping_hna( IPX_T *ipX, uint8_t prefixlen, struct orig_node *except )
{
        struct hna_node *un;
        struct avl_node *it = NULL;

        while ((un = avl_iterate_item(&global_uhna_tree, &it))) {

                assertion(-501353, (un->on));

                if (un->on != except && is_ip_net_equal(ipX, &un->key.ip, MIN(prefixlen, un->key.mask), AF_CFG))
                        return un;

        }
        return NULL;
}


static struct net_key *hna_net_keys = NULL;
static uint32_t hna_net_key_elements = 0;

STATIC_FUNC
int process_description_tlv_hna(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        ASSERTION(-500357, (it->frame_type == BMX_DSC_TLV_UHNA4 || it->frame_type == BMX_DSC_TLV_UHNA6));
        assertion(-500588, (it->on));

        struct orig_node *on = it->on;
        uint8_t op = it->op;
        uint8_t family = (it->frame_type == BMX_DSC_TLV_UHNA4 ? AF_INET : AF_INET6);

        uint32_t hna_net_curr = 0;

        assertion(-600004, (on != self ||
                op == TLV_OP_CUSTOM_NIIT6TO4_ADD || op == TLV_OP_CUSTOM_NIIT6TO4_DEL ||
                op == TLV_OP_CUSTOM_NIIT4TO6_ADD || op == TLV_OP_CUSTOM_NIIT4TO6_DEL));


        if (AF_CFG != family) {
                dbg_mute(10, DBGL_CHANGES, DBGT_WARN, "%s NOT supported in this mode", family2Str(family));
                return TLV_RX_DATA_IGNORED;
        }

        if (op == TLV_OP_NEW || op == TLV_OP_DEL) {
                struct hna_node *un;
                while ((un = find_orig_hna(on)))
                        configure_hna(DEL, &un->key, on, un->flags);

                on->primary_ip = ZERO_IP;
                ipXToStr(family, &ZERO_IP, on->primary_ip_str);

                if (op == TLV_OP_DEL)
                        return it->frame_msgs_length;
        }


        uint16_t msg_size = it->handl->min_msg_size;
        uint16_t pos;

        for (pos = 0; pos < it->frame_msgs_length; pos += msg_size) {

                struct net_key key;
                uint8_t flags;

                if (it->frame_type == BMX_DSC_TLV_UHNA4)
                        flags = set_hna_to_key(&key, (struct description_msg_hna4 *) (it->frame_data + pos), NULL);
                else
                        flags = set_hna_to_key(&key, NULL, (struct description_msg_hna6 *) (it->frame_data + pos));


                dbgf_track(DBGT_INFO, "%s %s %s %s=%s",
                        tlv_op_str(op), family2Str(family), globalIdAsString(&on->global_id), ARG_UHNA, netAsStr(&key));

                if (op == TLV_OP_TEST) {

                        struct hna_node *un = NULL;

                        if (!is_ip_valid(&key.ip, family) || 
                                is_ip_net_equal(&key.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6) ||
                                (un = find_overlapping_hna(&key.ip, key.mask, on))) {

                                dbgf_sys(DBGT_ERR, "global_id=%s %s=%s blocked (by global_id=%s)",
                                        globalIdAsString(&on->global_id), ARG_UHNA, netAsStr(&key),
                                        un ? globalIdAsString(&un->on->global_id) : "???");

                                return TLV_RX_DATA_BLOCKED;
                        }


                        // check if node announces the same key twice:
                        uint32_t i;
                        for (i = 0; i < hna_net_curr; i++) {
                                if (!memcmp(&hna_net_keys[i], &key, sizeof (key))) {
                                        dbgf_sys(DBGT_ERR, "global_id=%s %s=%s blocked due to duplicate announcement",
                                                globalIdAsString(&on->global_id), ARG_UHNA, netAsStr(&key));
                                        return TLV_RX_DATA_BLOCKED;
                                }
                        }

                        if (hna_net_key_elements < (i + 1))
                                hna_net_keys = debugRealloc(hna_net_keys, (i + 1) * sizeof (key), -300398);
                        memcpy(&hna_net_keys[i], &key, sizeof (key));
                        hna_net_key_elements = (hna_net_curr = (i + 1));
                         



                } else if (op == TLV_OP_NEW) {

                        ASSERTION( -500359, (!avl_find(&global_uhna_tree, &key)));

                        if (pos == 0) {
                                on->primary_ip = key.ip;
                                ipFToStr( &key.ip, on->primary_ip_str);
                        }

                        configure_hna(ADD, &key, on, flags);


                } else if (op >= TLV_OP_CUSTOM_MIN) {

                        dbgf_all(DBGT_INFO, "configure_niit... op=%d  global_id=%s blocked=%d",
                                op, globalIdAsString(&on->global_id), on->blocked);

                        if (!on->blocked  && !(flags & DESC_MSG_HNA_FLAG_NO_ROUTE)) {
                                //ASSERTION(-501314, (avl_find(&global_uhna_tree, &key)));

                                if (op == TLV_OP_CUSTOM_NIIT6TO4_ADD) {
                                        if (hna_configure_niit6to4)
                                                (*hna_configure_niit6to4)(ADD, &key);
                                } else if (op == TLV_OP_CUSTOM_NIIT6TO4_DEL) {
                                        if (hna_configure_niit6to4)
                                                (*hna_configure_niit6to4)(DEL, &key);
                                } else if (op == TLV_OP_CUSTOM_NIIT4TO6_ADD) {
                                        if (hna_configure_niit4to6)
                                                (*hna_configure_niit4to6)(ADD, &key);
                                } else if (op == TLV_OP_CUSTOM_NIIT4TO6_DEL) {
                                        if (hna_configure_niit4to6)
                                                (*hna_configure_niit4to6)(DEL, &key);
                                } else if (op == TLV_OP_CUSTOM_HNA_ROUTE_DEL) {
                                        if (hna_configure_niit4to6)
                                                (*hna_configure_niit4to6)(DEL, &key);
                                        configure_route(DEL, on, &key);
                                } else if (op == TLV_OP_CUSTOM_HNA_ROUTE_ADD) {
                                        configure_route(ADD, on, &key);
                                        if (hna_configure_niit4to6)
                                                (*hna_configure_niit4to6)(ADD, &key);
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

        return it->frame_msgs_length;
}





STATIC_FUNC
int32_t opt_uhna(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                struct net_key hna = ZERO_NETCFG_KEY;
                struct hna_node *un;

                dbgf_all(DBGT_INFO, "af_cfg=%s diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        family2Str(hna.af), patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (str2netw(patch->val, &hna.ip, cn, &hna.mask, &hna.af, NO) == FAILURE || !is_ip_valid(&hna.ip, hna.af)) {
                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid prefix: %s", patch->val);
                        return FAILURE;
                }

                set_opt_parent_val(patch, netAsStr(&hna));

                if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

                        if (patch->diff != DEL && (un = find_overlapping_hna(&hna.ip, hna.mask, self))) {

                                dbg_cn(cn, DBGL_CHANGES, DBGT_ERR,
                                        "%s=%s already blocked by global_id=%s !", ARG_UHNA, netAsStr(&hna),
                                        globalIdAsString(&un->on->global_id));

                                return FAILURE;
                        }
                }

                if (cmd == OPT_APPLY) {
                        configure_hna((patch->diff == DEL ? DEL : ADD), &hna, self, 0);
                        my_description_changed = YES;
                }


	} else if ( cmd == OPT_UNREGISTER ) {

                struct hna_node * un;

                while ((un = avl_first_item(&global_uhna_tree)))
                        configure_hna(DEL, &un->key, self, un->flags);
	}

	return SUCCESS;
}











STATIC_FUNC
IDM_T configure_tunnel_out(uint8_t del, struct tun_out_node *ton)
{
        TRACE_FUNCTION_CALL;
        assertion(-501292, (is_ip_set(&ton->localIp)));
        assertion(-501235, (ton->tunOutKey.on));
        assertion(-501321, (ton->tunOutKey.on != self));
        assertion(-501343, IMPLIES(!del, (is_ip_set(&ton->tunOutKey.on->primary_ip))));
        assertion(-501311, IMPLIES(ton->upIfIdx, ton->name.str[0]));
        assertion(-501344, IMPLIES(ton->upIfIdx, del));

        if (del && ton->upIfIdx) {

                kernel_set_tun(DEL, ton->name.str, 0, NULL, NULL);
                ton->upIfIdx = 0;
                ton->src4Ip = ZERO_IP;
                ton->src6Ip = ZERO_IP;

                return SUCCESS;


        } else if (!del && !ton->upIfIdx) {


                IPX_T *local = &ton->localIp;
                IPX_T *remote = &ton->remoteIp;

                if (ton->name_auto) {

                        static uint16_t tun_idx = 0;
                        struct if_link_node *iln = NULL;

                        do {
                                memset(&ton->name, 0, sizeof (ton->name));
                                snprintf(ton->name.str, IFNAMSIZ - 1, "%s_out%.4X", tun_name_prefix.str, tun_idx++);

                                struct avl_node *an = NULL;
                                iln = NULL;
                                //check if tun->name is already used:
                                while ((iln = avl_iterate_item(&if_link_tree, &an)) && strcmp(iln->name.str, ton->name.str));

                        } while (iln);

                }

                assertion(-501312, (strlen(ton->name.str)));

                if (kernel_set_tun(ADD, ton->name.str, IPPROTO_IP, local, remote) == SUCCESS &&
                        (ton->upIfIdx = get_if_index(&ton->name)) > 0 &&
                        (ton->orig_mtu = kernel_get_mtu(ton->name.str)) >= MIN_TUN_OUT_MTU ) {

                        return SUCCESS;
                }
        }

        if(ton->upIfIdx)
                configure_tunnel_out(DEL, ton);

        return FAILURE;
}


STATIC_FUNC
void _add_tun_bit_node(struct tun_search_node *tsna, struct tun_net_node *tnna)
{
        TRACE_FUNCTION_CALL;

        struct tun_bit_key_nodes tbkn;
        struct avl_node *itsn = NULL;

        while ((tbkn.tsn = tsna ? tsna : avl_iterate_item(&tun_search_tree, &itsn))) {

                struct avl_node *itnn = NULL;
                GLOBAL_ID_T *tsn_gid = &tbkn.tsn->global_id;
                struct net_key *tsn_netKey = &tbkn.tsn->net;
                struct net_key srcPrefix = tbkn.tsn->srcPrefix.mask ? tbkn.tsn->srcPrefix :
                        (tsn_netKey->af == AF_INET ? tun4_address : tun6_address);

                dbgf_track(DBGT_INFO, "%s=%s: %s=%s %s=%d %s=%s %s=%s ",
                        ARG_TUN_OUT, tbkn.tsn->nameKey, ARG_TUN_OUT_HOSTNAME, globalIdAsString(&tbkn.tsn->global_id),
                        ARG_TUN_OUT_TYPE, tbkn.tsn->srcType, ARG_TUN_OUT_NET, netAsStr(tsn_netKey),
                        ARG_TUN_OUT_IP, netAsStr(&srcPrefix));

                while ((tbkn.tnn = tnna ? tnna : avl_iterate_item(&tun_net_tree, &itnn))) {

//                        assertion(-501370, (!avl_find(&tun_bit_tree, )));
                        assertion(-501371, (!avl_find(&(tbkn.tsn->tun_bit_tree), &tbkn)));
                        assertion(-501372, (!avl_find(&(tbkn.tnn->tun_bit_tree), &tbkn)));

                        struct orig_node *on = tbkn.tnn->tunNetKey.tun->tunOutKey.on;
                        GLOBAL_ID_T *tnn_gid = &on->global_id;
                        struct net_key *tnn_netKey = &tbkn.tnn->tunNetKey.netKey;
                        struct net_key ingressPrefix = (tnn_netKey->af == AF_INET) ?
                                tbkn.tnn->tunNetKey.tun->ingress4Prefix : tbkn.tnn->tunNetKey.tun->ingress6Prefix;

                        dbgf_track(DBGT_INFO, "checking network=%s bw_fmu8=%d, ingress=%s localIp=%s tun6Id=%d from orig=%s",
                                netAsStr(tnn_netKey), tbkn.tnn->bandwidth.val.u8, netAsStr(&ingressPrefix),
                                ip6AsStr(&tbkn.tnn->tunNetKey.tun->localIp), tbkn.tnn->tunNetKey.tun->tunOutKey.tun6Id,
                                globalIdAsString(&on->global_id));

                        if (!(
                                (tbkn.tsn->bmx6RouteBits == 0 ||
                                bit_get( (uint8_t*)&tbkn.tsn->bmx6RouteBits, sizeof(tbkn.tsn->bmx6RouteBits), tbkn.tnn->tunNetKey.bmx6RouteType )) &&
                                tsn_netKey->af == tnn_netKey->af &&
                                (tbkn.tsn->netPrefixMax == TYP_TUN_OUT_PREFIX_NET ?
                                tsn_netKey->mask >= tnn_netKey->mask : tbkn.tsn->netPrefixMax >= tnn_netKey->mask) &&
                                (tbkn.tsn->netPrefixMin == TYP_TUN_OUT_PREFIX_NET ?
                                tsn_netKey->mask <= tnn_netKey->mask : tbkn.tsn->netPrefixMin <= tnn_netKey->mask) &&
                                is_ip_net_equal(&tsn_netKey->ip, &tnn_netKey->ip, MIN(tsn_netKey->mask, tnn_netKey->mask), tnn_netKey->af) &&
                                IMPLIES(strlen(tsn_gid->name), !strcmp(tsn_gid->name, tnn_gid->name)) &&
                                IMPLIES(!is_zero(&tsn_gid->pkid, GLOBAL_ID_PKID_LEN), !memcmp(&tsn_gid->pkid, &tnn_gid->pkid, GLOBAL_ID_PKID_LEN))
                                )) {

                                dbgf_track(DBGT_INFO, "failed A");

                        } else if (!(tbkn.tsn->srcType == TUN_SRC_TYPE_UNDEF || tbkn.tsn->srcType == TUN_SRC_TYPE_STATIC)) {

                                dbgf_track(DBGT_INFO, "failed B");

                        } else if (!srcPrefix.mask || srcPrefix.mask < ingressPrefix.mask ||
                                !is_ip_net_equal(&srcPrefix.ip, &ingressPrefix.ip, MIN(srcPrefix.mask, ingressPrefix.mask), tnn_netKey->af)) {

                                dbgf_track(DBGT_INFO, "failed C");

                        } else {

                                struct tun_bit_node *tbn = debugMalloc(sizeof ( struct tun_bit_node), -300455);
                                memset(tbn, 0, sizeof (struct tun_bit_node));

                                tbn->tunBitKey.beInvTunBitMetric = hton64(UMETRIC_MAX);
                                tbn->tunBitKey.beIpMetric = htonl(tbkn.tsn->ipmetric);
                                tbn->tunBitKey.keyNodes = tbkn;
                                tbn->tunBitKey.invNetKey = tsn_netKey->mask > tnn_netKey->mask ? *tsn_netKey : *tnn_netKey;
                                tbn->tunBitKey.invNetKey.mask = 128 - tbn->tunBitKey.invNetKey.mask;

                                avl_insert(&tun_bit_tree, tbn, -300456);
                                avl_insert(&tbkn.tsn->tun_bit_tree, tbn, -300457);
                                avl_insert(&tbkn.tnn->tun_bit_tree, tbn, -300458);
                        }

                        if (tnna)
                                break;
                }

                if (tsna)
                        break;
        }
}

STATIC_FUNC
void set_tun_out_mtu(struct tun_out_node *ton, uint16_t new_mtu) {

        if(ton->upIfIdx && new_mtu != ton->curr_mtu) {

                if(new_mtu == DEF_TUN_OUT_MTU) {
                        kernel_set_mtu(ton->name.str, ton->orig_mtu);
                        ton->curr_mtu = DEF_TUN_OUT_MTU;
                } else {
                        kernel_set_mtu(ton->name.str, new_mtu);
                        ton->curr_mtu = new_mtu;
                }
        }
}


STATIC_FUNC
void configure_tun_bit(uint8_t del, struct tun_bit_node *tbn)
{
        TRACE_FUNCTION_CALL;

        struct route_export rte, *rtep = NULL;
        if( tbn->tunBitKey.keyNodes.tsn->exportDistance != TYP_EXPORT_DISTANCE_INFINITE ) {
                memset(&rte, 0, sizeof(rte));
                rte.exportDistance = tbn->tunBitKey.keyNodes.tsn->exportDistance;
                rte.exportOnly = tbn->tunBitKey.keyNodes.tsn->exportOnly;
                rte.ipexport = NO; // not yet
                rtep = &rte;
        }

        if (del && tbn->active) {

                struct tun_out_node *ton = tbn->tunBitKey.keyNodes.tnn->tunNetKey.tun;
                struct net_key netKey = tbn->tunBitKey.invNetKey;
                netKey.mask = 128 - netKey.mask;
                uint8_t rtype = tbn->tunBitKey.keyNodes.tnn->tunNetKey.bmx6RouteType;

                iproute((IP_ROUTE_TUNS + rtype), DEL, NO, &netKey, RT_TABLE_TUN, 0, ton->upIfIdx, NULL, NULL, ntohl(tbn->tunBitKey.beIpMetric), rtep);

                tbn->active = NO;

                uint8_t used = NO;
                struct avl_node *used_tnn_it = NULL;
                struct tun_net_node *used_tnn;
                while (!used && (used_tnn = avl_iterate_item(&ton->tun_net_tree, &used_tnn_it))) {
                        struct avl_node *used_tbn_it = NULL;
                        struct tun_bit_node *used_tbn;
                        while (!used && (used_tbn = avl_iterate_item(&used_tnn->tun_bit_tree, &used_tbn_it))) {
                                if (used_tbn->active)
                                        used = YES;
                        }
                }

                assertion(-501236, IMPLIES(used, ton->upIfIdx));

                if (!used)
                        configure_tunnel_out(DEL, ton);

        } else if (!del && !tbn->active) {

                struct tun_search_node *tsn = tbn->tunBitKey.keyNodes.tsn;
                struct tun_net_node *tnn = tbn->tunBitKey.keyNodes.tnn;
                uint8_t rtype = tnn->tunNetKey.bmx6RouteType;
                struct tun_out_node *ton = tnn->tunNetKey.tun;
                struct net_key netKey = tbn->tunBitKey.invNetKey;
                netKey.mask = 128 - netKey.mask;

                if (!ton->upIfIdx && configure_tunnel_out(ADD, ton) == SUCCESS) {
                        
                        kernel_set_addr(ADD, ton->upIfIdx, AF_INET6, &ton->localIp, 128, YES /*deprecated*/);

                        if(tun_out_mtu != ton->curr_mtu)
                                set_tun_out_mtu(ton, tun_out_mtu);
                }

                if (ton->upIfIdx) {

                        if (tsn->net.af == AF_INET) {

                                IPX_T srcIp4 = tsn->srcPrefix.mask ? tsn->srcPrefix.ip : tun4_address.ip;

                                assertion(-501373, (is_ip_set(&srcIp4)));
                                assertion(-501374, IMPLIES(is_ip_set(&ton->src4Ip), is_ip_equal(&ton->src4Ip, &srcIp4)));

                                if (!is_ip_set(&ton->src4Ip)) {
                                        ton->src4Ip = srcIp4;
                                        kernel_set_addr(ADD, ton->upIfIdx, AF_INET, &srcIp4, 32, NO /*deprecated*/);
                                }

                        } else /*if (tsn->net.af == AF_INET6)*/ {
                                
                                assertion(-501375, (tsn->net.af == AF_INET6));

                                IPX_T srcIp6 = tsn->srcPrefix.mask ? tsn->srcPrefix.ip : tun6_address.ip;

                                assertion(-501376, (is_ip_set(&srcIp6)));
                                assertion(-501377, IMPLIES(is_ip_set(&ton->src6Ip), is_ip_equal(&ton->src6Ip, &srcIp6)));

                                if (!is_ip_set(&ton->src6Ip)) {

                                        ton->src6Ip = srcIp6;
                                        kernel_set_addr(ADD, ton->upIfIdx, AF_INET6, &srcIp6, 128, NO /*deprecated*/);
                                }
                        }

                        iproute((IP_ROUTE_TUNS + rtype), ADD, NO, &netKey, RT_TABLE_TUN, 0, ton->upIfIdx, NULL, NULL, tsn->ipmetric, rtep);

                        tbn->active = YES;
                }
        }
}

STATIC_FUNC
void _del_tun_bit_node(struct tun_search_node *tsn, struct tun_net_node *tnn)
{
        TRACE_FUNCTION_CALL;

        struct tun_bit_node *tbn;
        struct avl_tree *tbt = (tsn ? &tsn->tun_bit_tree : (tnn ? &tnn->tun_bit_tree : &tun_bit_tree));

        while ((tbn = avl_first_item(tbt))) {


                avl_remove(&(tbn->tunBitKey.keyNodes.tsn->tun_bit_tree), &tbn->tunBitKey.keyNodes, -300460);
                avl_remove(&(tbn->tunBitKey.keyNodes.tnn->tun_bit_tree), &tbn->tunBitKey.keyNodes, -300461);
                avl_remove(&tun_bit_tree, &tbn->tunBitKey, -300462);

                configure_tun_bit(DEL, tbn);

                debugFree(tbn, -300463);
        }
}


STATIC_FUNC
void upd_tun_bit_node(uint8_t del, struct tun_search_node *tsn, struct tun_net_node *tnn)
{
        assertion(-501378, (!(tsn && tnn)));
        if ( del)
                _del_tun_bit_node(tsn, tnn);
        else
                _add_tun_bit_node(tsn, tnn);
}




STATIC_FUNC
void _recalc_tun_bit_tree(void)
{
        TRACE_FUNCTION_CALL;

        static uint32_t eval_counter = 0;
        struct tun_bit_node *tbn_curr;
        struct tun_bit_key tbk_prev;
        memset(&tbk_prev, 0, sizeof (tbk_prev));

        eval_counter = (eval_counter + 1) ? (eval_counter + 1) : (eval_counter + 2);

        while ((tbn_curr = avl_next_item(&tun_bit_tree, &tbk_prev))) {

                struct tun_bit_key tbk_new = tbn_curr->tunBitKey;
                struct tun_bit_node *tbn_next = avl_next_item(&tun_bit_tree, &tbn_curr->tunBitKey);
                struct tun_net_node *tnn = tbn_curr->tunBitKey.keyNodes.tnn;
                struct tun_search_node *tsn = tbn_curr->tunBitKey.keyNodes.tsn;

                if (tnn->eval_counter != eval_counter) {

                        struct orig_node *on = tnn->tunNetKey.tun->tunOutKey.on;

                        UMETRIC_T linkQuality = UMETRIC_MAX;
                        UMETRIC_T linkMax = fmetric_to_umetric(fmetric_u8_to_fmu16(tnn->bandwidth));
                        UMETRIC_T pathMetric = on->curr_rt_local ? (on->curr_rt_local->mr.umetric) : 0;

                        if (linkMax <= UMETRIC_MIN__NOT_ROUTABLE || pathMetric <= UMETRIC_MIN__NOT_ROUTABLE)
                                tnn->e2eMetric = UMETRIC_MIN__NOT_ROUTABLE;
                        else
                                tnn->e2eMetric = apply_metric_algo(&linkQuality, &linkMax, &pathMetric, on->path_metricalgo);

                        dbgf_all(DBGT_INFO, "acceptable e2eMetric=%s,", umetric_to_human(tnn->e2eMetric));

                        tnn->eval_counter = eval_counter;
                }

                if (tnn->e2eMetric <= UMETRIC_MIN__NOT_ROUTABLE) {
                        tbk_new.beInvTunBitMetric = hton64(UMETRIC_MAX);
                } else {
                        UMETRIC_T tunBitMetric = ((((tnn->e2eMetric * (100 + tsn->bonus)) / 100) *
                                (100 + (tbn_curr->active ? tsn->hysteresis : 0))) / 100);

                        assertion(-501379, (UMETRIC_MAX >= tunBitMetric));

                        tbk_new.beInvTunBitMetric = hton64(UMETRIC_MAX - tunBitMetric);
                }

                assertion(-501380, (memcmp(&tbk_new, &tbk_prev, sizeof (struct tun_bit_key))));
                assertion(-501381, IMPLIES(tbn_next, memcmp(&tbk_new, &tbn_next->tunBitKey, sizeof (struct tun_bit_key))));

                if (memcmp(&tbk_new, &tbk_prev, sizeof (struct tun_bit_key)) < 0 ||
                        (tbn_next && memcmp(&tbk_new, &tbn_next->tunBitKey, sizeof (struct tun_bit_key)) > 0)) {

                        avl_remove(&tun_bit_tree, &tbn_curr->tunBitKey, -300464);
                        tbn_curr->tunBitKey = tbk_new;
                        avl_insert(&tun_bit_tree, tbn_curr, -300465);

                } else {
                        tbn_curr->tunBitKey = tbk_new;
                        tbk_prev = tbk_new;
                }
        }

}

STATIC_FUNC
void eval_tun_bit_tree(void  *unused)
{
        TRACE_FUNCTION_CALL;

        task_remove((void(*)(void*))eval_tun_bit_tree, NULL);

        if (tun_search_tree.items)
                task_register(5000, (void(*)(void*))eval_tun_bit_tree, NULL, -300466);

        _recalc_tun_bit_tree();

        struct tun_bit_node *tbn_curr = NULL;
        uint32_t af;

        for (af = AF_INET; af == AF_INET || af == AF_INET6; af += (AF_INET6 - AF_INET)) {

                uint32_t ipMetric_begin = ((uint32_t) - 1);
                struct tun_bit_node *tbn_begin = NULL;

                while ((tbn_curr = avl_next_item(&tun_bit_tree, tbn_curr ? &tbn_curr->tunBitKey : NULL))) {

                        if (af != tbn_curr->tunBitKey.invNetKey.af)
                                continue;

                        assertion(-501382, IMPLIES(af == AF_INET, is_ip_set(tbn_curr->tunBitKey.keyNodes.tsn->srcPrefix.mask ? &tbn_curr->tunBitKey.keyNodes.tsn->srcPrefix.ip : &tun4_address.ip)));
                        assertion(-501383, IMPLIES(af == AF_INET6, is_ip_set(tbn_curr->tunBitKey.keyNodes.tsn->srcPrefix.mask ? &tbn_curr->tunBitKey.keyNodes.tsn->srcPrefix.ip : &tun6_address.ip)));

                        if (ipMetric_begin != ntohl(tbn_curr->tunBitKey.beIpMetric)) {
                                ipMetric_begin = ntohl(tbn_curr->tunBitKey.beIpMetric);
                                tbn_begin = tbn_curr;
                        }

                        struct tun_bit_node *tbn_crash = tbn_begin;
                        uint8_t crash_is_better = YES;

                        for (; tbn_crash && tbn_crash->tunBitKey.beIpMetric == tbn_curr->tunBitKey.beIpMetric;
                                tbn_crash = avl_next_item(&tun_bit_tree, &tbn_crash->tunBitKey)) {

                                if (af != tbn_crash->tunBitKey.invNetKey.af)
                                        continue;

                                struct net_key currNet = tbn_curr->tunBitKey.invNetKey;
                                currNet.mask = 128 - currNet.mask;
                                struct net_key crashNet = tbn_crash->tunBitKey.invNetKey;
                                crashNet.mask = 128 - crashNet.mask;

                                if (tbn_crash == tbn_curr) {

                                        crash_is_better = NO;

                                } else if (crash_is_better) {

                                        if (currNet.mask >= crashNet.mask &&
                                                ((is_ip_equal(&currNet.ip, &crashNet.ip) && currNet.mask == crashNet.mask) || (

                                                !tbn_crash->tunBitKey.keyNodes.tsn->allowOverlappingLargerPrefixes &&
                                                !tbn_curr->tunBitKey.keyNodes.tsn->breakOverlappingSmallerPrefixes &&
                                                is_ip_net_equal(&currNet.ip, &crashNet.ip, crashNet.mask, af)
                                                ))) {

                                                if (tbn_curr->active)
                                                        configure_tun_bit(DEL, tbn_curr);

                                                break;
                                        }

                                } else {

                                        if (currNet.mask <= crashNet.mask &&
                                                ((is_ip_equal(&currNet.ip, &crashNet.ip) && currNet.mask == crashNet.mask) || (

                                                !tbn_crash->tunBitKey.keyNodes.tsn->breakOverlappingSmallerPrefixes &&
                                                !tbn_curr->tunBitKey.keyNodes.tsn->allowOverlappingLargerPrefixes &&
                                                is_ip_net_equal(&currNet.ip, &crashNet.ip, currNet.mask, af)
                                                ))) {

                                                if (tbn_crash->active)
                                                        configure_tun_bit(DEL, tbn_crash);

                                        }
                                }
                        }

                        if (!tbn_crash || tbn_crash->tunBitKey.beIpMetric != tbn_curr->tunBitKey.beIpMetric)
                                configure_tun_bit(ADD, tbn_curr);

                }
        }
}



STATIC_FUNC
int create_description_tlv_tun6_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        uint16_t m = 0;
        struct tun_in_node *tin;
        struct avl_node *an;
        struct description_msg_tun6_adv *adv = (struct description_msg_tun6_adv *) tx_iterator_cache_msg_ptr(it);


        if (!is_ip_set(&self->primary_ip) || AF_CFG != AF_INET6)
                return TLV_TX_DATA_IGNORED;



        if (!tun_in_tree.items) {

                if (m < tx_iterator_cache_msg_space_max(it) && default_tun_in.upIfIdx) {
                        adv->localIp = default_tun_in.remote;
                        return sizeof ( struct description_msg_tun6_adv);
                }

        } else {

                for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an)) && m < tx_iterator_cache_msg_space_max(it);) {

                        assertion(-501237, (tin->upIfIdx && tin->tun6Id == -1));
                        assertion(-501384, (tin->tun6Id == m));
                        adv[m].localIp = tin->remote;
                        m++;
                }
                
                return m * sizeof ( struct description_msg_tun6_adv);
        }

        return TLV_TX_DATA_IGNORED;
}



STATIC_FUNC
struct tun_out_key set_tun_adv_key(struct orig_node *on, int16_t tun6Id)
{
        struct tun_out_key key;
        memset(&key, 0, sizeof (key));
        key.on = on;
        key.tun6Id = tun6Id;
        return key;
}



STATIC_FUNC
IDM_T terminate_tun_out(struct orig_node *on, struct tun_out_node *tona, struct tun_net_node *tnna )
{
        TRACE_FUNCTION_CALL;
        IDM_T used = NO;

        struct tun_out_node *ton;
        struct tun_out_key key = set_tun_adv_key(on, 0);

        for (key.tun6Id = 0; (ton = (tona ? tona : avl_find_item(&tun_out_tree, &key))); key.tun6Id++) {

                struct tun_out_node *rtun;
                struct tun_net_node *tnn, *tnn1, *tnn2;


                assertion(-501247, (ton));

                dbgf_all(DBGT_INFO, "should remove tunnel_node localIp=%s tun6Id=%d orig=%s key=%s (tunnel_out.items=%d, tun->net.items=%d)",
                        ip6AsStr(&ton->localIp), ton->tunOutKey.tun6Id, globalIdAsString(&ton->tunOutKey.on->global_id),
                        memAsHexString(&ton->tunOutKey, sizeof (key)), tun_out_tree.items, ton->tun_net_tree.items);

                used |= (ton->upIfIdx) ? YES : NO;

                while ((tnn = (tnna ? tnna : avl_first_item(&ton->tun_net_tree)))) {

                        upd_tun_bit_node(DEL, NULL, tnn);
                        //unlink_tun_net(tnn, NULL, NULL);

                        tnn1 = avl_remove(&tun_net_tree, &tnn->tunNetKey, -300421);
                        tnn2 = avl_remove(&ton->tun_net_tree, &tnn->tunNetKey, -300423);

                        assertion_dbg(-501251, (tnn == tnn1 && tnn == tnn2),
                                "should remove %s orig=%s but removed %s orig=%s and %s orig=%s !",
                                netAsStr(&tnn->tunNetKey.netKey),
                                globalIdAsString(&tnn->tunNetKey.tun->tunOutKey.on->global_id),
                                tnn1 ? netAsStr(&tnn1->tunNetKey.netKey) : "---",
                                tnn1 ? globalIdAsString(&tnn1->tunNetKey.tun->tunOutKey.on->global_id) : "---",
                                tnn2 ? netAsStr(&tnn2->tunNetKey.netKey) : "---",
                                tnn2 ? globalIdAsString(&tnn2->tunNetKey.tun->tunOutKey.on->global_id) : "---");


                        debugFree(tnn, -300424);

                        if (tnna)
                                break;
                }

                if (!tnna) {
                        assertion(-501385, (!ton->tun_net_tree.items));

                        rtun = avl_remove(&tun_out_tree, &key, -300410);
                        assertion(-501253, (rtun == ton));
                        debugFree(ton, -300425);
                }

                checkIntegrity();

                if (tona)
                        break;
        }

        return used;
}


static uint8_t new_tun6_advs_changed;

STATIC_FUNC
int process_description_tlv_tun6_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        int16_t m;


        if (it->op == TLV_OP_DEL) {

                if (terminate_tun_out(it->on, NULL, NULL))
                        eval_tun_bit_tree(NULL);

                return it->frame_msgs_length;

        } else if (it->op == TLV_OP_NEW) {

                new_tun6_advs_changed = NO;

                if( !is_ip_set(&it->on->primary_ip) ) {

                        if (terminate_tun_out(it->on, NULL, NULL))
                                eval_tun_bit_tree(NULL);

                        return it->frame_msgs_length;
                }

                if (!new_tun6_advs_changed) {
                        struct tun_out_key key = set_tun_adv_key(it->on, 0);
                        struct tun_out_node *tun;

                        for (key.tun6Id = 0; (tun = avl_find_item(&tun_out_tree, &key)); key.tun6Id++) {

                                if (!is_ip_equal(&tun->remoteIp, &it->on->primary_ip)) {
                                        new_tun6_advs_changed = YES;
                                        break;
                                }
                        }
                }

                
                if (!new_tun6_advs_changed) {
                        uint8_t t;
                        uint8_t tlv_types[] = {
                                BMX_DSC_TLV_TUN6_ADV
                                ,BMX_DSC_TLV_TUN4IN6_INGRESS_ADV
                                ,BMX_DSC_TLV_TUN6IN6_INGRESS_ADV
                                ,BMX_DSC_TLV_TUN4IN6_SRC_ADV
                                ,BMX_DSC_TLV_TUN6IN6_SRC_ADV
/*
                                ,BMX_DSC_TLV_TUN4IN6_NET_ADV
                                ,BMX_DSC_TLV_TUN6IN6_NET_ADV
*/
                        };
                        for (t = 0; t < sizeof (tlv_types); t++) {

                                struct desc_tlv_hash_node * thn;

                                if ((thn = avl_find_item(&it->on->desc_tlv_hash_tree, &tlv_types[t])) && thn->test_changed) {
                                        new_tun6_advs_changed = YES;
                                        break;
                                }
                        }
                }


                if (!new_tun6_advs_changed) {
                        return it->frame_msgs_length;
                } else {
                        if (terminate_tun_out(it->on, NULL, NULL))
                                eval_tun_bit_tree(NULL);
                }
        }


        for (m = 0; m < it->frame_msgs_fixed; m++) {

                struct description_msg_tun6_adv *adv = &(((struct description_msg_tun6_adv *) (it->frame_data))[m]);
                struct tun_out_key key = set_tun_adv_key(it->on, m);

                dbgf_all(DBGT_INFO, "op=%s tunnel_out.items=%d tun_net.items=%d msg=%d/%d localIp=%s orig=%s (%p) key=%s",
                        tlv_op_str(it->op), tun_out_tree.items, tun_net_tree.items, m, it->frame_msgs_fixed,
                        ip6AsStr(&adv->localIp), globalIdAsString(&it->on->global_id), (void*) (it->on), memAsHexString(&key, sizeof (key)));

                if (it->op == TLV_OP_TEST) {

                        struct hna_node *un = NULL;
                        struct tun_in_node *tin = NULL;

                        if (!is_ip_valid(&adv->localIp, AF_INET6) ||
                                is_ip_net_equal(&adv->localIp, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6) ||
                                (tin = avl_find_item_by_field(&tun_in_tree, &adv->localIp, tun_in_node, remote)) ||
                                (un = find_overlapping_hna(&adv->localIp, 128, it->on))) {
                                dbgf_sys(DBGT_ERR, "globalId=%s %s=%s blocked (by my %s=%s or other's %s with globalId=%s)",
                                        globalIdAsString(&it->on->global_id), ARG_TUN_ADV, ip6AsStr(&adv->localIp),
                                        ARG_TUN_IN_NET, tin ? tin->nameKey.str : DBG_NIL,
                                        ARG_UHNA, un ? globalIdAsString(&un->on->global_id) : DBG_NIL);

                                return TLV_RX_DATA_BLOCKED;
                        }

                } else if (it->op == TLV_OP_NEW) {

                        assertion(-600005, (!avl_find_item(&tun_out_tree, &key)));

                        struct tun_out_node *tun = debugMalloc(sizeof (struct tun_out_node), -300426);
                        memset(tun, 0, sizeof (struct tun_out_node));
                        tun->tunOutKey = key;
                        tun->localIp = adv->localIp;
                        tun->remoteIp = it->on->primary_ip;
                        tun->name_auto = 1;
                        AVL_INIT_TREE(tun->tun_net_tree, struct tun_net_node, tunNetKey);
                        avl_insert(&tun_out_tree, tun, -300427);
                }
        }


        return it->frame_msgs_length;
}


STATIC_FUNC
int create_description_tlv_tunXin6_ingress_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tun_in_node *tun;
        struct avl_node *an = NULL;
        uint8_t isSrc4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_INGRESS_ADV);
        uint16_t pos = 0;
        uint16_t msg_size = isSrc4in6 ? sizeof (struct description_msg_tun4in6_ingress_adv) : sizeof (struct description_msg_tun6in6_ingress_adv);

        while ((tun = avl_iterate_item(&tun_in_tree, &an))) {

                if (tun->tun6Id >= 0 && (isSrc4in6 ? tun->ingress4Prefix.mask : tun->ingress6Prefix.mask)) {

                        if (pos + msg_size > tx_iterator_cache_data_space_max(it)) {
                                memset(tx_iterator_cache_msg_ptr(it), 0, pos);
                                return TLV_TX_DATA_FULL;
                        }

                        struct description_msg_tun6in6_ingress_adv *adv =
                                (struct description_msg_tun6in6_ingress_adv *) (tx_iterator_cache_msg_ptr(it) + pos);

                        adv->tun6Id = tun->tun6Id;
                        adv->ingressPrefixLen = isSrc4in6 ? tun->ingress4Prefix.mask: tun->ingress6Prefix.mask;

                        if (isSrc4in6)
                                *((IP4_T*) & adv->ingressPrefix) = ipXto4(tun->ingress4Prefix.ip);
                        else
                                adv->ingressPrefix = tun->ingress6Prefix.ip;

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

        if (it->op == TLV_OP_NEW) {

                //if (!tun6_cache_tlv_sha_if_changed(it))
                if (!new_tun6_advs_changed)
                        return it->frame_msgs_length;

        }

        if (it->op == TLV_OP_TEST || it->op == TLV_OP_NEW) {
                for (pos = 0; pos < it->frame_msgs_length; pos += it->handl->min_msg_size) {

                        struct description_msg_tun6in6_ingress_adv *adv =
                                (struct description_msg_tun6in6_ingress_adv *) (it->frame_data + pos);
                        struct tun_out_key key = set_tun_adv_key(it->on, adv->tun6Id);
                        struct tun_out_node *tun = avl_find_item(&tun_out_tree, &key);
                        IPX_T prefix = isSrc4 ? ip4ToX(*((IP4_T*) & adv->ingressPrefix)) : adv->ingressPrefix;

                        if (it->op == TLV_OP_TEST) {

                                assertion(-501265, (!tun || (tun->tunOutKey.on == it->on)));

                                if (ip_netmask_validate(&prefix, adv->ingressPrefixLen, isSrc4 ? AF_INET : AF_INET6, NO) == FAILURE)
                                        return TLV_RX_DATA_FAILURE;

                        } else if (it->op == TLV_OP_NEW) {

                                if (tun) {
                                        if (isSrc4)
                                                setNet(&tun->ingress4Prefix, AF_INET, adv->ingressPrefixLen, &prefix);
                                        else
                                                setNet(&tun->ingress6Prefix, AF_INET6, adv->ingressPrefixLen, &prefix);
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
struct tun_in_node * set_tun6Id(char *tun_name, struct description_msg_tun6in6_net_adv *adv)
{
        struct tun_in_node * tun = NULL;

        if (tun_name) {
                if (tun_in_tree.items)
                        tun = avl_find_item(&tun_in_tree, tun_name);
                else
                        tun = (!strcmp(tun_name, default_tun_in.nameKey.str)) ? &default_tun_in : NULL;
        } else {
                if (tun_in_tree.items)
                        tun = avl_first_item(&tun_in_tree);
                else
                        tun = (default_tun_in.upIfIdx) ? &default_tun_in : NULL;
        }

        if (tun && tun->upIfIdx) {
                assertion(-501386, (tun->tun6Id >= 0));
                assertion(-501387, (!strncmp(tun->nameKey.str, tun_name_prefix.str, strlen(tun_name_prefix.str))));
                adv->tun6Id = tun->tun6Id;
        } else {
                dbgf_sys(DBGT_WARN, "NO matching %s=%s found for %s=%s/%d ! Skiping announcement",
                        ARG_TUN_IN_NET_DEV, tun_name, ARG_TUN_IN_NET, ip6AsStr(&adv->network), adv->networkLen);
                return NULL;
        }

        return tun;
}

STATIC_FUNC
uint16_t create_description_tlv_tunXin6_net_adv_msg(struct tx_frame_iterator *it, struct description_msg_tun6in6_net_adv *adv, uint16_t m, char *tun_name)
{
        TRACE_FUNCTION_CALL;
        IDM_T is4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET_ADV) ? YES : NO;
        struct tun_in_node *tun = set_tun6Id(tun_name, adv);

        dbgf_track(DBGT_INFO, "src=%s dst=%s", tun ? ip6AsStr(&tun->remote) : "--", ip6AsStr(&adv->network));

        assertion(-501442, (adv->bandwidth.val.u8));
        assertion(-501443, ip_netmask_validate(&adv->network, adv->networkLen, (is4in6 ? AF_INET : AF_INET6), NO /*force*/) == SUCCESS);

        if (m < tx_iterator_cache_msg_space_max(it) && tun ) {

                if (is4in6) {
                        struct description_msg_tun4in6_net_adv *msg4 =
                                &(((struct description_msg_tun4in6_net_adv *) tx_iterator_cache_msg_ptr(it))[m]);

                        msg4->network = ipXto4(adv->network);
                        msg4->networkLen = adv->networkLen;
                        msg4->bandwidth = adv->bandwidth;
                        msg4->bmx6_route_type = adv->bmx6_route_type;
                        msg4->tun6Id = adv->tun6Id;

                } else {
                        ((struct description_msg_tun6in6_net_adv *) tx_iterator_cache_msg_ptr(it))[m] = *adv;
                }

                m++;

        } else if (tun) {
                dbgf_sys(DBGT_ERR, "NO description space left for src=%s dst=%s",
                        ip6AsStr(&tun->remote), ip6AsStr(&adv->network));
        }

        return m;
}

STATIC_FUNC
int create_description_tlv_tunXin6_net_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        IDM_T is4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET_ADV) ? YES : NO;
        uint16_t m = 0;
        struct opt_type *o = get_option(NULL, NO, ARG_TUN_IN_NET);
        struct opt_parent *p = NULL;
        struct description_msg_tun6in6_net_adv adv;

        if (is4in6 ? tun4_address.mask : tun6_address.mask) {

                UMETRIC_T umax = UMETRIC_FM8_MAX;

                memset(&adv, 0, sizeof (adv));
                adv.network = is4in6 ? tun4_address.ip : tun6_address.ip;
                adv.networkLen = is4in6 ? tun4_address.mask : tun6_address.mask;
                ip_netmask_validate(&adv.network, adv.networkLen, (is4in6 ? AF_INET : AF_INET6), YES /*force*/);
                adv.bandwidth = umetric_to_fmu8(&umax);
                adv.bmx6_route_type = BMX6_ROUTE_BMX6;

                m = create_description_tlv_tunXin6_net_adv_msg(it, &adv, m, NULL);
        }

        while ((p = list_iterate(&o->d.parents_instance_list, p))) {

                struct opt_child *c = NULL;
                uint8_t family = 0;
                UMETRIC_T um = 0;
                memset(&adv, 0, sizeof (adv));
                char *tun_name = NULL;

                str2netw(p->val, &adv.network, NULL, &adv.networkLen, &family, NO);

                dbgf_all(DBGT_INFO, "is4in6=%d family=%d dst=%s/%d", is4in6, family, ip6AsStr(&adv.network), adv.networkLen);

                if (family != (is4in6 ? AF_INET : AF_INET6))
                        continue;

                while ((c = list_iterate(&p->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_IN_NET_BW)) {
                                um = strtoull(c->val, NULL, 10);
                                adv.bandwidth = umetric_to_fmu8(&um);
                        } else if (!strcmp(c->opt->name, ARG_TUN_IN_NET_DEV)) {
                                tun_name = c->val;
                        }
                }

                adv.bmx6_route_type = BMX6_ROUTE_BMX6;

                if (um <= UMETRIC_MIN__NOT_ROUTABLE)
                        continue;

                m = create_description_tlv_tunXin6_net_adv_msg(it, &adv, m, tun_name);
        }


        struct tunXin6_net_adv_list_node *taln = NULL;
        while ((taln = list_iterate(&tunXin6_net_adv_list_list, taln))) {

                struct tunXin6_net_adv_node *tan = NULL;
                while ((tan = list_iterate(taln->adv_list, tan))) {

                        if (tan->net.af != (is4in6 ? AF_INET : AF_INET6))
                                continue;

                        adv.network = tan->net.ip;
                        adv.networkLen = tan->net.mask;
                        adv.bandwidth = tan->bandwidth;
                        adv.bmx6_route_type = tan->bmx6_route_type;

                        m = create_description_tlv_tunXin6_net_adv_msg(it, &adv, m, NULL);
                }
        }

        return m * (is4in6 ? sizeof (struct description_msg_tun4in6_net_adv) : sizeof (struct description_msg_tun6in6_net_adv));
}

STATIC_FUNC
int process_description_tlv_tunXin6_net_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        uint8_t family = it->frame_type == BMX_DSC_TLV_TUN4IN6_NET_ADV ? AF_INET : AF_INET6;
        uint16_t msg_size = it->handl->min_msg_size;
        uint16_t pos;
        static uint32_t tlv_new_counter = 0;

        uint8_t used = NO;

        tlv_new_counter = (tlv_new_counter + 1) ? (tlv_new_counter + 1) : (tlv_new_counter + 2);

        if (it->op == TLV_OP_NEW) {

                struct desc_tlv_hash_node *thn = avl_find_item(&it->on->desc_tlv_hash_tree, &it->frame_type);
                assertion(-501388, (thn));

                if (!new_tun6_advs_changed && !thn->prev_changed)
                        return it->frame_msgs_length;
        }

        if (it->op == TLV_OP_TEST || it->op == TLV_OP_NEW) {


                for (pos = 0; pos < it->frame_msgs_length; pos += msg_size) {

                        struct description_msg_tun6in6_net_adv *adv = (((struct description_msg_tun6in6_net_adv *) (it->frame_data + pos)));
                        struct net_key net;
                        IPX_T ipx = (family == AF_INET) ? ip4ToX(*((IP4_T*) & adv->network)) : adv->network;
                        setNet(&net, family, adv->networkLen, &ipx);

                        if (ip_netmask_validate(&net.ip, net.mask, net.af, NO) == FAILURE) {
                                dbgf_sys(DBGT_ERR, "network=%s", netAsStr(&net));
                                return TLV_RX_DATA_FAILURE;
                        }

                        if (adv->bandwidth.val.u8 == 0)
                                continue;

			if(adv->bmx6_route_type >= BMX6_ROUTE_MAX)
                                continue;

                        if (it->op == TLV_OP_NEW) {

                                struct tun_out_key tok = set_tun_adv_key(it->on, adv->tun6Id);
                                struct tun_out_node *ton = avl_find_item(&tun_out_tree, &tok);

                                if (ton) {

                                        struct tun_net_key tnk = ZERO_TUN_NET_KEY;
                                        tnk.tun = ton;
                                        tnk.netKey = net;
					tnk.bmx6RouteType = adv->bmx6_route_type;

                                        struct tun_net_node *tnn = avl_find_item(&tun_net_tree, &tnk);

                                        if (!tnn) {

                                                tnn = debugMalloc(sizeof (struct tun_net_node), -300418);
                                                memset(tnn, 0, sizeof (struct tun_net_node));
                                                tnn->tunNetKey = tnk;
                                                tnn->bandwidth = adv->bandwidth;

                                                AVL_INIT_TREE(tnn->tun_bit_tree, struct tun_bit_node, tunBitKey.keyNodes);

                                                avl_insert(&tun_net_tree, tnn, -300419);
                                                avl_insert(&ton->tun_net_tree, tnn, -300419);

                                                upd_tun_bit_node(ADD, NULL, tnn);
                                                used = YES;

                                        } else if (tnn->bandwidth.val.u8 != adv->bandwidth.val.u8) {

                                                upd_tun_bit_node(DEL, NULL, tnn);
                                                tnn->bandwidth = adv->bandwidth;
                                                upd_tun_bit_node(ADD, NULL, tnn);
                                                used = YES;

                                        } else {

                                                dbgf_sys(DBGT_WARN, "network=%s found for orig=%s tun6Id=%d",
                                                        netAsStr(&net), globalIdAsString(&tok.on->global_id), tok.tun6Id);
                                        }

                                        tnn->tlv_new_counter = tlv_new_counter;


                                } else {
                                        dbgf_sys(DBGT_WARN, "no matching tunnel_node found for orig=%s tun6Id=%d",
                                                globalIdAsString(&tok.on->global_id), tok.tun6Id);
                                }
                        }
                }
        }

        if (it->op == TLV_OP_NEW || it->op == TLV_OP_DEL) {

                // Purge tun6Xin6_net advertisements that were not updated:
                struct tun_out_key tok = set_tun_adv_key(it->on, 0);
                struct tun_out_node *ton;

                while ((ton = avl_find_item(&tun_out_tree, &tok))) {

                        struct tun_net_node *tnn;
                        struct avl_node *an = NULL;

                        while ((tnn = avl_iterate_item(&ton->tun_net_tree, &an))) {

                                if (tnn->tunNetKey.netKey.af != family)
                                        continue;

                                if (tnn->tlv_new_counter != tlv_new_counter)
                                        break;
                        }

                        if (tnn) {
                                assertion(-501389, (tnn->tlv_new_counter != tlv_new_counter));
                                assertion(-501390, (tnn->tunNetKey.netKey.af == family));
                                used |= terminate_tun_out(it->on, ton, tnn);
                                continue;
                        }

                        tok.tun6Id++;
                }


                if (used)
                        eval_tun_bit_tree(NULL);
                //set_tun_net(NULL);
        }



        return it->frame_msgs_length;
}





struct tun_out_status {
        char* name;
        char searchType[BMX6_ROUTE_MAX+1];
        char searchNet[IPX_PREFIX_STR_LEN];
        uint32_t min;
        uint32_t max;
        uint32_t aOLP;
        uint32_t bOSP;
        uint32_t hyst;
        uint32_t bonus;
        GLOBAL_ID_T *searchId;
        uint32_t ipMtc;
        char *tunName;
        char tunRoute[IPX_PREFIX_STR_LEN];
        GLOBAL_ID_T *remoteId;
        char* advType;
        char advNet[IPX_PREFIX_STR_LEN];
        UMETRIC_T advBwVal;
        UMETRIC_T *advBw;
        UMETRIC_T *pathMtc;
        UMETRIC_T *e2EMtc;
        UMETRIC_T tunMtcVal;
        UMETRIC_T *tunMtc;
        IPX_T *localTunIp;
        IPX_T *remoteTunIp;
//        uint16_t up;
};

static const struct field_format tun_out_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, name,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, searchType,  1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, searchNet,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, min,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, max,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, aOLP,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, bOSP,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, hyst,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, bonus,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, searchId,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, ipMtc,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunName,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, tunRoute,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, remoteId,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, advType,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, advNet,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, advBwVal,    1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, advBw,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, pathMtc,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, e2EMtc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, tunMtcVal,   1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, tunMtc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, localTunIp,  1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, remoteTunIp, 1, FIELD_RELEVANCE_MEDI),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, up,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t tun_out_status_creator(struct status_handl *handl, void *data)
{
        
        struct tun_net_node *tnn;
        struct tun_search_node *tsn;
        struct avl_node *an;

        int32_t status_size = tun_bit_tree.items * sizeof (struct tun_out_status);

        for (an = NULL; (tnn = avl_iterate_item(&tun_net_tree, &an));)
                status_size += (tnn->tun_bit_tree.items ? 0 : sizeof (struct tun_out_status));

        for (an = NULL; (tsn = avl_iterate_item(&tun_search_tree, &an));)
                status_size += (tsn->tun_bit_tree.items ? 0 : sizeof (struct tun_out_status));


        struct tun_out_status *status = (struct tun_out_status *) (handl->data = debugRealloc(handl->data, status_size, -300428));
        memset(status, 0, status_size);


        struct avl_tree * t[] = {&tun_search_tree, &tun_bit_tree, &tun_net_tree};
        uint8_t a;
        for (a = 0; a < 3; a++) {
                void *p;
                for (an = NULL; (p = avl_iterate_item(t[a], &an));) {

                        struct tun_bit_node *tbn = (t[a] == &tun_bit_tree) ? p : NULL;
                        struct tun_net_node *tnn = (t[a] == &tun_net_tree) ? p : (tbn ? tbn->tunBitKey.keyNodes.tnn : NULL);
                        struct tun_search_node *tsn = (t[a] == &tun_search_tree) ? p : (tbn ? tbn->tunBitKey.keyNodes.tsn : NULL);

                        if (tsn && !tbn && tsn->tun_bit_tree.items)
                                continue;

                        if (tnn && !tbn && tnn->tun_bit_tree.items)
                                continue;

                        if (tnn) {
                                struct tun_out_node *tun = tnn->tunNetKey.tun;

                                assertion(-501391, (tun));

                                status->remoteId = &tun->tunOutKey.on->global_id;
                                status->localTunIp = &tun->localIp;
                                status->remoteTunIp = &tun->remoteIp;
                                status->advType = bmx6_rt_dict[tnn->tunNetKey.bmx6RouteType].bmx2Name;
                                sprintf(status->advNet, netAsStr(&tnn->tunNetKey.netKey));
                                status->advBwVal = fmetric_to_umetric(fmetric_u8_to_fmu16(tnn->bandwidth));
                                status->advBw = status->advBwVal ? &status->advBwVal : NULL;
                                status->pathMtc = tun->tunOutKey.on->curr_rt_local ? &tun->tunOutKey.on->curr_rt_local->mr.umetric : NULL;
                                status->e2EMtc = tnn->e2eMetric ? &tnn->e2eMetric : NULL;
                                status->tunMtcVal = tbn ? (UMETRIC_MAX - ntoh64(tbn->tunBitKey.beInvTunBitMetric)) : 0;
                                status->tunMtc = status->tunMtcVal ? &status->tunMtcVal : NULL;
                        } else {
                                sprintf(status->advNet, DBG_NIL);
                        }
                        
                        if (tbn) {
                                struct tun_out_node *tun = tbn->tunBitKey.keyNodes.tnn->tunNetKey.tun;

                                status->tunName = (tbn->active ? (strlen(tun->name.str) ? tun->name.str : "ERROR") : DBG_NIL);
                                struct net_key tunRoute = tbn->tunBitKey.invNetKey;
                                tunRoute.mask = tbn ? (128 - tunRoute.mask) : 0;
                                sprintf(status->tunRoute, netAsStr(&tunRoute));
                        } else {
                                status->tunName = DBG_NIL;
                                sprintf(status->tunRoute, DBG_NIL);
                        }


                        if(tsn) {
                                status->name = tsn->nameKey;
                                sprintf(status->searchType, "%s", bmx6RouteBits2String(tsn->bmx6RouteBits));
                                sprintf(status->searchNet, "%s", netAsStr(&(tsn->net)));
                                status->searchId = &(tsn->global_id);
                                status->min = tsn->netPrefixMin == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMin;
                                status->max = tsn->netPrefixMax == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMax;
                                status->aOLP = tsn->allowOverlappingLargerPrefixes;
                                status->bOSP = tsn->breakOverlappingSmallerPrefixes;
                                status->hyst = tsn->hysteresis;
                                status->bonus = tsn->bonus;
                                status->ipMtc = tsn->ipmetric;
                        } else {
                                status->name = DBG_NIL;
                                strcpy(status->searchNet, DBG_NIL);
                        }
                        status++;
                }
        }

        assertion(-501322, (handl->data + status_size == (uint8_t*) status));

        return status_size;
}





STATIC_FUNC
int32_t opt_tun_in_net(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK) {

                struct net_key net = ZERO_NET_KEY;

                dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (AF_CFG != AF_INET6)
                        return FAILURE;

                if (str2netw(patch->val, &net.ip, cn, &net.mask, &net.af, NO) == FAILURE) {
                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s", ARG_TUN_IN_NET, patch->val);
                        return FAILURE;
                }

                if(cmd == OPT_ADJUST)
                        set_opt_parent_val(patch, netAsStr(&net));



                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_IN_NET_BW) && c->val) {

                                char *endptr;
                                unsigned long long ull = strtoul(c->val, &endptr, 10);

                                if (ull > UMETRIC_MAX || ull < UMETRIC_FM8_MIN || *endptr != '\0')
                                        return FAILURE;

                        } else if (!strcmp(c->opt->name, ARG_TUN_IN_NET_DEV) && c->val) {

                                if (strlen(c->val) >= NETWORK_NAME_LEN ||
                                        validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS ||
                                        strncmp(tun_name_prefix.str, c->val, strlen(tun_name_prefix.str))) {

                                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
                                                c->val, tun_name_prefix.str);

                                        return FAILURE;
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
int32_t opt_tun_search(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        struct tun_search_node *tsn = NULL;

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

                tsn = avl_find_item(&tun_search_tree, name);

                struct net_key net = ZERO_NET_KEY;
                net.af = tsn ? tsn->net.af : 0; // family of ARG_TUN_SEARCH_NETWORK and ARG_TUN_SEARCH_SRC must be the same!!!

                if (cmd == OPT_APPLY) {
                        
                        //unlink_tun_net(NULL, NULL, NULL);
                        
                        if (!tsn && patch->diff != DEL) {
                                tsn = debugMalloc(sizeof (struct tun_search_node), -300400);
                                memset(tsn, 0, sizeof (struct tun_search_node));
                                AVL_INIT_TREE(tsn->tun_bit_tree, struct tun_bit_node, tunBitKey.keyNodes);
                                strcpy(tsn->nameKey, name);
                                avl_insert(&tun_search_tree, tsn, -300433);
                                tsn->bmx6RouteBits = 0;
                                tsn->exportDistance = DEF_EXPORT_DISTANCE;
                                tsn->exportOnly = DEF_EXPORT_ONLY;
                                tsn->ipmetric = DEF_IP_METRIC;
                                tsn->hysteresis = DEF_TUN_OUT_HYSTERESIS;
                                tsn->netPrefixMin = DEF_TUN_OUT_PREFIX_MIN;
                                tsn->netPrefixMax = DEF_TUN_OUT_PREFIX_MAX;
                                tsn->allowOverlappingLargerPrefixes = DEF_TUN_OUT_OVLP_ALLOW;
                                tsn->breakOverlappingSmallerPrefixes = DEF_TUN_OUT_OVLP_BREAK;
                        } else if (tsn) {
                                upd_tun_bit_node(DEL, tsn, NULL);
                                assertion(-501392, !(tsn->tun_bit_tree.items));
                        }
                }

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_OUT_NET)) {

                                if (c->val) {

                                        if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, NO) == FAILURE)
                                                return FAILURE;

                                        set_opt_child_val(c, netAsStr(&net));

                                        if (cmd == OPT_APPLY && tsn) {
                                                tsn->net = net;
                                        }

                                } else if (cmd == OPT_APPLY && tsn) {
                                        setNet(&tsn->net, net.af, 0, NULL);
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_OUT_IP)) {

                                if (c->val) {
                                        struct hna_node *hna;

                                        if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, YES) == FAILURE)
                                                return FAILURE;

                                        set_opt_child_val(c, netAsStr(&net));

                                        //struct net_key find = (net.af == AF_INET) ? netX4ToNiit6(&net) : net;

                                        if ((hna = find_overlapping_hna(&net.ip, net.mask, self))) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s /%s=%s already used by orig=%s hna=%s",
                                                        ARG_TUN_OUT, name, ARG_TUN_OUT_IP, netAsStr(&net),
                                                        globalIdAsString(&hna->on->global_id), netAsStr(&hna->key));

                                                return FAILURE;
                                        }

                                        if (cmd == OPT_APPLY && tsn) {
                                                tsn->srcPrefix = net;
                                                tsn->net.af = net.af;
                                        }

                                } else if (cmd == OPT_APPLY && tsn) {
                                        setNet(&tsn->srcPrefix, net.af, 0, NULL);
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_OUT_HOSTNAME) ) {

                                if (c->val) {

                                        if (strlen(c->val) > GLOBAL_ID_NAME_LEN ||
                                                validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS)
                                                return FAILURE;

                                        if (cmd == OPT_APPLY && tsn) {
                                                memset(tsn->global_id.name, 0, sizeof (tsn->global_id.name));
                                                sprintf(tsn->global_id.name, c->val);
                                        }

                                } else if ( cmd == OPT_APPLY && tsn ) {
                                        memset(tsn->global_id.name, 0, sizeof (tsn->global_id.name));
                                }

                        } else if (!strcmp(c->opt->name, ARG_TUN_OUT_PKID)) {

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

                        } else if (cmd == OPT_APPLY && tsn) {

                               if (!strcmp(c->opt->name, ARG_TUN_OUT_PREFIX_MIN))
                                       tsn->netPrefixMin = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_PREFIX_MIN;

                               else if (!strcmp(c->opt->name, ARG_TUN_OUT_PREFIX_MAX))
                                        tsn->netPrefixMax = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_PREFIX_MAX;

                               else if (!strcmp(c->opt->name, ARG_TUN_OUT_OVLP_ALLOW))
                                       tsn->allowOverlappingLargerPrefixes = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_OVLP_ALLOW;

                               else if (!strcmp(c->opt->name, ARG_TUN_OUT_OVLP_BREAK))
                                       tsn->breakOverlappingSmallerPrefixes = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_OVLP_BREAK;

                               else if (!strcmp(c->opt->name, ARG_TUN_OUT_IPMETRIC))
                                       tsn->ipmetric = c->val ? strtol(c->val, NULL, 10) : DEF_IP_METRIC;

                               else if (!strcmp(c->opt->name, ARG_TUN_OUT_TYPE))
                                        tsn->srcType = c->val ? strtol(c->val, NULL, 10) : 0;

                               else if (!strcmp(c->opt->name, ARG_TUN_OUT_HYSTERESIS))
                                        tsn->hysteresis = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_HYSTERESIS;

                               else if (!strcmp(c->opt->name, ARG_TUN_OUT_BONUS))
                                       tsn->bonus = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_BONUS;

                               else if (!strcmp(c->opt->name, ARG_EXPORT_DISTANCE))
                                       tsn->exportDistance = c->val ? strtol(c->val, NULL, 10) : DEF_EXPORT_DISTANCE;

                               else if (!strcmp(c->opt->name, ARG_EXPORT_ONLY))
                                       tsn->exportDistance = c->val ? strtol(c->val, NULL, 10) : DEF_EXPORT_ONLY;

                               else {
                                       uint8_t t;
                                       for (t = 0; t < BMX6_ROUTE_MAX; t++) {
                                               if (!strcmp(c->opt->name, bmx6_rt_dict[t].bmx2Name)) {
                                                       bit_set((uint8_t*) &tsn->bmx6RouteBits,
                                                               sizeof (tsn->bmx6RouteBits) * 8,
                                                               t, (c->val && strtol(c->val, NULL, 10) == 1));
                                               }
                                       }
                               }

                        }
                }
        }

        if (cmd == OPT_APPLY) {

                assertion(-501394, (tsn));

                if (patch->diff == DEL) {
                        avl_remove(&tun_search_tree, &tsn->nameKey, -300402);
                        debugFree(tsn, -300403);

                } else {
                        upd_tun_bit_node(ADD, tsn, NULL);
                }

                eval_tun_bit_tree(NULL);

                //set_tun_net(NULL);
                //my_description_changed = YES;
        }


        if (  cmd == OPT_UNREGISTER ) {

                while ((tsn = avl_first_item(&tun_search_tree))) {

                        assertion(-501242, (!tsn->tun_bit_tree.items));

                        avl_remove(&tun_search_tree, &tsn->nameKey, -300404);
                        debugFree(tsn, -300405);
                }
        }

        return SUCCESS;
}




STATIC_FUNC
int32_t opt_tun_in_dev(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        struct tun_in_node *tin = NULL;

	if ( cmd == OPT_ADJUST  ||  cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                struct opt_child *c = NULL;
                char name[NETWORK_NAME_LEN] = {0};

                dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
                        patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

                if (AF_CFG != AF_INET6)
                        return FAILURE;

                if (strlen(patch->val) >= NETWORK_NAME_LEN ||
                        validate_name_string(patch->val, strlen(patch->val) + 1, NULL) != SUCCESS ||
                        strncmp(tun_name_prefix.str, patch->val, strlen(tun_name_prefix.str))) {

                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
                                patch->val, tun_name_prefix.str);

                        return FAILURE;
                }

                strcpy(name, patch->val);

                tin = avl_find_item(&tun_in_tree, name);

                if (!tin && tun_in_tree.items >= MAX_TUN_REMOTE_IPS)
                        return FAILURE;

                if (cmd == OPT_APPLY) {

                        if (default_tun_in.upIfIdx)
                                configure_tunnel_in(DEL, &default_tun_in);

                        if (tin)
                                configure_tunnel_in(DEL, tin);

                        if (tin && patch->diff == DEL) {

                                avl_remove(&tun_in_tree, name, -300467);
                                debugFree(tin, -300468);
                                tin = NULL;

                        } else if (!tin && patch->diff != DEL) {
                                tin = debugMalloc(sizeof (struct tun_in_node), -300469);
                                memset(tin, 0, sizeof (struct tun_in_node));
                                strcpy(tin->nameKey.str, name);
                                tin->tun6Id = -1;
                                tin->remote = ZERO_IP;
                                tin->remote_manual = 0;
                                tin->name_auto = 0;
                                avl_insert(&tun_in_tree, tin, -300470);
                        }
                }

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_TUN_ADV_REMOTE)) {

                                struct net_key p6 = ZERO_NET6_KEY;

                                if (c->val) {

                                        struct hna_node *un_remote = NULL;

                                        if (str2netw(c->val, &p6.ip, cn, NULL, &p6.af, YES) == FAILURE ||
                                                !is_ip_valid(&p6.ip, p6.af) ||
                                                (un_remote = find_overlapping_hna(&p6.ip, 128, self))) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s=%s or blocked by %s",
                                                        ARG_TUN_ADV, patch->val, ARG_TUN_ADV_REMOTE, c->val,
                                                        un_remote ? globalIdAsString(&un_remote->on->global_id) : DBG_NIL);

                                                return FAILURE;
                                        }

                                        set_opt_child_val(c, netAsStr(&p6));
                                }

                                if (cmd == OPT_APPLY && tin) {
                                        tin->remote = p6.ip;
                                        tin->remote_manual = c->val ? 1 : 0;
                                }


                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC4_TYPE)) {

                                if (cmd == OPT_APPLY && tin)
                                        tin->src4Type = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_INGRESS4)) {

                                struct net_key p4 = ZERO_NET4_KEY;

                                if (c->val) {

                                        if (str2netw(c->val, &p4.ip, cn, &p4.mask, &p4.af, NO) == FAILURE ||
                                                !is_ip_valid(&p4.ip, p4.af)) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s",
                                                        ARG_TUN_ADV_INGRESS4, patch->val, c->val);
                                                return FAILURE;
                                        }
                                }

                                if (cmd == OPT_APPLY && tin)
                                        tin->ingress4Prefix = p4;


                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC4_MIN)) {

                                if (cmd == OPT_APPLY && tin)
                                        tin->src4PrefixMin = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC6_TYPE)) {

                                if (cmd == OPT_APPLY && tin)
                                        tin->src6Type = c->val ? strtol(c->val, NULL, 10) : 0;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_INGRESS6)) {

                                struct net_key p6 = ZERO_NET6_KEY;

                                if (c->val) {

                                        if (str2netw(c->val, &p6.ip, cn, &p6.mask, &p6.af, NO) == FAILURE ||
                                                !is_ip_valid(&p6.ip, p6.af)) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s",
                                                        ARG_TUN_ADV_INGRESS6, patch->val, c->val);
                                                return FAILURE;
                                        }

                                        set_opt_child_val(c, netAsStr(&p6));
                                }

                                if (cmd == OPT_APPLY && tin)
                                        tin->ingress6Prefix = p6;

                        } else if (!strcmp(c->opt->name, ARG_TUN_ADV_SRC6_MIN)) {

                                if (cmd == OPT_APPLY && tin)
                                        tin->src6PrefixMin = c->val ? strtol(c->val, NULL, 10) : 0;

                        }
                }
        }


        if (cmd == OPT_APPLY)
                my_description_changed = YES;


        if (cmd == OPT_UNREGISTER) {

                if (default_tun_in.tun6Id >= 0)
                        configure_tunnel_in(DEL, &default_tun_in);

                while ((tin = avl_remove_first_item(&tun_in_tree, -300393))) {
                        configure_tunnel_in(DEL, tin);
                        debugFree(tin, -300394);
                }
        }

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_tun_name(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        if (cmd == OPT_CHECK) {

                struct tun_in_node *tun;
                struct avl_node *it = NULL;

                if (strlen(patch->val) > MAX_TUN_NAME_PREFIX_LEN ||
                        validate_name_string(patch->val, strlen(patch->val) + 1, NULL))
                        return FAILURE;

                while((tun = avl_iterate_item(&tun_in_tree, &it))) {
                        if (!tun->name_auto && strncmp(patch->val, tun->nameKey.str, strlen(patch->val)))
                                return FAILURE;
                }

                sprintf(tun_name_prefix.str, patch->val); //MUST be configured before opt_tunnel_in is checked

        } else if (cmd == OPT_POST && initializing) {

                struct avl_node *an = NULL;
                struct if_link_node *iln = NULL;

                while ((iln = avl_iterate_item(&if_link_tree, &an))) {

                        if (!strncmp(tun_name_prefix.str, iln->name.str, strlen(tun_name_prefix.str))) {
                                dbgf_sys(DBGT_WARN, "removing orphan tunnel dev=%s", iln->name.str);
                                kernel_set_tun(DEL, iln->name.str, 0, NULL, NULL);
                        }
                }
        }


        return SUCCESS;
}



STATIC_FUNC
int32_t opt_tun_out_mtu(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

        if ( cmd == OPT_APPLY ) {

                tun_out_mtu = patch->diff != DEL ? strtol(patch->val, NULL, 10) : DEF_TUN_OUT_MTU;


                struct tun_out_node *ton;
                struct avl_node *an = NULL;

                while((ton = avl_iterate_item(&tun_out_tree, &an))) {

                        dbgf_track(DBGT_INFO, "checking dev=%s, curr_mtu=%d orig_mtu=%d tun_out_mtu=%d",
                                ton->name.str, ton->curr_mtu, ton->orig_mtu, tun_out_mtu);

                        if(ton->upIfIdx && tun_out_mtu != ton->curr_mtu)
                                set_tun_out_mtu(ton, tun_out_mtu);

                }
        }
        
        return SUCCESS;
}


STATIC_FUNC
int32_t opt_tun_address(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

        struct net_key net = ZERO_NET_KEY;
        net.af = !strcmp(opt->name, ARG_TUN4_ADDRESS) ? AF_INET : AF_INET6;

        if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                if (AF_CFG != AF_INET6) {

                        return FAILURE;

                } else if (patch->diff == DEL) {

                        net = ZERO_NET_KEY;

                } else if (str2netw(patch->val, &net.ip, cn, &net.mask, &net.af, YES) == FAILURE || !is_ip_valid(&net.ip, net.af)) {

                        return FAILURE;

                } else if (net.mask < (net.af == AF_INET ? HNA4_PREFIXLEN_MIN : HNA6_PREFIXLEN_MIN)) {

                        return FAILURE;

                } else {

                        //struct net_key find = net.af == AF_INET ? netX4ToNiit6(&net) : net;
                        struct hna_node *hna;

                        if ((hna = find_overlapping_hna(&net.ip, net.mask, self))) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s already used by orig=%s hna=%s",
                                        opt->name, netAsStr(&net), globalIdAsString(&hna->on->global_id), netAsStr(&hna->key));

                                return FAILURE;
                        }
                }
        }

        if (cmd == OPT_APPLY) {

                if (!strcmp(opt->name, ARG_TUN4_ADDRESS)) {
                        tun4_address = net;
                } else {
                        tun6_address = net;
                }

                my_description_changed = YES;
                upd_tun_bit_node(DEL, NULL, NULL);
                upd_tun_bit_node(ADD, NULL, NULL);
                eval_tun_bit_tree(NULL);
                //unlink_tun_net(NULL, NULL, NULL);
                //set_tun_net(NULL);
        }

        if(cmd == OPT_REGISTER) {
                tun4_address = ZERO_NET_KEY;
                tun6_address = ZERO_NET_KEY;
        }

        return SUCCESS;
}


STATIC_FUNC
struct opt_type hna_options[]= {
//     		ord parent long_name   shrt Attributes				*ival		min		max		default		*function

	{ODI,0,ARG_UHNA,	 	'u',9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_PREFIX_FORM,"specify host-network announcement (HNA) for defined ip range"}
/*
        ,
	{ODI,ARG_UHNA,ARG_UHNA_NETWORK,	'n',9,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_NETW_FORM, 	"specify network of announcement"}
        ,
	{ODI,ARG_UHNA,ARG_UHNA_PREFIXLEN,'p',9,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_MASK_FORM, 	"specify network prefix of announcement"}
        ,
	{ODI,ARG_UHNA,ARG_UHNA_METRIC,   'm',9,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		MIN_UHNA_METRIC,MAX_UHNA_METRIC,DEF_UHNA_METRIC,0,opt_uhna,
			ARG_VALUE_FORM, "specify hna-metric of announcement (0 means highest preference)"}
*/
        ,
	{ODI,0,ARG_TUN4_ADDRESS,        0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_address,
			ARG_PREFIX_FORM,HLP_TUN4_ADDRESS},
	{ODI,0,ARG_TUN6_ADDRESS,        0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_address,
			ARG_PREFIX_FORM,HLP_TUN6_ADDRESS}
        ,
	{ODI,0,ARG_TUN_OUT_MTU,         0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0, MIN_TUN_OUT_MTU,MAX_TUN_OUT_MTU,DEF_TUN_OUT_MTU,0,		opt_tun_out_mtu,
			ARG_VALUE_FORM, "MTU of outgoing tunnel"},



	{ODI,0,ARG_TUN_NAME_PREFIX,    	0,9,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_name,
			ARG_NAME_FORM, "specify first letters of local tunnel-interface names"}
        ,
	{ODI,0,ARG_TUN_ADV, 	        0,9,1,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_in_dev,
                ARG_NAME_FORM, "define incoming ipip tunnel interface name\n"},
//                "        WARNING: This creates a general ipip link allowing to tunnel arbitrary IP packets to this node!\n"
//                "        Use /dev=<NAME> option and firewall rules to filter deprecated packets"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_REMOTE,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,	        0,              0,0,            opt_tun_in_dev,
			ARG_ADDR_FORM,	"remote dummy ip of tunnel interface"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_INGRESS4,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_PREFIX_FORM,"IPv4 source prefix (ingress filter)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_INGRESS6,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_PREFIX_FORM,"IPv6 source prefix (ingress filter)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC4_TYPE,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,    opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv4 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC4_MIN,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        32,             0,0,            opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv4 source prefix len usable for address auto configuration (0 = NO autoconfig)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC6_TYPE,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,    opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv6 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_ADV,ARG_TUN_ADV_SRC6_MIN,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        128,            0,0,            opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv6 source prefix len usable for address auto configuration (0 = NO autoconfig)"},
        
        {ODI,0,ARG_TUN_IN_NET,	 	0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,	        opt_tun_in_net,
			ARG_PREFIX_FORM,"network reachable via this tunnel"},
	{ODI,ARG_TUN_IN_NET,ARG_TUN_IN_NET_BW, 'b',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,	        0,              0,0,            opt_tun_in_net,
			ARG_VALUE_FORM,	"bandwidth to network as bits/sec (mandatory)"},
	{ODI,ARG_TUN_IN_NET,ARG_TUN_IN_NET_DEV,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY, 0,		0,              0,              0,0,            opt_tun_in_net,
			ARG_ADDR_FORM,	"to be used incoming tunnel interface (optional)"},
        
	{ODI,0,ARG_TUN_OUT,     	0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_search,
		        ARG_NAME_FORM,  "arbitrary but unique name for network which should be reached via tunnel depending on sub criterias"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_NET,'n',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,               0,              0,              0,0,            opt_tun_search,
			ARG_PREFIX_FORM,"network to be reached via tunnel (mandatory)"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_IP,'a',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,              0,              0,0,            opt_tun_search,
			ARG_PREFIX_FORM,"src IP address and prefixlen of tunnel (mandatory if tun6Address is not configured)"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_TYPE,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,      TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,   opt_tun_search,
			ARG_VALUE_FORM, "tunnel ip allocation mechanism (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_HOSTNAME,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,              0,              0,0,            opt_tun_search,
			ARG_NAME_FORM,  "hostname of remote tunnel endpoint"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_PREFIX_MIN,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_PREFIX,MAX_TUN_OUT_PREFIX,DEF_TUN_OUT_PREFIX_MIN,0,opt_tun_search,
			ARG_VALUE_FORM, "minumum prefix len for accepting advertised tunnel network, 129 = network prefix len"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_PREFIX_MAX,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_PREFIX,MAX_TUN_OUT_PREFIX,DEF_TUN_OUT_PREFIX_MAX,0,opt_tun_search,
			ARG_VALUE_FORM, "maximum prefix len for accepting advertised tunnel network, 129 = network prefix len"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_OVLP_ALLOW,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_OVLP,MAX_TUN_OUT_OVLP,DEF_TUN_OUT_OVLP_ALLOW,0,opt_tun_search,
			ARG_VALUE_FORM, "allow overlapping larger tunRoute prefixes (with worse tunMetric) configured with same ipMetric"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_OVLP_BREAK,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_OVLP,MAX_TUN_OUT_OVLP,DEF_TUN_OUT_OVLP_BREAK,0,opt_tun_search,
			ARG_VALUE_FORM, "let this tunRoute break smaller tunRoute prefixes with better tunMetric"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_PKID,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,              0,              0,0,            opt_tun_search,
			ARG_SHA2_FORM,  "pkid of remote tunnel endpoint"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_HYSTERESIS,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_HYSTERESIS,MAX_TUN_OUT_HYSTERESIS,DEF_TUN_OUT_HYSTERESIS,0,opt_tun_search,
			ARG_VALUE_FORM, "specify in percent how much the metric to an alternative GW must be better than to curr GW"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_BONUS,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,       MIN_TUN_OUT_BONUS,MAX_TUN_OUT_BONUS,DEF_TUN_OUT_BONUS,0,opt_tun_search,
			ARG_VALUE_FORM, "specify in percent a metric bonus (preference) for GWs matching this tunOut spec when compared with other tunOut specs for same network"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_IPMETRIC,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,         MAX_TUN_OUT_IPMETRIC,DEF_IP_METRIC,0,opt_tun_search,
			ARG_VALUE_FORM, "ip metric for local routing table entries"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_SYSTEM, 0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_KERNEL, 0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_CONNECT,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_RIP,    0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_RIPNG,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_OSPF,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_OSPF6,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_ISIS,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_BGP,    0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_BABEL,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_HSLS,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_OLSR,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_ROUTE_BATMAN, 0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,          opt_tun_search,
			ARG_PREFIX_FORM,"only route type"},
	{ODI,ARG_TUN_OUT,ARG_EXPORT_DISTANCE,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_EXPORT_DISTANCE,MAX_EXPORT_DISTANCE,DEF_EXPORT_DISTANCE,0,opt_tun_search,
			ARG_VALUE_FORM,	"export distance to network (256 == no export). Requires quagga plugin!"},
	{ODI,ARG_TUN_OUT,ARG_EXPORT_ONLY,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,            MIN_EXPORT_ONLY,MAX_EXPORT_ONLY,DEF_EXPORT_ONLY,0,opt_tun_search,
			ARG_PREFIX_FORM,"do not add route to bmx6 tun table!  Requires quagga plugin!"},
	{ODI,0,ARG_TUNS,	        0,9,2,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show announced and used tunnels and related networks"}

};


STATIC_FUNC
void hna_route_change_hook(uint8_t del, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        dbgf_all(DBGT_INFO, "global_id=%s", globalIdAsString(&on->global_id));

        if (!is_ip_set(&on->primary_ip))
                return;

        process_description_tlvs(NULL, on, on->desc, del ? TLV_OP_CUSTOM_HNA_ROUTE_DEL : TLV_OP_CUSTOM_HNA_ROUTE_ADD,
                AF_CFG == AF_INET ? BMX_DSC_TLV_UHNA4 : BMX_DSC_TLV_UHNA6, NULL, NULL);

}









STATIC_FUNC
void hna_cleanup( void )
{
        TRACE_FUNCTION_CALL;
        task_remove((void(*)(void*))eval_tun_bit_tree, NULL);
        set_route_change_hooks(hna_route_change_hook, DEL);
        if (hna_net_keys)
                debugFree(hna_net_keys, -300471);
}


STATIC_FUNC
int32_t hna_init( void )
{
        TRACE_FUNCTION_CALL;

        assertion(-501335, is_zero((void*) &ZERO_TUN_NET_KEY, sizeof (ZERO_TUN_NET_KEY)));
        //assertion(-501327, tun_search_net_tree.key_size == sizeof (struct tun_search_key));
        assertion(-501328, tun_search_tree.key_size == NETWORK_NAME_LEN);


        
        static const struct field_format hna4_format[] = DESCRIPTION_MSG_HNA4_FORMAT;
        static const struct field_format hna6_format[] = DESCRIPTION_MSG_HNA6_FORMAT;
        static const struct field_format tun6_adv_format[] = DESCRIPTION_MSG_TUN6_ADV_FORMAT;
        static const struct field_format tun4in6_ingress_adv_format[] = DESCRIPTION_MSG_TUN4IN6_INGRESS_ADV_FORMAT;
        static const struct field_format tun6in6_ingress_adv_format[] = DESCRIPTION_MSG_TUN6IN6_INGRESS_ADV_FORMAT;
        static const struct field_format tun4in6_src_adv_format[] = DESCRIPTION_MSG_TUN4IN6_SRC_ADV_FORMAT;
        static const struct field_format tun6in6_src_adv_format[] = DESCRIPTION_MSG_TUN6IN6_SRC_ADV_FORMAT;
        static const struct field_format tun4in6_adv_format[] = DESCRIPTION_MSG_TUN4IN6_NET_ADV_FORMAT;
        static const struct field_format tun6in6_adv_format[] = DESCRIPTION_MSG_TUN6IN6_NET_ADV_FORMAT;

        struct frame_handl tlv_handl;

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

        return &hna_plugin;
}


