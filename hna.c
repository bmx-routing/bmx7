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

//#include <linux/if_tun.h> /* TUNSETPERSIST, ... */
//#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <fcntl.h>        /* open(), O_RDWR */
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "sec.h"
#include "desc.h"
#include "content.h"
#include "ip.h"
#include "plugin.h"
#include "prof.h"
#include "hna.h"
#include "tools.h"
#include "iptools.h"
#include "schedule.h"
#include "allocate.h"

#define CODE_CATEGORY_NAME "hna"



static AVL_TREE(global_uhna_tree, struct hna_node, key );
//static AVL_TREE(local_uhna_tree, struct hna_node, key );
AVL_TREE(tun_in_tree, struct tun_in_node, nameKey); // configured tun_in tunnels

IFNAME_T tun_name_prefix = {
	{DEF_TUN_NAME_PREFIX}};

void (*set_tunXin6_net_adv_list) (uint8_t, void**) = NULL;



STATIC_FUNC
void configure_route(IDM_T del, struct orig_node *on, struct net_key *key)
{

        assertion(-501331, (key->af == AF_CFG));

        // update network routes:
        if (del) {

		iproute(IP_ROUTE_HNA, DEL, NO, key, BMX_TABLE_HNA, 0, 0, NULL, NULL, DEF_IP_METRIC, NULL);

        } else {

		LinkNode *link = on->neighPath.link;

                assertion(-500820, (link));
                ASSERTION(-500239, (avl_find(&link_tree, &(link->k))));
                assertion(-500579, (link->k.myDev->if_llocal_addr));

		iproute(IP_ROUTE_HNA, ADD, NO, key, BMX_TABLE_HNA, 0,
                        link->k.myDev->if_llocal_addr->ifa.ifa_index, &(link->k.linkDev->key.llocal_ip),
                        (key->af == AF_INET ? (&(my_primary_ip)) : NULL), DEF_IP_METRIC, NULL);

        }
}


STATIC_FUNC
uint8_t set_hna_to_key(struct net_key *key, struct dsc_msg_hna6 *uhna6)
{
        uint8_t flags;

	setNet(key, AF_INET6, uhna6->prefixlen, &uhna6->ip6);
	flags = uhna6->flags;

        ip_netmask_validate(&key->ip, key->mask, key->af, YES);

        return flags;
}


STATIC_FUNC
uint32_t _create_tlv_hna(uint8_t* data, uint32_t max_size, uint32_t pos, struct net_key *net, uint8_t flags)
{
        TRACE_FUNCTION_CALL;
	assertion(-502039, (net->af==AF_INET6));
        uint32_t i;


        if ((pos + sizeof (struct dsc_msg_hna6)) > max_size) {
                dbgf_sys(DBGT_ERR, "unable to announce %s! Exceeded %s=%d", netAsStr(net), ARG_UDPD_SIZE, max_size);
                return pos;
        }

        dbgf_track(DBGT_INFO, "hna=%s flags=%d ", netAsStr(net), flags);

        assertion(-500610, (!(is_ip_net_equal(&net->ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))));
        // this should be catched during configuration!!

	struct dsc_msg_hna6 *msg6 = ((struct dsc_msg_hna6 *) data);

	struct dsc_msg_hna6 hna6;
	memset( &hna6, 0, sizeof(hna6));
	hna6.ip6 = net->ip;
	hna6.prefixlen = net->mask;
	hna6.flags = flags;

	for (i = 0; i < pos / sizeof (struct dsc_msg_hna6); i++) {

		if (!memcmp(&(msg6[i]), &hna6, sizeof (struct dsc_msg_hna6)))
			return pos;
	}

	msg6[i] = hna6;

        return (pos + sizeof (struct dsc_msg_hna6));
}


STATIC_FUNC
int create_dsc_tlv_hna(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        assertion(-500765, (it->frame_type == BMX_DSC_TLV_HNA6));

        uint8_t *data = tx_iterator_cache_msg_ptr(it);
        uint32_t max_size = tx_iterator_cache_data_space_pref(it, 0, 0);

        uint32_t pos = 0;
//	struct hna_node *un;

        if (!is_ip_set(&my_primary_ip))
                return TLV_TX_DATA_IGNORED;

        pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, AF_INET6, 128, &my_primary_ip), 0);

//	IDM_T TODO_CheckIfThisShouldBeNeeded;
        struct avl_node *an;
	struct tun_in_node *tin;

	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));) {
		if (tin->upIfIdx && tin->tun6Id >= 0) {
			assertion(-501237, (tin->upIfIdx && tin->tun6Id >= 0));
			pos = _create_tlv_hna(data, max_size, pos, setNet(NULL, AF_INET6, 128, &tin->remote), DESC_MSG_HNA_FLAG_NO_ROUTE);
		}
	}

//	for (an = NULL; (un = avl_iterate_item(&local_uhna_tree, &an));)
//		pos = _create_tlv_hna(data, max_size, pos, &un->key, 0);
	struct opt_parent *p = NULL;
	while ((p = list_iterate(&(get_option(NULL, NO, ARG_UHNA)->d.parents_instance_list), p))) {
		struct net_key hna = ZERO_NETCFG_KEY;
		str2netw(p->val, &hna.ip, NULL, &hna.mask, &hna.af, NO);
		assertion(-502325, (is_ip_valid(&hna.ip, hna.af)));
		pos = _create_tlv_hna(data, max_size, pos, &hna, 0);
	}

        return pos;
}






STATIC_FUNC
struct hna_node * find_orig_hna(struct orig_node *on)
{
        struct hna_node *un;
        struct avl_node *it = NULL;

	on = (myKey && myKey->on == on) ? NULL : on;

        while ((un = avl_iterate_item(&global_uhna_tree, &it)) && un->on != on);

        return un;
}


struct hna_node * find_overlapping_hna( IPX_T *ipX, uint8_t prefixlen, struct orig_node *except )
{
        struct hna_node *un;
        struct avl_node *it = NULL;

	except = (myKey && myKey->on == except) ? NULL : except;

        while ((un = avl_iterate_item(&global_uhna_tree, &it))) {

                if (un->on != except && is_ip_net_equal(ipX, &un->key.ip, XMIN(prefixlen, un->key.mask), AF_CFG))
                        return un;

        }
        return NULL;
}



STATIC_FUNC
void configure_hna_(IDM_T del, struct net_key* key, struct orig_node *on, uint8_t flags)
{
        TRACE_FUNCTION_CALL;
        struct hna_node *un = avl_find_item( &global_uhna_tree, key );

        assertion(-500236, ((del && un) != (!del && !un)));

	on = (myKey && myKey->on == on) ? NULL : on;

        // update uhna_tree:
        if ( del ) {

                assertion(-500234, (on == un->on));
                avl_remove(&global_uhna_tree, &un->key, -300212);
                ASSERTION( -500233, (!avl_find( &global_uhna_tree, key)) ); // there should be only one element with this key

//		if (on->key == myKey)
//                        avl_remove(&local_uhna_tree, &un->key, -300213);

        } else {

                un = debugMalloc( sizeof (struct hna_node), -300090 );
                un->key = *key;
                un->on = on;
                un->flags = flags;
                avl_insert(&global_uhna_tree, un, -300149);

//		if (on->key == myKey)
//                        avl_insert(&local_uhna_tree, un, -300150);

	}


	if (!on) {

                // update throw routes:
		/*
		 * HNAs should not be thrown. They are a promise to be routed!
		 * The correct solution would be to drop conflicting OGMs
		 *
                if (policy_routing == POLICY_RT_ENABLED && ip_throw_rules_cfg) {
                        assertion(-501333, (key->af == AF_CFG));
                        iproute(IP_THROW_MY_HNA, del, NO, key, BMX_TABLE_HNA, 0, (key->af == AF_INET6 ? dev_lo_idx : 0), 0, 0, 0, NULL);
                        iproute(IP_THROW_MY_HNA, del, NO, key, RT_TABLE_TUN, 0, (key->af == AF_INET6 ? dev_lo_idx : 0), 0, 0, 0, NULL);
                }
		 */

        } else if (on->neighPath.link && !(flags & DESC_MSG_HNA_FLAG_NO_ROUTE)) {

                configure_route(del, on, key);
        }


        if (del)
                debugFree(un, -300089);

}

static struct net_key *hna_net_keys = NULL;
static uint32_t hna_net_key_elements = 0;

STATIC_FUNC
int process_dsc_tlv_hna(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        ASSERTION(-500357, (it->f_type == BMX_DSC_TLV_HNA6));

        struct orig_node *on = it->on;
        uint8_t op = it->op;

	assertion(-502326, (it->dcOp && it->dcOp->kn));
        assertion(-500588, IMPLIES(op==TLV_OP_NEW || op==TLV_OP_DEL || op>=TLV_OP_CUSTOM_MIN, on));

        uint32_t hna_net_curr = 0;

/*
	if (it->dcNew->key == myKey)
		return it->f_mlen;
*/


        if (op == TLV_OP_NEW || op == TLV_OP_DEL) {
                struct hna_node *un;
                while ((un = find_orig_hna(on)))
                        configure_hna_(DEL, &un->key, on, un->flags);

                on->primary_ip = ZERO_IP;

                if (op == TLV_OP_DEL)
                        return it->f_msgs_len;
	}

	int32_t pos;

        for (pos = 0; pos < it->f_msgs_len; pos += it->f_handl->min_msg_size) {

                struct net_key key;
                uint8_t flags = set_hna_to_key(&key, (struct dsc_msg_hna6 *) (it->f_data + pos));

                dbgf_track(DBGT_INFO, "%s nodeId=%s %s=%s",
                        tlv_op_str(op), cryptShaAsString(&it->dcOp->kn->kHash), ARG_UHNA, netAsStr(&key));

                if (op == TLV_OP_TEST) {

                        struct hna_node *un = NULL;

                        if (!is_ip_valid(&key.ip, AF_INET6) ||
                                is_ip_net_equal(&key.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6) ||
                                (un = find_overlapping_hna(&key.ip, key.mask, on))) {

                                dbgf_sys(DBGT_ERR, "nodeId=%s %s=%s blocked (by nodeId=%s)",
                                        cryptShaAsString(&it->dcOp->kn->kHash), ARG_UHNA, netAsStr(&key),
					un ? cryptShaAsString(un->on ? &un->on->k.nodeId : &myKey->kHash) : "???");

                                return TLV_RX_DATA_BLOCKED;
                        }


                        // check if node announces the same key twice:
                        uint32_t i;
                        for (i = 0; i < hna_net_curr; i++) {
//				if (is_ip_net_equal(&(hna_net_keys[i].ip), &key.ip, XMIN(hna_net_keys[i].mask, key.mask), AF_INET6)) {
                                if (!memcmp(&hna_net_keys[i], &key, sizeof (key))) {
                                        dbgf_sys(DBGT_ERR, "nodeId=%s FAILURE due to double hna=%s announcement",
                                                cryptShaAsString(&it->dcOp->kn->kHash), netAsStr(&key));
                                        return TLV_RX_DATA_FAILURE;
                                }
                        }

                        if (hna_net_key_elements < (i + 1)) {
                                hna_net_keys = debugRealloc(hna_net_keys, (i + 1) * sizeof (key), -300398);
				hna_net_key_elements = i + 1;
			}
                        hna_net_keys[i] = key;
			hna_net_curr = i + 1;

			if (is_ip_net_equal(&key.ip, &autoconf_prefix_cfg.ip, autoconf_prefix_cfg.mask - 4, AF_INET6)) {

				if (key.mask != 128 || verify_crypto_ip6_suffix(&key.ip, autoconf_prefix_cfg.mask, &it->dcOp->kn->kHash) != SUCCESS) {
                                        dbgf_sys(DBGT_ERR, "nodeId=%s FAILURE due to non-matching crypto hna=%s mask=%d announcement",
                                                cryptShaAsString(&it->dcOp->kn->kHash), netAsStr(&key), autoconf_prefix_cfg.mask);
					return TLV_RX_DATA_FAILURE;
				}
			}


                } else if (op == TLV_OP_NEW) {

                        ASSERTION( -500359, (!avl_find(&global_uhna_tree, &key)));

                        if (pos == 0) {
                                on->primary_ip = key.ip;
                        }

                        configure_hna_(ADD, &key, on, flags);


                } else if (op >= TLV_OP_CUSTOM_MIN) {

                        dbgf_all(DBGT_INFO, "configure TLV_OP_CUSTOM op=%d  nodeId=%s",
                                op, cryptShaAsString(&on->k.nodeId));

                        if (on && !(flags & DESC_MSG_HNA_FLAG_NO_ROUTE)) {
                                //ASSERTION(-501314, (avl_find(&global_uhna_tree, &key)));

                                if (op == TLV_OP_CUSTOM_HNA_ROUTE_DEL) {
                                        configure_route(DEL, on, &key);
                                } else if (op == TLV_OP_CUSTOM_HNA_ROUTE_ADD) {
                                        configure_route(ADD, on, &key);
                                } else {
                                        assertion(-501315, (NO));
                                }
                        }

                } else {
                        assertion( -500369, (NO));
                }
        }

        dbgf((it->f_msgs_len == pos) ? DBGL_ALL : DBGL_SYS, (it->f_msgs_len == pos) ? DBGT_INFO : DBGT_ERR,
                "processed %d bytes frame_msgs_len=%d msg_size=%d", pos, it->f_msgs_len, it->f_handl->min_msg_size);

        return it->f_msgs_len;
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

                        if (patch->diff != DEL && (un = find_overlapping_hna(&hna.ip, hna.mask, NULL))) {

                                dbg_cn(cn, DBGL_CHANGES, DBGT_ERR,
                                        "%s=%s already blocked by nodeId=%s !", ARG_UHNA, netAsStr(&hna),
                                        un->on ? cryptShaAsString(&un->on->k.nodeId) : "mySelf");

                                return FAILURE;
                        }

			if (is_ip_net_equal(&hna.ip, &autoconf_prefix_cfg.ip, autoconf_prefix_cfg.mask - 4, AF_INET6)) {

				if (hna.mask != 128 || memcmp(&hna.ip.s6_addr[(autoconf_prefix_cfg.mask / 8)], &myKey->kHash, ((128 - autoconf_prefix_cfg.mask) / 8))) {
					dbgf_cn(cn, DBGL_CHANGES, DBGT_ERR, "nodeId=%s FAILURE due to non-matching crypto hna=%s announcement",
                                                cryptShaAsString(&myKey->kHash), netAsStr(&hna));
					return FAILURE;
				}
			}



                }

                if (cmd == OPT_APPLY) {
                //      configure_hna((patch->diff == DEL ? DEL : ADD), &hna, myKey->currOrig, 0);
                        my_description_changed = YES;
                }

/*
	} else if ( cmd == OPT_UNREGISTER ) {

                struct hna_node * un;

                while ((un = avl_first_item(&global_uhna_tree)))
                        configure_hna(DEL, &un->key, myKey->currOrig, un->flags);
 */
	}

	return SUCCESS;
}






STATIC_FUNC
struct opt_type hna_options[]= {
//     		ord parent long_name   shrt Attributes				*ival		min		max		default		*function

	{ODI,0,ARG_UHNA,	 	'u',9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_uhna,
			ARG_NETW_FORM,"specify host-network announcement (HNA) for defined ip range"}

};


STATIC_FUNC
void hna_route_change_hook(uint8_t del, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        dbgf_all(DBGT_INFO, "nodeId=%s", cryptShaAsString(&on->k.nodeId));

        if (!is_ip_set(&on->primary_ip))
                return;

	process_description_tlvs(NULL, on, NULL, on->dc, del ? TLV_OP_CUSTOM_HNA_ROUTE_DEL : TLV_OP_CUSTOM_HNA_ROUTE_ADD, BMX_DSC_TLV_HNA6);

}









STATIC_FUNC
void hna_cleanup( void )
{
        TRACE_FUNCTION_CALL;

        set_route_change_hooks(hna_route_change_hook, DEL);

        if (hna_net_keys)
                debugFree(hna_net_keys, -300471);
}


STATIC_FUNC
int32_t hna_init( void )
{
        TRACE_FUNCTION_CALL;
        
        static const struct field_format hna6_format[] = DESCRIPTION_MSG_HNA6_FORMAT;

        struct frame_handl tlv_handl;
        memset( &tlv_handl, 0, sizeof(tlv_handl));

        tlv_handl.name = "DSC_HNA6";
        tlv_handl.min_msg_size = sizeof (struct dsc_msg_hna6);
        tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*)&dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*)&fref_dflt;
        tlv_handl.tx_frame_handler = create_dsc_tlv_hna;
        tlv_handl.rx_frame_handler = process_dsc_tlv_hna;
        tlv_handl.msg_format = hna6_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_HNA6, &tlv_handl);

        register_options_array(hna_options, sizeof ( hna_options), CODE_CATEGORY_NAME);

        set_route_change_hooks(hna_route_change_hook, ADD);

        return SUCCESS;
}


struct plugin *hna_get_plugin( void ) {

	static struct plugin hna_plugin;
	memset( &hna_plugin, 0, sizeof ( struct plugin ) );

	hna_plugin.plugin_name = CODE_CATEGORY_NAME;
	hna_plugin.plugin_size = sizeof ( struct plugin );
        hna_plugin.cb_init = hna_init;
	hna_plugin.cb_cleanup = hna_cleanup;

        return &hna_plugin;
}


