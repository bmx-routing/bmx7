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
#include "desc.h"
#include "ip.h"
#include "plugin.h"
#include "prof.h"
#include "hna.h"
#include "tun.h"
#include "tools.h"
#include "iptools.h"
#include "schedule.h"
#include "allocate.h"


#define CODE_CATEGORY_NAME "tun"


static AVL_TREE(tun_search_tree, struct tun_search_node, nameKey); // configured tun_out names searches
//static AVL_TREE(tun_search_net_tree, struct tun_search_node, tunSearchKey); //REMOVE // configured tun_out networks searches

static AVL_TREE(tun_bit_tree, struct tun_bit_node, tunBitKey); // identified matching bits (peaces) of tun_search and tun_net trees

static AVL_TREE(tun_net_tree, struct tun_net_node, tunNetKey); // rcvd tun_out network advs
static AVL_TREE(tun_out_tree, struct tun_out_node, tunOutKey); // rcvd tun_out advs
static AVL_TREE(tun_catch_tree, struct tun_dev_node, tunCatchKey); // active tun_out tunnels

LIST_SIMPEL(tunXin6_net_adv_list_list, struct tunXin6_net_adv_list_node, list, list);

static const struct tun_net_key ZERO_TUN_NET_KEY = {.ton = NULL};
//static const struct tun_catch_key ZERO_TUN_DEV_KEY = {.srcAf=0};

//static struct net_key tun4_address = ZERO_NET_KEY_INIT;
//char* tun4_dev = NULL;
//static struct net_key tun6_address = ZERO_NET_KEY_INIT;
//char* tun6_dev = NULL;




static int32_t tun_out_mtu = DEF_TUN_OUT_MTU;
static int32_t tun_dedicated_to = DEF_TUN_OUT_TO;
static int32_t tun_proactive_routes = DEF_TUN_PROACTIVE_ROUTES;


STATIC_FUNC
void configure_tun_bit(uint8_t del, struct tun_bit_node *tbn, IDM_T asDfltTun);

STATIC_FUNC
void set_tunXin6_net_adv_list_handl(uint8_t del, void **adv_list_ptr)
{
	struct tunXin6_net_adv_node **adv_list = (struct tunXin6_net_adv_node **)adv_list_ptr;
	struct list_node *list_pos, *tmp_pos, *prev_pos = (struct list_node *) &tunXin6_net_adv_list_list;
	struct tunXin6_net_adv_list_node *n;

	list_for_each_safe(list_pos, tmp_pos, &tunXin6_net_adv_list_list)
	{
		n = list_entry(list_pos, struct tunXin6_net_adv_list_node, list);

		if (adv_list == n->adv_list) {

			if (del) {
				list_del_next((&tunXin6_net_adv_list_list), prev_pos);
				debugFree(n, -300516);
				return;
			} else {
				cleanup_all(-501440);
			}

		} else {
			prev_pos = &n->list;
		}
	}

	assertion(-501441, (!del));

	n = debugMallocReset(sizeof( struct tunXin6_net_adv_list_node), -300517);

	n->adv_list = adv_list;
	list_add_tail((&tunXin6_net_adv_list_list), &n->list);
}

STATIC_FUNC
IFNAME_T tun_out_get_free_name(char *typename, char *proposedName)
{
	assertion(-501446, (strlen(tun_name_prefix.str) + strlen(typename) + 4 <= IFNAMSIZ - 1));

	static uint16_t tun_idx = 0;
	uint16_t tun_idx_check = tun_idx;
	IFNAME_T name;

	static char ifNameChars[] = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	memset(&name, 0, sizeof(name));
	snprintf(name.str + strlen(name.str), IFNAMSIZ - 1 - strlen(name.str), "%s", tun_name_prefix.str);

	assertion(-501447, (IFNAMSIZ - 1 > strlen(name.str)));
	snprintf(name.str + strlen(name.str), IFNAMSIZ - 1 - strlen(name.str), "%s", typename);

	if (IFNAMSIZ - 1 > strlen(name.str))
		snprintf(name.str + strlen(name.str), IFNAMSIZ - 1 - strlen(name.str), "%s", proposedName);
	//check if tun->name is already used:

	check_string(name.str, ifNameChars, '_');

	if (!kernel_dev_exists(name.str))
		return name;

	do {

		memset(&name, 0, sizeof(name));
		snprintf(name.str + strlen(name.str), IFNAMSIZ - 5 - strlen(name.str), "%s", tun_name_prefix.str);

		assertion(-501448, (IFNAMSIZ - 5 > strlen(name.str)));
		snprintf(name.str + strlen(name.str), IFNAMSIZ - 5 - strlen(name.str), "%s", typename);

		if (IFNAMSIZ - 5 > strlen(name.str))
			snprintf(name.str + strlen(name.str), IFNAMSIZ - 5 - strlen(name.str), "%s", proposedName);

		assertion(-501449, (IFNAMSIZ - 5 >= strlen(name.str)));
		snprintf(name.str + strlen(name.str), IFNAMSIZ - 1 - strlen(name.str), "%.4X", tun_idx++);

		//check if tun->name is already used:
		check_string(name.str, ifNameChars, '_');

		if (!kernel_dev_exists(name.str))
			return name;

	} while (tun_idx != tun_idx_check);


	assertion(-501450, (0));

	memset(&name, 0, sizeof(name));
	return name;
}

STATIC_FUNC
IDM_T configure_tunnel_in(uint8_t del, struct tun_in_node *tin, int16_t tun6Id)
{
	TRACE_FUNCTION_CALL;
	assertion(-501523, IMPLIES(!del, is_ip_set(&tin->remote)));
	assertion(-501341, IMPLIES(!del, (is_ip_set(&my_primary_ip))));
	assertion(-501311, IMPLIES(tin->upIfIdx, tin->nameKey.str[0]));
	assertion(-501342, IMPLIES(tin->upIfIdx, del));
	assertion(-501368, IMPLIES(del, ((tin->tun6Id >= 0) == (tin->upIfIdx > 0))));
	assertion(-501369, IMPLIES(!del, ((tun6Id >= 0) && (tin->upIfIdx == 0))));

	if (del && tin->upIfIdx) {

		IDM_T result = kernel_tun_del(tin->nameKey.str);
		assertion(-501451, (result == SUCCESS));
		tin->upIfIdx = 0;
		tin->tun6Id = -1;
		my_description_changed = YES;

	} else if (!del && !tin->upIfIdx) {

		IPX_T *local = &my_primary_ip;
		IPX_T *remote = &tin->remote;

		if (!is_ip_set(remote) || is_ip_local(remote) ||
			(tin->ingressPrefix46[0].mask && find_overlapping_hna(&tin->ingressPrefix46[0].ip, tin->ingressPrefix46[0].mask, NULL))) {

			dbgf_sys(DBGT_WARN, "FAILED creating tun remoteIp=%s", ip6AsStr(&tin->remote));
			return FAILURE;
		}

		assertion(-501312, (strlen(tin->nameKey.str)));

		if ((tin->upIfIdx = kernel_tun_add(tin->nameKey.str, IPPROTO_IP, local, remote)) > 0) {

			tin->tun6Id = tun6Id;

			if (tin->tunAddr46[1].mask)
				kernel_set_addr(ADD, tin->upIfIdx, AF_INET, &tin->tunAddr46[1].ip, 32, NO /*deprecated*/);

			if (tin->tunAddr46[0].mask)
				kernel_set_addr(ADD, tin->upIfIdx, AF_INET6, &tin->tunAddr46[0].ip, 128, NO /*deprecated*/);

			my_description_changed = YES;
		}
	}

	return(XOR(del, tin->upIfIdx)) ? SUCCESS : FAILURE;
}

STATIC_FUNC
void reconfigure_tun_ins(void)
{
	struct avl_node *an;
	struct tun_in_node *tin;


	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));)
		configure_tunnel_in(DEL, tin, -1);

	int16_t m = 0;
	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));) {

		if (!tin->remote_manual) {
			tin->remote = my_primary_ip;
			tin->remote.s6_addr[DEF_AUTO_TUNID_OCT_POS] += (m+MIN_AUTO_TUNID_OCT);
		}

		configure_tunnel_in(ADD, tin, m++);
		assertion(-502040, ((m + MIN_AUTO_TUNID_OCT) <= MAX_AUTO_TUNID_OCT));
		assertion(-501237, (tin->upIfIdx && tin->tun6Id >= 0));
	}
}

STATIC_FUNC
uint16_t set_tun_out_mtu(char *name, uint16_t orig_mtu, uint16_t def_mtu, uint16_t new_mtu)
{

	if (new_mtu == def_mtu) {
		kernel_set_mtu(name, orig_mtu);
		return def_mtu;
	} else {
		kernel_set_mtu(name, new_mtu);
		return new_mtu;
	}
}




#define MTU_MAX 1500

struct tun_packet {

	union {
		struct iphdr ip4hdr;
		struct ip6_hdr ip6hdr;
		uint8_t data[MTU_MAX + 1000];
	} t;
} __attribute__((packed));

STATIC_FUNC
void tun_out_state_set(struct tun_out_node *ton, IDM_T tdn_state)
{
	TRACE_FUNCTION_CALL;

	assertion(-500204, (ton));
	assertion(-501452, (tdn_state == TDN_STATE_CATCHALL || tdn_state == TDN_STATE_DEDICATED));

	assertion(-501453, (IMPLIES(tdn_state == TDN_STATE_CATCHALL, ton->tdnDedicated[0] || ton->tdnDedicated[1])));
	assertion(-501453, (IMPLIES(tdn_state == TDN_STATE_DEDICATED, ton->tdnCatchAll[0] || ton->tdnCatchAll[1])));

	struct avl_node *used_tnn_it = NULL;
	struct tun_net_node *used_tnn;
	while ((used_tnn = avl_iterate_item(&ton->tun_net_tree, &used_tnn_it))) {

		//		if (af == used_tnn->tunNetKey.netKey.af) {

		struct avl_node *used_tbn_it = NULL;
		struct tun_bit_node *used_tbn;
		while ((used_tbn = avl_iterate_item(&used_tnn->tun_bit_tree, &used_tbn_it))) {

			if (used_tbn->active_tdn)
				configure_tun_bit(ADD, used_tbn, tdn_state);
		}
		//	}
	}
}

STATIC_FUNC
void tun_out_state_catchAll(void *tonp)
{
	assertion(-502327, (tun_dedicated_to > 0));

	struct tun_out_node *ton = tonp;
	struct tun_dev_node *tdn = ton->tdnDedicated[0] ? ton->tdnDedicated[0] : ton->tdnDedicated[1];

	assertion(-502328, (tdn));
	assertion(-502329, IMPLIES(ton->tdnDedicated[0], ton->tdnDedicated[0] == tdn));
	assertion(-502330, IMPLIES(ton->tdnDedicated[1], ton->tdnDedicated[1] == tdn));

	IDM_T stats_captured = tdn->stats_captured;
	unsigned long long tx_packets = tdn->stats.tx_packets;

	tdn->stats_captured = kernel_get_ifstats(&tdn->stats, tdn->nameKey.str);

	if (stats_captured == SUCCESS && tdn->stats_captured == SUCCESS && tx_packets != tdn->stats.tx_packets) {
		task_register(tun_dedicated_to, tun_out_state_catchAll, ton, -300748);
		return;
	}

	tun_out_state_set(tonp, TDN_STATE_CATCHALL);
}

STATIC_FUNC
void tun_out_catchAll_hook(int fd)
{
	// pick catched packet,  open dedicated tunnel, reroute all related active tun_bit_nodes via dedicated tunnel, and retransmit catched packet

	TRACE_FUNCTION_CALL;
	dbgf_track(DBGT_INFO, "fd=%d", fd);

	static struct tun_packet tp;
	int32_t tp_len;

	assertion(-501456, (fcntl(fd, F_GETFL, 0) & O_NONBLOCK));



	while ((tp_len = read(fd, &tp, sizeof(tp))) > 0) {

		uint8_t isv4 = (tp.t.ip4hdr.version == 4);
		int32_t plen = -1;

		if (tp_len > MTU_MAX ||
			(tp.t.ip4hdr.version != 4 && tp.t.ip4hdr.version != 6) ||
			(isv4 && tp_len <= (int) sizeof(struct iphdr)) ||
			(!isv4 && tp_len <= (int) sizeof(struct ip6_hdr)) /*||
			(tp_len != (plen=ntohs( isv4 ? tp.t.ip4hdr.tot_len : tp.t.ip6hdr.ip6_ctlun.ip6_un1.ip6_un1_plen)))*/) {

			dbgf_sys(DBGT_ERR, "Rcvd invalid packet len=%d=%d ipVersion=%d !",
				tp_len, plen, tp.t.ip4hdr.version);

		} else {
			uint8_t af = isv4 ? AF_INET : AF_INET6;
			IPX_T dst4;
			IPX_T *dst;
			if (isv4) {
				dst4 = ip4ToX(tp.t.ip4hdr.daddr);
				dst = &dst4;
			} else {
				dst = &tp.t.ip6hdr.ip6_dst;
			}

			dbgf_track(DBGT_INFO, "Rcvd len=%d bytes ipVersion=%d len=%d src=%s dst=%s",
				tp_len, tp.t.ip4hdr.version,
				ntohs(isv4 ? tp.t.ip4hdr.tot_len : tp.t.ip6hdr.ip6_ctlun.ip6_un1.ip6_un1_plen),
				isv4 ? ip4AsStr(tp.t.ip4hdr.saddr) : ip6AsStr(&tp.t.ip6hdr.ip6_src), ipXAsStr(af, dst));

			struct tun_out_node *ton = NULL;
			struct avl_node *an = NULL;
			struct tun_bit_node *tbn;
			while ((tbn = avl_iterate_item(&tun_bit_tree, &an))) {

				if (tbn->active_tdn && tbn->tunBitKey.invRouteKey.af == af) {

					uint8_t mask = 128 - tbn->tunBitKey.invRouteKey.mask;

					if (is_ip_net_equal(dst, &tbn->tunBitKey.invRouteKey.ip, mask, af)) {

						ton = tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton;

						if (tbn->active_tdn->tunCatch_fd) {

							if (tun_proactive_routes)
								tun_out_state_set(ton, TDN_STATE_DEDICATED);
							else
								configure_tun_bit(ADD, tbn, TDN_STATE_DEDICATED);

						} else {
							dbgf_track(DBGT_WARN, "tunnel dev=%s to nodeId=%s already dedicated!",
								tbn->active_tdn->nameKey.str, cryptShaAsString(&ton->tunOutKey.on->k.nodeId));
						}
						break;
					}
				}
			}

			if (ton) {
				//if (af==AF_INET || af==AF_INET6) {

				// This should only work with IPv6 and non-local IPv6 src addresses. But it works always!!!!

				assertion(-501530, (tbn->active_tdn && tbn->active_tdn == ton->tdnDedicated[isv4] && !ton->tdnDedicated[isv4]->tunCatch_fd));

				struct tun_catch_key key = {.afKey = af};
				struct tun_dev_node *tdn = avl_next_item(&tun_catch_tree, &key);

				if (tdn && tdn->tunCatchKey.afKey == af) {

					int written = write(tdn->tunCatch_fd, &tp, tp_len);

					dbgf(written == tp_len ? DBGL_CHANGES : DBGL_SYS, written == tp_len ? DBGT_INFO : DBGT_ERR,
						"%ssendto dst=%s len=%d (wrote=%d) fd=%d dev=%s (via dev=%s)! %s",
						(written != tp_len) ? "Failed " : "",
						isv4 ? ip4AsStr(tp.t.ip4hdr.daddr) : ip6AsStr(&tp.t.ip6hdr.ip6_dst),
						tp_len, written, tdn->tunCatch_fd, tdn->nameKey.str,
						ton->tdnDedicated[isv4]->nameKey.str,
						(written != tp_len) ? strerror(errno) : "");

				} else {
					dbgf_sys(DBGT_ERR, "No catchAll available for dst=%s len=%d",
						isv4 ? ip4AsStr(tp.t.ip4hdr.daddr) : ip6AsStr(&tp.t.ip6hdr.ip6_dst), tp_len);
				}
/*
				} else {
					// This should always work with own addresses. But it does not with IPv4 !!!
					//http://www.pdbuchan.com/rawsock/rawsock.html
					// Request raw socket descriptor:
					int sockfd = socket(af, SOCK_RAW, IPPROTO_RAW);
					if ( sockfd <= 0 ) {
						dbgf_sys(DBGT_ERR, "Failed creating RAW socket=%d %s", sockfd, strerror(errno));
					}

					if (af == AF_INET) {
						// For whatever reason this does not work for IPv4 !!!

						// Set flag that socket expects provided IPv4 header:
						const int optval = 1;
						int sockopt = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
						if ( sockopt != 0 ) {
							dbgf_sys(DBGT_ERR, "Failed sockopt=%d %s", sockopt, strerror(errno));
						}

						// Bind socket to interface index:
						struct ifreq ifr;
						memset (&ifr, 0, sizeof (ifr));
						snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", ton->tdnUP[isv4]->name.str);
						ifr.ifr_ifindex = ton->tdnUP[isv4]->ifIdx;

						if (setsockopt (sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
							dbgf_sys(DBGT_ERR, "Failed bind to interface %s", strerror(errno));
						}
					}

					struct sockaddr_storage sast = set_sockaddr_storage(af, dst ,0);
					int written = sendto( sockfd, &tp, tp_len, 0, (struct sockaddr *) &sast, sizeof(sast) );

					dbgf(written==tp_len? DBGL_CHANGES: DBGL_SYS, written==tp_len? DBGT_INFO : DBGT_ERR,
						"%ssendto dst=%s len=%d (wrote=%d) fd=%d dev=%s idx=%d! %s",
						( written != tp_len ) ? "Failed " : "",
						isv4 ? ip4AsStr(tp.t.ip4hdr.daddr) : ip6AsStr(&tp.t.ip6hdr.ip6_dst),
						tp_len, written, sockfd, ton->tdnUP[isv4]->name.str, ton->tdnUP[isv4]->ifIdx,
						( written != tp_len ) ? strerror(errno) : "");

					if ( sockfd > 0 )
						close(sockfd);
				}
*/
			} else {
				dbgf_track(DBGT_WARN, "NO tunnel found for dst=%s len=%d ! Discarding packet!",
					isv4 ? ip4AsStr(tp.t.ip4hdr.daddr) : ip6AsStr(&tp.t.ip6hdr.ip6_dst), tp_len);

			}
		}
	}
}
STATIC_FUNC
struct tun_dev_node * tun_dev_out_del(struct tun_bit_node *tbn)
{
	TRACE_FUNCTION_CALL;

	struct tun_search_node *tsn = tbn->tunBitKey.keyNodes.tsn;
	struct tun_net_node *tnn = tbn->tunBitKey.keyNodes.tnn;
	struct tun_out_node *ton = tnn->tunNetKey.ton;
	uint8_t af = tsn->net.af;
	uint8_t isv4 = (af == AF_INET);
	struct tun_dev_node *tdn = tbn->active_tdn;

	dbgf_track(DBGT_INFO, "tunnel dev=%s", tdn->nameKey.str);

	assertion(-501460, (is_ip_set(&ton->localIp)));
	assertion(-501461, (ton->tunOutKey.on));
	assertion(-501462, (ton->tunOutKey.on != myKey->currOrig));
	assertion(-501463, (tdn));
	assertion(-501464, (tdn->ifIdx));
	assertion(-501465, (tdn->orig_mtu));
	assertion(-501466, (tdn->nameKey.str[0]));
	assertion(-501469, avl_find_item(&tdn->tun_bit_tree[isv4], &tbn->tunBitKey.keyNodes));

	if (tdn->tunCatch_fd) {

		assertion(-501467, (tdn->tunCatchKey.afKey == af));
		assertion(-501468, (tdn->tunCatch_fd > 0));

		avl_remove(&tdn->tun_bit_tree[isv4], &tbn->tunBitKey.keyNodes, -300526);

		struct avl_node *an = NULL;
		struct tun_bit_node *ton_tbn;
		while ((ton_tbn = avl_iterate_item(&tdn->tun_bit_tree[isv4], &an)) && ton_tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton != ton);
		if (!ton_tbn)
			ton->tdnCatchAll[isv4] = NULL;

		if (!tdn->tun_bit_tree[isv4].items) {

			set_fd_hook(tdn->tunCatch_fd, tun_out_catchAll_hook, DEL);

			avl_remove(&tdn->tunCatchKey.tin->tun_dev_tree, &tdn->nameKey, -300555);

			// always keep one per each address family for re-sending catched packets (via tun_dflt):
//			if (!is_ip_equal(&tdnActive->tunCatchKey.srcIp, (isv4?&tun4_address.ip:&tun6_address.ip))) {
			struct tun_catch_key catchKey = {.afKey = af};
			struct tun_dev_node *afTdn1, *afTdn2;
			if (((afTdn1 = avl_next_item(&tun_catch_tree, &catchKey)) && afTdn1->tunCatchKey.afKey == af) &&
				((afTdn2 = avl_next_item(&tun_catch_tree, &afTdn1->tunCatchKey)) && afTdn2->tunCatchKey.afKey == af)) {

				avl_remove(&tun_catch_tree, &tdn->tunCatchKey, -300527);
				kernel_dev_tun_del(tdn->nameKey.str, tdn->tunCatch_fd);
				debugFree(tdn, -300528);
			}
		}

	} else { //dedicated:

		assertion(-501468, (tdn == ton->tdnDedicated[isv4]));
		assertion(-501470, IMPLIES(tdn != ton->tdnDedicated[!isv4], ton->tdnDedicated[!isv4] == NULL));

		avl_remove(&tdn->tun_bit_tree[isv4], &tbn->tunBitKey.keyNodes, -300548);

		if (!tdn->tun_bit_tree[isv4].items) {

			ton->tdnDedicated[isv4] = NULL;

			if (!tdn->tun_bit_tree[!isv4].items) {
				assertion(-501532, (!ton->tdnDedicated[!isv4]));

				avl_remove(&tdn->tunCatchKey.tin->tun_dev_tree, &tdn->nameKey, -300556);

				IDM_T result = kernel_tun_del(tdn->nameKey.str);
				assertion(-501471, (result == SUCCESS));
				debugFree(tdn, -300531);

				task_remove(tun_out_state_catchAll, ton);
			}

		}
	}

	return(tbn->active_tdn = NULL);
}

STATIC_FUNC
IDM_T assert_tbn_ton_tdn(IDM_T isv4, struct tun_out_node *ton, struct tun_bit_node *tbn)
{

	assertion(-501546, (ton));
	assertion(-501547, IMPLIES(ton->tdnCatchAll[isv4], ton->tdnCatchAll[isv4]->tunCatchKey.tin));
	assertion(-501548, IMPLIES(ton->tdnCatchAll[isv4], ton->tdnCatchAll[isv4]->tunCatchKey.tin->tunAddr46[isv4].mask));
	assertion(-501549, IMPLIES(ton->tdnCatchAll[isv4], is_ip_set(&(ton->tdnCatchAll[isv4]->tunCatchKey.tin->tunAddr46[isv4].ip))));
	assertion(-501550, IMPLIES(ton->tdnCatchAll[isv4], ton->tdnCatchAll[isv4]->tunCatchKey.tin->tunAddr46[isv4].mask >= ton->ingressPrefix[isv4].mask));
	assertion(-501551, IMPLIES(ton->tdnCatchAll[isv4], is_ip_net_equal(&ton->tdnCatchAll[isv4]->tunCatchKey.tin->tunAddr46[isv4].ip, &ton->ingressPrefix[isv4].ip, ton->ingressPrefix[isv4].mask, isv4 ? AF_INET : AF_INET6)));

	assertion(-501552, IMPLIES(ton->tdnDedicated[isv4], ton->tdnDedicated[isv4]->tunCatchKey.tin));
	assertion(-501553, IMPLIES(ton->tdnDedicated[isv4], ton->tdnDedicated[isv4]->tunCatchKey.tin->tunAddr46[isv4].mask));
	assertion(-501554, IMPLIES(ton->tdnDedicated[isv4], is_ip_set(&(ton->tdnDedicated[isv4]->tunCatchKey.tin->tunAddr46[isv4].ip))));
	assertion(-501555, IMPLIES(ton->tdnDedicated[isv4], ton->tdnDedicated[isv4]->tunCatchKey.tin->tunAddr46[isv4].mask >= ton->ingressPrefix[isv4].mask));
	assertion(-501556, IMPLIES(ton->tdnDedicated[isv4], is_ip_net_equal(&ton->tdnDedicated[isv4]->tunCatchKey.tin->tunAddr46[isv4].ip, &ton->ingressPrefix[isv4].ip, ton->ingressPrefix[isv4].mask, isv4 ? AF_INET : AF_INET6)));

	assertion(-501557, IMPLIES(tbn, tbn->tunBitKey.keyNodes.tnn));
	assertion(-501558, IMPLIES(tbn, ton == tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton));
//	assertion(-501559, IMPLIES(tbn, tbn->active_tdn==tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnCatchAll[isv4] || tbn->active_tdn==tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnDedicated[isv4] ));
	return YES;
}

STATIC_FUNC
struct tun_in_node *find_matching_tun_in_node(IDM_T isv4, struct tun_search_node *tsn, struct tun_out_node *ton)
{
	struct tun_dev_node *tdn;
	struct tun_in_node *tin;
	struct avl_node *an = NULL;

	assertion(-501560, assert_tbn_ton_tdn(isv4, ton, NULL));

	if ((tdn = (ton->tdnDedicated[isv4] ? ton->tdnDedicated[isv4] : ton->tdnCatchAll[isv4])))
		return tdn->tunCatchKey.tin;



	while ((tin = avl_iterate_item(&tun_in_tree, &an))) {

		struct net_key tinAddr = tin->tunAddr46[isv4];

		if (!tinAddr.mask)
			continue;

		else if (!ton->ingressPrefix[isv4].mask)
			return tin;

		else if (tinAddr.mask >= ton->ingressPrefix[isv4].mask &&
			is_ip_net_equal(&tinAddr.ip, &ton->ingressPrefix[isv4].ip, ton->ingressPrefix[isv4].mask, isv4 ? AF_INET : AF_INET6))
			return tin;

	}

	return NULL;
}

STATIC_FUNC
struct tun_dev_node *tun_dev_out_add(struct tun_bit_node *tbn, IDM_T tdn_state)
{
	TRACE_FUNCTION_CALL;

	struct tun_search_node *tsn = tbn->tunBitKey.keyNodes.tsn;
	struct tun_net_node *tnn = tbn->tunBitKey.keyNodes.tnn;
	struct tun_out_node *ton = tnn->tunNetKey.ton;
	uint8_t isv4 = (tsn->net.af == AF_INET);
	struct tun_dev_node *tdn = tbn->active_tdn;

	struct tun_in_node *tin = find_matching_tun_in_node(isv4, tsn, ton);

	assertion(-501472, (tin && is_ip_set(&tin->tunAddr46[isv4].ip)));

	assertion(-501524, (is_ip_set(&ton->localIp)));
	assertion(-501235, (ton->tunOutKey.on));
	assertion(-501321, (ton->tunOutKey.on != myKey->currOrig));
	assertion(-501343, (is_ip_set(&ton->tunOutKey.on->primary_ip)));

	dbgf_track(DBGT_INFO, "tdn_state=%d", tdn_state);

	assertion(-501473, (tdn_state == TDN_STATE_CATCHALL || tdn_state == TDN_STATE_DEDICATED || tdn_state == TDN_STATE_CURRENT));

	if (tdn_state == TDN_STATE_CATCHALL ||
		(tdn_state == TDN_STATE_CURRENT && (tdn ? (tdn->tunCatch_fd > 0) : (!tdn && tun_dedicated_to > 0)))) {

		//set TDN_STATE_CATCHALL
		struct tun_catch_key tunCatchKey2 = {.afKey = tsn->net.af, .tin = tin};


		if (tdn && !tdn->tunCatch_fd)
			tdn = tun_dev_out_del(tbn);

		if (!tdn) {

			if (!(tdn = avl_find_item(&tun_catch_tree, &tunCatchKey2))) {

				assertion(-501561, (!ton->tdnCatchAll[isv4]));

				tdn = debugMalloc(sizeof(struct tun_dev_node), -300532);
				memset(tdn, 0, sizeof(struct tun_dev_node));
				AVL_INIT_TREE(tdn->tun_bit_tree[0], struct tun_bit_node, tunBitKey.keyNodes);
				AVL_INIT_TREE(tdn->tun_bit_tree[1], struct tun_bit_node, tunBitKey.keyNodes);

				tdn->nameKey = tun_out_get_free_name(isv4 ? DEF_TUN_NAME_TYPE_CATCH4 : DEF_TUN_NAME_TYPE_CATCH6, tin->nameKey.str + strlen(tun_name_prefix.str));
				tdn->ifIdx = kernel_dev_tun_add(tdn->nameKey.str, &tdn->tunCatch_fd, isv4 ? 1 : 0);
				tdn->orig_mtu = kernel_get_mtu(tdn->nameKey.str);
				tdn->curr_mtu = set_tun_out_mtu(tdn->nameKey.str, tdn->orig_mtu, DEF_TUN_OUT_MTU, tun_out_mtu);

				kernel_set_addr(ADD, tdn->ifIdx, isv4 ? AF_INET : AF_INET6, &tin->tunAddr46[isv4].ip, isv4 ? 32 : 128, NO/*deprecated*/);

				avl_insert(&tin->tun_dev_tree, tdn, -300557);

				tdn->tunCatchKey = tunCatchKey2;
				avl_insert(&tun_catch_tree, tdn, -300533);
			}

			if (!tdn->tun_bit_tree[0].items && !tdn->tun_bit_tree[1].items)
				set_fd_hook(tdn->tunCatch_fd, tun_out_catchAll_hook, ADD);

			avl_insert(&tdn->tun_bit_tree[isv4], tbn, -300534);

			assertion(-501534, IMPLIES(ton->tdnCatchAll[isv4], ton->tdnCatchAll[isv4] == tdn));
			ton->tdnCatchAll[isv4] = tdn;
		}

		assertion(-501474, (tdn));
		assertion(-501475, (tdn->tunCatch_fd > 0));
		assertion(-501476, (tdn->ifIdx > 0));
		assertion(-501477, (tdn->orig_mtu >= MIN_TUN_OUT_MTU));
		assertion(-501562, (tunCatchKey2.afKey == tsn->net.af));
		assertion(-501479, (is_ip_set(&tin->tunAddr46[isv4].ip)));
		assertion(-501481, (avl_find_item(&tun_catch_tree, &tunCatchKey2)));
		assertion(-501482, (avl_find_item(&tdn->tun_bit_tree[isv4], &tbn->tunBitKey.keyNodes)));
		assertion(-501536, (ton->tdnCatchAll[isv4] == tdn));

	} else if (tdn_state == TDN_STATE_DEDICATED ||
		(tdn_state == TDN_STATE_CURRENT && (tdn ? (tdn->tunCatch_fd == 0) : (tun_dedicated_to == 0)))) {

		if (tdn && tdn->tunCatch_fd)
			tdn = tun_dev_out_del(tbn);

		if (!tdn) {

			if (!((tdn = ton->tdnDedicated[isv4]) || (tdn = ton->tdnDedicated[!isv4]))) {

				assertion(-501563, (!ton->tdnDedicated[isv4]));

				tdn = debugMalloc(sizeof(struct tun_dev_node), -300535);
				memset(tdn, 0, sizeof(struct tun_dev_node));
				AVL_INIT_TREE(tdn->tun_bit_tree[0], struct tun_bit_node, tunBitKey.keyNodes);
				AVL_INIT_TREE(tdn->tun_bit_tree[1], struct tun_bit_node, tunBitKey.keyNodes);

				tdn->nameKey = tun_out_get_free_name(DEF_TUN_NAME_TYPE_OUT, cryptShaAsString(&ton->tunOutKey.on->k.nodeId));
				tdn->ifIdx = kernel_tun_add(tdn->nameKey.str, IPPROTO_IP, &ton->localIp, &ton->remoteIp);
				tdn->orig_mtu = kernel_get_mtu(tdn->nameKey.str);
				tdn->curr_mtu = set_tun_out_mtu(tdn->nameKey.str, tdn->orig_mtu, DEF_TUN_OUT_MTU, tun_out_mtu);

				tdn->stats_captured = kernel_get_ifstats(&tdn->stats, tdn->nameKey.str);

				assertion(-501485, (tdn->ifIdx > 0));
				assertion(-501486, (tdn->orig_mtu >= MIN_TUN_OUT_MTU));
				assertion(-501487, (!tdn->tunCatch_fd));

				kernel_set_addr(ADD, tdn->ifIdx, AF_INET6, &ton->localIp, 128, YES /*deprecated*/);

				if (tin->tunAddr46[1].mask)
					kernel_set_addr(ADD, tdn->ifIdx, AF_INET, &tin->tunAddr46[1].ip, 32, NO/*deprecated*/);

				if (tin->tunAddr46[0].mask)
					kernel_set_addr(ADD, tdn->ifIdx, AF_INET6, &tin->tunAddr46[0].ip, 128, NO/*deprecated*/);

				avl_insert(&tin->tun_dev_tree, tdn, -300558);

				tdn->tunCatchKey.tin = tin;
			}

			avl_insert(&tdn->tun_bit_tree[isv4], tbn, -300549);

			assertion(-501537, IMPLIES(ton->tdnDedicated[isv4], ton->tdnDedicated[isv4] == tdn));
			ton->tdnDedicated[isv4] = tdn;
		}

		assertion(-501484, (tdn));
		assertion(-501538, (ton->tdnDedicated[isv4] == tdn));

		task_remove(tun_out_state_catchAll, ton);

		if (tun_dedicated_to > 0)
			task_register(tun_dedicated_to, tun_out_state_catchAll, ton, -300536);


	} else {
		assertion(-501489, (0));
	}

	dbgf_track(DBGT_INFO, "tunnel dev=%s dflt_fd=%d done!", tdn->nameKey.str, tdn->tunCatch_fd);

	assertion(-501539, IMPLIES(tbn->active_tdn, tbn->active_tdn == tdn));
	return(tbn->active_tdn = tdn);
}

/*
STATIC_FUNC
IDM_T configure_tunnel_out(uint8_t del, struct tun_out_node *ton)
{
        TRACE_FUNCTION_CALL;
        assertion(-501525, (is_ip_set(&ton->localIp)));
        assertion(-501235, (ton->tunOutKey.on));
        assertion(-501321, (ton->tunOutKey.on != myKey->orig));
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

                assertion(-501312, (strlen(ton->name.str)));

                if ((ton->upIfIdx = kernel_set_tun(ADD, ton->name.str, IPPROTO_IP, &ton->localIp, &ton->remoteIp)) > 0 &&
                        (ton->orig_mtu = kernel_get_mtu(ton->name.str)) >= MIN_TUN_OUT_MTU ) {

                        return SUCCESS;
                }
        }

        if(ton->upIfIdx)
                configure_tunnel_out(DEL, ton);

        return FAILURE;
}
*/




STATIC_FUNC
void configure_tun_bit(uint8_t del, struct tun_bit_node *tbn, IDM_T tdn_state)
{
	TRACE_FUNCTION_CALL;

	struct tun_search_node *tsn = tbn->tunBitKey.keyNodes.tsn;
	struct tun_net_node *tnn = tbn->tunBitKey.keyNodes.tnn;
	struct tun_out_node *ton = tnn->tunNetKey.ton;
	//uint8_t isv4 = (tsn->net.af==AF_INET);
	uint8_t rtype = tsn->routeSetProto;
	struct net_key routeKey = tbn->tunBitKey.invRouteKey;
	routeKey.mask = 128 - routeKey.mask;
	struct route_export rte, *rtep = NULL;
	if (tsn->exportDistance != TYP_EXPORT_DISTANCE_INFINITE) {
		memset(&rte, 0, sizeof(rte));
		rte.exportDistance = tsn->exportDistance;
		rte.exportOnly = tsn->exportOnly;
		rte.ipexport = NO; // not yet
		rtep = &rte;
	}

	int dbgl = DBGL_CHANGES;

	assertion(-501490, (tsn->net.af == tnn->tunNetKey.netKey.af));
	assertion(-501491, (tsn->net.af == tbn->tunBitKey.invRouteKey.af));
	assertion(-501492, (tdn_state == TDN_STATE_CURRENT || tdn_state == TDN_STATE_DEDICATED || tdn_state == TDN_STATE_CATCHALL));

	if (del && tbn->active_tdn) {

		iproute((IP_ROUTE_TUNS + rtype), DEL, NO, &routeKey, tbn->ipTable, 0, tbn->active_tdn->ifIdx, NULL, NULL, ntohl(tbn->tunBitKey.beIpMetric), rtep);

		tun_dev_out_del(tbn);

	} else if (!del && (!tbn->active_tdn || (tbn->active_tdn && (
		(tdn_state == TDN_STATE_DEDICATED && tbn->active_tdn->tunCatch_fd > 0) ||
		(tdn_state == TDN_STATE_CATCHALL && tbn->active_tdn->tunCatch_fd <= 0))))) {

		if (tbn->active_tdn)
			iproute((IP_ROUTE_TUNS + rtype), DEL, NO, &routeKey, tbn->ipTable, 0, tbn->active_tdn->ifIdx, NULL, NULL, ntohl(tbn->tunBitKey.beIpMetric), rtep);

		tun_dev_out_add(tbn, tdn_state);
		assertion(-501540, (tbn->active_tdn));
		iproute((IP_ROUTE_TUNS + rtype), ADD, NO, &routeKey, tbn->ipTable, 0, tbn->active_tdn->ifIdx, NULL, NULL, ntohl(tbn->tunBitKey.beIpMetric), rtep);

	} else {
		dbgl = DBGL_ALL;
	}

	dbgf(dbgl, DBGT_INFO, "%s %s via nodeId=%s asDfltTun=%d tbn_active=%s",
		del ? "DEL" : "ADD", netAsStr(&routeKey), cryptShaAsString(&ton->tunOutKey.on->k.nodeId),
		tdn_state, tbn->active_tdn ? tbn->active_tdn->nameKey.str : "---");

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
		uint8_t isv4 = (tsn_netKey->af == AF_INET);

		dbgf_track(DBGT_INFO, "%s=%s: %s=%s %s=%s %s=%d %s=%s", ARG_TUN_OUT, tbkn.tsn->nameKey,
			ARG_TUN_OUT_PKID, cryptShaAsString(&tbkn.tsn->global_id), ARG_TUN_OUT_GWNAME, tbkn.tsn->gwName,
			ARG_TUN_OUT_TYPE, tbkn.tsn->srcType, ARG_TUN_OUT_NET, netAsStr(tsn_netKey));

		while ((tbkn.tnn = tnna ? tnna : avl_iterate_item(&tun_net_tree, &itnn))) {

			//                        assertion(-501370, (!avl_find(&tun_bit_tree, )));
			assertion(-501371, (!avl_find(&(tbkn.tsn->tun_bit_tree), &tbkn)));
			assertion(-501372, (!avl_find(&(tbkn.tnn->tun_bit_tree), &tbkn)));

			struct orig_node *on = tbkn.tnn->tunNetKey.ton->tunOutKey.on;
			GLOBAL_ID_T *tnn_gid = &on->k.nodeId;
			struct net_key *tnn_netKey = &tbkn.tnn->tunNetKey.netKey;
			struct net_key ingressPrefix = tbkn.tnn->tunNetKey.ton->ingressPrefix[isv4];

			dbgf_track(DBGT_INFO, "checking network=%s bw_fmu8=%d, ingress=%s localIp=%s tun6Id=%d from nodeId=%s hostname=%s",
				netAsStr(tnn_netKey), tbkn.tnn->bandwidth.val.u8, netAsStr(&ingressPrefix),
				ip6AsStr(&tbkn.tnn->tunNetKey.ton->localIp), tbkn.tnn->tunNetKey.ton->tunOutKey.tun6Id,
				cryptShaAsString(&on->k.nodeId), on->k.hostname);

			if (!(
				(tbkn.tsn->routeSearchProto == TYP_TUN_PROTO_ALL || tbkn.tsn->routeSearchProto == tbkn.tnn->tunNetKey.bmx7RouteType) &&
				tsn_netKey->af == tnn_netKey->af &&
				(tbkn.tsn->netPrefixMax == TYP_TUN_OUT_PREFIX_NET ?
				tsn_netKey->mask >= tnn_netKey->mask : tbkn.tsn->netPrefixMax >= tnn_netKey->mask) &&
				(tbkn.tsn->netPrefixMin == TYP_TUN_OUT_PREFIX_NET ?
				tsn_netKey->mask <= tnn_netKey->mask : tbkn.tsn->netPrefixMin <= tnn_netKey->mask) &&
				is_ip_net_equal(&tsn_netKey->ip, &tnn_netKey->ip, XMIN(tsn_netKey->mask, tnn_netKey->mask), tnn_netKey->af) &&
				IMPLIES(strlen(tbkn.tsn->gwName), !strcmp(tbkn.tsn->gwName, on->k.hostname)) &&
				IMPLIES(!is_zero(tsn_gid, sizeof(GLOBAL_ID_T)), cryptShasEqual(tsn_gid, tnn_gid))
				)) {

				dbgf_track(DBGT_INFO, "failed A");

			} else if (!(tbkn.tsn->srcType == TUN_SRC_TYPE_UNDEF || tbkn.tsn->srcType == TUN_SRC_TYPE_STATIC)) {

				dbgf_track(DBGT_INFO, "failed B");

			} else if (tbkn.tsn->srcRtNet.mask && ingressPrefix.mask && !(
				tbkn.tsn->srcRtNet.mask >= ingressPrefix.mask &&
				is_ip_net_equal(&tbkn.tsn->srcRtNet.ip, &ingressPrefix.ip, ingressPrefix.mask, ingressPrefix.af))) {

				dbgf_track(DBGT_INFO, "failed C");

			} else if (!find_matching_tun_in_node(isv4, tbkn.tsn, tbkn.tnn->tunNetKey.ton)) {

				dbgf_track(DBGT_INFO, "failed D");

			} else {

				struct tun_bit_node *tbn = debugMalloc(sizeof( struct tun_bit_node), -300455);
				memset(tbn, 0, sizeof(struct tun_bit_node));

				tbn->tunBitKey.beInvTunBitMetric = hton64(UMETRIC_MAX);
				tbn->tunBitKey.beIpRule = htonl(tbkn.tsn->iprule);
				tbn->tunBitKey.beIpMetric = htonl(tbkn.tsn->ipmetric);
				tbn->tunBitKey.keyNodes = tbkn;
				tbn->tunBitKey.invRouteKey = tsn_netKey->mask > tnn_netKey->mask ? *tsn_netKey : *tnn_netKey;
				tbn->tunBitKey.invRouteKey.mask = 128 - tbn->tunBitKey.invRouteKey.mask;

				tbn->ipTable = tbkn.tsn->iptable;

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
void _del_tun_bit_node(struct tun_search_node *tsn, struct tun_net_node *tnn)
{
	TRACE_FUNCTION_CALL;

	struct tun_bit_node *tbn;
	struct avl_tree *tbt = (tsn ? &tsn->tun_bit_tree : (tnn ? &tnn->tun_bit_tree : &tun_bit_tree));

	while ((tbn = avl_first_item(tbt))) {


		avl_remove(&(tbn->tunBitKey.keyNodes.tsn->tun_bit_tree), &tbn->tunBitKey.keyNodes, -300460);
		avl_remove(&(tbn->tunBitKey.keyNodes.tnn->tun_bit_tree), &tbn->tunBitKey.keyNodes, -300461);
		avl_remove(&tun_bit_tree, &tbn->tunBitKey, -300462);

		configure_tun_bit(DEL, tbn, TDN_STATE_CURRENT);

		debugFree(tbn, -300463);
	}
}

STATIC_FUNC
void upd_tun_bit_node(uint8_t del, struct tun_search_node *tsn, struct tun_net_node *tnn)
{
	assertion(-501378, (!(tsn && tnn)));
	if (del)
		_del_tun_bit_node(tsn, tnn);
	else
		_add_tun_bit_node(tsn, tnn);
}

STATIC_FUNC
IDM_T _recalc_tun_bit_tree(void)
{
	TRACE_FUNCTION_CALL;

	prof_start(_recalc_tun_bit_tree, main);

	IDM_T changedOrder = NO;
	struct tun_bit_node *tbn_curr;
	struct tun_bit_key tbk_prev;
	memset(&tbk_prev, 0, sizeof(tbk_prev));

	while ((tbn_curr = avl_next_item(&tun_bit_tree, &tbk_prev))) {

		struct tun_bit_key tbk_new = tbn_curr->tunBitKey;
		struct tun_bit_node *tbn_next = avl_next_item(&tun_bit_tree, &tbn_curr->tunBitKey);
		struct tun_net_node *tnn = tbn_curr->tunBitKey.keyNodes.tnn;
		struct tun_search_node *tsn = tbn_curr->tunBitKey.keyNodes.tsn;


		struct orig_node *on = tnn->tunNetKey.ton->tunOutKey.on;

		UMETRIC_T linkMax = UMETRIC_MAX;
		UMETRIC_T tnnBandwidth = fmetric_u8_to_umetric(tnn->bandwidth);
		UMETRIC_T linkQuality = tnnBandwidth >= tsn->minBW ? UMETRIC_MAX : tnnBandwidth;
		UMETRIC_T pathMetric = on->curr_rt_link ? on->ogmMetric : 0;
		UMETRIC_T e2eMetric;

		if (linkQuality <= UMETRIC_MIN__NOT_ROUTABLE || pathMetric <= UMETRIC_MIN__NOT_ROUTABLE)
			e2eMetric = UMETRIC_MIN__NOT_ROUTABLE;
		else
			e2eMetric = apply_metric_algo(&linkQuality, &linkMax, &pathMetric, on->path_metricalgo);

		dbgf_all(DBGT_INFO, "acceptable e2eMetric=%s,", umetric_to_human(e2eMetric));

		if (e2eMetric <= UMETRIC_MIN__NOT_ROUTABLE) {
			tbk_new.beInvTunBitMetric = hton64(UMETRIC_MAX);
		} else {
			UMETRIC_T tunBitMetric = ((((e2eMetric * (tsn->rating)) / 100) *
				(100 + (tbn_curr->active_tdn ? tsn->hysteresis : 0))) / 100);

			tbk_new.beInvTunBitMetric = hton64(UMETRIC_MAX - tunBitMetric);
		}

		assertion(-501380, (memcmp(&tbk_new, &tbk_prev, sizeof(struct tun_bit_key))));
		assertion(-501381, IMPLIES(tbn_next, memcmp(&tbk_new, &tbn_next->tunBitKey, sizeof(struct tun_bit_key))));

		if (memcmp(&tbk_new, &tbk_prev, sizeof(struct tun_bit_key)) < 0 ||
			(tbn_next && memcmp(&tbk_new, &tbn_next->tunBitKey, sizeof(struct tun_bit_key)) > 0)) {

			avl_remove(&tun_bit_tree, &tbn_curr->tunBitKey, -300464);
			tbn_curr->tunBitKey = tbk_new;
			avl_insert(&tun_bit_tree, tbn_curr, -300465);
			changedOrder = YES;
		} else {
			tbn_curr->tunBitKey = tbk_new;
			tbk_prev = tbk_new;
		}
	}
	prof_stop();
	return changedOrder;
}

STATIC_FUNC
void eval_tun_bit_tree(void *onlyIfOrderChanged)
{
	TRACE_FUNCTION_CALL;

	task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 1));

	if (tun_search_tree.items)
		task_register(5000, (void(*)(void*))eval_tun_bit_tree, ((void*) 1), -300466);

	IDM_T changedOrder = _recalc_tun_bit_tree();

	struct tun_bit_node *tbn_curr = NULL;
	IDM_T isv4;

	if (onlyIfOrderChanged && !changedOrder)
		return;

	prof_start(eval_tun_bit_tree, main);

	dbgf_track(DBGT_INFO, "changedOrder=%d", changedOrder);

	for (isv4 = 0; isv4 <= 1; isv4++) {

		uint32_t af = isv4 ? AF_INET : AF_INET6;
		struct tun_bit_node *tbn_begin = NULL;
		IDM_T tbn_range_allowLarger = YES;

		while ((tbn_curr = avl_next_item(&tun_bit_tree, tbn_curr ? &tbn_curr->tunBitKey : NULL))) {

			if (af != tbn_curr->tunBitKey.invRouteKey.af)
				continue;

			struct tun_bit_key currBKey = tbn_curr->tunBitKey;
			struct net_key currRoute = {.af = af, .ip = currBKey.invRouteKey.ip, .mask = 128 - currBKey.invRouteKey.mask};

			assertion(-501564, (currBKey.keyNodes.tnn));
			assertion(-501565, (currBKey.keyNodes.tnn->tunNetKey.ton));
			assertion(-501574, (assert_tbn_ton_tdn(isv4, currBKey.keyNodes.tnn->tunNetKey.ton, tbn_curr)));
			//TODO: This one would casually cause bmx7 to crash. But later 501577 seems NOT !!?
			//assertion(-501575, IMPLIES(tbn_curr,
			//	tbn_curr->active_tdn==tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnCatchAll[isv4] ||
			//	tbn_curr->active_tdn==tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnDedicated[isv4] ));

			if (!tbn_begin ||
				tbn_begin->tunBitKey.beIpRule != currBKey.beIpRule ||
				tbn_begin->tunBitKey.beIpMetric != currBKey.beIpMetric ||
				tbn_begin->tunBitKey.invRouteKey.af != currBKey.invRouteKey.af) {

				struct tun_bit_node *tbn_range;

				tbn_begin = tbn_curr;
				tbn_range_allowLarger = YES;

				// check if any tbn in current range has tsn->allowLarger == NO:

				for (tbn_range = tbn_begin;
					(tbn_range &&
					tbn_range->tunBitKey.beIpRule == tbn_begin->tunBitKey.beIpRule &&
					tbn_range->tunBitKey.beIpMetric == tbn_begin->tunBitKey.beIpMetric &&
					tbn_range->tunBitKey.invRouteKey.af == tbn_begin->tunBitKey.invRouteKey.af);
					tbn_range = avl_next_item(&tun_bit_tree, &tbn_range->tunBitKey)) {

					if (!tbn_range->tunBitKey.keyNodes.tsn->allowLargerPrefixRoutesWithWorseTunMetric)
						tbn_range_allowLarger = NO;

					tbn_range->possible = YES;
				}
			}

			dbgf_track(DBGT_INFO, "current: pref=%d ipmetric=%d route=%s tunMtc=%s gwId=%s possible=%d dev=%s",
				ntohl(currBKey.beIpRule), ntohl(currBKey.beIpMetric), netAsStr(&currRoute),
				umetric_to_human(UMETRIC_MAX - ntoh64(currBKey.beInvTunBitMetric)),
				cryptShaAsString(&tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tunOutKey.on->k.nodeId),
				tbn_curr->possible, tbn_curr->active_tdn ? tbn_curr->active_tdn->nameKey.str : "---");

			if (!tbn_curr->possible)
				continue;

			struct tun_bit_node *tbn_crash;

			for (tbn_crash = avl_next_item(&tun_bit_tree, &tbn_curr->tunBitKey);
				(tbn_crash &&
				tbn_crash->tunBitKey.beIpRule == tbn_begin->tunBitKey.beIpRule &&
				tbn_crash->tunBitKey.beIpMetric == tbn_begin->tunBitKey.beIpMetric &&
				tbn_crash->tunBitKey.invRouteKey.af == tbn_begin->tunBitKey.invRouteKey.af);
				tbn_crash = avl_next_item(&tun_bit_tree, &tbn_crash->tunBitKey)) {

				struct tun_bit_key crashBKey = tbn_crash->tunBitKey;
				struct net_key crashRoute = {.af = af, .ip = crashBKey.invRouteKey.ip, .mask = 128 - crashBKey.invRouteKey.mask};
				IDM_T break_loop = NO;

				assertion(-501610, (tbn_crash != tbn_curr));

				if (currRoute.mask == crashRoute.mask &&
					is_ip_net_equal(&currRoute.ip, &crashRoute.ip, crashRoute.mask, af)) {

					if (tbn_crash->active_tdn)
						configure_tun_bit(DEL, tbn_crash, TDN_STATE_CURRENT);

					tbn_crash->possible = NO;

				} else if (tbn_range_allowLarger &&
					currBKey.keyNodes.tsn->breakSmallerPrefixRoutesWithBetterTunMetric) {

					break_loop = YES;

				} else if (
					!(crashBKey.keyNodes.tsn->allowLargerPrefixRoutesWithWorseTunMetric &&
					currBKey.keyNodes.tsn->breakSmallerPrefixRoutesWithBetterTunMetric) &&
					is_ip_net_equal(&currRoute.ip, &crashRoute.ip, crashRoute.mask, af) &&
					((UMETRIC_MAX - ntoh64(crashBKey.beInvTunBitMetric)) >
					(UMETRIC_MAX - ntoh64(currBKey.beInvTunBitMetric)))
					) {

					tbn_curr->possible = NO;
					configure_tun_bit(DEL, tbn_curr, TDN_STATE_CURRENT);
					break_loop = YES;
				}


				dbgf_track(DBGT_INFO, " crash?: pref=%d ipmetric=%d route=%s tunMtc=%s gwId=%s possible=%d dev=%s ",
					ntohl(crashBKey.beIpRule), ntohl(crashBKey.beIpMetric), netAsStr(&crashRoute),
					umetric_to_human(UMETRIC_MAX - ntoh64(crashBKey.beInvTunBitMetric)),
					cryptShaAsString(&tbn_crash->tunBitKey.keyNodes.tnn->tunNetKey.ton->tunOutKey.on->k.nodeId),
					tbn_crash->possible, tbn_crash->active_tdn ? tbn_crash->active_tdn->nameKey.str : "---");

				if (break_loop)
					break;
			}

			if (tbn_curr->possible) {
				dbgf_track(DBGT_INFO, " adding: pref=%d ipmetric=%d route=%s tunMtc=%s gwId=%s possible=%d dev=%s ",
					ntohl(currBKey.beIpRule), ntohl(currBKey.beIpMetric), netAsStr(&currRoute),
					umetric_to_human(UMETRIC_MAX - ntoh64(currBKey.beInvTunBitMetric)),
					cryptShaAsString(&tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tunOutKey.on->k.nodeId),
					tbn_curr->possible, tbn_curr->active_tdn ? tbn_curr->active_tdn->nameKey.str : "---");

				configure_tun_bit(ADD, tbn_curr, TDN_STATE_CURRENT);
			}

			assertion(-501576, (assert_tbn_ton_tdn(isv4, currBKey.keyNodes.tnn->tunNetKey.ton, tbn_curr)));
			assertion(-501577, IMPLIES(tbn_curr,
				tbn_curr->active_tdn == tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnCatchAll[isv4] ||
				tbn_curr->active_tdn == tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnDedicated[isv4]));

		}
	}
	prof_stop();
}

STATIC_FUNC
int create_dsc_tlv_tun6(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	uint16_t m = 0;
	struct tun_in_node *tin;
	struct avl_node *an = NULL;
	struct dsc_msg_tun6 *adv = (struct dsc_msg_tun6 *) tx_iterator_cache_msg_ptr(it);

	assertion(-502041, is_ip_set(&my_primary_ip));

	while ((tin = avl_iterate_item(&tun_in_tree, &an)) && tx_iterator_cache_data_space_pref(it, ((m + 1) * sizeof(struct dsc_msg_tun6)), 0)) {

		if (tin->upIfIdx && tin->tun6Id >= 0) {
			assertion(-501541, (tin->upIfIdx && tin->tun6Id >= 0));
			assertion(-501384, (tin->tun6Id == m));
			adv[m].localIp = tin->remote;
			m++;
		}
	}

	if (m)
		return m * sizeof( struct dsc_msg_tun6);
	else
		return TLV_TX_DATA_IGNORED;
}

STATIC_FUNC
struct tun_out_key set_tun_adv_key(struct orig_node *on, int16_t tun6Id)
{
	struct tun_out_key key;
	memset(&key, 0, sizeof(key));
	key.on = on;
	key.tun6Id = tun6Id;
	return key;
}

STATIC_FUNC
IDM_T terminate_tun_out(struct orig_node *on, struct tun_out_node *tona, struct tun_net_node *tnna)
{
	TRACE_FUNCTION_CALL;
	IDM_T used = NO;

	struct tun_out_node *ton;
	struct tun_out_key key = set_tun_adv_key(on, 0);

	for (key.tun6Id = 0; (ton = (tona ? tona : avl_find_item(&tun_out_tree, &key))); key.tun6Id++) {

		struct tun_out_node *rtun;
		struct tun_net_node *tnn, *tnn1, *tnn2;


		assertion(-501247, (ton));

		dbgf_all(DBGT_INFO, "should remove tunnel_node localIp=%s tun6Id=%d nodeId=%s key=%s (tunnel_out.items=%d, tun->net.items=%d)",
			ip6AsStr(&ton->localIp), ton->tunOutKey.tun6Id, cryptShaAsString(&ton->tunOutKey.on->k.nodeId),
			memAsHexString(&ton->tunOutKey, sizeof(key)), tun_out_tree.items, ton->tun_net_tree.items);

		used |= (ton->tdnDedicated[0] || ton->tdnDedicated[1] || ton->tdnCatchAll[0] || ton->tdnCatchAll[1]);

		while ((tnn = (tnna ? tnna : avl_first_item(&ton->tun_net_tree)))) {

			upd_tun_bit_node(DEL, NULL, tnn);
			//unlink_tun_net(tnn, NULL, NULL);

			tnn1 = avl_remove(&tun_net_tree, &tnn->tunNetKey, -300421);
			tnn2 = avl_remove(&ton->tun_net_tree, &tnn->tunNetKey, -300423);

			assertion_dbg(-501251, (tnn == tnn1 && tnn == tnn2),
				"should remove %s %s but removed %s %s and %s %s !",
				netAsStr(&tnn->tunNetKey.netKey),
				cryptShaAsString(&tnn->tunNetKey.ton->tunOutKey.on->k.nodeId),
				tnn1 ? netAsStr(&tnn1->tunNetKey.netKey) : "---",
				tnn1 ? cryptShaAsString(&tnn1->tunNetKey.ton->tunOutKey.on->k.nodeId) : "---",
				tnn2 ? netAsStr(&tnn2->tunNetKey.netKey) : "---",
				tnn2 ? cryptShaAsString(&tnn2->tunNetKey.ton->tunOutKey.on->k.nodeId) : "---");


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

		CHECK_INTEGRITY();

		if (tona)
			break;
	}

	return used;
}


static uint8_t new_tun6_advs_changed;

STATIC_FUNC
int process_dsc_tlv_tun6(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	int16_t m;

	if (it->dcOp->key == myKey)
		return it->f_msgs_len;


	if (it->op == TLV_OP_DEL) {

		if (terminate_tun_out(it->on, NULL, NULL))
			eval_tun_bit_tree(NULL);

		return it->f_msgs_len;

	} else if (it->op == TLV_OP_NEW) {

		new_tun6_advs_changed = (it->on ? NO : YES);

		if (!new_tun6_advs_changed) {
			if (!is_ip_set(&it->on->primary_ip))
				new_tun6_advs_changed = YES;
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

			if (key.tun6Id != it->f_msgs_len / it->f_handl->min_msg_size)
				new_tun6_advs_changed = YES;
		}


		if (!new_tun6_advs_changed) {
			uint8_t t;
			uint8_t tlv_types[] = {BMX_DSC_TLV_TUN6
				, BMX_DSC_TLV_TUN4IN6_INGRESS, BMX_DSC_TLV_TUN6IN6_INGRESS
				, BMX_DSC_TLV_TUN4IN6_SRC, BMX_DSC_TLV_TUN6IN6_SRC
				//                      ,BMX_DSC_TLV_TUN4IN6_NET_ADV, BMX_DSC_TLV_TUN6IN6_NET_ADV
			};

			for (t = 0; t < sizeof(tlv_types); t++) {

				if (desc_frame_changed(it, tlv_types[t])) {
					new_tun6_advs_changed = YES;
					break;
				}
			}
		}


		if (!new_tun6_advs_changed)
			return it->f_msgs_len;

		if (terminate_tun_out(it->on, NULL, NULL))
			eval_tun_bit_tree(NULL);

		if (!is_ip_set(&it->on->primary_ip))
			return it->f_msgs_len;
	}


	for (m = 0; m < it->f_msgs_fixed; m++) {

		struct dsc_msg_tun6 *adv = &(((struct dsc_msg_tun6 *) (it->f_data))[m]);
		struct tun_out_key key = set_tun_adv_key(it->on, m);

		dbgf_all(DBGT_INFO, "op=%s tunnel_out.items=%d tun_net.items=%d msg=%d/%d localIp=%s nodeId=%s key=%s",
			tlv_op_str(it->op), tun_out_tree.items, tun_net_tree.items, m, it->f_msgs_fixed,
			ip6AsStr(&adv->localIp), nodeIdAsStringFromDescAdv(it->dcOp->desc_frame),
			memAsHexString(&key, sizeof(key)));

		if (it->op == TLV_OP_TEST) {

			struct hna_node *un = NULL;
			struct tun_in_node *tin = NULL;

			if (!is_ip_valid(&adv->localIp, AF_INET6) ||
				is_ip_net_equal(&adv->localIp, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6) ||
				(tin = avl_find_item_by_field(&tun_in_tree, &adv->localIp, tun_in_node, remote)) ||
				(un = find_overlapping_hna(&adv->localIp, 128, it->on))) {
				dbgf_sys(DBGT_ERR, "nodeId=%s %s=%s blocked (by my %s=%s or other's %s with nodeId=%s)",
					nodeIdAsStringFromDescAdv(it->dcOp->desc_frame),
					ARG_TUN_DEV, ip6AsStr(&adv->localIp),
					ARG_TUN_IN, tin ? tin->nameKey.str : DBG_NIL,
					ARG_UHNA, un ? cryptShaAsString(un->on ? &un->on->k.nodeId : &myKey->kHash) : DBG_NIL);

				return TLV_RX_DATA_BLOCKED;
			}

		} else if (it->op == TLV_OP_NEW) {

			assertion(-600005, (!avl_find_item(&tun_out_tree, &key)));

			struct tun_out_node *tun = debugMallocReset(sizeof(struct tun_out_node), -300426);
			tun->tunOutKey = key;
			tun->localIp = adv->localIp;
			tun->remoteIp = it->on->primary_ip;
			tun->ingressPrefix[1] = ZERO_NET4_KEY;
			tun->ingressPrefix[0] = ZERO_NET6_KEY;
			AVL_INIT_TREE(tun->tun_net_tree, struct tun_net_node, tunNetKey);
			avl_insert(&tun_out_tree, tun, -300427);
		}
	}


	return it->f_msgs_len;
}

STATIC_FUNC
int create_dsc_tlv_tunXin6ingress(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	struct tun_in_node *tin;
	struct avl_node *an = NULL;
	uint8_t isSrc4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_INGRESS);
	int32_t pos = 0;
	uint16_t msg_size = isSrc4in6 ? sizeof(struct dsc_msg_tun4in6ingress) : sizeof(struct dsc_msg_tun6in6ingress);


	while ((tin = avl_iterate_item(&tun_in_tree, &an))) {

		if (tin->upIfIdx && tin->tun6Id >= 0 && tin->ingressPrefix46[isSrc4in6].mask) {

			if (pos + msg_size > tx_iterator_cache_data_space_pref(it, 0, 0)) {
				memset(tx_iterator_cache_msg_ptr(it), 0, pos);
				return TLV_TX_DATA_FULL;
			}

			struct dsc_msg_tun6in6ingress *adv =
				(struct dsc_msg_tun6in6ingress *) (tx_iterator_cache_msg_ptr(it) + pos);

			adv->tun6Id = tin->tun6Id;
			adv->ingressPrefixLen = tin->ingressPrefix46[isSrc4in6].mask;

			if (isSrc4in6)
				*((IP4_T*) & adv->ingressPrefix) = ipXto4(tin->ingressPrefix46[1].ip);
			else
				adv->ingressPrefix = tin->ingressPrefix46[0].ip;

			pos += msg_size;
		}
	}
	return pos;
}

STATIC_FUNC
int process_dsc_tlv_tunXin6ingress(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	uint8_t isSrc4 = (it->f_type == BMX_DSC_TLV_TUN4IN6_INGRESS);
	int32_t pos;

	if (it->dcOp->key == myKey)
		return it->f_msgs_len;


	if (it->op == TLV_OP_NEW) {

		//if (!tun6_cache_tlv_sha_if_changed(it))
		if (!new_tun6_advs_changed)
			return it->f_msgs_len;

	}

	if (it->op == TLV_OP_TEST || it->op == TLV_OP_NEW) {
		for (pos = 0; pos < it->f_msgs_len; pos += it->f_handl->min_msg_size) {

			struct dsc_msg_tun6in6ingress *adv =
				(struct dsc_msg_tun6in6ingress *) (it->f_data + pos);
			struct tun_out_key key = set_tun_adv_key(it->on, adv->tun6Id);
			struct tun_out_node *tun = avl_find_item(&tun_out_tree, &key);
			IPX_T prefix = isSrc4 ? ip4ToX(*((IP4_T*) & adv->ingressPrefix)) : adv->ingressPrefix;

			if (it->op == TLV_OP_TEST) {

				assertion(-501265, (!tun || (tun->tunOutKey.on == it->on)));

				if (ip_netmask_validate(&prefix, adv->ingressPrefixLen, (isSrc4 ? AF_INET : AF_INET6), NO) == FAILURE)
					return TLV_RX_DATA_FAILURE;

			} else if (it->op == TLV_OP_NEW) {

				if (tun)
					setNet(&tun->ingressPrefix[isSrc4], (isSrc4 ? AF_INET : AF_INET6), adv->ingressPrefixLen, &prefix);
			}
		}
	}
	return it->f_msgs_len;
}

STATIC_FUNC
int create_dsc_tlv_tunXin6src(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	return TLV_TX_DATA_IGNORED;
}

STATIC_FUNC
int process_dsc_tlv_tunXin6src(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	return it->f_msgs_len;
}

STATIC_FUNC
struct tun_in_node * set_tun6Id(char *tun_name, struct dsc_msg_tun6in6net *adv)
{
	struct tun_in_node * tun = NULL;

	if (tun_name) {
		IFNAME_T nameKey = {.str =
			{0}};
		strcpy(nameKey.str, tun_name);

		if (tun_in_tree.items)
			tun = avl_find_item(&tun_in_tree, nameKey.str);
	} else {
		if (tun_in_tree.items)
			tun = avl_first_item(&tun_in_tree);
	}

	if (tun && tun->upIfIdx) {
		assertion(-501386, (tun->tun6Id >= 0));
		assertion(-501387, (!strncmp(tun->nameKey.str, tun_name_prefix.str, strlen(tun_name_prefix.str))));
		adv->tun6Id = tun->tun6Id;
	} else {
		dbgf_all(DBGT_WARN, "NO matching %s=%s found for %s=%s/%d ! Skiping announcement",
			ARG_TUN_DEV, tun_name, ARG_TUN_IN, ip6AsStr(&adv->network), adv->networkLen);
		return NULL;
	}

	return tun;
}

STATIC_FUNC
uint32_t create_description_tlv_tunXin6_net_adv_msg(struct tx_frame_iterator *it, struct dsc_msg_tun6in6net *adv, uint32_t m, char *tun_name)
{
	TRACE_FUNCTION_CALL;

	IDM_T is4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET) ? YES : NO;
	struct tun_in_node *tun = set_tun6Id(tun_name, adv);


	dbgf_all(DBGT_INFO, "name=%s src=%s dst=%s/%d",
		tun_name, tun ? ip6AsStr(&tun->remote) : "MISSING!", ip6AsStr(&adv->network), adv->networkLen);

	assertion(-501442, (adv->bandwidth.val.u8));
	assertion(-501443, ip_netmask_validate(&adv->network, adv->networkLen, (is4in6 ? AF_INET : AF_INET6), NO /*force*/) == SUCCESS);

	if (tun && tx_iterator_cache_data_space_pref(it, ((m + 1) * it->handl->min_msg_size), 100)) {

		if (is4in6) {
			struct dsc_msg_tun4in6net *msg4 =
				&(((struct dsc_msg_tun4in6net *) tx_iterator_cache_msg_ptr(it))[m]);


			msg4->network = ipXto4(adv->network);
			msg4->networkLen = adv->networkLen;
			msg4->bandwidth = adv->bandwidth;
			msg4->proto_type = adv->proto_type;
			msg4->tun6Id = adv->tun6Id;

		} else {
			((struct dsc_msg_tun6in6net *) tx_iterator_cache_msg_ptr(it))[m] = *adv;
		}

		m++;

	} else if (tun) {
		dbgf_mute(30, DBGL_SYS, DBGT_ERR, "NO description space left for src=%s dst=%s",
			ip6AsStr(&tun->remote), ip6AsStr(&adv->network));
	}

	return m;
}

STATIC_FUNC
int create_dsc_tlv_tunXin6net(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	IDM_T is4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET) ? YES : NO;
	uint8_t af = is4in6 ? AF_INET : AF_INET6;
	uint32_t m = 0, should = 0;
	UMETRIC_T umax = UMETRIC_FM8_MAX;

	struct tun_in_node *tin;
	struct avl_node *an = NULL;
	while ((tin = avl_iterate_item(&tun_in_tree, &an))) {

		if (tin->tun6Id >= 0 && tin->upIfIdx && tin->tunAddr46[is4in6].mask) {

			struct dsc_msg_tun6in6net adv = {
				.network = tin->tunAddr46[is4in6].ip,
				.networkLen = tin->tunAddr46[is4in6].mask,
				.proto_type = tin->advProto,
				.bandwidth = umetric_to_fmu8(&umax)
			};

			ip_netmask_validate(&adv.network, adv.networkLen, af, YES /*force*/);

			m = create_description_tlv_tunXin6_net_adv_msg(it, &adv, m, tin->nameKey.str);
			should++;

			dbgf_track(DBGT_INFO, "%s=%s dst=%s/%d type=%d tun6Id=%d bw=%d",
				ARG_TUN_DEV, tin->nameKey.str, ipXAsStr(af, &adv.network), adv.networkLen,
				adv.proto_type, adv.tun6Id, adv.bandwidth.val.u8);

		}
	}

	struct opt_parent *p = NULL;
	while ((p = list_iterate(&(get_option(NULL, NO, ARG_TUN_IN)->d.parents_instance_list), p))) {

		struct opt_child *c = NULL;
		uint8_t family = 0;
		UMETRIC_T um = DEF_TUN_IN_BW;
		char *tun_name = NULL;
		struct dsc_msg_tun6in6net adv = {.proto_type = DEF_TUN_PROTO_ADV, .bandwidth = umetric_to_fmu8(&um)};

		while ((c = list_iterate(&p->childs_instance_list, c))) {

			if (!strcmp(c->opt->name, ARG_TUN_IN_NET)) {

				str2netw(c->val, &adv.network, NULL, &adv.networkLen, &family, NO);

			} else if (!strcmp(c->opt->name, ARG_TUN_IN_BW)) {

				um = strtoull(c->val, NULL, 10);
				adv.bandwidth = umetric_to_fmu8(&um);

			} else if (!strcmp(c->opt->name, ARG_TUN_DEV)) {

				tun_name = c->val;

			} else if (!strcmp(c->opt->name, ARG_TUN_PROTO_ADV)) {

				adv.proto_type = strtol(c->val, NULL, 10);
			}
		}

		if (family != af)
			continue;

		m = create_description_tlv_tunXin6_net_adv_msg(it, &adv, m, tun_name);
		should++;

		dbgf_track(DBGT_INFO, "%s=%s dst=%s/%d type=%d tun6Id=%d bw=%d",
			ARG_TUN_IN, p->val, ipXAsStr(af, &adv.network), adv.networkLen,
			adv.proto_type, adv.tun6Id, adv.bandwidth.val.u8);
	}


	struct tunXin6_net_adv_list_node *taln = NULL;
	while ((taln = list_iterate(&tunXin6_net_adv_list_list, taln))) {

		struct tunXin6_net_adv_node *tan = NULL;
		for (tan = *taln->adv_list; tan; tan++) {

			if (tan->af == af) {
				m = create_description_tlv_tunXin6_net_adv_msg(it, &tan->adv, m, tan->tunInDev);
				should++;
			}

			if (!tan->more)
				break;
		}
	}

	dbgf((should != m ? DBGL_SYS : DBGL_CHANGES), (should != m ? DBGT_WARN : DBGT_INFO), "created %d of %d %s advs %s",
		m, should, (is4in6 ? "v4" : "v6"), (should != m ? "due to lack of description space!!" : ""));

	return m * (is4in6 ? sizeof(struct dsc_msg_tun4in6net) : sizeof(struct dsc_msg_tun6in6net));
}

STATIC_FUNC
int process_dsc_tlv_tunXin6net(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	uint8_t family = it->f_type == BMX_DSC_TLV_TUN4IN6_NET ? AF_INET : AF_INET6;
	uint16_t msg_size = it->f_handl->min_msg_size;
	int32_t pos = 0, cnt = 0;
	static uint32_t tlv_new_counter = 0;

	uint8_t used = NO;

	if (it->dcOp->key == myKey && it->op != TLV_OP_TEST)
		return it->f_msgs_len;


	tlv_new_counter = (tlv_new_counter + 1) ? (tlv_new_counter + 1) : (tlv_new_counter + 2);

	if (it->op == TLV_OP_NEW) {

		if (!new_tun6_advs_changed && !desc_frame_changed(it, it->f_type))
			return it->f_msgs_len;
	}

	if (it->op == TLV_OP_TEST || it->op == TLV_OP_NEW) {


		for (pos = 0; pos < it->f_msgs_len; pos += msg_size) {

			struct dsc_msg_tun6in6net *adv = (((struct dsc_msg_tun6in6net *) (it->f_data + pos)));
			struct net_key net;
			IPX_T ipx = (family == AF_INET) ? ip4ToX(*((IP4_T*) & adv->network)) : adv->network;
			setNet(&net, family, adv->networkLen, &ipx);

			if (ip_netmask_validate(&net.ip, net.mask, net.af, NO) == FAILURE) {
				dbgf_sys(DBGT_ERR, "network=%s", netAsStr(&net));
				return TLV_RX_DATA_FAILURE;
			}

			if (adv->bandwidth.val.u8 == 0)
				continue;

			if (it->op == TLV_OP_NEW) {

				struct tun_out_key tok = set_tun_adv_key(it->on, adv->tun6Id);
				struct tun_out_node *ton = avl_find_item(&tun_out_tree, &tok);

				if (ton) {

					struct tun_net_key tnk = ZERO_TUN_NET_KEY;
					tnk.ton = ton;
					tnk.netKey = net;
					tnk.bmx7RouteType = adv->proto_type;

					struct tun_net_node *tnn = avl_find_item(&tun_net_tree, &tnk);
					char *what = NULL;

					if (!tnn) {

						tnn = debugMallocReset(sizeof(struct tun_net_node), -300418);
						tnn->tunNetKey = tnk;
						tnn->bandwidth = adv->bandwidth;

						AVL_INIT_TREE(tnn->tun_bit_tree, struct tun_bit_node, tunBitKey.keyNodes);

						avl_insert(&tun_net_tree, tnn, -300419);
						avl_insert(&ton->tun_net_tree, tnn, -300419);

						upd_tun_bit_node(ADD, NULL, tnn);
						used = YES;
						what = "NEW";

					} else if (tnn->bandwidth.val.u8 != adv->bandwidth.val.u8) {

						upd_tun_bit_node(DEL, NULL, tnn);
						tnn->bandwidth = adv->bandwidth;
						upd_tun_bit_node(ADD, NULL, tnn);
						used = YES;
						what = "CHANGED";

					} else {

						what = "OLD";
					}

					dbgf_track(DBGT_INFO, "%s network=%s bw=%d, found for orig=%s tun6Id=%d",
						what, netAsStr(&net), adv->bandwidth.val.u8, cryptShaAsString(&tok.on->k.nodeId), tok.tun6Id);

					assertion(-501578, (tnn->tunNetKey.ton->tunOutKey.on == tok.on));

					tnn->tlv_new_counter = tlv_new_counter;
					cnt++;

				} else {
					dbgf_sys(DBGT_WARN, "no matching tunnel_node found for nodeId=%s tun6Id=%d",
						cryptShaAsString(&tok.on->k.nodeId), tok.tun6Id);
				}
			}
		}
		dbgf_track(DBGT_INFO, "accepted %d/%d %s msgs", cnt, (pos / msg_size), (family == AF_INET ? "v4" : "v6"));
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



	return it->f_msgs_len;
}

struct tun_out_status {
	char* tunOut;
	GLOBAL_ID_T *id;
	GLOBAL_ID_T *longId;
	char *gwName;
	int16_t proto;
	char src[IPX_PREFIX_STR_LEN];
	char net[IPX_PREFIX_STR_LEN];
	uint32_t min;
	uint32_t max;
	uint32_t aOLP;
	uint32_t bOSP;
	uint32_t hyst;
	uint32_t rating;
	UMETRIC_T *minBw;
	uint32_t pref;
	uint32_t table;
	uint32_t ipMtc;
	char *tunIn;
	char *tunName;
	int16_t setProto;
	char tunRoute[IPX_PREFIX_STR_LEN];
	GLOBAL_ID_T *remoteId;
	GLOBAL_ID_T *remoteLongId;
	char* remoteName;
	uint32_t tunId;
	int16_t advProto;
	char advNet[IPX_PREFIX_STR_LEN];
	char srcIngress[IPX_PREFIX_STR_LEN];
	UMETRIC_T advBwVal;
	UMETRIC_T *advBw;
	UMETRIC_T *pathMtc;
	UMETRIC_T tunMtcVal;
	UMETRIC_T *tunMtc;
	IPX_T *localTunIp;
	IPX_T *remoteTunIp;
};

static const struct field_format tun_out_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunOut,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  tun_out_status, id,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, longId,      1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, gwName,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, src,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, proto,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, net,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, min,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, max,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, aOLP,        1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, bOSP,        1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, hyst,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, rating,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, minBw,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, pref,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, table,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, ipMtc,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunIn,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunName,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, setProto,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, tunRoute,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  tun_out_status, remoteId,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, remoteLongId,1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, remoteName,  1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, tunId,       1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, advProto,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, advNet,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, srcIngress,  1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, advBwVal,    1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, advBw,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, pathMtc,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, tunMtcVal,   1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, tunMtc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, localTunIp,  1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, remoteTunIp, 1, FIELD_RELEVANCE_LOW),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, up,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t tun_out_status_creator(struct status_handl *handl, void *data)
{

	struct tun_net_node *tnn;
	struct tun_search_node *tsn;
	struct avl_node *an;

	int32_t status_size = tun_bit_tree.items * sizeof(struct tun_out_status);

	for (an = NULL; (tnn = avl_iterate_item(&tun_net_tree, &an));)
		status_size += (tnn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));

	for (an = NULL; (tsn = avl_iterate_item(&tun_search_tree, &an));)
		status_size += (tsn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));


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

			if (!tbn && tsn && tsn->tun_bit_tree.items)
				continue;

			if (!tbn && tnn && tnn->tun_bit_tree.items)
				continue;

			if (tsn) {
				status->tunOut = tsn->nameKey;
				status->id = &tsn->global_id;
				status->longId = &tsn->global_id;
				status->gwName = strlen(tsn->gwName) ? tsn->gwName : DBG_NIL;
				status->proto = tsn->routeSearchProto;
				status->setProto = tsn->routeSetProto;
				strcpy(status->net, netAsStr(&(tsn->net)));
				strcpy(status->src, tsn->srcRtNet.mask ? netAsStr(&(tsn->srcRtNet)) : DBG_NIL);
				status->min = tsn->netPrefixMin == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMin;
				status->max = tsn->netPrefixMax == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMax;
				status->aOLP = tsn->allowLargerPrefixRoutesWithWorseTunMetric;
				status->bOSP = tsn->breakSmallerPrefixRoutesWithBetterTunMetric;
				status->hyst = tsn->hysteresis;
				status->rating = tsn->rating;
				status->minBw = tsn->minBW ? &tsn->minBW : NULL;
				status->table = tsn->iptable;
				status->pref = tsn->iprule;
				status->ipMtc = tsn->ipmetric;
			} else {
				status->tunOut = DBG_NIL;
				status->gwName = DBG_NIL;
				status->proto = -1;
				status->setProto = -1;
				strcpy(status->net, DBG_NIL);
				strcpy(status->src, DBG_NIL);
			}

			if (tbn) {
				struct net_key tunRoute = tbn->tunBitKey.invRouteKey;
				tunRoute.mask = tbn ? (128 - tunRoute.mask) : 0;
				strcpy(status->tunRoute, netAsStr(&tunRoute));

				status->tunName = (tbn->active_tdn ? tbn->active_tdn->nameKey.str : DBG_NIL);
				status->tunIn = (tbn->active_tdn ? tbn->active_tdn->tunCatchKey.tin->nameKey.str : DBG_NIL);
				status->tunMtcVal = UMETRIC_MAX - ntoh64(tbn->tunBitKey.beInvTunBitMetric);
				status->tunMtc = status->tunMtcVal ? &status->tunMtcVal : NULL;

			} else {
				strcpy(status->tunRoute, DBG_NIL);
				status->tunName = DBG_NIL;
				status->tunIn = DBG_NIL;
			}

			if (tnn) {
				struct tun_out_node *tun = tnn->tunNetKey.ton;

				assertion(-501391, (tun));

				status->remoteName = tun->tunOutKey.on->k.hostname;
				status->remoteId = &tun->tunOutKey.on->k.nodeId;
				status->localTunIp = &tun->localIp;
				status->remoteTunIp = &tun->remoteIp;
				status->tunId = tun->tunOutKey.tun6Id;
				status->advProto = tnn->tunNetKey.bmx7RouteType;
				strcpy(status->advNet, netAsStr(&tnn->tunNetKey.netKey));
				strcpy(status->srcIngress, netAsStr(&tun->ingressPrefix[(tnn->tunNetKey.netKey.af == AF_INET)]));
				status->advBwVal = fmetric_u8_to_umetric(tnn->bandwidth);
				status->advBw = status->advBwVal ? &status->advBwVal : NULL;
				status->pathMtc = tun->tunOutKey.on->curr_rt_link ? &tun->tunOutKey.on->ogmMetric : NULL;
			} else {
				strcpy(status->advNet, DBG_NIL);
				strcpy(status->srcIngress, DBG_NIL);
			}

			status++;
		}
	}

	assertion(-501322, (handl->data + status_size == (uint8_t*) status));

	return status_size;
}

STATIC_FUNC
int32_t opt_tun_in(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

	dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
		patch ? patch->diff : -1, opt_cmd2str[cmd], _save, opt->name, patch ? patch->val : NULL);

	if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

		struct opt_child *c = NULL;


		while ((c = list_iterate(&patch->childs_instance_list, c))) {

			if (!strcmp(c->opt->name, ARG_TUN_IN_NET) && c->val) {

				struct net_key net = ZERO_NET_KEY;

				if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, NO) == FAILURE) {
					dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s", ARG_TUN_IN, patch->val);
					return FAILURE;
				}

				if (cmd == OPT_ADJUST)
					set_opt_child_val(c, netAsStr(&net));

			} else if (!strcmp(c->opt->name, ARG_TUN_IN_BW) && c->val) {

				char *endptr;
				unsigned long long int ull = strtoull(c->val, &endptr, 10);

				if (ull > MAX_TUN_IN_BW || ull < MIN_TUN_IN_BW || *endptr != '\0')
					return FAILURE;

			} else if (!strcmp(c->opt->name, ARG_TUN_DEV) && c->val) {

				if (strlen(c->val) >= NETWORK_NAME_LEN ||
					validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS ||
					strncmp(tun_name_prefix.str, c->val, strlen(tun_name_prefix.str))) {

					dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
						c->val, tun_name_prefix.str);

					return FAILURE;
				}
			}
		}

		if (cmd == OPT_APPLY) {

			if (policy_routing == POLICY_RT_ENABLED && ip_throw_rules_cfg &&
				(patch->diff == ADD || patch->diff == DEL)) {

				// This command may fail unless the following kernel patch is appplied:
				// http://permalink.gmane.org/gmane.linux.network/242277
				// iproute(IP_THROW_MY_TUNS, patch->diff, NO, &net, RT_TABLE_TUN, 0, 0 /*(net.af == AF_INET6 ? dev_lo_idx : 0)*/, 0, 0, 0, NULL);
			}


			my_description_changed = YES;
		}
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

		if (strlen(patch->val) >= NETWORK_NAME_LEN || validate_name_string(patch->val, strlen(patch->val) + 1, NULL) != SUCCESS)
			return FAILURE;

		strcpy(name, patch->val);

		tsn = avl_find_item(&tun_search_tree, name);

		struct net_key net = ZERO_NET_KEY;
		net.af = tsn ? tsn->net.af : 0; // family of ARG_TUN_SEARCH_NETWORK and ARG_TUN_SEARCH_SRC must be the same!!!

		if (cmd == OPT_APPLY) {

			//unlink_tun_net(NULL, NULL, NULL);

			if (!tsn && patch->diff != DEL) {
				tsn = debugMallocReset(sizeof(struct tun_search_node), -300400);
				AVL_INIT_TREE(tsn->tun_bit_tree, struct tun_bit_node, tunBitKey.keyNodes);
				strcpy(tsn->nameKey, name);
				avl_insert(&tun_search_tree, tsn, -300433);
				tsn->routeSearchProto = DEF_TUN_PROTO_SEARCH;
				tsn->routeSetProto = DEF_TUN_PROTO_SET;
				tsn->exportDistance = DEF_EXPORT_DISTANCE;
				tsn->exportOnly = DEF_EXPORT_ONLY;
				tsn->ipmetric = DEF_TUN_OUT_IPMETRIC;
				tsn->iptable = DEF_TUN_OUT_TABLE;
				tsn->iprule = DEF_TUN_OUT_RULE;
				tsn->hysteresis = DEF_TUN_OUT_HYSTERESIS;
				UMETRIC_T ull = DEF_TUN_OUT_MIN_BW;
				tsn->minBW = fmetric_u8_to_umetric(umetric_to_fmu8(&ull));
				tsn->rating = DEF_TUN_OUT_RATING;
				tsn->netPrefixMin = DEF_TUN_OUT_PREFIX_MIN;
				tsn->netPrefixMax = DEF_TUN_OUT_PREFIX_MAX;
				tsn->allowLargerPrefixRoutesWithWorseTunMetric = DEF_TUN_OUT_OVLP_ALLOW;
				tsn->breakSmallerPrefixRoutesWithBetterTunMetric = DEF_TUN_OUT_OVLP_BREAK;
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
						tsn->srcRtNet.af = net.af;
					}

				} else if (cmd == OPT_APPLY && tsn) {
					setNet(&tsn->net, net.af, 0, NULL);
				}

/*
							} else if (!strcmp(c->opt->name, ARG_TUN_DEV)) {

								if (c->val && (strlen(c->val) >= NETWORK_NAME_LEN ||
									validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS ||
									strncmp(tun_name_prefix.str, c->val, strlen(tun_name_prefix.str)))) {

									dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
										c->val, tun_name_prefix.str);

									return FAILURE;

								} else if (cmd == OPT_APPLY && tsn) {

									memset(&tsn->tunName, 0, sizeof(IFNAME_T));

									if (c->val)
										strcpy(tsn->tunName.str, c->val);
								}
				 */

			} else if (!strcmp(c->opt->name, ARG_TUN_OUT_SRCRT)) {

				if (c->val) {

					if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, NO) == FAILURE)
						return FAILURE;

					set_opt_child_val(c, netAsStr(&net));

					if (cmd == OPT_APPLY && tsn) {
						tsn->srcRtNet = net;
						tsn->net.af = net.af;
					}

				} else if (cmd == OPT_APPLY && tsn) {
					setNet(&tsn->srcRtNet, net.af, 0, NULL);
				}


			} else if (!strcmp(c->opt->name, ARG_TUN_OUT_GWNAME)) {

				if (c->val) {

					if (strlen(c->val) > MAX_HOSTNAME_LEN ||
						validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS)
						return FAILURE;

					if (cmd == OPT_APPLY && tsn) {
						memset(tsn->gwName, 0, sizeof(tsn->gwName));
						strcpy(tsn->gwName, c->val);
					}

				} else if (cmd == OPT_APPLY && tsn) {
					memset(tsn->gwName, 0, sizeof(tsn->gwName));
				}

			} else if (!strcmp(c->opt->name, ARG_TUN_OUT_PKID)) {

				GLOBAL_ID_T pkid = {.h.u32 =
					{0}};

				if (c->val) {

					if (hexStrToMem(c->val, pkid.h.u8, sizeof(pkid)) == FAILURE)
						return FAILURE;


					set_opt_child_val(c, memAsHexString(&pkid, sizeof(pkid)));

					if (cmd == OPT_APPLY && tsn)
						memcpy(&tsn->global_id, &pkid, sizeof(pkid));

				} else if (cmd == OPT_APPLY && tsn) {
					memset(&tsn->global_id, 0, sizeof(pkid));
				}

			} else if (!strcmp(c->opt->name, ARG_TUN_OUT_MIN_BW)) {

				if (c->val) {

					char *endptr;
					UMETRIC_T ull = strtoull(c->val, &endptr, 10);

					if (ull > MAX_TUN_IN_BW || ull < MIN_TUN_IN_BW || *endptr != '\0')
						return FAILURE;

					if (cmd == OPT_APPLY && tsn)
						tsn->minBW = fmetric_u8_to_umetric(umetric_to_fmu8(&ull));

				} else if (cmd == OPT_APPLY && tsn) {
					UMETRIC_T ull = DEF_TUN_OUT_MIN_BW;
					tsn->minBW = fmetric_u8_to_umetric(umetric_to_fmu8(&ull));
				}

			} else if (!strcmp(c->opt->name, ARG_TUN_OUT_TRULE)) {

				long int iptable = DEF_TUN_OUT_TABLE;
				long int iprule = DEF_TUN_OUT_RULE;

				if (c->val) {
					char *slashptr = strchr(c->val, '/');
					*slashptr = '\0';
					iprule = strtol(c->val, NULL, 10);
					iptable = strtol(slashptr + 1, NULL, 10);
					*slashptr = '/';

					if (iptable < MIN_TUN_OUT_TABLE || iptable > MAX_TUN_OUT_TABLE ||
						iprule < MIN_TUN_OUT_RULE || iprule > MAX_TUN_OUT_RULE) {
						dbgf_cn(cn, DBGL_SYS, DBGT_ERR,
							"Invalid %s=%s /%s=%s ! Format must be %s with ranges [%d..%d]>/[%d..%d]",
							opt->name, tsn->nameKey, c->opt->name, c->val, FORM_TUN_OUT_TRULE,
							MIN_TUN_OUT_RULE, MAX_TUN_OUT_RULE, MIN_TUN_OUT_TABLE, MAX_TUN_OUT_TABLE);
						return FAILURE;
					}

					if (iprule <= ip_prio_hna_cfg || iptable == ip_table_hna_cfg) {
						dbgf_cn(cn, DBGL_SYS, DBGT_ERR,
							"Invalid %s=%s /%s=%s ! Format MUST be %s, PREF MUST be greater %s=%d and TABLE MUST NOT be %s=%d!",
							opt->name, tsn->nameKey, c->opt->name, c->val, FORM_TUN_OUT_TRULE,
							ARG_IP_RULE_HNA, ip_prio_hna_cfg, ARG_IP_TABLE_HNA, ip_table_hna_cfg);
						return FAILURE;
					}
				}

				struct avl_node *an = NULL;
				struct tun_search_node *tsnCrash;
				while ((tsnCrash = avl_iterate_item(&tun_search_tree, &an))) {
					if (tsnCrash != tsn && (
						(tsnCrash->iptable == (uint32_t) iptable && tsnCrash->iprule != (uint32_t) iprule) ||
						(tsnCrash->iptable != (uint32_t) iptable && tsnCrash->iprule == (uint32_t) iprule))) {
						dbgf_cn(cn, DBGL_SYS, DBGT_ERR,
							"%s=%s /%s=%s conflicts with %s=%s /%s=%d/%d !"
							"Each iptable value can be combined only with one ip rule preference ",
							opt->name, tsn->nameKey, c->opt->name, c->val,
							opt->name, tsnCrash->nameKey, c->opt->name, tsnCrash->iptable, tsnCrash->iprule);
						return FAILURE;
					}
				}

				if (cmd == OPT_APPLY) {

					if (!initializing)
						iproute(IP_RULE_DEFAULT, DEL, NO, (tsn->net.af == AF_INET ? &ZERO_NET4_KEY : &ZERO_NET6_KEY), tsn->iptable, tsn->iprule, 0, 0, 0, 0, NULL);

					tsn->iptable = iptable;
					tsn->iprule = iprule;

					if (!initializing)
						iproute(IP_RULE_DEFAULT, ADD, NO, (tsn->net.af == AF_INET ? &ZERO_NET4_KEY : &ZERO_NET6_KEY), tsn->iptable, tsn->iprule, 0, 0, 0, 0, NULL);
				}

			} else if (cmd == OPT_APPLY && tsn) {

				if (!strcmp(c->opt->name, ARG_TUN_OUT_PREFIX_MIN)) {
					tsn->netPrefixMin = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_PREFIX_MIN;

				} else if (!strcmp(c->opt->name, ARG_TUN_OUT_PREFIX_MAX)) {
					tsn->netPrefixMax = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_PREFIX_MAX;

				} else if (!strcmp(c->opt->name, ARG_TUN_OUT_OVLP_ALLOW)) {
					tsn->allowLargerPrefixRoutesWithWorseTunMetric = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_OVLP_ALLOW;

				} else if (!strcmp(c->opt->name, ARG_TUN_OUT_OVLP_BREAK)) {
					tsn->breakSmallerPrefixRoutesWithBetterTunMetric = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_OVLP_BREAK;

				} else if (!strcmp(c->opt->name, ARG_TUN_OUT_IPMETRIC)) {
					tsn->ipmetric = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_IPMETRIC;

				} else if (!strcmp(c->opt->name, ARG_TUN_OUT_TYPE)) {
					tsn->srcType = c->val ? strtol(c->val, NULL, 10) : 0;

				} else if (!strcmp(c->opt->name, ARG_TUN_OUT_HYSTERESIS)) {
					tsn->hysteresis = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_HYSTERESIS;

				} else if (!strcmp(c->opt->name, ARG_TUN_OUT_RATING)) {
					tsn->rating = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_OUT_RATING;

				} else if (!strcmp(c->opt->name, ARG_EXPORT_DISTANCE)) {
					tsn->exportDistance = c->val ? strtol(c->val, NULL, 10) : DEF_EXPORT_DISTANCE;

				} else if (!strcmp(c->opt->name, ARG_EXPORT_ONLY)) {
					tsn->exportOnly = c->val ? strtol(c->val, NULL, 10) : DEF_EXPORT_ONLY;

				} else if (!strcmp(c->opt->name, ARG_TUN_PROTO_SEARCH)) {
					tsn->routeSearchProto = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_PROTO_SEARCH;

				} else if (!strcmp(c->opt->name, ARG_TUN_PROTO_SET)) {
					tsn->routeSetProto = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_PROTO_SET;

				} else if (!strcmp(c->opt->name, ARG_EXPORT_ONLY)) {
					tsn->exportOnly = c->val ? strtol(c->val, NULL, 10) : DEF_EXPORT_ONLY;

				}
			}
		}
	}

	if (cmd == OPT_APPLY) {

		assertion(-501394, (tsn));

		if (patch->diff == DEL) {
			iproute(IP_RULE_DEFAULT, DEL, NO, (tsn->net.af == AF_INET ? &ZERO_NET4_KEY : &ZERO_NET6_KEY), tsn->iptable, tsn->iprule, 0, 0, 0, 0, NULL);
			avl_remove(&tun_search_tree, &tsn->nameKey, -300402);
			debugFree(tsn, -300403);

		} else {
			upd_tun_bit_node(ADD, tsn, NULL);
		}

		eval_tun_bit_tree(NULL);

		//set_tun_net(NULL);
		//my_description_changed = YES;
	}

	if (cmd == OPT_SET_POST && initializing) {
		struct avl_node *an;
		for (an = NULL; (tsn = avl_iterate_item(&tun_search_tree, &an));) {
			ip_flush_routes(tsn->net.af, tsn->iptable);
			ip_flush_rules(tsn->net.af, tsn->iptable);
		}
		for (an = NULL; (tsn = avl_iterate_item(&tun_search_tree, &an));) {
			iproute(IP_RULE_DEFAULT, ADD, NO, (tsn->net.af == AF_INET ? &ZERO_NET4_KEY : &ZERO_NET6_KEY), tsn->iptable, tsn->iprule, 0, 0, 0, 0, NULL);
		}
	}


	if (cmd == OPT_UNREGISTER) {

		while ((tsn = avl_first_item(&tun_search_tree))) {

			assertion(-501242, (!tsn->tun_bit_tree.items));

			//should be flushed by ip_flush_tracked()
			//iproute(IP_RULE_DEFAULT, DEL, NO, (tsn->net.af==AF_INET?&ZERO_NET4_KEY:&ZERO_NET6_KEY), tsn->iptable, tsn->iprule, 0, 0, 0, 0, NULL);

			avl_remove(&tun_search_tree, &tsn->nameKey, -300404);
			debugFree(tsn, -300405);
		}
	}

	return SUCCESS;
}

STATIC_FUNC
void purge_tunCatchTree(void)
{
	struct tun_dev_node *tdnUP;
	while ((tdnUP = avl_first_item(&tun_catch_tree))) {
		assertion(-501543, (!tdnUP->tun_bit_tree[0].items && !tdnUP->tun_bit_tree[1].items));
		avl_remove(&tun_catch_tree, &tdnUP->tunCatchKey, -300546);
		avl_remove(&tdnUP->tunCatchKey.tin->tun_dev_tree, &tdnUP->nameKey, -300559);
		kernel_dev_tun_del(tdnUP->nameKey.str, tdnUP->tunCatch_fd);
		debugFree(tdnUP, -300547);
	}
}

STATIC_FUNC
int32_t opt_tun_in_dev(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;
	struct tun_in_node *tin = NULL;

	if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

		struct opt_child *c = NULL;
		char name[NETWORK_NAME_LEN] = {0};

		dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
			patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

		if (strlen(patch->val) >= NETWORK_NAME_LEN - strlen(tun_name_prefix.str) ||
			validate_name_string(patch->val, strlen(patch->val) + 1, NULL) != SUCCESS) {

			dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s %s", patch->val, tun_name_prefix.str);

			return FAILURE;
		}

		sprintf(name, "%s%s", tun_name_prefix.str, patch->val);

		tin = avl_find_item(&tun_in_tree, name);

		if (!tin && tun_in_tree.items >= MAX_AUTO_TUNID_OCT)
			return FAILURE;

		if (cmd == OPT_APPLY) {

			if (tin)
				configure_tunnel_in(DEL, tin, -1);

			if (tin && patch->diff == DEL) {

				avl_remove(&tun_in_tree, name, -300467);
				debugFree(tin, -300468);
				tin = NULL;

			} else if (!tin && patch->diff != DEL) {
				tin = debugMallocReset(sizeof(struct tun_in_node), -300469);
				strcpy(tin->nameKey.str, name);
				tin->tun6Id = -1;
				tin->remote = ZERO_IP;
				tin->tunAddr46[1] = ZERO_NET4_KEY;
				tin->tunAddr46[0] = ZERO_NET6_KEY;
				tin->remote_manual = 0;
				tin->advProto = DEF_TUN_PROTO_ADV;
				AVL_INIT_TREE(tin->tun_dev_tree, struct tun_dev_node, nameKey);
				avl_insert(&tun_in_tree, tin, -300470);
			}
		}

		while ((c = list_iterate(&patch->childs_instance_list, c))) {

			if (!strcmp(c->opt->name, ARG_TUN_DEV_ADDR4) || !strcmp(c->opt->name, ARG_TUN_DEV_ADDR6)) {

				struct net_key net = ZERO_NET_KEY;
				net.af = !strcmp(c->opt->name, ARG_TUN_DEV_ADDR4) ? AF_INET : AF_INET6;
				struct hna_node *hna;

				if (!c->val) {

					net = ZERO_NET_KEY;

				} else if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, YES) == FAILURE ||
					!is_ip_valid(&net.ip, net.af)) {

					return FAILURE;

				} else if (net.mask < (net.af == AF_INET ? HNA4_PREFIXLEN_MIN : HNA6_PREFIXLEN_MIN)) {

					return FAILURE;

				} else if (net.af == AF_CFG && (hna = find_overlapping_hna(&net.ip, net.mask, NULL))) {

					dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s /%s=%s already used by nodeId=%s hna=%s",
						opt->name, patch->val, c->opt->name, netAsStr(&net),
						hna->on ? cryptShaAsString(&hna->on->k.nodeId) : "mySelf", netAsStr(&hna->key));

					return FAILURE;

				} else if (cmd == OPT_ADJUST) {

					set_opt_child_val(c, netAsStr(&net));
				}

				if (cmd == OPT_APPLY && tin)
					tin->tunAddr46[!strcmp(c->opt->name, ARG_TUN_DEV_ADDR4)] = net;


			} else if (!strcmp(c->opt->name, ARG_TUN_DEV_REMOTE)) {

				struct net_key p6 = ZERO_NET6_KEY;

				if (c->val) {

					struct hna_node *un_remote = NULL;

					if (str2netw(c->val, &p6.ip, cn, NULL, &p6.af, YES) == FAILURE ||
						!is_ip_valid(&p6.ip, p6.af) ||
						(un_remote = find_overlapping_hna(&p6.ip, 128, NULL))) {

						dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s=%s or blocked by nodeId=%s",
							ARG_TUN_DEV, patch->val, ARG_TUN_DEV_REMOTE, c->val,
							(un_remote && un_remote->on) ? cryptShaAsString(&un_remote->on->k.nodeId) : DBG_NIL);

						return FAILURE;
					}

					set_opt_child_val(c, netAsStr(&p6));
				}

				if (cmd == OPT_APPLY && tin) {
					tin->remote = p6.ip;
					tin->remote_manual = c->val ? 1 : 0;
				}


			} else if (!strcmp(c->opt->name, ARG_TUN_DEV_SRC4_TYPE) || !strcmp(c->opt->name, ARG_TUN_DEV_SRC6_TYPE)) {

				if (cmd == OPT_APPLY && tin)
					tin->srcType46[!strcmp(c->opt->name, ARG_TUN_DEV_SRC4_TYPE)] = c->val ? strtol(c->val, NULL, 10) : 0;

			} else if (!strcmp(c->opt->name, ARG_TUN_DEV_INGRESS4) || !strcmp(c->opt->name, ARG_TUN_DEV_INGRESS6)) {

				IDM_T isv4 = !strcmp(c->opt->name, ARG_TUN_DEV_INGRESS4);
				struct net_key net = isv4 ? ZERO_NET4_KEY : ZERO_NET6_KEY;

				if (c->val) {

					if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, NO) == FAILURE ||
						!is_ip_valid(&net.ip, net.af)) {

						dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s",
							isv4 ? ARG_TUN_DEV_INGRESS4 : ARG_TUN_DEV_INGRESS4, patch->val, c->val);
						return FAILURE;
					}
				}

				if (cmd == OPT_APPLY && tin)
					tin->ingressPrefix46[isv4] = net;


			} else if (!strcmp(c->opt->name, ARG_TUN_DEV_SRC4_MIN) || !strcmp(c->opt->name, ARG_TUN_DEV_SRC6_MIN)) {

				if (cmd == OPT_APPLY && tin)
					tin->srcPrefixMin46[!strcmp(c->opt->name, ARG_TUN_DEV_SRC4_MIN)] = c->val ? strtol(c->val, NULL, 10) : 0;

			} else if (!strcmp(c->opt->name, ARG_TUN_PROTO_ADV)) {

				if (cmd == OPT_APPLY && tin)
					tin->advProto = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_PROTO_ADV;

			}
		}
	}


	if (cmd == OPT_APPLY) {

		upd_tun_bit_node(DEL, NULL, NULL);
		purge_tunCatchTree();
		reconfigure_tun_ins();

		upd_tun_bit_node(ADD, NULL, NULL);
		eval_tun_bit_tree(NULL);

	}

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_tun_name_prefix(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;
	if (cmd == OPT_CHECK) {

		if (strlen(patch->val) > MAX_TUN_NAME_PREFIX_LEN ||
			validate_name_string(patch->val, strlen(patch->val) + 1, NULL))
			return FAILURE;

		strcpy(tun_name_prefix.str, patch->val); //MUST be configured before opt_tunnel_in is checked

	} else if (cmd == OPT_SET_POST && initializing) {

		struct avl_node *an = NULL;
		struct if_link_node *iln = NULL;

		while ((iln = avl_iterate_item(&if_link_tree, &an))) {

			if (!strncmp(tun_name_prefix.str, iln->name.str, strlen(tun_name_prefix.str))) {
				dbgf_sys(DBGT_WARN, "removing orphan tunnel dev=%s", iln->name.str);
				if (kernel_tun_del(iln->name.str) != SUCCESS) {
					IDM_T result = kernel_link_del(iln->name.str);
					assertion(-501493, (result == SUCCESS));
				}
			}
		}
	}


	return SUCCESS;
}

STATIC_FUNC
int32_t opt_tun_state_dedicated_to(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

	if (cmd == OPT_APPLY) {

		static int32_t prev_to = DEF_TUN_OUT_TO;
		prev_to = tun_dedicated_to;
		tun_dedicated_to = patch->diff != DEL ? strtol(patch->val, NULL, 10) : DEF_TUN_OUT_TO;

		struct tun_out_node *ton;
		struct avl_node *an = NULL;

		while ((ton = avl_iterate_item(&tun_out_tree, &an))) {
			uint8_t isv4;
			struct tun_dev_node *tdnUP;

			for (isv4 = 0; isv4 <= 1; isv4++) {

				if ((tdnUP = ton->tdnCatchAll[isv4])) {

					assertion(-501544, (tdnUP->tunCatch_fd > 0));

					if (tun_dedicated_to == 0) {
						tun_out_state_set(ton, TDN_STATE_DEDICATED);
					} else if (tun_dedicated_to > 0) {

					}
				}

				if ((tdnUP = ton->tdnDedicated[isv4])) {

					assertion(-501545, (tdnUP->tunCatch_fd == 0));

					if (tun_dedicated_to > 0) {
						tun_out_state_set(ton, TDN_STATE_CATCHALL);
					} else if (tun_dedicated_to == 0) {
						if (prev_to > 0)
							task_remove(tun_out_state_catchAll, ton);
					}
				}
			}
		}

		if (prev_to > 0 && tun_dedicated_to == 0)
			purge_tunCatchTree();
	}
	return SUCCESS;
}

STATIC_FUNC
int32_t opt_tun_out_mtu(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

	if (cmd == OPT_APPLY) {

		tun_out_mtu = patch->diff != DEL ? strtol(patch->val, NULL, 10) : DEF_TUN_OUT_MTU;

		struct tun_out_node *ton;
		struct avl_node *an = NULL;

		while ((ton = avl_iterate_item(&tun_out_tree, &an))) {
			uint8_t isv4;
			for (isv4 = 0; isv4 <= 1; isv4++) {
				struct tun_dev_node *tdnUP = ton->tdnDedicated[isv4];
				if (tdnUP && tun_out_mtu != tdnUP->curr_mtu)
					tdnUP->curr_mtu = set_tun_out_mtu(tdnUP->nameKey.str, tdnUP->orig_mtu, DEF_TUN_OUT_MTU, tun_out_mtu);
			}
		}
	}
	return SUCCESS;
}


/*
STATIC_FUNC
int32_t opt_tun_address(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

        struct net_key net = !strcmp(opt->name, ARG_TUN4_ADDRESS) ? ZERO_NET4_KEY : ZERO_NET6_KEY;
	struct hna_node *hna;

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

                if (AF_CFG != AF_INET6) {

			return FAILURE;

                } else if (patch->diff == DEL) {

                        net = ZERO_NET_KEY;

                } else if (str2netw(patch->val, &net.ip, cn, &net.mask, &net.af, YES) == FAILURE ||
			!is_ip_valid(&net.ip, net.af)) {

                        return FAILURE;

                } else if (net.mask < (net.af == AF_INET ? HNA4_PREFIXLEN_MIN : HNA6_PREFIXLEN_MIN)) {

                        return FAILURE;

                } else if ((hna = find_overlapping_hna(&net.ip, net.mask, myKey->orig))) {

			dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s already used by orig=%s hna=%s",
				opt->name, netAsStr(&net), globalIdAsString(&hna->on->global_id), netAsStr(&hna->key));

			return FAILURE;

		} else if (cmd == OPT_ADJUST ) {

			set_opt_parent_val(patch, netAsStr(&net));
		}

                if (cmd == OPT_APPLY) {

			*((!strcmp(opt->name, ARG_TUN4_ADDRESS))?&tun4_address:&tun6_address) = net;

			my_description_changed = YES;
			upd_tun_bit_node(DEL, NULL, NULL);
			upd_tun_bit_node(ADD, NULL, NULL);
			eval_tun_bit_tree(NULL);
		}
	}

        return SUCCESS;
}
*/








static struct opt_type tun_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	{ODI,0,ARG_TUN_NAME_PREFIX,    	0,8,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,	0,DEF_TUN_NAME_PREFIX,	opt_tun_name_prefix,
			ARG_NAME_FORM, "specify first letters of local tunnel-interface names"},


        {ODI,0,ARG_TUN_PROACTIVE_ROUTES,0,9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &tun_proactive_routes,MIN_TUN_PROACTIVE_ROUTES,MAX_TUN_PROACTIVE_ROUTES,DEF_TUN_PROACTIVE_ROUTES,0,   0,
			ARG_VALUE_FORM,	HLP_TUN_PROACTIVE_ROUTES}
        ,
	{ODI,0,ARG_TUN_OUT_TIMEOUT,     0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,              MIN_TUN_OUT_TO,MAX_TUN_OUT_TO,DEF_TUN_OUT_TO,0, opt_tun_state_dedicated_to,
			ARG_VALUE_FORM, "timeout for reactive (dedicated) outgoing tunnels"},

	{ODI,0,ARG_TUN_OUT_MTU,         0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,              MIN_TUN_OUT_MTU,MAX_TUN_OUT_MTU,DEF_TUN_OUT_MTU,0, opt_tun_out_mtu,
			ARG_VALUE_FORM, "MTU of outgoing tunnels"},



//order must be after ARG_HOSTNAME (which initializes self via init_self(), called from opt_hostname):
	{ODI,0,ARG_TUN_DEV, 	        0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_in_dev,
                ARG_NAME_FORM, "define incoming ipip tunnel interface name (prefix is " ARG_TUN_NAME_PREFIX "=" DEF_TUN_NAME_PREFIX ") and sub criteria\n"
	"        eg: " ARG_TUN_DEV "=Default (resulting interface name would be: " DEF_TUN_NAME_PREFIX "Default )\n"
	"        WARNING: This creates a general ipip tunnel device allowing to tunnel arbitrary IP packets to this node!\n"
	"        Use firewall rules to filter deprecated packets!"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_ADDR4,  0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_ADDR_FORM,HLP_TUN_DEV_ADDR4},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_ADDR6,  0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_ADDR_FORM,HLP_TUN_DEV_ADDR6},
#ifndef LESS_OPTIONS
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_REMOTE,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,	        0,              0,0,            opt_tun_in_dev,
			ARG_IP_FORM,	"remote dummy ip of tunnel interface"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_INGRESS4,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_NETW_FORM,"IPv4 source prefix (ingress filter)"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_INGRESS6,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_NETW_FORM,"IPv6 source prefix (ingress filter)"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_SRC4_TYPE,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,    opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv4 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_SRC4_MIN,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        32,             0,0,            opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv4 source prefix len usable for address auto configuration (0 = NO autoconfig)"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_SRC6_TYPE,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,    opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv6 source address type (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_SRC6_MIN,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        128,            0,0,            opt_tun_in_dev,
			ARG_VALUE_FORM, "IPv6 source prefix len usable for address auto configuration (0 = NO autoconfig)"},
	{ODI,ARG_TUN_DEV,ARG_TUN_PROTO_ADV, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0, MIN_TUN_PROTO_ADV,MAX_TUN_PROTO_ADV,DEF_TUN_PROTO_ADV,0,     opt_tun_in_dev,
			ARG_VALUE_FORM, HLP_TUN_PROTO_ADV},

#endif
        {ODI,0,ARG_TUN_IN,	 	0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,	        opt_tun_in,
			ARG_NAME_FORM,"arbitrary but unique name for tunnel network to be announced with given sub criterias"},
	{ODI,ARG_TUN_IN,ARG_TUN_IN_NET,'n',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,               0,              0,              0,0,            opt_tun_in,
			ARG_ADDR_FORM,"network to be offered via incoming tunnel (mandatory)"},
	{ODI,ARG_TUN_IN,ARG_TUN_IN_BW, 'b',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,		0,	        0,              0,0,            opt_tun_in,
			ARG_VALUE_FORM,	HLP_TUN_IN_BW},
	{ODI,ARG_TUN_IN,ARG_TUN_DEV,    0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,		0,              0,              0,0,            opt_tun_in,
			ARG_NAME_FORM,	HLP_TUN_IN_DEV},
	{ODI,ARG_TUN_IN,ARG_TUN_PROTO_ADV, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0, MIN_TUN_PROTO_ADV,MAX_TUN_PROTO_ADV,DEF_TUN_PROTO_ADV,0,      opt_tun_in,
			ARG_VALUE_FORM, HLP_TUN_PROTO_ADV},

	{ODI,0,ARG_TUN_OUT,     	0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_search,
		        ARG_NAME_FORM,  "arbitrary but unique name for network which should be reached via tunnel depending on sub criterias"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_NET,'n',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,               0,              0,              0,0,            opt_tun_search,
			ARG_NETW_FORM,"network to be searched via outgoing tunnel (mandatory)"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_SRCRT,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,              0,              0,0,            opt_tun_search,
			ARG_NETW_FORM,"additional source-address range to-be routed via tunnel"},
	{ODI,ARG_TUN_OUT,ARG_TUN_PROTO_SEARCH,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0, MIN_TUN_PROTO_SEARCH,MAX_TUN_PROTO_SEARCH,DEF_TUN_PROTO_SEARCH,0,opt_tun_search,
			ARG_VALUE_FORM, HLP_TUN_PROTO_SEARCH},
	{ODI,ARG_TUN_OUT,ARG_TUN_PROTO_SET,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0, MIN_TUN_PROTO_SET,MAX_TUN_PROTO_SET,DEF_TUN_PROTO_SET,0,opt_tun_search,
			ARG_VALUE_FORM, HLP_TUN_PROTO_SET},
#ifndef LESS_OPTIONS
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_TYPE,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,      TUN_SRC_TYPE_MIN,TUN_SRC_TYPE_MAX,TUN_SRC_TYPE_UNDEF,0,   opt_tun_search,
			ARG_VALUE_FORM, "tunnel ip allocation mechanism (0 = static/global, 1 = static, 2 = auto, 3 = AHCP)"},
#endif
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_GWNAME,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,              0,              0,0,            opt_tun_search,
			ARG_NAME_FORM,  "hostname of remote tunnel endpoint"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_PREFIX_MIN,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_PREFIX,MAX_TUN_OUT_PREFIX,DEF_TUN_OUT_PREFIX_MIN,0,opt_tun_search,
			ARG_VALUE_FORM, "minumum prefix len for accepting advertised tunnel network, 129 = network prefix len"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_PREFIX_MAX,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_PREFIX,MAX_TUN_OUT_PREFIX,DEF_TUN_OUT_PREFIX_MAX,0,opt_tun_search,
			ARG_VALUE_FORM, "maximum prefix len for accepting advertised tunnel network, 129 = network prefix len"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_OVLP_ALLOW,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_OVLP,MAX_TUN_OUT_OVLP,DEF_TUN_OUT_OVLP_ALLOW,0,opt_tun_search,
			ARG_VALUE_FORM, "allow overlapping other tunRoutes with worse tunMetric but larger prefix length"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_OVLP_BREAK,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_OVLP,MAX_TUN_OUT_OVLP,DEF_TUN_OUT_OVLP_BREAK,0,opt_tun_search,
			ARG_VALUE_FORM, "let this tunRoute break other tunRoutes with better tunMetric but smaller prefix length"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_PKID,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,              0,              0,0,            opt_tun_search,
			ARG_SHA2_FORM,  "pkid of remote tunnel endpoint"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_HYSTERESIS,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_HYSTERESIS,MAX_TUN_OUT_HYSTERESIS,DEF_TUN_OUT_HYSTERESIS,0,opt_tun_search,
			ARG_VALUE_FORM, "specify in percent how much the metric to an alternative GW must be better than to curr GW"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_RATING,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,       MIN_TUN_OUT_RATING,MAX_TUN_OUT_RATING,DEF_TUN_OUT_RATING,0,opt_tun_search,
			ARG_VALUE_FORM, "specify in percent a metric rating for GWs matching this tunOut spec when compared with other tunOut specs for same network"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_MIN_BW, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,	        0,              0,0,            opt_tun_search,
			ARG_VALUE_FORM,	"min bandwidth as bits/sec beyond which GW's advertised bandwidth is ignored  default: 100000  range: [36 ... 128849018880]"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_IPMETRIC,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_OUT_IPMETRIC,MAX_TUN_OUT_IPMETRIC,DEF_TUN_OUT_IPMETRIC,0,opt_tun_search,
			ARG_VALUE_FORM, "ip metric for local routing table entries"},
	{ODI,ARG_TUN_OUT,ARG_TUN_OUT_TRULE,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,	          0,              0,         0,DEF_TUN_OUT_TRULE,opt_tun_search,
			FORM_TUN_OUT_TRULE, "ip rules tabel and preference to maintain matching tunnels"},
	{ODI,ARG_TUN_OUT,ARG_EXPORT_ONLY,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,            MIN_EXPORT_ONLY,MAX_EXPORT_ONLY,DEF_EXPORT_ONLY,0,opt_tun_search,
			ARG_VALUE_FORM,"do not add route to bmx7 tun table!  Requires quagga plugin!"},
	{ODI,ARG_TUN_OUT,ARG_EXPORT_DISTANCE,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_EXPORT_DISTANCE,MAX_EXPORT_DISTANCE,DEF_EXPORT_DISTANCE,0,opt_tun_search,
			ARG_VALUE_FORM,	"export distance to network (256 == no export). Requires quagga plugin!"},

	{ODI,0,ARG_TUNS,	        0,9,2,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show announced and used tunnels and related networks"}

};


STATIC_FUNC
void tun_dev_event_hook(int32_t cb_id, void* unused)
{
        TRACE_FUNCTION_CALL;

	IDM_T TODO_CheckIfThisFunctionIsneededAsPrimaryIpCanNotChangeAnymore;

        struct tun_in_node *tun;
        struct avl_node *an = NULL;
        while ((tun = avl_iterate_item(&tun_in_tree, &an))) {

                if (tun->upIfIdx && is_ip_local(&tun->remote)) {
                        dbgf_sys(DBGT_WARN, "ERROR: %s=%s remote=%s already used!!!",
				ARG_TUN_DEV, tun->nameKey.str, ip6AsStr(&tun->remote));
                        my_description_changed = YES;
                }
        }

	static IP6_T prev_primary_ip;

	if ( memcmp(&prev_primary_ip, &my_primary_ip, sizeof(IP6_T))) {

		prev_primary_ip = my_primary_ip;

		reconfigure_tun_ins();
	}
}

static void tun_cleanup(void)
{
	task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 1));

	purge_tunCatchTree();

	struct tun_in_node *tin;
	while ((tin = avl_remove_first_item(&tun_in_tree, -300393))) {
		configure_tunnel_in(DEL, tin, -1);
		debugFree(tin, -300394);
	}
}

static int32_t tun_init(void)
{
	assertion(-501335, is_zero((void*) &ZERO_TUN_NET_KEY, sizeof(ZERO_TUN_NET_KEY)));
	//assertion(-501327, tun_search_net_tree.key_size == sizeof (struct tun_search_key));
	assertion(-501328, tun_search_tree.key_size == NETWORK_NAME_LEN);

	static const struct field_format tun6_adv_format[] = DESCRIPTION_MSG_TUN6_ADV_FORMAT;
	static const struct field_format tun4in6_ingress_adv_format[] = DESCRIPTION_MSG_TUN4IN6_INGRESS_ADV_FORMAT;
	static const struct field_format tun6in6_ingress_adv_format[] = DESCRIPTION_MSG_TUN6IN6_INGRESS_ADV_FORMAT;
	static const struct field_format tun4in6_src_adv_format[] = DESCRIPTION_MSG_TUN4IN6_SRC_ADV_FORMAT;
	static const struct field_format tun6in6_src_adv_format[] = DESCRIPTION_MSG_TUN6IN6_SRC_ADV_FORMAT;
	static const struct field_format tun4in6_adv_format[] = DESCRIPTION_MSG_TUN4IN6_NET_ADV_FORMAT;
	static const struct field_format tun6in6_adv_format[] = DESCRIPTION_MSG_TUN6IN6_NET_ADV_FORMAT;

	struct frame_handl tlv_handl;
	memset(&tlv_handl, 0, sizeof(tlv_handl));

	tlv_handl.name = "DSC_TUN6";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun6);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tun6;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tun6;
	tlv_handl.msg_format = tun6_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN6, &tlv_handl);

	tlv_handl.name = "DSC_TUN4IN6_INGRESS";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun4in6ingress);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6ingress;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6ingress;
	tlv_handl.msg_format = tun4in6_ingress_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN4IN6_INGRESS, &tlv_handl);

	tlv_handl.name = "DSC_TUN6IN6_INGRESS";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun6in6ingress);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6ingress;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6ingress;
	tlv_handl.msg_format = tun6in6_ingress_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN6IN6_INGRESS, &tlv_handl);

	tlv_handl.name = "DSC_TUN4IN6_SRC";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun4in6src);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6src;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6src;
	tlv_handl.msg_format = tun4in6_src_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN4IN6_SRC, &tlv_handl);

	tlv_handl.name = "DSC_TUN6IN6_SRC";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun6in6src);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6src;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6src;
	tlv_handl.msg_format = tun6in6_src_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN6IN6_SRC, &tlv_handl);

	tlv_handl.name = "DSC_TUN4IN6_NET";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun4in6net);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6net;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6net;
	tlv_handl.msg_format = tun4in6_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN4IN6_NET, &tlv_handl);

	tlv_handl.name = "DSC_TUN6IN6_NET";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun6in6net);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6net;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6net;
	tlv_handl.msg_format = tun6in6_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN6IN6_NET, &tlv_handl);

	set_tunXin6_net_adv_list = set_tunXin6_net_adv_list_handl;

	register_options_array(tun_options, sizeof( tun_options), CODE_CATEGORY_NAME);

	register_status_handl(sizeof(struct tun_out_status), 1, tun_out_status_format, ARG_TUNS, tun_out_status_creator);

	return SUCCESS;
}

struct plugin* get_plugin(void)
{

	static struct plugin tun_plugin;

	memset(&tun_plugin, 0, sizeof( struct plugin));


	tun_plugin.plugin_name = CODE_CATEGORY_NAME;
	tun_plugin.plugin_size = sizeof( struct plugin);
	tun_plugin.cb_init = tun_init;
	tun_plugin.cb_cleanup = tun_cleanup;
        tun_plugin.cb_plugin_handler[PLUGIN_CB_SYS_DEV_EVENT] = tun_dev_event_hook;

	return &tun_plugin;
}


