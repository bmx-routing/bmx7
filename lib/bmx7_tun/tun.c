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
#include <linux/ip.h>
#include <netinet/ip6.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
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

static AVL_TREE(tun_bit_tree, struct tun_bit_node, tunBitKey); // identified matching bits (peaces) of tun_search and tun_net trees

static AVL_TREE(tun_net_tree, struct tun_net_offer, tunNetKey); // rcvd tun_out network advs
static AVL_TREE(tun_out_tree, struct tun_dev_offer, tunOutKey); // rcvd tun_out advs
static AVL_TREE(tun_catch_tree, struct tun_dev_out, tunCatchKey); // active tun_out tunnels

LIST_SIMPEL(tunXin6_net_adv_list_list, struct tunXin6_net_adv_list_node, list, list);

static const struct tun_net_offer_key ZERO_TUN_NET_KEY = { .ton = NULL };
//static const struct tun_catch_key ZERO_TUN_DEV_KEY = {.srcAf=0};

//static struct net_key tun4_address = ZERO_NET_KEY_INIT;
//char* tun4_dev = NULL;
//static struct net_key tun6_address = ZERO_NET_KEY_INIT;
//char* tun6_dev = NULL;



static int32_t tun_out_delay = DEF_TUN_OUT_DELAY;
static int32_t tun_out_mtu = DEF_TUN_OUT_MTU;
static int32_t tun_dedicated_to = DEF_TUN_OUT_TO;
static int32_t tun_proactive_routes = DEF_TUN_PROACTIVE_ROUTES;

static uint8_t tun6_advs_added;
static uint8_t tun6_nets_resetted;

STATIC_FUNC
void configure_tun_bit(uint8_t del, struct tun_bit_node *tbn, IDM_T asDfltTun);

STATIC_FUNC
void set_tunXin6_net_adv_list_handl(uint8_t del, void **adv_list_ptr)
{
	struct tunXin6_net_adv_node **adv_list = (struct tunXin6_net_adv_node **) adv_list_ptr;
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
void tun_out_state_set(struct tun_dev_offer *ton, IDM_T tdn_state)
{
	assertion(-500204, (ton));
	assertion(-501452, (tdn_state == TDN_STATE_CATCHALL || tdn_state == TDN_STATE_DEDICATED));

	assertion(-501453, (IMPLIES(tdn_state == TDN_STATE_CATCHALL, ton->tdnDedicated46[0] || ton->tdnDedicated46[1])));
	assertion(-501453, (IMPLIES(tdn_state == TDN_STATE_DEDICATED, ton->tdnCatchAll46[0] || ton->tdnCatchAll46[1])));

	struct avl_node *used_tnn_it = NULL;
	struct tun_net_offer *used_tnn;
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
	prof_start(tun_out_state_catchAll, main);
	assertion(-502327, (tun_dedicated_to > 0));

	struct tun_dev_offer *ton = tonp;
	struct tun_dev_out *tdn = ton->tdnDedicated46[0] ? ton->tdnDedicated46[0] : ton->tdnDedicated46[1];

	assertion(-502328, (tdn));
	assertion(-502329, IMPLIES(ton->tdnDedicated46[0], ton->tdnDedicated46[0] == tdn));
	assertion(-502330, IMPLIES(ton->tdnDedicated46[1], ton->tdnDedicated46[1] == tdn));

	IDM_T stats_captured = tdn->stats_captured;
	unsigned long long tx_packets = tdn->stats.tx_packets;

	tdn->stats_captured = kernel_get_ifstats(&tdn->stats, tdn->nameKey.str);

	if (stats_captured == SUCCESS && tdn->stats_captured == SUCCESS && tx_packets != tdn->stats.tx_packets) {
		task_register(tun_dedicated_to, tun_out_state_catchAll, ton, -300748);

	} else {
		tun_out_state_set(tonp, TDN_STATE_CATCHALL);
	}

	prof_stop();
}

STATIC_FUNC
void tun_out_catchAll_hook(int fd)
{
	// pick catched packet,  open dedicated tunnel, reroute all related active tun_bit_nodes via dedicated tunnel, and retransmit catched packet

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

			struct tun_dev_offer *ton = NULL;
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

				assertion(-501530, (tbn->active_tdn && tbn->active_tdn == ton->tdnDedicated46[isv4] && !ton->tdnDedicated46[isv4]->tunCatch_fd));

				struct tun_catch_key key = { .afKey = af };
				struct tun_dev_out *tdn = avl_next_item(&tun_catch_tree, &key);

				if (tdn && tdn->tunCatchKey.afKey == af) {

					if (tun_out_delay)
						wait_sec_usec(0, tun_out_delay); //delay reschedule to complete proper tunnel-setup (e.g. local address, mtu, ...)

					int written = write(tdn->tunCatch_fd, &tp, tp_len);

					dbgf(written == tp_len ? DBGL_CHANGES : DBGL_SYS, written == tp_len ? DBGT_INFO : DBGT_ERR,
						"%ssendto dst=%s len=%d (wrote=%d) fd=%d dev=%s (via dev=%s)! %s",
						(written != tp_len) ? "Failed " : "",
						isv4 ? ip4AsStr(tp.t.ip4hdr.daddr) : ip6AsStr(&tp.t.ip6hdr.ip6_dst),
						tp_len, written, tdn->tunCatch_fd, tdn->nameKey.str,
						ton->tdnDedicated46[isv4]->nameKey.str,
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
struct tun_dev_out * tun_dev_out_del(struct tun_bit_node *tbn)
{
	struct tun_search_node *tsn = tbn->tunBitKey.keyNodes.tsn;
	struct tun_net_offer *tnn = tbn->tunBitKey.keyNodes.tnn;
	struct tun_dev_offer *ton = tnn->tunNetKey.ton;
	uint8_t af = tsn->net.af;
	uint8_t isv4 = (af == AF_INET);
	struct tun_dev_out *tdn = tbn->active_tdn;

	dbgf_track(DBGT_INFO, "tunnel dev=%s", tdn->nameKey.str);

	assertion(-501460, (is_ip_set(&ton->localIp)));
	assertion(-501461, (ton->tunOutKey.on));
	assertion(-501462, (ton->tunOutKey.on != myKey->on));
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
			ton->tdnCatchAll46[isv4] = NULL;

		if (!tdn->tun_bit_tree[isv4].items) {

			set_fd_hook(tdn->tunCatch_fd, tun_out_catchAll_hook, DEL);

			// always keep one per each address family for re-sending catched packets (via tun_dflt):
			//			if (!is_ip_equal(&tdnActive->tunCatchKey.srcIp, (isv4?&tun4_address.ip:&tun6_address.ip))) {
			struct tun_catch_key catchKey = { .afKey = af };
			struct tun_dev_out *afTdn1, *afTdn2;
			if (((afTdn1 = avl_next_item(&tun_catch_tree, &catchKey)) && afTdn1->tunCatchKey.afKey == af) &&
				((afTdn2 = avl_next_item(&tun_catch_tree, &afTdn1->tunCatchKey)) && afTdn2->tunCatchKey.afKey == af)) {

				avl_remove(&tun_catch_tree, &tdn->tunCatchKey, -300527);
				kernel_dev_tun_del(tdn->nameKey.str, tdn->tunCatch_fd);
				debugFree(tdn, -300528);
			}
		}

	} else { //dedicated:

		assertion(-501468, (tdn == ton->tdnDedicated46[isv4]));
		assertion(-501470, IMPLIES(tdn != ton->tdnDedicated46[!isv4], ton->tdnDedicated46[!isv4] == NULL));

		avl_remove(&tdn->tun_bit_tree[isv4], &tbn->tunBitKey.keyNodes, -300548);

		if (!tdn->tun_bit_tree[isv4].items) {

			ton->tdnDedicated46[isv4] = NULL;

			if (!tdn->tun_bit_tree[!isv4].items) {
				assertion(-501532, (!ton->tdnDedicated46[!isv4]));

				IDM_T result = kernel_tun_del(tdn->nameKey.str);
				assertion(-501471, (result == SUCCESS));
				debugFree(tdn, -300531);

				task_remove(tun_out_state_catchAll, ton);
			}

		}
	}

	return(tbn->active_tdn = NULL);
}

struct tun_net_offer * find_overlapping_tun( struct net_key *try, struct orig_node *except, struct ctrl_node *cn )
{
        struct tun_net_offer *tnn;
        struct avl_node *it = NULL;

        while ((tnn = avl_iterate_item(&tun_net_tree, &it))) {

		struct tun_net_offer_key *tnk = &tnn->tunNetKey;

		dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "try=%s net=%s orig=%s",
			netAsStr(try), netAsStr(&tnk->netKey), tnk->ton->tunOutKey.on->k.hostname);

                if (tnk->ton->tunOutKey.on != except &&
			is_ip_net_equal(&try->ip, &tnk->netKey.ip, XMIN(try->mask, tnk->netKey.mask), try->af))
                        return tnn;
        }
        return NULL;
}


STATIC_FUNC
struct net_key *_find_free_local_prefix(struct net_key *range, uint8_t mask, struct net_key * result, struct ctrl_node *cn)
{
	if (result && result->af == range->af && result->mask == mask && result->mask >= range->mask &&
		is_ip_net_equal(&result->ip, &range->ip, range->mask, range->af)) {

		dbgf_sys(DBGT_INFO, "Reusing %s within %s", netAsStr(result), netAsStr(range));
		return result;
	}

	uint8_t rangeMask = (range->af == AF_INET) ? ((128 - 32) + range->mask) : range->mask;
	uint8_t subMask = (range->af == AF_INET) ? ((128 - 32) + mask) : mask;

	uint8_t revMaskHave = 128 - rangeMask;
	uint8_t revMaskWant = 128 - subMask;

	if (revMaskHave >= revMaskWant) {
		uint8_t revMaskOpts = revMaskHave - revMaskWant;
		uint64_t revMaskRand = 0x1122334455667788;
//		uint64_t revMaskRand = 0xFFFFFFFFFFFFFFFF;
//		cryptRand(&revMaskRand, sizeof(revMaskRand));
		uint8_t revMaskZeros = (revMaskOpts <= 64) ? (64-revMaskOpts) : 0;

		revMaskRand = (revMaskZeros >= 64) ? 0 : ((revMaskRand) >> revMaskZeros);


		uint64_t revMaskTry = revMaskRand;
		uint64_t netRand = hton64(revMaskRand);
		dbgf_cn(cn, DBGL_ALL, DBGT_INFO, "have=%d want=%d opts=%d zeros=%d rand=%s", 
			revMaskHave, revMaskWant, revMaskOpts, revMaskZeros, memAsHexStringSep(&netRand, sizeof(netRand), 4, ":"));

		static struct net_key found;
		found.ip = ZERO_IP;
		found.af = range->af;
		found.mask = mask;

		do {
			uint64_t ip[2] = {
				hton64(rangeMask >= 64 ? 0 : (revMaskZeros >= 64 ? 0 : ((revMaskTry << revMaskZeros) >> rangeMask))),
				hton64(revMaskWant >= 64 ? 0 : (revMaskTry << revMaskWant))};

			found.ip = *((IP6_T*)&ip[0]);
			found.ip.s6_addr32[0] |= range->ip.s6_addr32[0];
			found.ip.s6_addr32[1] |= range->ip.s6_addr32[1];
			found.ip.s6_addr32[2] |= range->ip.s6_addr32[2];
			found.ip.s6_addr32[3] |= range->ip.s6_addr32[3];
			found.ip.s6_addr32[3] |= htonl(1);

			dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "Trying %s within %s", netAsStr(&found), netAsStr(range));
//			assertion(-500000, is_ip_net_equal(&find.ip, &range->ip, range->mask, range->af));
//			assertion(-500000, range->mask <= find.mask);

			if (!(
				find_overlapping_hna( &found.ip, subMask, myKey->on) ||
				find_overlapping_tun( &found, myKey->on, cn)
				)) {

				dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "Found=%s (%s/%d) from range=%s (%s/%d)",
					netAsStr(&found), memAsHexStringSep(&found.ip, sizeof(found.ip), 4, ":"), subMask,
					netAsStr(range), memAsHexStringSep(&range->ip, sizeof(range->ip), 4, ":"), rangeMask);
				IDM_T TODO_ReVerify_this_when_others_annoucements_changed;

				if (result)
					*result = found;

				return &found;
			}

			revMaskTry++;
			revMaskTry &= (~(U64_MAX<<revMaskOpts));

		} while ( revMaskTry != revMaskRand );
	}

	return NULL;
}


int32_t opt_find_prefix(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
#define ARG_FIND_PREFIX "findPrefix"
#define ARG_FIND_PREFIX_MASK "mask"
#define ARG_MATCH_PREFIX "matchPrefix"

        if ( cmd == OPT_CHECK) {

                int32_t mask = 48;
		struct net_key match = ZERO_NET_KEY;

                struct opt_child *c = NULL;
		while ((c = list_iterate(&patch->childs_instance_list, c))) {

			if (!strcmp(c->opt->name, ARG_FIND_PREFIX_MASK))
				mask = strtol(c->val, NULL, 10);

			if (!strcmp(c->opt->name, ARG_MATCH_PREFIX))
				str2netw(c->val, &match.ip, NULL, &match.mask, &match.af, NO);
		}

		struct net_key range = ZERO_NET_KEY;
		struct net_key result = ZERO_NET_KEY;
		str2netw(patch->val, &range.ip, NULL, &range.mask, &range.af, NO);
		_find_free_local_prefix(&range, mask, &result, cn);


		uint8_t min = XMIN(result.mask, match.mask);
		IPX_T r = result.ip;
		IPX_T m = match.ip;
		ip_netmask_validate(&r, min, result.af, YES /*force*/);
		ip_netmask_validate(&m, min, match.af, YES /*force*/);

		dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "range=%s>=%d (%s) -> result=%s -> %s/%d (%s) match=%s -> %s/%d (%s) equal=%d",
			netAsStr(&range), mask, memAsHexStringSep(&range.ip, sizeof(range.ip), 4, ":"),
			netAsStr(&result), ipXAsStr(result.af, &r), min, memAsHexStringSep(&r, sizeof(r), 4, ":"),
			netAsStr(&match), ipXAsStr(match.af, &m), min, memAsHexStringSep(&m, sizeof(m), 4, ":"),
			is_ip_equal(&m, &r));

	}
	return SUCCESS;
}



IDM_T assert_tbn_ton_tdn(IDM_T isv4, struct tun_dev_offer *ton, struct tun_bit_node *tbn)
{
	uint8_t af = (isv4 ? AF_INET : AF_INET6);
	assertion(-501546, (ton));
	struct tun_dev_out *tdoC = ton->tdnCatchAll46[isv4];
	struct tun_dev_in *tdiC = tdoC ? tdoC->tunCatchKey.tin : NULL;
	assertion(-501547, IMPLIES(tdoC, tdiC));
	assertion(-500000, IMPLIES(tdoC, tdiC == ton->tin46[isv4]));
	assertion(-500000, IMPLIES(tdoC, tdiC->tunAddr.af == af));
	assertion(-501548, IMPLIES(tdoC, tdiC->tunAddr.mask));
	assertion(-501549, IMPLIES(tdoC, is_ip_set(&(tdiC->tunAddr.ip))));
	assertion(-501550, IMPLIES(tdoC, tdiC->tunAddr.mask >= ton->ingressPrefix46[isv4].mask));
	assertion(-501551, IMPLIES(tdoC, is_ip_net_equal(&tdiC->tunAddr.ip, &ton->ingressPrefix46[isv4].ip, ton->ingressPrefix46[isv4].mask, af)));

	struct tun_dev_out *tdoD = ton->tdnDedicated46[isv4];
	struct tun_dev_in *tdiD = tdoD ? tdoD->tunCatchKey.tin : NULL;
	assertion(-501552, IMPLIES(tdoD, tdiD));
	assertion(-500000, IMPLIES(tdoD, tdiD == ton->tin46[isv4]));
	assertion(-500000, IMPLIES(tdoD, tdiD->tunAddr.af == af));
	assertion(-501553, IMPLIES(tdoD, tdiD->tunAddr.mask));
	assertion(-501554, IMPLIES(tdoD, is_ip_set(&(tdiD->tunAddr.ip))));
	assertion(-501555, IMPLIES(tdoD, tdiD->tunAddr.mask >= ton->ingressPrefix46[isv4].mask));
	assertion(-501556, IMPLIES(tdoD, is_ip_net_equal(&tdiD->tunAddr.ip, &ton->ingressPrefix46[isv4].ip, ton->ingressPrefix46[isv4].mask, af)));

	assertion(-501557, IMPLIES(tbn, tbn->tunBitKey.keyNodes.tnn));
	assertion(-501558, IMPLIES(tbn, ton == tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton));
//	assertion(-501559, IMPLIES(tbn, tbn->active_tdn==tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnCatchAll[isv4] || tbn->active_tdn==tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnDedicated[isv4] ));
	return YES;
}


STATIC_FUNC
struct tun_dev_out *_tun_dev_out_add(struct tun_bit_node *tbn, IDM_T tdn_state)
{
	uint8_t isv4 = (tbn->tunBitKey.keyNodes.tsn->net.af == AF_INET);
	struct tun_dev_offer *ton = tbn->tunBitKey.keyNodes.tnn->tunNetKey.ton;
	struct tun_dev_out *tdn = tbn->active_tdn;

//	struct tun_in_node *tin = find_matching_tun_in_node(tsn, ton);
	struct tun_dev_in *tin = ton->tin46[isv4];
	assertion(-501472, (tin && is_ip_set(&tin->tunAddr.ip)));

	assertion(-501524, (is_ip_set(&ton->localIp)));
	assertion(-501235, (ton->tunOutKey.on));
	assertion(-501321, (ton->tunOutKey.on != myKey->on));
	assertion(-501343, (is_ip_set(&ton->tunOutKey.on->primary_ip)));

	dbgf_track(DBGT_INFO, "tdn_state=%d", tdn_state);

	assertion(-501473, (tdn_state == TDN_STATE_CATCHALL || tdn_state == TDN_STATE_DEDICATED || tdn_state == TDN_STATE_CURRENT));

	if (tdn_state == TDN_STATE_CATCHALL ||
		(tdn_state == TDN_STATE_CURRENT && (tdn ? (tdn->tunCatch_fd > 0) : (!tdn && tun_dedicated_to > 0)))) {

		//set TDN_STATE_CATCHALL
		struct tun_catch_key tck = {.afKey = (isv4 ? AF_INET : AF_INET6), .tin = tin};


		if (tdn && !tdn->tunCatch_fd)
			tdn = tun_dev_out_del(tbn);

		if (!tdn) {

			if (!(tdn = avl_find_item(&tun_catch_tree, &tck))) {

				assertion(-501561, (!ton->tdnCatchAll46[isv4]));

				tdn = debugMallocReset(sizeof(struct tun_dev_out), -300532);
				AVL_INIT_TREE(tdn->tun_bit_tree[0], struct tun_bit_node, tunBitKey.keyNodes);
				AVL_INIT_TREE(tdn->tun_bit_tree[1], struct tun_bit_node, tunBitKey.keyNodes);

				tdn->nameKey = tun_out_get_free_name(isv4 ? DEF_TUN_NAME_TYPE_CATCH4 : DEF_TUN_NAME_TYPE_CATCH6, tin->nameKey.str + strlen(tun_name_prefix.str));
				tdn->ifIdx = kernel_dev_tun_add(tdn->nameKey.str, &tdn->tunCatch_fd, isv4 ? 1 : 0);
				tdn->orig_mtu = kernel_get_mtu(tdn->nameKey.str);
				tdn->curr_mtu = set_tun_out_mtu(tdn->nameKey.str, tdn->orig_mtu, DEF_TUN_OUT_MTU, tun_out_mtu);

				kernel_set_addr(ADD, tdn->ifIdx, isv4 ? AF_INET : AF_INET6, &tin->tunAddr.ip, isv4 ? 32 : 128, NO/*deprecated*/);

				tdn->tunCatchKey = tck;
				avl_insert(&tun_catch_tree, tdn, -300533);
			}

			if (!tdn->tun_bit_tree[0].items && !tdn->tun_bit_tree[1].items)
				set_fd_hook(tdn->tunCatch_fd, tun_out_catchAll_hook, ADD);

			avl_insert(&tdn->tun_bit_tree[isv4], tbn, -300534);

			assertion(-501534, IMPLIES(ton->tdnCatchAll46[isv4], ton->tdnCatchAll46[isv4] == tdn));
			ton->tdnCatchAll46[isv4] = tdn;
		}

		assertion(-501474, (tdn));
		assertion(-501475, (tdn->tunCatch_fd > 0));
		assertion(-501476, (tdn->ifIdx > 0));
		assertion(-501477, (tdn->orig_mtu >= MIN_TUN_OUT_MTU));
		assertion(-501479, (is_ip_set(&tin->tunAddr.ip)));
		assertion(-501481, (avl_find_item(&tun_catch_tree, &tck)));
		assertion(-501482, (avl_find_item(&tdn->tun_bit_tree[isv4], &tbn->tunBitKey.keyNodes)));
		assertion(-501536, (ton->tdnCatchAll46[isv4] == tdn));

	} else if (tdn_state == TDN_STATE_DEDICATED ||
		(tdn_state == TDN_STATE_CURRENT && (tdn ? (tdn->tunCatch_fd == 0) : (tun_dedicated_to == 0)))) {

		if (tdn && tdn->tunCatch_fd)
			tdn = tun_dev_out_del(tbn);

		if (!tdn) {

			if (!((tdn = ton->tdnDedicated46[isv4]) || (tdn = ton->tdnDedicated46[!isv4]))) {

				assertion(-501563, (!ton->tdnDedicated46[isv4]));

				tdn = debugMallocReset(sizeof(struct tun_dev_out), -300535);
				AVL_INIT_TREE(tdn->tun_bit_tree[0], struct tun_bit_node, tunBitKey.keyNodes);
				AVL_INIT_TREE(tdn->tun_bit_tree[1], struct tun_bit_node, tunBitKey.keyNodes);

				tdn->nameKey = tun_out_get_free_name(DEF_TUN_NAME_TYPE_OUT, cryptShaAsString(&ton->tunOutKey.on->k.nodeId));
				tdn->ifIdx = kernel_tun_add(tdn->nameKey.str, IPPROTO_IP, &ton->localIp, &ton->tunOutKey.on->primary_ip);
				tdn->orig_mtu = kernel_get_mtu(tdn->nameKey.str);
				tdn->curr_mtu = set_tun_out_mtu(tdn->nameKey.str, tdn->orig_mtu, DEF_TUN_OUT_MTU, tun_out_mtu);

				tdn->stats_captured = kernel_get_ifstats(&tdn->stats, tdn->nameKey.str);

				assertion(-501485, (tdn->ifIdx > 0));
				assertion(-501486, (tdn->orig_mtu >= MIN_TUN_OUT_MTU));
				assertion(-501487, (!tdn->tunCatch_fd));

				kernel_set_addr(ADD, tdn->ifIdx, AF_INET6, &ton->localIp, 128, YES /*deprecated*/);

				if (tin->tunAddr.mask)
					kernel_set_addr(ADD, tdn->ifIdx, AF_INET, &tin->tunAddr.ip, (isv4 ? 32 : 128), NO/*deprecated*/);

				tdn->tunCatchKey.tin = tin;
			}

			avl_insert(&tdn->tun_bit_tree[isv4], tbn, -300549);

			assertion(-501537, IMPLIES(ton->tdnDedicated46[isv4], ton->tdnDedicated46[isv4] == tdn));
			ton->tdnDedicated46[isv4] = tdn;
		}

		assertion(-501484, (tdn));
		assertion(-501538, (ton->tdnDedicated46[isv4] == tdn));

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
	struct tun_search_node *tsn = tbn->tunBitKey.keyNodes.tsn;
	struct tun_net_offer *tnn = tbn->tunBitKey.keyNodes.tnn;
	struct tun_dev_offer *ton = tnn->tunNetKey.ton;
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

		_tun_dev_out_add(tbn, tdn_state);
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
IDM_T match_tsn_requirements(struct tun_search_node *tsn, struct tun_net_offer *tnn)
{
	struct orig_node *on = tnn->tunNetKey.ton->tunOutKey.on;
	struct net_key *tnn_netKey = &tnn->tunNetKey.netKey;
	struct net_key *ingressPrefix = &tnn->tunNetKey.ton->ingressPrefix46[(tsn->net.af == AF_INET)];

	dbgf_track(DBGT_INFO, "checking network=%s bw_fmu8=%d, ingress=%s localIp=%s tun6Id=%d from nodeId=%s hostname=%s",
		netAsStr(tnn_netKey), tnn->bandwidth.val.u8, netAsStr(ingressPrefix),
		ip6AsStr(&tnn->tunNetKey.ton->localIp), tnn->tunNetKey.ton->tunOutKey.tun6Id,
		cryptShaAsString(&on->k.nodeId), on->k.hostname);

	return (
		(tsn->routeSearchProto == TYP_TUN_PROTO_ALL || tsn->routeSearchProto == tnn->tunNetKey.bmx7RouteType) &&
		tsn->net.af == tnn_netKey->af &&
		(tsn->netPrefixMax == TYP_TUN_OUT_PREFIX_NET ?
		tsn->net.mask >= tnn_netKey->mask : tsn->netPrefixMax >= tnn_netKey->mask) &&
		(tsn->netPrefixMin == TYP_TUN_OUT_PREFIX_NET ?
		tsn->net.mask <= tnn_netKey->mask : tsn->netPrefixMin <= tnn_netKey->mask) &&
		is_ip_net_equal(&tsn->net.ip, &tnn_netKey->ip, XMIN(tsn->net.mask, tnn_netKey->mask), tnn_netKey->af) &&
		IMPLIES(strlen(tsn->gwName), !strcmp(tsn->gwName, on->k.hostname)) &&
		IMPLIES(!is_zero(&tsn->gwId, sizeof(GLOBAL_ID_T)), cryptShasEqual(&tsn->gwId, &on->k.nodeId)) &&
		(!ingressPrefix->mask || !tsn->srcRtNet.mask || (
		tsn->srcRtNet.mask >= ingressPrefix->mask &&
		is_ip_net_equal(&tsn->srcRtNet.ip, &ingressPrefix->ip, ingressPrefix->mask, ingressPrefix->af)))
		);

}

STATIC_FUNC
void _assign_ton_in_nodes(void) {

	IDM_T isv4;
	for (isv4=0; isv4<=1; isv4++) {
		struct avl_node *an = NULL;
		struct tun_dev_in *tin;
		while ((tin = avl_iterate_item(&tun_in_tree, &an))) {
			struct tun_search_node *tsn;

			dbgf_track(DBGT_INFO, "Checking af=%s=%d tunIn=%s seachName=%s mode=%d localPrefix=%s<=%d addr=%s",
				(isv4 ? "IPv4" : "IPv6"),tin->af, tin->nameKey.str, tin->tunSearchNameKey, tin->localPrefixMode,
				netAsStr(&tin->localPrefix), tin->localPrefixMax, netAsStr(&tin->tunAddr));

			if (!(
				tin->af == (isv4 ? AF_INET : AF_INET6) &&
				tin->localPrefixMode == TYP_TUN_DEV_MODE_AUTO &&
				strlen(tin->tunSearchNameKey) &&
				(tsn = avl_find_item(&tun_search_tree, tin->tunSearchNameKey)) &&
				(!strcmp(tsn->tunInNameKey.str, tin->nameKey.str))
				))
				continue;

			if (is_zero(&tsn->gwId, sizeof(tsn->gwId)))
				continue;

			struct tun_dev_offer *ton;
			struct tun_dev_offer_key tok = {.on = avl_find_item(&orig_tree, &tsn->gwId), .tun6Id = 0 };
			for (; (tok.on && (ton = avl_find_item(&tun_out_tree, &tok))); tok.tun6Id++) {

				dbgf_track(DBGT_INFO, "Checking ton name=%s tunId=%d mode=%d srcOffer=%s>=%d",
					ton->tunOutKey.on->k.hostname, ton->tunOutKey.tun6Id,
					ton->remoteMode46[isv4], netAsStr(&ton->remotePrefix46[isv4]), ton->remotePrefixMin46[isv4]);

				if (!(
					!ton->tin46[isv4] &&
					ton->remoteMode46[isv4] == TYP_TUN_DEV_MODE_AUTO &&
					tin->localPrefixMax >= ton->remotePrefixMin46[isv4] &&
					ton->remotePrefixMin46[isv4] >= ton->remotePrefix46[isv4].mask &&
					tin->localPrefix.mask <= ton->remotePrefix46[isv4].mask &&
					is_ip_net_equal(&tin->localPrefix.ip, &ton->remotePrefix46[isv4].ip, tin->localPrefix.mask, isv4 ? AF_INET : AF_INET6)
					))
					continue;

				struct net_key ingress = ton->ingressPrefix46[isv4];
				struct tun_net_offer *tnn;
				struct avl_node *itnn = NULL;
				while ((tnn = avl_iterate_item(&ton->tun_net_tree, &itnn))) {

					dbgf_track(DBGT_INFO, "Checking net=%s", netAsStr(&tnn->tunNetKey.netKey));

					struct net_key result = tin->tunAddr;
					if (!(
						tnn->tunNetKey.netKey.af == (isv4 ? AF_INET : AF_INET6) &&
						match_tsn_requirements(tsn, tnn) &&
						(result.mask || _find_free_local_prefix(&ton->remotePrefix46[isv4], tin->localPrefixMax, &result, NULL)) &&
						(!ingress.mask || (result.mask >= ingress.mask && is_ip_net_equal(&result.ip, &ingress.ip, ingress.mask, ingress.af)))
						))
						continue;

					ton->tin46[isv4] = tin;
					avl_insert(&tin->tun_dev_offer_tree, ton, -300000);

					if (!tin->tunAddr.mask) {
						tin->tunAddr = result;
						kernel_set_addr(ADD, tin->upIfIdx, result.af, &result.ip, (result.af == AF_INET ? 32 : 128), NO /*deprecated*/);
						my_description_changed = YES;
					}

					dbgf_track(DBGT_INFO, "Found");
					break;
				}
			}
		}
	}
}

STATIC_FUNC
struct tun_dev_in *_find_matching_tun_in_node(struct tun_search_node *tsn, struct tun_dev_offer *ton)
{
	struct avl_node *an = NULL;
	IDM_T isv4 = (tsn->net.af == AF_INET);
	struct net_key ingressPrefix = ton->ingressPrefix46[isv4];
	struct tun_dev_in *tin = NULL;

	assertion(-501560, assert_tbn_ton_tdn(isv4, ton, NULL));

//	struct tun_dev_node *tdn;
//	if ((tdn = (ton->tdnDedicated46[isv4] ? ton->tdnDedicated46[isv4] : ton->tdnCatchAll46[isv4])))
//		return tdn->tunCatchKey.tin;

	while ((tin = (ton->tin46[isv4] ? ton->tin46[isv4] : avl_iterate_item(&tun_in_tree, &an)))) {

		if ((tin->tunAddr.mask) && (tin->tunAddr.af == tsn->net.af) &&
			!(strlen(tsn->tunInNameKey.str) && strcmp(tsn->tunInNameKey.str, tin->nameKey.str)) &&
			!(ingressPrefix.mask && !(
			tin->tunAddr.mask >= ingressPrefix.mask &&
			is_ip_net_equal(&tin->tunAddr.ip, &ingressPrefix.ip, ingressPrefix.mask, ingressPrefix.af)))) {

			dbgf_track(DBGT_INFO, "Found %s tin address=%s", ton->tin46[isv4] ? "OLD" : "NEW", netAsStr(&tin->tunAddr));

			if (!ton->tin46[isv4]) {
				ton->tin46[isv4] = tin;
				avl_insert(&tin->tun_dev_offer_tree, ton, -300000);
			}
			assertion(-500000, (ton->tin46[isv4] == tin));
			return tin;
		}

		if (ton->tin46[isv4])
			break;
	}
	dbgf_track(DBGT_INFO, "None found");
	return NULL;
}


STATIC_FUNC
void _add_tun_bit_node(struct tun_search_node *tsna, struct tun_net_offer *tnna)
{
	_assign_ton_in_nodes();

	struct tun_bit_key_nodes tbkn;

	struct avl_node *itnn = NULL;
	while ((tbkn.tnn = tnna ? tnna : avl_iterate_item(&tun_net_tree, &itnn))) {

		struct avl_node *itsn = NULL;
		while ((tbkn.tsn = tsna ? tsna : avl_iterate_item(&tun_search_tree, &itsn))) {

			dbgf_track(DBGT_INFO, "%s=%s: %s=%s %s=%s %s=%s",
				ARG_TUN_OUT, tbkn.tsn->nameKey,
				ARG_TUN_OUT_PKID, cryptShaAsString(&tbkn.tsn->gwId),
				ARG_TUN_OUT_GWNAME, tbkn.tsn->gwName,
				ARG_TUN_OUT_NET, netAsStr(&tbkn.tsn->net));

			struct tun_dev_in *tin;
			struct tun_bit_node *tbn = avl_find_item(&(tbkn.tnn->tun_bit_tree), &tbkn);
			assertion(-501371, (tbn == avl_find_item(&(tbkn.tsn->tun_bit_tree), &tbkn)));

			if (tbn) {
				dbgf_track(DBGT_INFO, "Already added");

			} else if (!match_tsn_requirements(tbkn.tsn, tbkn.tnn)) {
				dbgf_track(DBGT_INFO, "failed A");

			} else if (!(tin = _find_matching_tun_in_node(tbkn.tsn, tbkn.tnn->tunNetKey.ton))) {
				dbgf_track(DBGT_INFO, "failed D");

			} else {

				tbn = debugMalloc(sizeof( struct tun_bit_node), -300455);
				memset(tbn, 0, sizeof(struct tun_bit_node));

				tbn->tunBitKey.beInvTunBitMetric = hton64(UMETRIC_MAX);
				tbn->tunBitKey.beIpRule = htonl(tbkn.tsn->iprule);
				tbn->tunBitKey.beIpMetric = htonl(tbkn.tsn->ipmetric);
				tbn->tunBitKey.keyNodes = tbkn;
				tbn->tunBitKey.invRouteKey = tbkn.tsn->net.mask > tbkn.tnn->tunNetKey.netKey.mask ? tbkn.tsn->net : tbkn.tnn->tunNetKey.netKey;
				tbn->tunBitKey.invRouteKey.mask = 128 - tbn->tunBitKey.invRouteKey.mask;

				tbn->ipTable = tbkn.tsn->iptable;

				avl_insert(&tun_bit_tree, tbn, -300456);
				avl_insert(&tbkn.tsn->tun_bit_tree, tbn, -300457);
				avl_insert(&tbkn.tnn->tun_bit_tree, tbn, -300458);
			}

			if (tsna)
				break;
		}

		if (tnna)
			break;
	}
}

STATIC_FUNC
void _del_tun_bit_node(struct tun_search_node *tsn, struct tun_net_offer *tnn)
{
	struct tun_bit_node *tbn;
	struct avl_tree *tbt = (tsn ? &tsn->tun_bit_tree : (tnn ? &tnn->tun_bit_tree : &tun_bit_tree));

	while ((tbn = avl_first_item(tbt))) {

		tsn = tbn->tunBitKey.keyNodes.tsn;
		tnn = tbn->tunBitKey.keyNodes.tnn;
		assertion(-500000, (tsn->net.af == tnn->tunNetKey.netKey.af));
		IDM_T isv4 = (tnn->tunNetKey.netKey.af == AF_INET);
		struct tun_dev_offer *ton = tnn->tunNetKey.ton;
		struct tun_dev_in *tin = ton->tin46[isv4];
		assertion(-500000, (tin));

		avl_remove(&(tsn->tun_bit_tree), &tbn->tunBitKey.keyNodes, -300460);
		avl_remove(&(tnn->tun_bit_tree), &tbn->tunBitKey.keyNodes, -300461);
		avl_remove(&tun_bit_tree, &tbn->tunBitKey, -300462);
		configure_tun_bit(DEL, tbn, TDN_STATE_CURRENT);
		debugFree(tbn, -300463);

		if (!strcmp(tin->tunSearchNameKey, tsn->nameKey)) {

			struct tun_dev_offer *tinTon;
			while ((tinTon = avl_remove_first_item(&tin->tun_dev_offer_tree, -300000))) {

				tinTon->tin46[isv4] = NULL;

				struct tun_net_offer *tinTonTnn;
				struct avl_node *an = NULL;
				while ((tinTonTnn = avl_iterate_item(&tinTon->tun_net_tree, &an))) {

					if (tinTonTnn->tunNetKey.netKey.af != (isv4 ? AF_INET : AF_INET6))
						continue;

					struct tun_bit_node *tinTonTnnTbn;
					while ((tinTonTnnTbn = avl_first_item(&tinTonTnn->tun_bit_tree))) {

						assertion(-500000, (tinTonTnnTbn->tunBitKey.keyNodes.tnn->tunNetKey.ton == tinTon));

						avl_remove(&(tinTonTnnTbn->tunBitKey.keyNodes.tsn->tun_bit_tree), &tinTonTnnTbn->tunBitKey.keyNodes, -300000);
						avl_remove(&(tinTonTnnTbn->tunBitKey.keyNodes.tnn->tun_bit_tree), &tinTonTnnTbn->tunBitKey.keyNodes, -300000);
						avl_remove(&tun_bit_tree, &tinTonTnnTbn->tunBitKey, -300000);
						configure_tun_bit(DEL, tinTonTnnTbn, TDN_STATE_CURRENT);
						debugFree(tinTonTnnTbn, -300000);
					}
				}
			}
		}

		if (!tnn->tun_bit_tree.items) {
			struct tun_net_offer *tonTnn;
			struct avl_node *an = NULL;
			while((tonTnn = avl_iterate_item(&ton->tun_net_tree, &an)) && 
				(!tonTnn->tun_bit_tree.items || tonTnn->tunNetKey.netKey.af != (isv4 ? AF_INET : AF_INET6)));
			if (!tonTnn && avl_find(&tin->tun_dev_offer_tree, &ton->tunOutKey)) {
				avl_remove(&tin->tun_dev_offer_tree, &ton->tunOutKey, -300000);
				ton->tin46[isv4] = NULL;
			}
			if (!tin->tun_dev_offer_tree.items && tin->localPrefixMode == TYP_TUN_DEV_MODE_AUTO) {
				assertion(-500000, (tin->tunAddr.mask));
				kernel_set_addr(DEL, tin->upIfIdx, tin->tunAddr.af, &tin->tunAddr.ip, (isv4 ? 32 : 128), NO /*deprecated*/);
				tin->tunAddr = ZERO_NET_KEY;
				my_description_changed = YES;
			}
		}
	}
}

STATIC_FUNC
void upd_tun_bit_node(uint8_t del, struct tun_search_node *tsn, struct tun_net_offer *tnn)
{
	dbgf_track(DBGT_INFO, "%s tsn=%s tnn=%s ton=%s", del ? "DEL" : "ADD", tsn ? tsn->nameKey : DBG_NIL,
		tnn ? netAsStr(&tnn->tunNetKey.netKey) : DBG_NIL, tnn ? tnn->tunNetKey.ton->tunOutKey.on->k.hostname : DBG_NIL);

	assertion(-501378, ((!!tsn + !!tnn) <= 1));
	if (del)
		_del_tun_bit_node(tsn, tnn);
	else
		_add_tun_bit_node(tsn, tnn);
}

STATIC_FUNC
IDM_T _recalc_tun_bit_tree(void)
{
	prof_start(_recalc_tun_bit_tree, main);

	IDM_T changedOrder = NO;
	struct tun_bit_node *tbn_curr;
	struct tun_bit_key tbk_prev;
	memset(&tbk_prev, 0, sizeof(tbk_prev));

	while ((tbn_curr = avl_next_item(&tun_bit_tree, &tbk_prev))) {

		struct tun_bit_key tbk_new = tbn_curr->tunBitKey;
		struct tun_bit_node *tbn_next = avl_next_item(&tun_bit_tree, &tbn_curr->tunBitKey);
		struct tun_net_offer *tnn = tbn_curr->tunBitKey.keyNodes.tnn;
		struct tun_search_node *tsn = tbn_curr->tunBitKey.keyNodes.tsn;

		struct orig_node *on = tnn->tunNetKey.ton->tunOutKey.on;

		assertion_dbg(-502533, ((on->neighPath.um & ~UMETRIC_MASK) == 0), "um=%ju mask=%ju max=%ju", on->neighPath.um, UMETRIC_MASK, UMETRIC_MAX);

		UMETRIC_T tnnBandwidth = fmetric_u8_to_umetric(tnn->bandwidth);
		UMETRIC_T tnnQuality = tnnBandwidth >= tsn->minBW ? UMETRIC_MAX : tnnBandwidth;
		UMETRIC_T pathMetric = on->neighPath.link ? on->neighPath.um : 0;
		UMETRIC_T e2eMetric = XMIN(tnnQuality, pathMetric);

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
	task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 1));
	if (task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 0)) == SUCCESS)
		onlyIfOrderChanged = NULL;

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
			struct net_key currRoute = { .af = af, .ip = currBKey.invRouteKey.ip, .mask = 128 - currBKey.invRouteKey.mask };

			assertion(-501564, (currBKey.keyNodes.tnn));
			assertion(-501565, (currBKey.keyNodes.tnn->tunNetKey.ton));
//			assertion(-501574, (assert_tbn_ton_tdn(isv4, currBKey.keyNodes.tnn->tunNetKey.ton, tbn_curr)));
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
				struct net_key crashRoute = { .af = af, .ip = crashBKey.invRouteKey.ip, .mask = 128 - crashBKey.invRouteKey.mask };
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

//			assertion(-501576, (assert_tbn_ton_tdn(isv4, currBKey.keyNodes.tnn->tunNetKey.ton, tbn_curr)));
			assertion(-501577, IMPLIES(tbn_curr,
				tbn_curr->active_tdn == tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnCatchAll46[isv4] ||
				tbn_curr->active_tdn == tbn_curr->tunBitKey.keyNodes.tnn->tunNetKey.ton->tdnDedicated46[isv4]));

		}
	}
	prof_stop();
}

STATIC_FUNC
IDM_T get_free_tun6Id(void) {
	uint8_t tun6Id = 0;

	for (tun6Id = 0; tun6Id < MAX_AUTO_TUNID_OCT; tun6Id++) {
		struct avl_node *an;
		struct tun_dev_in *tin;
		for (an = NULL; ((tin = avl_iterate_item(&tun_in_tree, &an)) && tin->tun6Id != tun6Id););

		if (!tin)
			return tun6Id;
	}
	return -1;
}


STATIC_FUNC
IDM_T get_max_tun6Id(void) {
	int16_t tun6Id = -1;

	struct avl_node *an;
	struct tun_dev_in *tin;
	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));)
		tun6Id = XMAX(tun6Id, tin->tun6Id);

	assertion(-500000, (tun6Id < MAX_AUTO_TUNID_OCT));

	return tun6Id;
}


STATIC_FUNC
struct tun_dev_in *get_tun6Id_node(int16_t tun6Id) {
	struct avl_node *an;
	struct tun_dev_in *tin;
	for (an = NULL; (tin = avl_iterate_item(&tun_in_tree, &an));) {

		if (tun6Id == tin->tun6Id)
			return tin;
	}

	return NULL;
}


STATIC_FUNC
int create_dsc_tlv_tun6(struct tx_frame_iterator *it)
{
	struct dsc_msg_tun6 *adv = (struct dsc_msg_tun6 *) tx_iterator_cache_msg_ptr(it);
	int16_t m, tun6IdMax = get_max_tun6Id();
	struct tun_dev_in *tin;

	assertion(-502041, is_ip_set(&my_primary_ip));
	for (m = 0; (m <= tun6IdMax && tx_iterator_cache_data_space_pref(it, ((m + 1) * sizeof(struct dsc_msg_tun6)), 0)); m++) {

		if ((tin = get_tun6Id_node(m)) && tin->upIfIdx && is_ip_set(&tin->remoteDummyIp6))
			adv[m].localIp = tin->remoteDummyIp6;
		else
			adv[m].localIp = my_primary_ip;
	}

	if (m)
		return m * sizeof( struct dsc_msg_tun6);
	else
		return TLV_TX_DATA_IGNORED;
}

STATIC_FUNC
struct tun_dev_offer_key set_tun_adv_key(struct orig_node *on, int16_t tun6Id)
{
	struct tun_dev_offer_key key;
	memset(&key, 0, sizeof(key));
	key.on = on;
	key.tun6Id = tun6Id;
	return key;
}


STATIC_FUNC
void del_tun_net_node(struct tun_net_offer *tnn)
{
	struct tun_dev_offer *ton = tnn->tunNetKey.ton;
	struct tun_net_offer *tnn1 = avl_remove(&tun_net_tree, &tnn->tunNetKey, -300421);
	struct tun_net_offer *tnn2 = avl_remove(&ton->tun_net_tree, &tnn->tunNetKey, -300423);
#ifndef NO_ASSERTIONS
	assertion_dbg(-501251, (tnn == tnn1 && tnn == tnn2),
		"should remove %s %s but removed %s %s and %s %s !",
		netAsStr(&tnn->tunNetKey.netKey),
		cryptShaAsString(&tnn->tunNetKey.ton->tunOutKey.on->k.nodeId),
		tnn1 ? netAsStr(&tnn1->tunNetKey.netKey) : "---",
		tnn1 ? cryptShaAsString(&tnn1->tunNetKey.ton->tunOutKey.on->k.nodeId) : "---",
		tnn2 ? netAsStr(&tnn2->tunNetKey.netKey) : "---",
		tnn2 ? cryptShaAsString(&tnn2->tunNetKey.ton->tunOutKey.on->k.nodeId) : "---");
#endif

	debugFree(tnn, -300424);
	CHECK_INTEGRITY();
}


STATIC_FUNC
void reset_tun_out(struct tun_dev_offer *ton, uint8_t only_af)
{
	dbgf_all(DBGT_INFO, "should remove tunnel_node localIp=%s tun6Id=%d nodeId=%s key=%s (tunnel_out.items=%d, tun->net.items=%d)",
		ip6AsStr(&ton->localIp), ton->tunOutKey.tun6Id, cryptShaAsString(&ton->tunOutKey.on->k.nodeId),
		memAsHexString(&ton->tunOutKey, sizeof(struct tun_dev_offer_key)), tun_out_tree.items, ton->tun_net_tree.items);

	struct tun_net_offer *tnn;

	for (tnn = NULL; ((tnn = avl_next_item(&ton->tun_net_tree, tnn ? &tnn->tunNetKey : NULL)));) {
		if ((!only_af || only_af == tnn->tunNetKey.netKey.af) ) {
//			struct tun_bit_node *tbn = NULL;
//			while ((tbn = avl_next_item(&tnn->tun_bit_tree, tbn ? &tbn->tunBitKey : NULL)) && !tbn->active_tdn);
//			used |= (tbn && tbn->active_tdn);
			upd_tun_bit_node(DEL, NULL, tnn);
			del_tun_net_node(tnn);
			tun6_nets_resetted = YES;
		}
	}
}


STATIC_FUNC
void terminate_tun_out(struct orig_node *on, struct tun_dev_offer *only_ton)
{
	IDM_T used = 0;
	struct tun_dev_offer_key key = set_tun_adv_key(on, 0);
	struct tun_dev_offer *ton;

	while ((ton = (only_ton ? only_ton : avl_closest_item(&tun_out_tree, &key))) && ton->tunOutKey.on == on) {
		key = ton->tunOutKey;


		dbgf_all(DBGT_INFO, "should remove tunnel_node localIp=%s tun6Id=%d nodeId=%s key=%s (tunnel_out.items=%d, tun->net.items=%d)",
			ip6AsStr(&ton->localIp), ton->tunOutKey.tun6Id, cryptShaAsString(&ton->tunOutKey.on->k.nodeId),
			memAsHexString(&ton->tunOutKey, sizeof(key)), tun_out_tree.items, ton->tun_net_tree.items);

		struct tun_net_offer *tnn;
		while ((tnn = avl_first_item(&ton->tun_net_tree))) {
			uint8_t isv4 = (tnn->tunNetKey.netKey.af == AF_INET);
			used |= (ton->tdnDedicated46[isv4] || ton->tdnDedicated46[isv4]);
			upd_tun_bit_node(DEL, NULL, tnn);
			del_tun_net_node(tnn);
		}

		assertion(-501385, (!ton->tun_net_tree.items));
		struct tun_dev_offer *rtun = avl_remove(&tun_out_tree, &key, -300410);
		assertion(-501253, (rtun == ton));
		debugFree(rtun, -300425);
		CHECK_INTEGRITY();

		if (only_ton)
			break;
		else
			key.tun6Id++;
	}

	if (used) {
		task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 0));
		task_register(0, (void(*)(void*))eval_tun_bit_tree, ((void*) 0), -300000);
	}
}



STATIC_FUNC
int process_dsc_tlv_tun6(struct rx_frame_iterator *it)
{
	int32_t m;

	if (it->dcOp->kn == myKey)
		return it->f_msgs_len;

	if (it->op == TLV_OP_DEL || (it->op == TLV_OP_NEW && !is_ip_set(&it->on->primary_ip))) {

		tun6_advs_added = NO;
		tun6_nets_resetted = NO;
		terminate_tun_out(it->on, NULL);

		return it->f_msgs_len;

	} else if (it->op == TLV_OP_NEW) {

		tun6_advs_added = NO;
		tun6_nets_resetted = NO;
		assertion(-500000, (is_ip_set(&it->on->primary_ip)));

		if (!desc_frame_changed(it->dcOld, it->dcOp, it->f_type))
			return it->f_msgs_len;


	} else if (it->op != TLV_OP_TEST) {

		return it->f_msgs_len;
	}

	assertion(-500000, (it->op == TLV_OP_TEST || it->op == TLV_OP_NEW));

	if (it->op == TLV_OP_TEST) {
		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6 *adv = &(((struct dsc_msg_tun6 *) (it->f_data))[m]);
			struct tun_dev_offer_key key = set_tun_adv_key(it->on, m);

			dbgf_track(DBGT_INFO, "op=%s tunnel_out.items=%d tun_net.items=%d msg=%d/%d localIp=%s nodeId=%s key=%s",
				tlv_op_str(it->op), tun_out_tree.items, tun_net_tree.items, m, it->f_msgs_fixed,
				ip6AsStr(&adv->localIp), nodeIdAsStringFromDescAdv(it->dcOp->desc_frame),
				memAsHexString(&key, sizeof(key)));

			struct hna_node *un = NULL;
			struct tun_dev_in *tin = NULL;

			if (!is_ip_valid(&adv->localIp, AF_INET6) ||
				is_ip_net_equal(&adv->localIp, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6) ||
				(tin = avl_find_item_by_field(&tun_in_tree, &adv->localIp, tun_dev_in, remoteDummyIp6)) ||
				(un = find_overlapping_hna(&adv->localIp, 128, it->on))) {
				dbgf_sys(DBGT_ERR, "nodeId=%s %s=%s blocked (by my %s=%s or other's %s with nodeId=%s)",
					nodeIdAsStringFromDescAdv(it->dcOp->desc_frame),
					ARG_TUN_DEV, ip6AsStr(&adv->localIp),
					ARG_TUN_IN, tin ? tin->nameKey.str : DBG_NIL,
					ARG_UHNA, un ? cryptShaAsString(un->on ? &un->on->k.nodeId : &myKey->kHash) : DBG_NIL);

				return TLV_RX_DATA_BLOCKED;
			}
		}

	} else if (it->op == TLV_OP_NEW) {
		struct tun_dev_offer_key key;
		struct tun_dev_offer *ton;

		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6 *adv = &(((struct dsc_msg_tun6 *) (it->f_data))[m]);
			key = set_tun_adv_key(it->on, m);
			if ((ton = avl_find_item(&tun_out_tree, &key)) && !is_ip_equal(&ton->localIp, &adv->localIp)) {
				reset_tun_out(ton, NO);
				ton->localIp = adv->localIp;
			}
			if (!ton) {
				assertion(-500005, (!avl_find_item(&tun_out_tree, &key)));
				struct tun_dev_offer *ton = debugMallocReset(sizeof(struct tun_dev_offer), -300426);
				ton->tunOutKey = key;
				ton->localIp = adv->localIp;
				ton->ingressPrefix46[1] = ZERO_NET4_KEY;
				ton->ingressPrefix46[0] = ZERO_NET6_KEY;
				ton->remotePrefix46[1] = ZERO_NET4_KEY;
				ton->remotePrefix46[0] = ZERO_NET6_KEY;
				AVL_INIT_TREE(ton->tun_net_tree, struct tun_net_offer, tunNetKey);
				avl_insert(&tun_out_tree, ton, -300427);
				reset_tun_out(ton, NO);
				tun6_advs_added = YES;
			}
		}

		key = set_tun_adv_key(it->on, it->f_msgs_fixed - 1);
		while ((ton = avl_next_item(&tun_out_tree, &key)) && ton->tunOutKey.on == it->on)
			terminate_tun_out(it->on, ton);
	}

	return it->f_msgs_len;
}

STATIC_FUNC
int create_dsc_tlv_tunXin6ingress(struct tx_frame_iterator *it)
{
	struct tun_dev_in *tin;
	struct avl_node *an = NULL;
	uint8_t isv4 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_INGRESS);
	uint8_t af = (isv4 ? AF_INET : AF_INET6);
	int32_t pos = 0;
	uint16_t msg_size = isv4 ? sizeof(struct dsc_msg_tun4in6ingress) : sizeof(struct dsc_msg_tun6in6ingress);


	while ((tin = avl_iterate_item(&tun_in_tree, &an))) {

		if (tin->upIfIdx && tin->ingressPrefix.af == af && tin->ingressPrefix.mask && tin->ingressPrefix.mask <= (isv4 ? 32 : 128)) {

			if (pos + msg_size > tx_iterator_cache_data_space_pref(it, 0, 0)) {
				memset(tx_iterator_cache_msg_ptr(it), 0, pos);
				return TLV_TX_DATA_FULL;
			}

			struct dsc_msg_tun6in6ingress *adv =
				(struct dsc_msg_tun6in6ingress *) (tx_iterator_cache_msg_ptr(it) + pos);

			adv->tun6Id = tin->tun6Id;
			adv->ingressPrefixLen = tin->ingressPrefix.mask;

			if (isv4)
				*((IP4_T*) & adv->ingressPrefix) = ipXto4(tin->ingressPrefix.ip);
			else
				adv->ingressPrefix = tin->ingressPrefix.ip;

			pos += msg_size;
		}
	}
	return pos;
}

STATIC_FUNC
int process_dsc_tlv_tunXin6ingress(struct rx_frame_iterator *it)
{
	uint8_t isv4 = (it->f_type == BMX_DSC_TLV_TUN4IN6_INGRESS);
	int32_t m;
	struct tun_dev_offer_key key;
	struct tun_dev_offer *ton;

	if (it->dcOp->kn == myKey)
		return it->f_msgs_len;

	if (it->op == TLV_OP_NEW && !desc_frame_changed(it->dcOld, it->dcOp, it->f_type) && !tun6_advs_added)
		return it->f_msgs_len;

	if (it->op == TLV_OP_DEL) {
		for (key = set_tun_adv_key(it->on, 0); ((ton = avl_closest_item(&tun_out_tree, &key)) && ton->tunOutKey.on == it->on); key.tun6Id = (ton->tunOutKey.tun6Id + 1)) {
			if (ton->ingressPrefix46[isv4].mask)
				reset_tun_out(ton, (isv4 ? AF_INET : AF_INET6));
			ton->ingressPrefix46[isv4] = isv4 ? ZERO_NET4_KEY : ZERO_NET6_KEY;
		}
	}

	if (it->op == TLV_OP_TEST) {

		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6in6ingress *adv = (((struct dsc_msg_tun6in6ingress *) &(it->f_data[m*it->f_handl->min_msg_size])));
			IPX_T prefix = isv4 ? ip4ToX(*((IP4_T*) & adv->ingressPrefix)) : adv->ingressPrefix;
			if (ip_netmask_validate(&prefix, adv->ingressPrefixLen, (isv4 ? AF_INET : AF_INET6), NO) == FAILURE)
				return TLV_RX_DATA_FAILURE;
		}
	}

	if (it->op == TLV_OP_NEW) {

		for (key = set_tun_adv_key(it->on, 0); ((ton = avl_closest_item(&tun_out_tree, &key)) && ton->tunOutKey.on == it->on); key.tun6Id = (ton->tunOutKey.tun6Id + 1)) {
			ton->updated46[isv4] = NO;
		}

		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6in6ingress *adv = (((struct dsc_msg_tun6in6ingress *) &(it->f_data[m*it->f_handl->min_msg_size])));
			IPX_T prefix = isv4 ? ip4ToX(*((IP4_T*) & adv->ingressPrefix)) : adv->ingressPrefix;
			struct net_key net = *setNet(NULL, (isv4 ? AF_INET : AF_INET6), adv->ingressPrefixLen, &prefix);

			key = set_tun_adv_key(it->on, adv->tun6Id);
			
			if ((ton = avl_find_item(&tun_out_tree, &key))) {
				if (memcmp(&ton->ingressPrefix46[isv4], &net, sizeof(net))) {
					reset_tun_out(ton, (isv4 ? AF_INET : AF_INET6));
					ton->ingressPrefix46[isv4] = net;
				}
				ton->updated46[isv4] = YES;
			}
		}

		for (key = set_tun_adv_key(it->on, 0); ((ton = avl_closest_item(&tun_out_tree, &key)) && ton->tunOutKey.on == it->on); key.tun6Id = (ton->tunOutKey.tun6Id + 1)) {
			if (!ton->updated46[isv4])
				reset_tun_out(ton, (isv4 ? AF_INET : AF_INET6));
		}
	}
	return it->f_msgs_len;
}

STATIC_FUNC
int create_dsc_tlv_tunXin6remote(struct tx_frame_iterator *it)
{
	struct tun_dev_in *tin;
	struct avl_node *an = NULL;
	uint8_t isv4 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_SRC);
	uint8_t af = (it->frame_type == BMX_DSC_TLV_TUN4IN6_SRC) ? AF_INET : AF_INET6;
	int32_t pos = 0;
	uint16_t msg_size = isv4 ? sizeof(struct dsc_msg_tun4in6remote) : sizeof(struct dsc_msg_tun6in6remote);


	while ((tin = avl_iterate_item(&tun_in_tree, &an))) {

		if (tin->upIfIdx && tin->remotePrefix.af == af && tin->remotePrefix.mask && tin->remotePrefix.mask <= (isv4 ? 32 : 128)) {

			if (pos + msg_size > tx_iterator_cache_data_space_pref(it, 0, 0)) {
				memset(tx_iterator_cache_msg_ptr(it), 0, pos);
				return TLV_TX_DATA_FULL;
			}

			struct dsc_msg_tun6in6remote *adv =
				(struct dsc_msg_tun6in6remote *) (tx_iterator_cache_msg_ptr(it) + pos);

			adv->tun6Id = tin->tun6Id;
			adv->mode.srcType = tin->remotePrefixMode;
			adv->mode.reserved = 0;
			adv->mode.exhausted = 0;
			adv->srcPrefixLen = tin->remotePrefix.mask;
			adv->srcPrefixMin = XMAX(tin->remotePrefixMin, tin->remotePrefix.mask);

			if (isv4)
				*((IP4_T*) & adv->srcPrefix) = ipXto4(tin->remotePrefix.ip);
			else
				adv->srcPrefix= tin->remotePrefix.ip;

			pos += msg_size;
		}
	}
	return pos;
}

STATIC_FUNC
int process_dsc_tlv_tunXin6remote(struct rx_frame_iterator *it)
{
	uint8_t isv4 = (it->f_type == BMX_DSC_TLV_TUN4IN6_SRC);
	int32_t m;
	struct tun_dev_offer_key key;
	struct tun_dev_offer *ton;

	if (it->dcOp->kn == myKey)
		return it->f_msgs_len;

	if (it->op == TLV_OP_NEW && !desc_frame_changed(it->dcOld, it->dcOp, it->f_type) && !tun6_advs_added)
		return it->f_msgs_len;

	if (it->op == TLV_OP_DEL) {
		for (key = set_tun_adv_key(it->on, 0); ((ton = avl_closest_item(&tun_out_tree, &key)) && ton->tunOutKey.on == it->on); key.tun6Id = (ton->tunOutKey.tun6Id + 1)) {
			if (ton->remotePrefix46[isv4].mask)
				reset_tun_out(ton, (isv4 ? AF_INET : AF_INET6));
			ton->remotePrefix46[isv4] = isv4 ? ZERO_NET4_KEY : ZERO_NET6_KEY;
			ton->remotePrefixMin46[isv4] = 0;
			ton->remoteMode46[isv4] = 0;
		}
	}

	if (it->op == TLV_OP_TEST) {
		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6in6remote *adv = (((struct dsc_msg_tun6in6remote *) &(it->f_data[m*it->f_handl->min_msg_size])));
			IPX_T prefix = isv4 ? ip4ToX(*((IP4_T*) & adv->srcPrefix)) : adv->srcPrefix;
			if (
				!adv->srcPrefixLen ||
				ip_netmask_validate(&prefix, adv->srcPrefixLen, (isv4 ? AF_INET : AF_INET6), NO) == FAILURE ||
				adv->srcPrefixMin > (isv4 ? 32 : 128) ||
				adv->srcPrefixMin < adv->srcPrefixLen ||
				adv->mode.srcType > MAX_TUN_DEV_MODE) {

				return TLV_RX_DATA_FAILURE;
			}
		}
	}

	if (it->op == TLV_OP_NEW) {
		for (key = set_tun_adv_key(it->on, 0); ((ton = avl_closest_item(&tun_out_tree, &key)) && ton->tunOutKey.on == it->on); key.tun6Id = (ton->tunOutKey.tun6Id + 1)) {
			ton->updated46[isv4] = NO;
		}
		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6in6remote *adv = (((struct dsc_msg_tun6in6remote *) &(it->f_data[m*it->f_handl->min_msg_size])));
			IPX_T prefix = isv4 ? ip4ToX(*((IP4_T*) & adv->srcPrefix)) : adv->srcPrefix;
			struct net_key net = *setNet(NULL, (isv4 ? AF_INET : AF_INET6), adv->srcPrefixLen, &prefix);

			key = set_tun_adv_key(it->on, adv->tun6Id);

			if ((ton = avl_find_item(&tun_out_tree, &key))) {
				if (memcmp(&ton->remotePrefix46[isv4], &net, sizeof(net)) ||
					ton->remotePrefixMin46[isv4] != adv->srcPrefixMin ||
					ton->remoteMode46[isv4] != adv->mode.srcType )
				{
					reset_tun_out(ton, (isv4 ? AF_INET : AF_INET6));
					ton->remotePrefix46[isv4] = net;
					ton->remotePrefixMin46[isv4] = adv->srcPrefixMin;
					ton->remoteMode46[isv4] = adv->mode.srcType;
				}

				ton->updated46[isv4] = YES;
			}
		}
		for (key = set_tun_adv_key(it->on, 0); ((ton = avl_closest_item(&tun_out_tree, &key)) && ton->tunOutKey.on == it->on); key.tun6Id = (ton->tunOutKey.tun6Id + 1)) {
			if (!ton->updated46[isv4])
				reset_tun_out(ton, (isv4 ? AF_INET : AF_INET6));
		}
	}
	return it->f_msgs_len;
}


STATIC_FUNC
uint32_t create_description_tlv_tunXin6_net_adv_msg(struct tx_frame_iterator *it, struct dsc_msg_tun6in6net *adv, uint32_t m, char *tun_name)
{
	IDM_T is4in6 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET) ? YES : NO;
	IFNAME_T nameKey = {.str = {0}};
	strcpy(nameKey.str, tun_name ? tun_name : "");
	struct tun_dev_in *tun = tun_name ? avl_find_item(&tun_in_tree, nameKey.str) : avl_first_item(&tun_in_tree);

	dbgf_all(DBGT_INFO, "name=%s src=%s dst=%s/%d",
		tun_name, tun ? ip6AsStr(&tun->remoteDummyIp6) : "MISSING!", ip6AsStr(&adv->network), adv->networkLen);

	assertion(-501442, (adv->bandwidth.val.u8));
	assertion(-501443, ip_netmask_validate(&adv->network, adv->networkLen, (is4in6 ? AF_INET : AF_INET6), NO /*force*/) == SUCCESS);

	if (tun && tun->upIfIdx && tx_iterator_cache_data_space_pref(it, ((m + 1) * it->handl->min_msg_size), 100)) {

		assertion(-501387, (!strncmp(tun->nameKey.str, tun_name_prefix.str, strlen(tun_name_prefix.str))));
		adv->tun6Id = tun->tun6Id;

		if (is4in6) {
			struct dsc_msg_tun4in6net *msg4 = &(((struct dsc_msg_tun4in6net *) tx_iterator_cache_msg_ptr(it))[m]);
			msg4->network = ipXto4(adv->network);
			msg4->networkLen = adv->networkLen;
			msg4->bandwidth = adv->bandwidth;
			msg4->proto_type = adv->proto_type;
			msg4->tun6Id = adv->tun6Id;

		} else {
			((struct dsc_msg_tun6in6net *) tx_iterator_cache_msg_ptr(it))[m] = *adv;
		}

		m++;

	} else if (tun && tun->upIfIdx) {
		dbgf_mute(30, DBGL_SYS, DBGT_ERR, "NO description space left for src=%s dst=%s",
			ip6AsStr(&tun->remoteDummyIp6), ip6AsStr(&adv->network));
	}

	return m;
}

STATIC_FUNC
int create_dsc_tlv_tunXin6net(struct tx_frame_iterator *it)
{
	IDM_T isv4 = (it->frame_type == BMX_DSC_TLV_TUN4IN6_NET) ? YES : NO;
	uint8_t af = isv4 ? AF_INET : AF_INET6;
	uint32_t m = 0, should = 0;
	UMETRIC_T umax = UMETRIC_FM8_MAX;

	struct tun_dev_in *tin;
	struct avl_node *an = NULL;
	while ((tin = avl_iterate_item(&tun_in_tree, &an))) {

		if (tin->upIfIdx && tin->tunAddr.mask && tin->tunAddr.af == af) {

			struct dsc_msg_tun6in6net adv = {
				.network = tin->tunAddr.ip,
				.networkLen = tin->tunAddr.mask,
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
		struct dsc_msg_tun6in6net adv = { .proto_type = DEF_TUN_PROTO_ADV, .bandwidth = umetric_to_fmu8(&um) };

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
		m, should, (isv4 ? "v4" : "v6"), (should != m ? "due to lack of description space!!" : ""));

	return m * (isv4 ? sizeof(struct dsc_msg_tun4in6net) : sizeof(struct dsc_msg_tun6in6net));
}

STATIC_FUNC
int process_dsc_tlv_tunXin6net(struct rx_frame_iterator *it)
{
	uint8_t family = (it->f_type == BMX_DSC_TLV_TUN4IN6_NET ? AF_INET : AF_INET6);
	int32_t m = 0;
	uint8_t used = NO;

	if (it->dcOp->kn == myKey && it->op != TLV_OP_TEST)
		return it->f_msgs_len;

	if (it->op == TLV_OP_NEW && !desc_frame_changed(it->dcOld, it->dcOp, it->f_type) && !tun6_advs_added && !tun6_nets_resetted)
		return it->f_msgs_len;

	if (it->op == TLV_OP_TEST) {

		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6in6net *adv = (((struct dsc_msg_tun6in6net *) &(it->f_data[m*it->f_handl->min_msg_size])));
			IPX_T ipx = (family == AF_INET) ? ip4ToX(*((IP4_T*) & adv->network)) : adv->network;

			if (ip_netmask_validate(&ipx, adv->networkLen, family, NO) == FAILURE) {
				dbgf_sys(DBGT_ERR, "net=%s/%d", ipXAsStr(family, &ipx), adv->networkLen);
				return TLV_RX_DATA_FAILURE;
			}
			dbgf_track(DBGT_INFO, "accepted msg %d/%d: net=%s/%d", m, it->f_msgs_fixed, ipXAsStr(family, &ipx), adv->networkLen);
		}
	}

	if (it->op == TLV_OP_NEW) {

		for (m = 0; m < it->f_msgs_fixed; m++) {
			struct dsc_msg_tun6in6net *adv = (((struct dsc_msg_tun6in6net *) &(it->f_data[m*it->f_handl->min_msg_size])));
			IPX_T ipx = (family == AF_INET) ? ip4ToX(*((IP4_T*) & adv->network)) : adv->network;
			struct tun_dev_offer_key tok = set_tun_adv_key(it->on, adv->tun6Id);
			struct tun_dev_offer *ton = avl_find_item(&tun_out_tree, &tok);
			char *what = "No tun_out or zero bw for";

			if (ton && adv->bandwidth.val.u8) {
				struct tun_net_offer_key tnk = ZERO_TUN_NET_KEY;
				tnk.ton = ton;
				setNet(&tnk.netKey, family, adv->networkLen, &ipx);
				tnk.bmx7RouteType = adv->proto_type;

				struct tun_net_offer *tnn = avl_find_item(&tun_net_tree, &tnk);

				if (!tnn) {
					tnn = debugMallocReset(sizeof(struct tun_net_offer), -300418);
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

				assertion(-501578, (tnn->tunNetKey.ton->tunOutKey.on == tok.on));
				tnn->updated = YES;
			}
			dbgf_track(ton ? DBGT_INFO : DBGT_WARN, "%s net=%s/%d bw=%d orig=%s tun6Id=%d",
				what, ipXAsStr(family, &ipx), adv->networkLen, adv->bandwidth.val.u8, cryptShaAsString(&tok.on->k.nodeId), tok.tun6Id);
		}
	}

	if (it->op == TLV_OP_NEW || it->op == TLV_OP_DEL) {

		// Purge tun6Xin6_net advertisements that were not updated:
		struct tun_dev_offer_key tok;
		struct tun_dev_offer *ton;
		for (tok = set_tun_adv_key(it->on, 0); ((ton = avl_find_item(&tun_out_tree, &tok))); tok.tun6Id++) {

			struct tun_net_offer *tnn;
			struct tun_net_offer_key tnk = ZERO_TUN_NET_KEY;
			while ((tnn = avl_next_item(&ton->tun_net_tree, &tnk))) {
				tnk = tnn->tunNetKey;

				if (tnn->tunNetKey.netKey.af != family)
					continue;

				if (tnn->updated) {
					tnn->updated = NO;
				} else {
					assertion(-501390, (tnn->tunNetKey.netKey.af == family));
					struct tun_bit_node *tbn = NULL;
					while ((tbn = avl_next_item(&tnn->tun_bit_tree, tbn ? &tbn->tunBitKey : NULL)) && !tbn->active_tdn);
					used |= (tbn && tbn->active_tdn);
					upd_tun_bit_node(DEL, NULL, tnn);
					del_tun_net_node(tnn);
				}
			}
		}

		if (used)
			eval_tun_bit_tree(NULL);
	}

	return it->f_msgs_len;
}

struct tun_out_status {
	char* tunOut;
	GLOBAL_ID_T *gwId;
	GLOBAL_ID_T *longGwId;
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
	char *tunOutDev;
	char *tunDev;
	char *tunDevOut;
	char srcSearch[IPX_PREFIX_STR_LEN+4];
	int16_t sSMode;
	char srcAddr[IPX_PREFIX_STR_LEN];
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
	char srcOffer[IPX_PREFIX_STR_LEN+4];
	int16_t srcMode;
	UMETRIC_T advBwVal;
	UMETRIC_T *advBw;
	UMETRIC_T *pathMtc;
	UMETRIC_T tunMtcVal;
	UMETRIC_T *tunMtc;
	IPX_T *localTunIp;
	IPX_T *remoteTunIp;
};

#define FIELD_RELEVANCE_TUNPROT FIELD_RELEVANCE_LOW

static const struct field_format tun_out_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunOut,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  tun_out_status, gwId,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, longGwId,    1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, gwName,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, src,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, proto,       1, FIELD_RELEVANCE_TUNPROT),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, net,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, min,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, max,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, aOLP,        1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, bOSP,        1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, hyst,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, rating,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, minBw,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, pref,        1, FIELD_RELEVANCE_TUNPROT),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, table,       1, FIELD_RELEVANCE_TUNPROT),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, ipMtc,       1, FIELD_RELEVANCE_TUNPROT),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunOutDev,   1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunDev,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunDevOut,   1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, srcSearch,   1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, sSMode,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, srcAddr,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, tunName,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, setProto,    1, FIELD_RELEVANCE_TUNPROT),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, tunRoute,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  tun_out_status, remoteId,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, tun_out_status, remoteLongId,1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      tun_out_status, remoteName,  1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, tunId,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, advProto,    1, FIELD_RELEVANCE_TUNPROT),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, advNet,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, srcIngress,  1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       tun_out_status, srcOffer,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, srcMode,     1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, advBwVal,    1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, advBw,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, pathMtc,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           tun_out_status, tunMtcVal,   1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_UMETRIC,   tun_out_status, tunMtc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, localTunIp,  1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             tun_out_status, remoteTunIp, 1, FIELD_RELEVANCE_MEDI),
//        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              tun_out_status, up,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t tun_out_status_creator(struct status_handl *handl, void *data)
{

	struct tun_net_offer *tnn;
	struct tun_search_node *tsn;
	struct avl_node *an;

	int32_t status_size = tun_bit_tree.items * sizeof(struct tun_out_status);

	for (an = NULL; (tnn = avl_iterate_item(&tun_net_tree, &an));)
		status_size += (tnn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));

	for (an = NULL; (tsn = avl_iterate_item(&tun_search_tree, &an));)
		status_size += (tsn->tun_bit_tree.items ? 0 : sizeof(struct tun_out_status));


	struct tun_out_status *s = (struct tun_out_status *) (handl->data = debugRealloc(handl->data, status_size, -300428));
	memset(s, 0, status_size);

	struct avl_tree * t[] = { &tun_search_tree, &tun_bit_tree, &tun_net_tree };
	uint8_t a;
	for (a = 0; a < 3; a++) {
		void *p;
		for (an = NULL; (p = avl_iterate_item(t[a], &an));) {

			struct tun_bit_node *tbn = (t[a] == &tun_bit_tree) ? p : NULL;
			struct tun_net_offer *tnn = (t[a] == &tun_net_tree) ? p : (tbn ? tbn->tunBitKey.keyNodes.tnn : NULL);
			struct tun_search_node *tsn = (t[a] == &tun_search_tree) ? p : (tbn ? tbn->tunBitKey.keyNodes.tsn : NULL);

			if (!tbn && tsn && tsn->tun_bit_tree.items)
				continue;

			if (!tbn && tnn && tnn->tun_bit_tree.items)
				continue;
			
			assertion(-500000, (tsn || tnn));

			IDM_T isv4 = ((tsn ? tsn->net.af : tnn->tunNetKey.netKey.af) == AF_INET);

			if (tsn) {
				s->tunOut = tsn->nameKey;
				s->gwId = &tsn->gwId;
				s->longGwId = &tsn->gwId;
				s->gwName = strlen(tsn->gwName) ? tsn->gwName : DBG_NIL;
				s->proto = tsn->routeSearchProto;
				s->setProto = tsn->routeSetProto;
				strcpy(s->net, netAsStr(&(tsn->net)));
				strcpy(s->src, tsn->srcRtNet.mask ? netAsStr(&(tsn->srcRtNet)) : DBG_NIL);
				s->min = tsn->netPrefixMin == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMin;
				s->max = tsn->netPrefixMax == TYP_TUN_OUT_PREFIX_NET ? tsn->net.mask : tsn->netPrefixMax;
				s->aOLP = tsn->allowLargerPrefixRoutesWithWorseTunMetric;
				s->bOSP = tsn->breakSmallerPrefixRoutesWithBetterTunMetric;
				s->hyst = tsn->hysteresis;
				s->rating = tsn->rating;
				s->minBw = tsn->minBW ? &tsn->minBW : NULL;
				s->table = tsn->iptable;
				s->pref = tsn->iprule;
				s->ipMtc = tsn->ipmetric;
				s->tunOutDev = strlen(tsn->tunInNameKey.str) ? tsn->tunInNameKey.str : DBG_NIL;
			} else {
				s->tunOutDev = DBG_NIL;
				s->tunOut = DBG_NIL;
				s->gwName = DBG_NIL;
				s->proto = -1;
				s->setProto = -1;
				strcpy(s->net, DBG_NIL);
				strcpy(s->src, DBG_NIL);
			}

			if (tbn) {
				struct net_key tunRoute = tbn->tunBitKey.invRouteKey;
				tunRoute.mask = tbn ? (128 - tunRoute.mask) : 0;
				strcpy(s->tunRoute, netAsStr(&tunRoute));

				s->tunName = (tbn->active_tdn ? tbn->active_tdn->nameKey.str : DBG_NIL);
				s->tunMtcVal = UMETRIC_MAX - ntoh64(tbn->tunBitKey.beInvTunBitMetric);
				s->tunMtc = s->tunMtcVal ? &s->tunMtcVal : NULL;

			} else {
				strcpy(s->tunRoute, DBG_NIL);
				s->tunName = DBG_NIL;
			}

			struct tun_dev_in *tin = tnn && tnn->tunNetKey.ton->tin46[isv4] ? tnn->tunNetKey.ton->tin46[isv4] : NULL;

			if (tin) {
				s->tunDev = tin->nameKey.str;
				s->tunDevOut = strlen(tin->tunSearchNameKey) ? tin->tunSearchNameKey : DBG_NIL;
				sprintf(s->srcSearch, "%s<=%d",netAsStr(&tin->localPrefix),tin->localPrefixMax);
				s->sSMode = tin->localPrefixMode;
				strcpy(s->srcAddr, netAsStr(&tin->tunAddr));
			} else {
				s->tunDev = DBG_NIL;
				s->tunDevOut = DBG_NIL;
				strcpy(s->srcSearch, DBG_NIL);
				strcpy(s->srcAddr, DBG_NIL);
			}




			if (tnn) {
				struct tun_dev_offer *ton = tnn->tunNetKey.ton;
				assertion(-501391, (ton));

				s->remoteName = strlen(ton->tunOutKey.on->k.hostname) ? ton->tunOutKey.on->k.hostname : DBG_NIL;
				s->remoteId = &ton->tunOutKey.on->k.nodeId;
				s->localTunIp = &ton->localIp;
				s->remoteTunIp = &ton->tunOutKey.on->primary_ip;
				s->tunId = ton->tunOutKey.tun6Id;
				s->advProto = tnn->tunNetKey.bmx7RouteType;
				strcpy(s->advNet, netAsStr(&tnn->tunNetKey.netKey));
				strcpy(s->srcIngress, netAsStr(&ton->ingressPrefix46[isv4]));
				sprintf(s->srcOffer, "%s>=%d",netAsStr(&ton->remotePrefix46[isv4]), ton->remotePrefixMin46[isv4]);
				s->srcMode = ton->remoteMode46[isv4];
				s->advBwVal = fmetric_u8_to_umetric(tnn->bandwidth);
				s->advBw = s->advBwVal ? &s->advBwVal : NULL;
				s->pathMtc = ton->tunOutKey.on->neighPath.link ? &ton->tunOutKey.on->neighPath.um : NULL;
			} else {
				strcpy(s->advNet, DBG_NIL);
				strcpy(s->srcIngress, DBG_NIL);
				strcpy(s->srcOffer, DBG_NIL);
			}

			s++;
		}
	}

	assertion(-501322, (handl->data + status_size == (uint8_t*) s));

	return status_size;
}

STATIC_FUNC
int32_t opt_tun_in(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
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
	struct tun_search_node *tsn = NULL;

	if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

		struct opt_child *c = NULL;
		char name[NETWORK_NAME_LEN] = { 0 };

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

			} else if (!strcmp(c->opt->name, ARG_TUN_DEV)) {

				if (c->val && (strlen(c->val) >= NETWORK_NAME_LEN ||
					validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS ||
					strncmp(tun_name_prefix.str, c->val, strlen(tun_name_prefix.str)))) {

					dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s (MUST begin with: %s)",
						c->val, tun_name_prefix.str);

					return FAILURE;

				} else if (cmd == OPT_APPLY && tsn) {

					memset(&tsn->tunInNameKey, 0, sizeof(IFNAME_T));

					if (c->val)
						strcpy(tsn->tunInNameKey.str, c->val);
				}

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

				GLOBAL_ID_T pkid = { .h.u32 =
					{0 } };

				if (c->val) {

					if (hexStrToMem(c->val, pkid.h.u8, sizeof(pkid), YES/*strict*/) == FAILURE)
						return FAILURE;


					set_opt_child_val(c, memAsHexString(&pkid, sizeof(pkid)));

					if (cmd == OPT_APPLY && tsn)
						memcpy(&tsn->gwId, &pkid, sizeof(pkid));

				} else if (cmd == OPT_APPLY && tsn) {
					memset(&tsn->gwId, 0, sizeof(pkid));
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
	struct tun_dev_out *tdnUP;
	while ((tdnUP = avl_first_item(&tun_catch_tree))) {
		assertion(-501543, (!tdnUP->tun_bit_tree[0].items && !tdnUP->tun_bit_tree[1].items));
		avl_remove(&tun_catch_tree, &tdnUP->tunCatchKey, -300546);
		kernel_dev_tun_del(tdnUP->nameKey.str, tdnUP->tunCatch_fd);
		debugFree(tdnUP, -300547);
	}
}

STATIC_FUNC
IDM_T opt_tun_in_dev_args(uint8_t cmd, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn, struct tun_dev_in *tin)
{

	struct opt_child *c = NULL;

	while ((c = list_iterate(&patch->childs_instance_list, c))) {

		struct net_key net = ZERO_NET_KEY;
		net.af = tin ? tin->af : 0;

		dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "tin=%s af=%d cmd=%s name=%s val=%s",
			tin ? tin->nameKey.str : NULL, tin ? tin->af : 0, opt_cmd2str[cmd], c->opt->name, c->val);

		if (
			!strcmp(c->opt->name, ARG_TUN_DEV_ADDR) ||
			!strcmp(c->opt->name, ARG_TUN_DEV_MODE_LOCALPREFIX) ||
			!strcmp(c->opt->name, ARG_TUN_DEV_MODE_REMOTEPREFIX) ||
			!strcmp(c->opt->name, ARG_TUN_DEV_INGRESS)
			) {

			if (!c->val) {

				net = ZERO_NET_KEY;

			} else if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, !strcmp(c->opt->name, ARG_TUN_DEV_ADDR)) == FAILURE ||
				((!strcmp(c->opt->name, ARG_TUN_DEV_ADDR) || !strcmp(c->opt->name, ARG_TUN_DEV_MODE_REMOTEPREFIX)) && !is_ip_valid(&net.ip, net.af)) ||
				(!strcmp(c->opt->name, ARG_TUN_DEV_ADDR) && net.mask < (net.af ? HNA4_PREFIXLEN_MIN : HNA6_PREFIXLEN_MIN))) {

				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s or invalid af=%s",
					c->opt->name, patch->val, c->val, net.af==AF_INET ? "IPv4":"IPv6");
				return FAILURE;

			} else if (cmd == OPT_ADJUST) {

				set_opt_child_val(c, netAsStr(&net));
			}

			if (cmd == OPT_APPLY && tin) {

				if (!strcmp(c->opt->name, ARG_TUN_DEV_ADDR))
					tin->tunAddr = net;
				
				if (!strcmp(c->opt->name, ARG_TUN_DEV_MODE_LOCALPREFIX))
					tin->localPrefix = net;

				if (!strcmp(c->opt->name, ARG_TUN_DEV_MODE_REMOTEPREFIX))
					tin->remotePrefix = net;

				if (!strcmp(c->opt->name, ARG_TUN_DEV_INGRESS))
					tin->ingressPrefix = net;

				tin->af = net.af ? net.af : tin->af;
			}

		} else if (!strcmp(c->opt->name, ARG_TUN_DEV_REMOTE_DUMMY)) {

			struct net_key p6 = ZERO_NET6_KEY;

			if (c->val) {

				struct hna_node *un_remote = NULL;

				if (str2netw(c->val, &p6.ip, cn, NULL, &p6.af, YES) == FAILURE ||
					!is_ip_valid(&p6.ip, p6.af) ||
					(un_remote = find_overlapping_hna(&p6.ip, 128, NULL))) {

					dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid %s=%s %s=%s or blocked by nodeId=%s",
						ARG_TUN_DEV, patch->val, ARG_TUN_DEV_REMOTE_DUMMY, c->val,
						(un_remote && un_remote->on) ? cryptShaAsString(&un_remote->on->k.nodeId) : DBG_NIL);

					return FAILURE;
				}

				set_opt_child_val(c, netAsStr(&p6));
			}

			if (cmd == OPT_APPLY && tin) {
				tin->remoteDummyIp6 = p6.ip;
				tin->remoteDummy_manual = c->val ? 1 : 0;
			}

		} else if (!strcmp(c->opt->name, ARG_TUN_DEV_MODE_REMOTE)) {

			if (cmd == OPT_APPLY && tin)
				tin->remotePrefixMode = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_DEV_MODE;


		} else if (!strcmp(c->opt->name, ARG_TUN_DEV_MODE_REMOTE_MIN)) {

			if (cmd == OPT_APPLY && tin)
				tin->remotePrefixMin = c->val ? strtol(c->val, NULL, 10) : 0;


		} else if (!strcmp(c->opt->name, ARG_TUN_OUT)) {

			if (c->val && (strlen(c->val) >= NETWORK_NAME_LEN ||
				validate_name_string(c->val, strlen(c->val) + 1, NULL) != SUCCESS)) {

				return FAILURE;

			} else if (cmd == OPT_APPLY && tin) {

				memset(&tin->tunSearchNameKey, 0, sizeof(IFNAME_T));

				if (c->val)
					strcpy(tin->tunSearchNameKey, c->val);
			}

		} else if (!strcmp(c->opt->name, ARG_TUN_DEV_MODE_LOCAL)) {

			if (cmd == OPT_APPLY && tin)
				tin->localPrefixMode = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_DEV_MODE;


		} else if (!strcmp(c->opt->name, ARG_TUN_DEV_MODE_LOCAL_MAX)) {

			if (cmd == OPT_APPLY && tin)
				tin->localPrefixMax = c->val ? strtol(c->val, NULL, 10) : 0;


		} else if (!strcmp(c->opt->name, ARG_TUN_PROTO_ADV)) {

			if (cmd == OPT_APPLY && tin)
				tin->advProto = c->val ? strtol(c->val, NULL, 10) : DEF_TUN_PROTO_ADV;

		}
	}
	return SUCCESS;
}

STATIC_FUNC
void configure_tunnel_in(uint8_t del, struct tun_dev_in *tin)
{
	assertion(-501341, IMPLIES(!del, (is_ip_set(&my_primary_ip))));
	assertion(-501311, IMPLIES(tin->upIfIdx, tin->nameKey.str[0]));
	assertion(-501342, IMPLIES(tin->upIfIdx, del));

	if (del && tin->upIfIdx) {

		struct tun_dev_offer *ton;
		while ((ton = avl_first_item(&tin->tun_dev_offer_tree))) {
			dbgf_track(DBGT_INFO, "Removing ton name=%s tunId=%d", ton->tunOutKey.on->k.hostname, ton->tunOutKey.tun6Id);
			struct avl_node *an = NULL;
			struct tun_net_offer *tnn;
			while ((tnn = avl_iterate_item(&ton->tun_net_tree, &an))) {
				upd_tun_bit_node(DEL, NULL, tnn);
			}
		}

		IDM_T result = kernel_tun_del(tin->nameKey.str);
		assertion(-501451, (result == SUCCESS));
		tin->upIfIdx = 0;
		my_description_changed = YES;

	} else if (!del && !tin->upIfIdx) {

		IPX_T *local = &my_primary_ip;
		IPX_T *remote = &tin->remoteDummyIp6;

		if (!tin->remoteDummy_manual) {
			tin->remoteDummyIp6 = my_primary_ip;
			tin->remoteDummyIp6.s6_addr[DEF_AUTO_TUNID_OCT_POS] += (tin->tun6Id + MIN_AUTO_TUNID_OCT);
		}

		assertion(-500000, (is_ip_set(remote) && !is_ip_local(remote)));
		assertion(-501312, (strlen(tin->nameKey.str)));

		if ((tin->upIfIdx = kernel_tun_add(tin->nameKey.str, IPPROTO_IP, local, remote)) > 0) {

			if (tin->tunAddr.mask)
				kernel_set_addr(ADD, tin->upIfIdx, tin->tunAddr.af, &tin->tunAddr.ip, ((tin->tunAddr.af == AF_INET) ? 32 : 128), NO /*deprecated*/);

			my_description_changed = YES;
		}

		upd_tun_bit_node(ADD, NULL, NULL);
	}

	assertion(-500000, (XOR(del, tin->upIfIdx)));
}


STATIC_FUNC
int32_t opt_tun_in_dev(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

		char name[NETWORK_NAME_LEN] = {0};
		snprintf(name, sizeof(name), "%s%s", tun_name_prefix.str, patch->val);
		struct tun_dev_in *tin = avl_find_item(&tun_in_tree, name);

		dbgf_all(DBGT_INFO, "diff=%d cmd=%s  save=%d  opt=%s  patch=%s",
			patch->diff, opt_cmd2str[cmd], _save, opt->name, patch->val);

		if ( (!tin && tun_in_tree.items >= MAX_AUTO_TUNID_OCT) ||
			strlen(patch->val) >= NETWORK_NAME_LEN - strlen(tun_name_prefix.str) ||
			validate_name_string(patch->val, strlen(patch->val) + 1, NULL) != SUCCESS) {

			dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid name: %s %s", patch->val, tun_name_prefix.str);
			return FAILURE;
		}

		if (cmd == OPT_APPLY) {

			purge_tunCatchTree();

			if (tin)
				configure_tunnel_in(DEL, tin);

			assertion(-500000, IMPLIES(tin, !tin->tun_dev_offer_tree.items));
			assertion(-500000, IMPLIES(tin, !tin->upIfIdx));

			if (tin && patch->diff == DEL) {

				avl_remove(&tun_in_tree, name, -300467);
				debugFree(tin, -300468);
				tin = NULL;

			} else if (!tin && patch->diff != DEL) {
				tin = debugMallocReset(sizeof(struct tun_dev_in), -300469);
				strcpy(tin->nameKey.str, name);
				tin->tun6Id = get_free_tun6Id();
				tin->remoteDummyIp6 = ZERO_IP;
				tin->tunAddr = ZERO_NET_KEY;
				tin->ingressPrefix = ZERO_NET_KEY;
				tin->remotePrefix = ZERO_NET_KEY;
				tin->localPrefix = ZERO_NET_KEY;

				tin->remoteDummy_manual = 0;
				tin->advProto = DEF_TUN_PROTO_ADV;
				AVL_INIT_TREE(tin->tun_dev_offer_tree, struct tun_dev_offer, tunOutKey);
				avl_insert(&tun_in_tree, tin, -300470);
			}
		}

		if (opt_tun_in_dev_args(cmd, opt, patch, cn, tin) != SUCCESS)
			return FAILURE;

		if (cmd == OPT_APPLY) {

			if (tin)
				configure_tunnel_in(ADD, tin);

			eval_tun_bit_tree(NULL);
		}
	}
	return SUCCESS;
}

STATIC_FUNC
int32_t opt_tun_name_prefix(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
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
	if (cmd == OPT_APPLY) {

		static int32_t prev_to = DEF_TUN_OUT_TO;
		prev_to = tun_dedicated_to;
		tun_dedicated_to = patch->diff != DEL ? strtol(patch->val, NULL, 10) : DEF_TUN_OUT_TO;

		struct tun_dev_offer *ton;
		struct avl_node *an = NULL;

		while ((ton = avl_iterate_item(&tun_out_tree, &an))) {
			uint8_t isv4;
			struct tun_dev_out *tdnUP;

			for (isv4 = 0; isv4 <= 1; isv4++) {

				if ((tdnUP = ton->tdnCatchAll46[isv4])) {

					assertion(-501544, (tdnUP->tunCatch_fd > 0));

					if (tun_dedicated_to == 0) {
						tun_out_state_set(ton, TDN_STATE_DEDICATED);
					} else if (tun_dedicated_to > 0) {

					}
				}

				if ((tdnUP = ton->tdnDedicated46[isv4])) {

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
	if (cmd == OPT_APPLY) {

		tun_out_mtu = patch->diff != DEL ? strtol(patch->val, NULL, 10) : DEF_TUN_OUT_MTU;

		struct tun_dev_offer *ton;
		struct avl_node *an = NULL;

		while ((ton = avl_iterate_item(&tun_out_tree, &an))) {
			uint8_t isv4;
			for (isv4 = 0; isv4 <= 1; isv4++) {
				struct tun_dev_out *tdnUP = ton->tdnDedicated46[isv4];
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

	{ODI,0,ARG_TUN_OUT_DELAY,       0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&tun_out_delay, MIN_TUN_OUT_DELAY,MAX_TUN_OUT_DELAY,DEF_TUN_OUT_DELAY,0, 0,
			ARG_VALUE_FORM, "Delay catched tunnel packets for given us before rescheduling (avoid dmesg warning ip6_tunnel: X7Out_.. xmit: Local address not yet configured!)"},


//order must be after ARG_HOSTNAME (which initializes self via init_self(), called from opt_hostname):
	{ODI,0,ARG_TUN_DEV, 	        0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_tun_in_dev,
                ARG_NAME_FORM, "define incoming ipip tunnel interface name (prefix is " ARG_TUN_NAME_PREFIX "=" DEF_TUN_NAME_PREFIX ") and sub criteria\n"
	"        eg: " ARG_TUN_DEV "=Default (resulting interface name would be: " DEF_TUN_NAME_PREFIX "Default )\n"
	"        WARNING: This creates a general ipip tunnel device allowing to tunnel arbitrary IP packets to this node!\n"
	"        Use firewall rules to filter deprecated packets!"},

	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_ADDR,  0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_ADDR_FORM,HLP_TUN_DEV_ADDR},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_INGRESS,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_NETW_FORM, HLP_TUN_DEV_INGRESS},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_MODE_LOCALPREFIX,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_NETW_FORM,HLP_TUN_DEV_MODE_LOCALXPREFIX},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_MODE_LOCAL,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_DEV_MODE,MAX_TUN_DEV_MODE,DEF_TUN_DEV_MODE,0,    opt_tun_in_dev,
			ARG_VALUE_FORM, HLP_TUN_DEV_MODE_LOCAL},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_MODE_LOCAL_MAX,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        128,             0,0,            opt_tun_in_dev,
			ARG_VALUE_FORM, HLP_TUN_DEV_MODE_LOCALX_MAX},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_MODE_REMOTEPREFIX,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        0,              0,0,            opt_tun_in_dev,
			ARG_NETW_FORM,HLP_TUN_DEV_MODE_REMOTEXPREFIX},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_MODE_REMOTE,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_TUN_DEV_MODE,MAX_TUN_DEV_MODE,DEF_TUN_DEV_MODE,0,   opt_tun_in_dev,
			ARG_VALUE_FORM, HLP_TUN_DEV_MODE_REMOTEX},
	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_MODE_REMOTE_MIN,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	        0,	        128,             0,0,            opt_tun_in_dev,
			ARG_VALUE_FORM, HLP_TUN_DEV_MODE_REMOTEX_MIN},
	{ODI,ARG_TUN_DEV,ARG_TUN_OUT,0,9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,		0,              0,              0,0,            opt_tun_in_dev,
			ARG_NAME_FORM,	"tunOut config allowed to trigger automatic tunnel source address (prefix) configuration"},

	{ODI,ARG_TUN_DEV,ARG_TUN_DEV_REMOTE_DUMMY,0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,	0,	        0,              0,0,            opt_tun_in_dev,
			ARG_IP_FORM,	"remote dummy ip of tunnel interface"},
	{ODI,ARG_TUN_DEV,ARG_TUN_PROTO_ADV, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0, MIN_TUN_PROTO_ADV,MAX_TUN_PROTO_ADV,DEF_TUN_PROTO_ADV,0,     opt_tun_in_dev,
			ARG_VALUE_FORM, HLP_TUN_PROTO_ADV},

        {ODI,0,ARG_TUN_IN,	 	0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,	        opt_tun_in,
			ARG_NAME_FORM,"arbitrary but unique name for tunnel network to be announced with given sub criterias"},
	{ODI,ARG_TUN_IN,ARG_TUN_IN_NET,'n',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,               0,              0,              0,0,            opt_tun_in,
			ARG_ADDR_FORM,"network to be offered via incoming tunnel (mandatory)"},
	{ODI,ARG_TUN_IN,ARG_TUN_IN_BW, 'b',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,		0,	        0,              0,0,            opt_tun_in,
			ARG_VALUE_FORM,	HLP_TUN_IN_BW},
	{ODI,ARG_TUN_IN,ARG_TUN_DEV,    0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,		0,              0,              0,0,            opt_tun_in,
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
	{ODI,ARG_TUN_OUT,ARG_TUN_PROTO_SET,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0, MIN_TUN_PROTO_SET,MAX_TUN_PROTO_SET,DEF_TUN_PROTO_SET,0,      opt_tun_search,
			ARG_VALUE_FORM, HLP_TUN_PROTO_SET},
	{ODI,ARG_TUN_OUT,ARG_TUN_DEV,    0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,		0,              0,              0,0,            opt_tun_search,
			ARG_NAME_FORM,	HLP_TUN_IN_DEV},
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
	{ODI,0, ARG_FIND_PREFIX,	   0,  9,2, A_PS1N,A_USR, A_DYN, A_ARG, A_ANY, 0,        0,              0,             0,0,             opt_find_prefix,
			ARG_NETW_FORM,	""},
	{ODI,ARG_FIND_PREFIX,ARG_FIND_PREFIX_MASK,0,9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,         0,             128,            0,0,             opt_find_prefix,
			ARG_VALUE_FORM,	""},
	{ODI,ARG_FIND_PREFIX,ARG_MATCH_PREFIX,0,9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,         0,             0,            0,0,             opt_find_prefix,
			ARG_VALUE_FORM,	""}
        ,

	{ODI,0,ARG_TUNS,	        0,9,2,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show announced and used tunnels and related networks"}

};
STATIC_FUNC
void tun_dev_event_hook(int32_t cb_id, void* unused)
{
        struct tun_dev_in *tun;
        struct avl_node *an = NULL;
        while ((tun = avl_iterate_item(&tun_in_tree, &an))) {

                if (tun->upIfIdx && is_ip_local(&tun->remoteDummyIp6)) {
                        dbgf_sys(DBGT_WARN, "ERROR: %s=%s remote=%s already used!!!",
				ARG_TUN_DEV, tun->nameKey.str, ip6AsStr(&tun->remoteDummyIp6));
                        my_description_changed = YES;
                }
        }
}

static void tun_cleanup(void)
{
	task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 1));
	task_remove((void(*)(void*))eval_tun_bit_tree, ((void*) 0));

	purge_tunCatchTree();

	struct tun_dev_in *tin;
	while ((tin = avl_remove_first_item(&tun_in_tree, -300393))) {
		assertion(-500000, (!tin->tun_dev_offer_tree.items));
		configure_tunnel_in(DEL, tin);
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
	static const struct field_format tun4in6_src_adv_format[] = DESCRIPTION_MSG_TUN4IN6_REMOTE_ADV_FORMAT;
	static const struct field_format tun6in6_src_adv_format[] = DESCRIPTION_MSG_TUN6IN6_REMOTE_ADV_FORMAT;
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
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun4in6remote);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6remote;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6remote;
	tlv_handl.msg_format = tun4in6_src_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_TUN4IN6_SRC, &tlv_handl);

	tlv_handl.name = "DSC_TUN6IN6_SRC";
	tlv_handl.min_msg_size = sizeof(struct dsc_msg_tun6in6remote);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
	tlv_handl.tx_frame_handler = create_dsc_tlv_tunXin6remote;
	tlv_handl.rx_frame_handler = process_dsc_tlv_tunXin6remote;
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
