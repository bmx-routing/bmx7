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
 *
 * Contributors:
 *	Simó Albert i Beltran
 */


 #define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <sys/types.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>


#include "bmx.h"
#include "ip.h"
#include "msg.h"
#include "schedule.h"
#include "plugin.h"
#include "tools.h"
#include "metrics.h"
#include "hna.h"

#define CODE_CATEGORY_NAME "ip"

uint8_t __af_cfg = DEF_IP_FAMILY;
struct net_key __ZERO_NETCFG_KEY = {.af = DEF_IP_FAMILY};

const struct net_key ZERO_NET_KEY = {.af = 0};
const struct net_key ZERO_NET4_KEY = {.af = AF_INET};
const struct net_key ZERO_NET6_KEY = {.af = AF_INET6};


const IFNAME_T ZERO_IFNAME = {{0}};

static const char *_af_cfg_read = NULL;

static int dev_lo_idx = 0;



static int32_t ip_prio_hna_cfg = DEF_IP_RULE_HNA;
static int32_t ip_prio_tun_cfg = DEF_IP_RULE_TUN;
static int32_t ip_table_hna_cfg = DEF_IP_TABLE_HNA;
static int32_t ip_table_tun_cfg = DEF_IP_TABLE_TUN;
static int32_t ip_prio_rules_cfg = DEF_IP_PRIO_RULES;
int32_t ip_throw_rules_cfg = DEF_IP_THROW_RULES;
int32_t ip_policy_rt_cfg = DEF_IP_POLICY_ROUTING;


int32_t policy_routing = POLICY_RT_UNSET;

static int32_t base_port = DEF_BASE_PORT;

#ifdef WITH_UNUSED
static int32_t Lo_rule = DEF_LO_RULE;
#endif

const IPX_T ZERO_IP = {{{0}}};
const MAC_T ZERO_MAC = {{0}};

//TODO: make this configurable
static struct net_key llocal_prefix_cfg;
static struct net_key global_prefix_cfg;
static struct net_key autoconf_prefix_cfg;
struct net_key remote_prefix_cfg;
struct tun_in_node default_tun_in;


//#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
//#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

const IP6_T IP6_LOOPBACK_ADDR = { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } };


//const IP6_T   IP6_ALLROUTERS_MC_ADDR = {.s6_addr[0] = 0xFF, .s6_addr[1] = 0x02, .s6_addr[15] = 0x02};
const IP6_T   IP6_ALLROUTERS_MC_ADDR = {{{0xFF,0x02,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x02}}};

//const IP6_T   IP6_LINKLOCAL_UC_PREF = {.s6_addr[0] = 0xFE, .s6_addr[1] = 0x80};
const IP6_T   IP6_LINKLOCAL_UC_PREF = {{{0xFE,0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}}};
const uint8_t IP6_LINKLOCAL_UC_PLEN = 10;

//const IP6_T   IP6_MC_PREF = {.s6_addr[0] = 0xFF};
const IP6_T   IP6_MC_PREF = {{{0xFF,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}}};
const uint8_t IP6_MC_PLEN = 8;


static int nlsock_default = -1;
static int nlsock_flush_all = -1;


static int rt_sock = 0;

struct rtnl_handle ip_rth = { .fd = -1 };

static IDM_T opt_dev_changed = YES;

struct dev_node *primary_dev = NULL;
struct dev_node *primary_phy = NULL;


//IDM_T niit_enabled = NO;

AVL_TREE(if_link_tree, struct if_link_node, index);

AVL_TREE(dev_ip_tree, struct dev_node, llocal_ip_key);
AVL_TREE(dev_name_tree, struct dev_node, name_phy_cfg);

AVL_TREE(iptrack_tree, struct track_node, k);


static LIST_SIMPEL( throw4_list, struct throw_node, list, list );

static int ifevent_sk = -1;


//static Sha ip_sha;



static int32_t Pedantic_cleanup = DEF_PEDANTIC_CLEANUP;
static int32_t if6_forward_orig = -1;
static int32_t if4_forward_orig = -1;
static int32_t if4_rp_filter_all_orig = -1;
static int32_t if4_rp_filter_default_orig = -1;
static int32_t if4_send_redirects_all_orig = -1;
static int32_t if4_send_redirects_default_orig = -1;




STATIC_FUNC
int rtnl_open(struct rtnl_handle *rth)
{
        unsigned subscriptions = 0;
        int protocol = NETLINK_ROUTE;
	socklen_t addr_len;
	int sndbuf = 32768;
        int rcvbuf = 1024 * 1024;

	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (rth->fd < 0) {
                dbgf_sys(DBGT_ERR, "Cannot open netlink socket");
		return FAILURE;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
		dbgf_sys(DBGT_ERR, "SO_SNDBUF");
		return FAILURE;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
		dbgf_sys(DBGT_ERR, "SO_RCVBUF");
		return FAILURE;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		dbgf_sys(DBGT_ERR, "Cannot bind netlink socket");
		return FAILURE;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
                dbgf_sys(DBGT_ERR, "Cannot getsockname");
		return FAILURE;
	}
	if (addr_len != sizeof(rth->local)) {
                dbgf_sys(DBGT_ERR, "Wrong address length %d\n", addr_len);
		return FAILURE;
	}
	if (rth->local.nl_family != AF_NETLINK) {
                dbgf_sys(DBGT_ERR, "Wrong address family %d\n", rth->local.nl_family);
		return FAILURE;
	}
	rth->seq = time(NULL);
	return SUCCESS;
}



STATIC_FUNC
int open_netlink_socket( void ) {

        int sock = 0;
	if ( ( sock = socket( AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE ) ) < 0 ) {

		dbgf_sys(DBGT_ERR, "can't create netlink socket for routing table manipulation: %s",
		     strerror(errno) );

		return -1;
	}


	if ( fcntl( sock, F_SETFL, O_NONBLOCK) < 0 ) {

		dbgf_sys(DBGT_ERR, "can't set netlink socket nonblocking : (%s)",  strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}




STATIC_FUNC
void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}

	if (len) {
                dbgf_sys(DBGT_ERR, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
        }

}

STATIC_FUNC
IDM_T get_if_req(IFNAME_T *dev_name, struct ifreq *if_req, int siocgi_req)
{

	memset( if_req, 0, sizeof (struct ifreq) );

        if (dev_name)
                strncpy(if_req->ifr_name, dev_name->str, IFNAMSIZ - 1);

        errno = 0;
        if ( ioctl( rt_sock, siocgi_req, if_req ) < 0 ) {

                if (siocgi_req != SIOCGIWNAME) {
                        dbgf_sys(DBGT_ERR, "can't get SIOCGI %d of interface %s: %s",
                                siocgi_req, dev_name->str, strerror(errno));
                }
                return FAILURE;
	}

	return SUCCESS;
}

extern unsigned int if_nametoindex (const char *);

uint32_t get_if_index(IFNAME_T *name) {
        return if_nametoindex(name->str);
}


STATIC_FUNC
void add_rtattr(struct nlmsghdr *nlh, int rta_type, char *data, uint16_t data_len, uint16_t family)
{
	TRACE_FUNCTION_CALL;
        IP4_T ip4;
        if (family == AF_INET) {
                ip4 = ipXto4((*((IPX_T*)data)));
                data_len = sizeof (ip4);
                data = (char*) & ip4;
        }

        struct rtattr *rta = (struct rtattr *)(((char *) nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
        int len = RTA_LENGTH(data_len);

        nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(len);

        assertion(-50173, (NLMSG_ALIGN(nlh->nlmsg_len) < RT_REQ_BUFFSIZE));
        // if this fails then double req buff size !!

        rta->rta_type = rta_type;
        rta->rta_len = len;
        memcpy( RTA_DATA(rta), data, data_len );
}






STATIC_FUNC
uint32_t prio_macro_to_prio(int8_t prio_macro)
{
        assertion(-501100, (IMPLIES(prio_macro, (prio_macro >= RT_PRIO_MIN && prio_macro <= RT_PRIO_MAX))));

        if (policy_routing == POLICY_RT_DISABLED)
                return 0;

        else if (prio_macro == RT_PRIO_HNA)
		return ip_prio_hna_cfg;

        else if (prio_macro == RT_PRIO_TUNS)
		return ip_prio_tun_cfg;

	return 0;
}


STATIC_FUNC
uint32_t table_macro_to_table(int8_t table_macro)
{
        assertion(-501101, (IMPLIES(table_macro, (table_macro >= RT_TABLE_MIN && table_macro <= RT_TABLE_MAX))));

        if (policy_routing == POLICY_RT_DISABLED)
                return 0;

	else if ( table_macro == RT_TABLE_HNA )
		return ip_table_hna_cfg;

	else if ( table_macro == RT_TABLE_TUN )
		return ip_table_tun_cfg;

	return 0;
}

STATIC_FUNC
char *del2str(IDM_T del)
{
        return ( del ? "DEL" : "ADD");
}

#ifdef WITH_UNUSED
STATIC_FUNC
char *rtn2str(uint8_t rtn)
{
	if ( rtn == RTN_UNICAST )
		return "RTN_UNICAST";

	else if ( rtn == RTN_THROW )
		return "RTN_THROW  ";

	return "RTN_ILLEGAL";
}

STATIC_FUNC
char *rta2str(uint8_t rta)
{
	if ( rta == RTA_DST )
		return "RTA_DST";

	return "RTA_ILLEGAL";
}
#endif

STATIC_FUNC
char *trackt2str(uint8_t cmd)
{
	if ( cmd == IP_NOP )
		return "TRACK_NOP";

        else if ( cmd == IP_RULE_FLUSH )
		return "RULE_FLUSH";

        else if ( cmd == IP_RULE_DEFAULT )
		return "RULE_DEFAULT";

        else if ( cmd == IP_RULE_TEST )
		return "RULE_TEST";

        else if (cmd == IP_ROUTE_FLUSH_ALL)
                return "ROUTE_FLUSH_ALL";

        else if (cmd == IP_ROUTE_FLUSH)
                return "ROUTE_FLUSH";

        else if ( cmd == IP_THROW_MY_HNA )
		return "THROW_MY_HNA";

	else if ( cmd == IP_THROW_MY_NET )
		return "THROW_MY_NET";

	else if ( cmd == IP_ROUTE_HOST )
		return "ROUTE_HOST";

	else if ( cmd == IP_ROUTE_HNA )
		return "ROUTE_HNA";

	else if ( cmd == IP_ROUTE_TUNS )
		return "ROUTE_TUNS";

	else if ( cmd == IP_ADDRESS )
		return "ADDRESS";

        return "TRACK_ILLEGAL";
}

char *family2Str(uint8_t family)
{
        static char b[B64_SIZE];

        switch (family) {
        case AF_INET:
                return "inet";
        case AF_INET6:
                return "inet6";
        default:
                sprintf( b, "%d ???", family);
                return b;
        }
}




void ipXToStr(int family, const IPX_T *addr, char *str)
{
        assertion(-500583, (str));
        uint32_t *a;

        if (!addr && (family == AF_INET6 || family == AF_INET)) {

                strcpy(str, "---");
                return;

        } else if (family == AF_INET) {

                a = (uint32_t *)&(addr->s6_addr32[3]);

        } else if (family == AF_INET6) {
                
                a = (uint32_t *)&(addr->s6_addr32[0]);

        } else {
                strcpy(str, "ERROR");
                return;
        }

        inet_ntop(family, a, str, family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);
	return;
}

void ipFToStr(const IPX_T *addr, char *str)
{
        ipXToStr(AF_CFG, addr, str);
}

IPX_T ip4ToX(IP4_T ip4)
{
        IPX_T ip = ZERO_IP;
        ip.s6_addr32[3] = ip4;
        return ip;
}

char *ipXAsStr(int family, const IPX_T *addr)
{
	static uint8_t c=0;
        static char str[IP2S_ARRAY_LEN][INET6_ADDRSTRLEN];

	c = (c+1) % IP2S_ARRAY_LEN;

        ipXToStr(family, addr, str[c]);

        return str[c];
}

char *ipFAsStr(const IPX_T *addr)
{
        return ipXAsStr(AF_CFG, addr);
}

char *ip4AsStr( IP4_T addr )
{

	static uint8_t c=0;
	static char str[IP2S_ARRAY_LEN][INET_ADDRSTRLEN];

	c = (c+1) % IP2S_ARRAY_LEN;

	inet_ntop( AF_INET, &addr, str[c], INET_ADDRSTRLEN );

	return str[c];
}

char *netAsStr(const struct net_key *net)
{
	static uint8_t c=0;
        static char str[IP2S_ARRAY_LEN][IPXNET_STR_LEN];

	c = (c+1) % IP2S_ARRAY_LEN;

        if(net) {
                ipXToStr(net->af, &net->ip, str[c]);
                sprintf(&((str[c]) [ strlen(str[c])]), "/%d", net->mask);
        } else {
                sprintf(str[c], "---");
        }

        return str[c];
}

struct net_key * setNet(struct net_key *netp, uint8_t family, uint8_t prefixlen, IPX_T *ip)
{
        static struct net_key net;
        netp = netp ? netp : &net;
        *netp = ZERO_NET_KEY;
        netp->af = family;
        netp->mask = prefixlen;
        netp->ip = ip ? *ip : ZERO_IP;
        return netp;
}

char* macAsStr(const MAC_T* mac)
{
        return memAsHexString( mac, sizeof(MAC_T));
}

IDM_T is_mac_equal(const MAC_T *a, const MAC_T *b)
{
        return (a->u16[2] == b->u16[2] &&
                a->u16[1] == b->u16[1] &&
                a->u16[0] == b->u16[0]);

}


IDM_T is_ip_equal(const IPX_T *a, const IPX_T *b)
{
        return (a->s6_addr32[3] == b->s6_addr32[3] &&
                a->s6_addr32[2] == b->s6_addr32[2] &&
                a->s6_addr32[1] == b->s6_addr32[1] &&
                a->s6_addr32[0] == b->s6_addr32[0]);

}

IDM_T is_ip_net_equal(const IPX_T *netA, const IPX_T *netB, const uint8_t plen, const uint8_t family)
{

        IPX_T aprefix = *netA;
        IPX_T bprefix = *netB;

        ip_netmask_validate(&aprefix, plen, family, YES /*force*/);
        ip_netmask_validate(&bprefix, plen, family, YES /*force*/);

        return is_ip_equal(&aprefix, &bprefix);
}




IDM_T is_ip_set(const IPX_T *ip)
{
        return (ip && !is_ip_equal(ip, &ZERO_IP));
}

IDM_T is_ip_valid( const IPX_T *ip, const uint8_t family )
{
	TRACE_FUNCTION_CALL;

        if (!is_ip_set(ip))
                return NO;

        if (family != (is_zero((void*) ip, sizeof ( IPX_T) - sizeof (IP4_T)) ? AF_INET : AF_INET6))
                return NO;

        if (family == AF_INET6 ) {

                if (!is_ip_equal(ip, &IP6_LOOPBACK_ADDR))
                        return YES;
                

        } else if (family == AF_INET ) {

                if (ipXto4(*ip) != INADDR_LOOPBACK && ipXto4(*ip) != INADDR_NONE)
                        return YES;
        }

        return NO;
}

IDM_T is_ip_local(IPX_T *ip)
{

        struct if_link_node *iln;
        struct avl_node *lan = NULL;

        while ((iln = avl_iterate_item(&if_link_tree, &lan))) {

                if (iln->flags & IFF_UP)
                        continue;

                struct if_addr_node *ian;
                struct avl_node *aan = NULL;

                while ((ian = avl_iterate_item(&iln->if_addr_tree, &aan))) {
                        if (is_ip_equal(&ian->ip_addr, ip))
                                return YES;
                }
        }
        return NO;
}

IDM_T ip_netmask_validate(IPX_T *ipX, uint8_t mask, uint8_t family, uint8_t force)
{
	TRACE_FUNCTION_CALL;
        uint8_t nmask = mask;
        int i;
        IP4_T ip32 = 0, m32 = 0;

        if (nmask > (family == AF_INET ? 32 : 128))
                goto validate_netmask_error;

        if (family == AF_INET)
                nmask += (IP6_MAX_PREFIXLEN - IP4_MAX_PREFIXLEN);

        for (i = 3; i >= 0 && i >= (nmask / 32); i--) {

                if (!(ip32 = ipX->s6_addr32[i]))
                        continue;

                if ( force ) {

                        if (nmask <= (i * 32))
                                ipX->s6_addr32[i] = 0;
                        else
                                ipX->s6_addr32[i] = (ip32 & (m32 = htonl(0xFFFFFFFF << (32 - (nmask - (i * 32))))));

                } else {

                        if (nmask <= (i * 32))
                                goto validate_netmask_error;

                        else if (ip32 != (ip32 & (m32 = htonl(0xFFFFFFFF << (32 - (nmask - (i * 32)))))))
                                goto validate_netmask_error;
                }
        }


        return SUCCESS;
validate_netmask_error:

        dbgf_sys(DBGT_ERR, "inconsistent network prefix %s/%d (force=%d  nmask=%d, ip32=%s m32=%s)",
                ipXAsStr(family, ipX), mask, force, nmask, ip4AsStr(ip32), ip4AsStr(m32));

        return FAILURE;

}


STATIC_FUNC
struct dev_node * dev_get_by_name(char *name)
{
        IFNAME_T key = ZERO_IFNAME;

        strcpy(key.str, name);

        return avl_find_item(&dev_name_tree, &key);
}


STATIC_FUNC
IDM_T kernel_if_fix(IDM_T purge_all, uint16_t curr_sqn)
{
	TRACE_FUNCTION_CALL;
        uint16_t changed = 0;
        struct if_link_node *iln;
        int index = 0;

        while ((iln = avl_next_item(&if_link_tree, &index))) {

                index = iln->index;
                IPX_T addr = ZERO_IP;
                struct if_addr_node *ian;
                IDM_T addr_changed = 0;

                while ((ian = avl_next_item(&iln->if_addr_tree, &addr))) {

                        addr = ian->ip_addr;

                        if ( purge_all || curr_sqn != ian->update_sqn) {

                                dbgf(terminating || initializing ? DBGL_ALL : DBGL_SYS, DBGT_WARN,
                                        "addr index %d %s addr %s REMOVED",
                                        iln->index, ian->label.str, ipXAsStr(ian->ifa.ifa_family, &ian->ip_addr));

                                if (ian->dev) {
                                        ian->dev->hard_conf_changed = YES;
                                        ian->dev->if_llocal_addr = NULL;
                                        ian->dev->if_global_addr = NULL;
                                }

                                avl_remove(&iln->if_addr_tree, &addr, -300236);
                                debugFree(ian, -300237);
                                changed++;

                                continue;

                        } else {

                                changed += ian->changed;

                                addr_changed = YES;

                        }
                }

                struct dev_node *dev = dev_get_by_name(iln->name.str);

                if (purge_all || curr_sqn != iln->update_sqn) {

                        assertion(-500565, (!iln->if_addr_tree.items));

                        dbgf(terminating || initializing ? DBGL_ALL : DBGL_SYS, DBGT_WARN,
                                "link index %d %s addr %s REMOVED",
                                iln->index, iln->name.str, memAsHexString(&iln->addr, iln->alen));

                        avl_remove(&if_link_tree, &iln->index, -300232);
                        avl_remove(&if_link_tree, &iln->name, -300234);
                        debugFree(iln, -300230);
                        changed++;


                } else if (iln->changed || (addr_changed && dev && !dev->if_llocal_addr && !dev->if_global_addr)) {

                        if (dev)
                                dev->hard_conf_changed = YES;

                        changed += iln->changed;

                        dbgf_sys(DBGT_WARN, "link=%s dev=%s configuration CHANGED",
                                iln->name.str, dev ? dev->label_cfg.str : "ERROR");

                }
        }

        if (changed) {

                dbgf_sys(DBGT_WARN, "network configuration CHANGED");
                return YES;
        
        } else {

                dbgf_all(DBGT_INFO, "network configuration UNCHANGED");
                return NO;
        }
}

STATIC_INLINE_FUNC
void kernel_if_addr_config(struct nlmsghdr *nlhdr, uint16_t index_sqn)
{
        TRACE_FUNCTION_CALL;

        int len = nlhdr->nlmsg_len;
        struct ifaddrmsg *if_addr = NLMSG_DATA(nlhdr);
        int index = if_addr->ifa_index;
        int family = if_addr->ifa_family;
        struct if_link_node *iln = avl_find_item(&if_link_tree, &index);

        if (!iln)
                return;

        if (family != AF_INET && family != AF_INET6)
                return;

        if (nlhdr->nlmsg_type != RTM_NEWADDR)
                return;

        if (len < (int) NLMSG_LENGTH(sizeof (if_addr)))
                return;


        len -= NLMSG_LENGTH(sizeof (*if_addr));
        if (len < 0) {
                dbgf_sys(DBGT_ERR, "BUG: wrong nlmsg len %d", len);
                return;
        }

        struct rtattr * rta_tb[IFA_MAX + 1];

        parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(if_addr), nlhdr->nlmsg_len - NLMSG_LENGTH(sizeof (*if_addr)));


        if (!rta_tb[IFA_LOCAL])
                rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];

        if (!rta_tb[IFA_LOCAL] || !if_addr)
                return;

        IPX_T ip_addr = ZERO_IP;

        uint32_t alen = MIN(sizeof (ip_addr), RTA_PAYLOAD(rta_tb[IFA_LOCAL]));

        memcpy(&ip_addr, RTA_DATA(rta_tb[IFA_LOCAL]), alen);

        if (family == AF_INET)
                ip_addr = ip4ToX(*((IP4_T*) (&ip_addr)));

        if (!is_ip_valid(&ip_addr, family)) // specially catch loopback ::1/128
                return;



        struct if_addr_node *new_ian = NULL;
        struct if_addr_node *old_ian = avl_find_item(&iln->if_addr_tree, &ip_addr);

        if (old_ian) {

                old_ian->changed = 0;

                if (old_ian->update_sqn == index_sqn) {
                        dbgf_sys(DBGT_ERR,
                                "ifi %d addr %s found several times!",
                                iln->index, ipXAsStr(old_ian->ifa.ifa_family, &ip_addr));
                }

                if (nlhdr->nlmsg_len > old_ian->nlmsghdr->nlmsg_len) {

                        if (old_ian->dev) {
                                old_ian->dev->hard_conf_changed = YES;
                                old_ian->dev->if_llocal_addr = NULL;
                                old_ian->dev->if_global_addr = NULL;
                        }

                        avl_remove(&iln->if_addr_tree, &ip_addr, -300239);
                        dbgf_sys(DBGT_ERR, "new size");

                } else if (memcmp(nlhdr, old_ian->nlmsghdr, nlhdr->nlmsg_len)) {

                        if (nlhdr->nlmsg_len != old_ian->nlmsghdr->nlmsg_len) {
                                dbgf_sys(DBGT_ERR, "different data and size %d != %d",
                                        nlhdr->nlmsg_len, old_ian->nlmsghdr->nlmsg_len);
                        }

                        memcpy(old_ian->nlmsghdr, nlhdr, nlhdr->nlmsg_len);
                        new_ian = old_ian;

                } else {
                        new_ian = old_ian;
                }

        }

        if (!new_ian) {
                new_ian = debugMalloc(sizeof (struct if_addr_node) +nlhdr->nlmsg_len, -300234);
                memset(new_ian, 0, sizeof (struct if_addr_node) +nlhdr->nlmsg_len);
                memcpy(new_ian->nlmsghdr, nlhdr, nlhdr->nlmsg_len);
                new_ian->ip_addr = ip_addr;
                new_ian->iln = iln;
                avl_insert(&iln->if_addr_tree, new_ian, -300238);
        }

        IFNAME_T label = {{0}};
        IPX_T ip_mcast = ZERO_IP;

        if (rta_tb[IFA_LABEL])
                strcpy(label.str, (char*) RTA_DATA(rta_tb[IFA_LABEL]));
        else
                label = iln->name;


        if (family == AF_INET && rta_tb[IFA_BROADCAST]) {

                memcpy(&ip_mcast, RTA_DATA(rta_tb[IFA_BROADCAST]), alen);
                ip_mcast = ip4ToX(*((IP4_T*) (&ip_mcast)));

        } else if (family == AF_INET6) {

                ip_mcast = IP6_ALLROUTERS_MC_ADDR;
        }


        if (!old_ian ||
                old_ian->ifa.ifa_family != if_addr->ifa_family ||
                old_ian->ifa.ifa_flags != if_addr->ifa_flags ||
                old_ian->ifa.ifa_prefixlen != if_addr->ifa_prefixlen ||
                old_ian->ifa.ifa_scope != if_addr->ifa_scope ||
                old_ian->ifa.ifa_index != if_addr->ifa_index ||
                memcmp(&old_ian->label, &label, sizeof (label)) ||
                //                                                memcmp(&old_ian->ip_any, &ip_any, alen) ||
                memcmp(&old_ian->ip_mcast, &ip_mcast, alen)
                ) {

                dbgf_track(DBGT_INFO, "%s addr %s CHANGED", label.str, ipXAsStr(family, &ip_addr));

                if (new_ian->dev) {
                        new_ian->dev->hard_conf_changed = YES;
                        new_ian->dev->if_llocal_addr = NULL;
                        new_ian->dev->if_global_addr = NULL;
                }


                new_ian->changed++;
        }

        new_ian->ifa.ifa_family = if_addr->ifa_family;
        new_ian->ifa.ifa_flags = if_addr->ifa_flags;
        new_ian->ifa.ifa_prefixlen = if_addr->ifa_prefixlen;
        new_ian->ifa.ifa_scope = if_addr->ifa_scope;
        new_ian->ifa.ifa_index = if_addr->ifa_index;

        new_ian->label = label;
        new_ian->ip_mcast = ip_mcast;

        new_ian->update_sqn = index_sqn;

        if (old_ian && old_ian != new_ian)
                debugFree(old_ian, -300240);

}


STATIC_FUNC
int kernel_if_link_config(struct nlmsghdr *nlhdr, uint16_t update_sqn)
{
	TRACE_FUNCTION_CALL;

	struct ifinfomsg *if_link_info = NLMSG_DATA(nlhdr);
	//struct idxmap *im, **imp;
	struct rtattr *tb[IFLA_MAX+1];

        uint16_t changed = 0;

	if (nlhdr->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (nlhdr->nlmsg_len < NLMSG_LENGTH(sizeof(if_link_info)))
		return -1;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(if_link_info), IFLA_PAYLOAD(nlhdr));

        if (!tb[IFLA_IFNAME])
                return 0;

        int index = if_link_info->ifi_index;
        struct if_link_node *new_ilx = NULL;
        struct if_link_node *old_ilx = avl_find_item(&if_link_tree, &index);

        if (old_ilx) {

                if (old_ilx->update_sqn == update_sqn) {
                        dbgf_sys(DBGT_ERR, "ifi %d found several times!", old_ilx->index);
                }

                assertion(-500902, (nlhdr->nlmsg_len >= sizeof (struct nlmsghdr)));

                if (nlhdr->nlmsg_len > old_ilx->nlmsghdr->nlmsg_len) {

                        avl_remove(&if_link_tree, &index, -300240);
                        dbgf_track(DBGT_INFO, "CHANGED and MORE nlmsg_len");

                } else if (memcmp(nlhdr, old_ilx->nlmsghdr, nlhdr->nlmsg_len)) {

                        if (nlhdr->nlmsg_len != old_ilx->nlmsghdr->nlmsg_len) {
                                dbgf_track(DBGT_INFO, "CHANGED and LESS nlmsg_len %d < %d",
                                        nlhdr->nlmsg_len, old_ilx->nlmsghdr->nlmsg_len);
                        } else {
                                dbgf_track(DBGT_INFO, "CHANGED but EQUAL nlmsg_len %d", nlhdr->nlmsg_len);
                        }
                        
                        memcpy(old_ilx->nlmsghdr, nlhdr, nlhdr->nlmsg_len);
                        new_ilx = old_ilx;
                
                } else {
                        new_ilx = old_ilx;
                }
        }

        if (!new_ilx) {
                new_ilx = debugMalloc(sizeof (struct if_link_node) + nlhdr->nlmsg_len, -300231);
                memset(new_ilx, 0, sizeof (struct if_link_node));
                new_ilx->index = if_link_info->ifi_index;
                AVL_INIT_TREE(new_ilx->if_addr_tree, struct if_addr_node, ip_addr);
                avl_insert(&if_link_tree, new_ilx, -300233);
                memcpy(new_ilx->nlmsghdr, nlhdr, nlhdr->nlmsg_len);
        }

        IFNAME_T devname = ZERO_IFNAME;
        strcpy(devname.str, RTA_DATA(tb[IFLA_IFNAME]));

        if (!strcmp(devname.str, DEV_LO)) {
                assertion(-501346, IMPLIES(dev_lo_idx, dev_lo_idx == if_link_info->ifi_index));
                dev_lo_idx = if_link_info->ifi_index;
        }

        int32_t alen = (tb[IFLA_ADDRESS]) ? RTA_PAYLOAD(tb[IFLA_ADDRESS]) : 0;
        ADDR_T addr = {{0}};
        memcpy(&addr, RTA_DATA(tb[IFLA_ADDRESS]), MIN(alen, (int)sizeof (addr)));

        if (!old_ilx ||
                old_ilx->type != if_link_info->ifi_type ||
                old_ilx->flags != if_link_info->ifi_flags ||
                old_ilx->alen != alen /*(int)RTA_PAYLOAD(tb[IFLA_ADDRESS])*/ ||
                memcmp(&old_ilx->addr, RTA_DATA(tb[IFLA_ADDRESS]), MIN(alen, (int)sizeof(old_ilx->addr))) ||
                memcmp(&old_ilx->name, &devname, sizeof (devname))) {

                dbgf_track(DBGT_INFO, "link=%s status type or flags or addr=%s CHANGED",
                        devname.str, memAsHexString(RTA_DATA(tb[IFLA_ADDRESS]), alen));

                changed++;
        }

        new_ilx->type = if_link_info->ifi_type;
        new_ilx->flags = if_link_info->ifi_flags;

        new_ilx->alen = alen;
        new_ilx->addr = addr;

        new_ilx->name = devname;

        new_ilx->update_sqn = update_sqn;
        new_ilx->changed = changed;

        if (old_ilx && old_ilx != new_ilx)
                debugFree(old_ilx, -300241);

	return 0;
}






static IDM_T kernel_if_config(void)
{
	TRACE_FUNCTION_CALL;

        static uint16_t index_sqn = 0;
        int rtm_type[2] = {RTM_GETLINK, RTM_GETADDR};
        int msg_count;
        int info;

        index_sqn++;
        dbgf_all( DBGT_INFO, "%d", index_sqn);

        for (info = LINK_INFO; info <= ADDR_INFO; info++) {

                struct ip_req req;
                struct sockaddr_nl nla;
                struct iovec iov;
                struct msghdr msg = {.msg_name = &nla, .msg_namelen = sizeof (nla), .msg_iov = &iov, .msg_iovlen = 1};
                char buf[4096]; //char buf[16384];

                iov.iov_base = buf;

                memset(&req, 0, sizeof (req));
                req.nlh.nlmsg_len = sizeof (req);
                req.nlh.nlmsg_type = rtm_type[info];
                req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
                req.nlh.nlmsg_pid = 0;
                req.nlh.nlmsg_seq = ip_rth.dump = ++ip_rth.seq;
                req.rtg.rtgen_family = AF_UNSPEC;

                if (send(ip_rth.fd, (void*) & req, sizeof (req), 0) < 0) {
                        dbgf_sys(DBGT_ERR, "failed");
                        return FAILURE;
                }

                dbgf(DBGL_TEST, DBGT_INFO, "send %s_INFO request", info == LINK_INFO ? "LINK" : "ADDR");

                while (1) {

                        iov.iov_len = sizeof (buf);

                        int status = recvmsg(ip_rth.fd, &msg, 0);
                        int err = errno;

                        dbgf(DBGL_TEST, DBGT_INFO, "rcvd %s_INFO status=%d",
                                info == LINK_INFO ? "LINK" : "ADDR", status);

                        if (status < 0) {

                                if (err == EINTR || err == EAGAIN)
                                        continue;

                                dbgf_sys(DBGT_ERR, "netlink receive error %s (%d)", strerror(err), err);
                                return FAILURE;

                        } else if (status == 0) {

                                dbgf_sys(DBGT_ERR, "EOF on netlink");
                                return FAILURE;
                        }

                        struct nlmsghdr *nlhdr = (struct nlmsghdr*) buf;

                        msg_count = 0;

                        for (; NLMSG_OK(nlhdr, (unsigned) status); nlhdr = NLMSG_NEXT(nlhdr, status)) {

                                msg_count++;

                                if (nla.nl_pid || nlhdr->nlmsg_pid != ip_rth.local.nl_pid || nlhdr->nlmsg_seq != ip_rth.dump) {
                                        dbgf_sys(DBGT_ERR, "pid/sqn mismatch: msg=%d status=%d  "
                                                "nl_pid=%d ==0!?  nlmsg_pid=%d == local.nl_pid=%d!? "
                                                "nlmsg_seq=%d == ip_rth.dump=%d!?",
                                                msg_count, status, nla.nl_pid, nlhdr->nlmsg_pid,
                                                ip_rth.local.nl_pid, nlhdr->nlmsg_seq, ip_rth.dump);
                                        continue;
                                }

                                if (nlhdr->nlmsg_type == NLMSG_DONE) {
                                        dbgf(DBGL_TEST, DBGT_INFO, "NLMSG_DONE");
                                        break;
                                }

                                if (nlhdr->nlmsg_type == NLMSG_ERROR) {
                                        dbgf_sys(DBGT_ERR, "NLMSG_ERROR");
                                        return FAILURE;
                                }


                                if (info == LINK_INFO )
                                        kernel_if_link_config(nlhdr, index_sqn);
                                else
                                        kernel_if_addr_config(nlhdr, index_sqn);

                        }

                        dbgf(DBGL_TEST, DBGT_INFO, "processed %d %s msgs status=%d",
                                msg_count, info == LINK_INFO ? "LINK" : "ADDR", status);
                        
                        if (nlhdr->nlmsg_type == NLMSG_DONE) {
                                dbgf(DBGL_TEST, DBGT_INFO, "NLMSG_DONE");
                                break;
                        }

                        if (msg.msg_flags & MSG_TRUNC) {
                                dbgf_sys(DBGT_ERR, "Message truncated");
                                continue;
                        }

                        if (status) {
                                dbgf_sys(DBGT_ERR, "Remnant of size %d", status);
                                return FAILURE;
                        }
                }
        }

        return kernel_if_fix(NO, index_sqn);

}


STATIC_FUNC
IDM_T rtnl_talk(void *req, int len, uint8_t family, uint8_t cmd, int8_t del, uint8_t quiet,
        const IPX_T *net, uint8_t nmask, IPX_T *via, int8_t table_macro)
{

        // DONT USE setNet() here (because return pointer is static)!!!!!!!!!!!!!

        uint32_t table = table_macro_to_table(table_macro);
        uint8_t more_data;
	struct nlmsghdr *nh;
        struct sockaddr_nl nladdr;
        memset(&nladdr, 0, sizeof (struct sockaddr_nl));
	nladdr.nl_family = AF_NETLINK;

        int nlsock = 0;

        if ( cmd == IP_ROUTE_FLUSH_ALL )
                nlsock = nlsock_flush_all;
        else
                nlsock = nlsock_default;


        if (sendto(nlsock, req, len, 0, (struct sockaddr *) & nladdr, sizeof (struct sockaddr_nl)) < 0) {

                dbgf_sys(DBGT_ERR, "can't send netlink message to kernel: %s", strerror(errno));
                EXITERROR(-501095, (0));
		return FAILURE;
        }

        int max_retries = 10;

        //TODO: see ip/libnetlink.c rtnl_talk() for HOWTO
        while (1) {
                struct msghdr msg;
                char buf[4096]; // less causes lost messages !!??
                memset(&msg, 0, sizeof (struct msghdr));

                memset(&nladdr, 0, sizeof (struct sockaddr_nl));
                nladdr.nl_family = AF_NETLINK;

                memset(buf, 0, sizeof(buf));
                struct iovec iov = {.iov_base = buf, .iov_len = sizeof (buf)};

		msg.msg_name = (void *)&nladdr;
		msg.msg_namelen = sizeof(nladdr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;

		errno=0;
		int status = recvmsg( nlsock, &msg, 0 );

                more_data = NO;

		if ( status < 0 ) {

			if ( errno == EINTR ) {

                                dbgf_sys(DBGT_WARN, "(EINTR) %s", strerror(errno));

                        } else if (errno == EWOULDBLOCK || errno == EAGAIN) {

                                dbgf_sys(DBGT_ERR, "(EWOULDBLOCK || EAGAIN) %s", strerror(errno));

                        } else {

                                dbgf_sys(DBGT_ERR, "%s", strerror(errno));
                        }

                        if ( max_retries-- > 0 ) {
                                usleep(500);
                                upd_time( NULL );
                                continue;
                        } else {
                                dbgf_sys(DBGT_ERR, "giving up!");
                                EXITERROR(-501096, (0));
                                return FAILURE;
                        }

		} else if (status == 0) {
                        dbgf_sys(DBGT_ERR, "netlink EOF");
                        EXITERROR(-501097, (0));
                        return FAILURE;
                }

                if (msg.msg_flags & MSG_TRUNC) {
                        dbgf_track(DBGT_INFO, "MSG_TRUNC");
                        more_data = YES;
                }

		nh = (struct nlmsghdr *)buf;

		while ( NLMSG_OK(nh, (size_t)status) ) {

                        if (nh->nlmsg_flags & NLM_F_MULTI) {
                                dbgf_all( DBGT_INFO, "NLM_F_MULTI");
                                more_data = YES;
                        }

                        if (nh->nlmsg_type == NLMSG_DONE) {
                                dbgf_track(DBGT_INFO, "NLMSG_DONE");
                                more_data = NO;
                                break;

                        } else if ((nh->nlmsg_type == NLMSG_ERROR) && (((struct nlmsgerr*) NLMSG_DATA(nh))->error != 0)) {

                                dbgf(quiet ? DBGL_ALL : DBGL_SYS, quiet ? DBGT_INFO : DBGT_ERR,
                                        "can't %s %s to %s/%i via %s table %i: %s",
                                        del2str(del), trackt2str(cmd), ipXAsStr(family, net), nmask, ipXAsStr(family, via),
                                        table, strerror(-((struct nlmsgerr*) NLMSG_DATA(nh))->error));

                                EXITERROR(-501098, (cmd == IP_RULE_FLUSH || cmd == IP_ROUTE_FLUSH || cmd == IP_RULE_TEST));
                                return FAILURE;
                        }

                        if (cmd == IP_ROUTE_FLUSH_ALL) {

                                struct rtmsg *rtm = (struct rtmsg *) NLMSG_DATA(nh);
                                struct rtattr *rtap = (struct rtattr *) RTM_RTA(rtm);
                                int rtl = RTM_PAYLOAD(nh);

                                while (rtm->rtm_table == table && RTA_OK(rtap, rtl)) {

                                        if (rtap->rta_type == RTA_DST) {


                                                IPX_T fip;
                                                struct net_key netf;

                                                if (rtm->rtm_family == AF_INET6)
                                                        fip = *((IPX_T *) RTA_DATA(rtap));
                                                else
                                                        fip = ip4ToX(*((IP4_T *) RTA_DATA(rtap)));

                                                setNet(&netf, family, rtm->rtm_dst_len, &fip);
                                                ip(IP_ROUTE_FLUSH, DEL, YES, &netf, table_macro, 0, 0, 0, 0, 0, 0);

                                        }

                                        rtap = RTA_NEXT(rtap, rtl);
                                }
                        }

                        nh = NLMSG_NEXT(nh, status);
		}

                if ( more_data ) {
                        dbgf_track(DBGT_INFO, "more data via netlink socket %d...", nlsock);
                } else {
                        break;
                }
        }

        return SUCCESS;
}


IDM_T ipaddr(IDM_T del, uint32_t if_index, uint8_t family, IPX_T *ipX, uint8_t prefixlen, IDM_T deprecated)
{

        struct ifamsg_req req;
        struct ifa_cacheinfo cinfo;

	memset(&req, 0, sizeof(req));

        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (del ? 0 : (NLM_F_CREATE | NLM_F_EXCL));
        req.nlh.nlmsg_type = del ? RTM_DELADDR : RTM_NEWADDR;
	req.ifa.ifa_family = family;
        req.ifa.ifa_index = if_index;

        req.ifa.ifa_prefixlen = prefixlen;
        req.ifa.ifa_scope = 0;

        add_rtattr(&req.nlh, IFA_LOCAL, (char*) ipX, sizeof (IPX_T), family);

/*
        if (family == AF_INET) {
                IP4_T ip4 = ipXto4(*ipX);
                add_rtattr(&req.nlh, IFA_LOCAL, (char*) &ip4, sizeof (ip4), req.ifa.ifa_family);
        } else {
                add_rtattr(&req.nlh, IFA_LOCAL, (char*) ipX, sizeof (IPX_T), req.ifa.ifa_family);
        }
*/

        if(deprecated) {
                memset(&cinfo, 0, sizeof (cinfo));
		cinfo.ifa_prefered = 0;
		cinfo.ifa_valid = INFINITY_LIFE_TIME;
                add_rtattr(&req.nlh, IFA_CACHEINFO, (char*) &cinfo, sizeof (cinfo), 0);
        }

        dbgf_track(DBGT_INFO, "del=%d ifidx=%d ip=%s/%d deprecated=%d", del, if_index, ipXAsStr(family, ipX), prefixlen, deprecated);

        return rtnl_talk(&req, req.nlh.nlmsg_len, family, IP_ADDRESS, del, NO, ipX, prefixlen, NULL, 0);
}

IDM_T iptunnel(IDM_T del, char *name, uint8_t proto, IPX_T *local, IPX_T *remote)
{

        dbgf_track(DBGT_INFO, "del=%d name=%s proto=%d local=%s remote=%s",
                del, name, proto, ip6AsStr(local), ip6AsStr(remote));

        struct ip6_tnl_parm p;
        struct ifreq req;

        assertion(-501293, (name && strlen(name)));

        memset(&p, 0, sizeof (p));
        strncpy(p.name, name, IFNAMSIZ);
        p.hop_limit = DEFAULT_TNL_HOP_LIMIT;
        p.encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
        p.proto = proto;

        if(remote)
                p.raddr = *remote;
        if(local)
                p.laddr = *local;

        memset(&req, 0, sizeof (req));
        strncpy(req.ifr_name, del ? name : "ip6tnl0", IFNAMSIZ);
        req.ifr_ifru.ifru_data = &p;

        if ((ioctl(rt_sock, del ? SIOCDELTUNNEL : SIOCADDTUNNEL, &req))) {
                dbgf_sys(DBGT_ERR, "creating tunnel dev name=%s %s", name, strerror(errno));
                return FAILURE;
        }

        if(!del) {
                memset(&req, 0, sizeof (req));
                strncpy(req.ifr_name, name, IFNAMSIZ);
                if ((ioctl(rt_sock, SIOCGIFFLAGS, &req))) {
                        dbgf_sys(DBGT_ERR, "getting tunnel flags name=%s %s", name, strerror(errno));
                        iptunnel(DEL, name, 0, NULL, NULL);
                        return FAILURE;
                }

                if ((req.ifr_flags & IFF_UP) != IFF_UP) {
                        req.ifr_flags |= IFF_UP;
                        if ((ioctl(rt_sock, SIOCSIFFLAGS, &req))) {
                                dbgf_sys(DBGT_ERR, "setting tunnel flags name=%s %s", name, strerror(errno));
                                iptunnel(DEL, name, 0, NULL, NULL);
                                return FAILURE;
                        }
                }
        }

        return SUCCESS;
}

IDM_T change_mtu(char *name, uint16_t mtu)
{
	struct ifreq req;

	req.ifr_addr.sa_family = AF_INET;
	strcpy(req.ifr_name, name);
	if (ioctl(rt_sock, SIOCGIFMTU, (caddr_t)&req) < 0) {
        	dbgf_sys(DBGT_ERR, "Can't read '%s' device %s", name, strerror(errno));
        	return FAILURE;
	}
    
	req.ifr_mtu = mtu;
    	if (ioctl(rt_sock, SIOCSIFMTU, (caddr_t)&req) < 0) {
        	dbgf_sys(DBGT_ERR, "Can't set MTU from '%s' %s", name, strerror(errno));
                return FAILURE;

	}
	return SUCCESS;
}


STATIC_FUNC
IDM_T iptrack(uint8_t family, uint8_t cmd, uint8_t quiet, int8_t del, const IPX_T *net, uint8_t mask, int8_t table_macro,
        int8_t prio_macro, IFNAME_T *iif, uint32_t metric)
{

        // DONT USE setNet() here (because return pointer is static)!!!!!!!!!!!!!

	TRACE_FUNCTION_CALL;
        assertion(-501232, (net));
        assertion(-500628, (cmd != IP_NOP));
        assertion(-500629, (del || (cmd != IP_ROUTE_FLUSH && cmd != IP_RULE_FLUSH)));

        if( cmd == IP_RULE_TEST)
                return YES;

        IDM_T flush = (cmd == IP_RULE_FLUSH || cmd == IP_ROUTE_FLUSH_ALL || cmd == IP_ROUTE_FLUSH);


        uint8_t cmd_t = (cmd > IP_ROUTES && cmd < IP_ROUTE_MAX) ? IP_ROUTES :
                ((cmd > IP_RULES && cmd < IP_RULE_MAX) ? IP_RULES : IP_NOP);

        struct track_key sk;
        memset(&sk, 0, sizeof (sk));
        sk.net = *net;
        sk.iif = iif ? *iif : ZERO_IFNAME;
        sk.prio_macro = prio_macro;
        sk.table_macro = table_macro;
        sk.family = family;
        sk.mask = mask;
        sk.metric = metric;
        sk.cmd_type = cmd_t;

        int found = 0, exact = 0;
        struct track_node *first_tn = NULL;
        struct avl_node *an = avl_find(&iptrack_tree, &sk);
        struct track_node *tn = an ? an->item : NULL;

        while (tn) {

                if (!first_tn && (tn->cmd == cmd || flush))
                        first_tn = tn;

                if (tn->cmd == cmd) {
                        assertion(-500887, (exact == 0));
                        exact += tn->items;
                }

                found += tn->items;

                tn = (tn = avl_iterate_item(&iptrack_tree, &an)) && !memcmp(&sk, &tn->k, sizeof (sk)) ? tn : NULL;
        }

        if (flush || (del && !first_tn) || (del && found != 1) || (!del && found > 0)) {

                dbgf(
                        quiet ? DBGL_ALL  : (flush || (del && !first_tn)) ? DBGL_SYS : DBGL_CHANGES,
                        quiet ? DBGT_INFO : (flush || (del && !first_tn)) ? DBGT_ERR : DBGT_INFO,
                        "   %s %s %s/%d  table %d  prio %d  dev %s exists %d tims with %d exact match",
                        del2str(del), trackt2str(cmd), ipXAsStr(family, net), mask,
                        table_macro_to_table(table_macro), prio_macro_to_prio(prio_macro),
                        iif ? iif->str : NULL, found, exact);

                EXITERROR(-500700, (!(!quiet && (flush || (del && !first_tn)))));
        }

        if (flush)
                return YES;

        if (del) {

                if (!first_tn) {
                        
                        assertion(-500883, (0));

                } else if (first_tn->items == 1) {

                        struct track_node *rem_tn = avl_remove(&iptrack_tree, &first_tn->k, -300250);
                        assertion(-501233, (rem_tn));
                        assertion(-500882, (rem_tn == first_tn));
                        debugFree(rem_tn, -300072);

                } else if (first_tn->items > 1) {

                        first_tn->items--;
                }

                if ( found != 1 )
                        return NO;

	} else {

                if (exact) {

                        assertion(-500886, (first_tn));
                        assertion(-500884, (!memcmp(&sk, &first_tn->k, sizeof (sk))));
                        assertion(-500885, (first_tn->cmd == cmd));

                        first_tn->items++;

                } else {

                        struct track_node *tn = debugMalloc(sizeof ( struct track_node), -300030);
                        memset(tn, 0, sizeof ( struct track_node));
                        tn->k = sk;
                        tn->items = 1;
                        tn->cmd = cmd;

                        avl_insert(&iptrack_tree, tn, -300251);
                }

                if (found > 0)
                        return NO;

	}

        return YES;
}



IDM_T ip(uint8_t cmd, int8_t del, uint8_t quiet, const struct net_key *dst,
        int8_t table_macro, int8_t prio_macro, IFNAME_T *iifname, int oif_idx, IPX_T *via, IPX_T *src, uint32_t metric)
{
        // DONT USE setNet() here (because return pointer is static)!!!!!!!!!!!!!

	TRACE_FUNCTION_CALL;

        assertion(-501127, IMPLIES(policy_routing == POLICY_RT_UNSET, (cmd == IP_RULE_TEST && initializing)));
        assertion(-501234, (dst));
        assertion(-500650, IMPLIES(is_ip_set(&dst->ip), is_ip_valid(&dst->ip, dst->af)));
        assertion(-500651, IMPLIES(via, is_ip_valid(via, dst->af)));
        assertion(-500652, IMPLIES(src, is_ip_valid(src, dst->af)));
        assertion(-500653, (dst->af == AF_INET || dst->af == AF_INET6));

        struct rtmsg_req req;

        dbgf_all(DBGT_INFO, "1");

        uint32_t prio = prio_macro_to_prio(prio_macro);
        uint32_t table = table_macro_to_table(table_macro);


        assertion(-500672, (ip_netmask_validate((IPX_T*) &dst->ip, dst->mask, dst->af, NO) == SUCCESS));


        IDM_T llocal = (via && is_ip_equal(via, &dst->ip)) ? YES : NO;

/*
        if (!is_ip_set(src))
                src = NULL;
*/

        if ((cmd == IP_THROW_MY_HNA || cmd == IP_THROW_MY_NET) && (policy_routing != POLICY_RT_ENABLED || !ip_throw_rules_cfg))
		return SUCCESS;

        if (table == DEF_IP_TABLE_MAIN &&
                (cmd == IP_RULE_DEFAULT || cmd == IP_RULE_FLUSH || cmd == IP_ROUTE_FLUSH || cmd == IP_ROUTE_FLUSH_ALL))
                        return SUCCESS;



        if (iptrack(dst->af, cmd, quiet, del, &dst->ip, dst->mask, table_macro, prio_macro, iifname, metric) == NO)
                return SUCCESS;


#ifndef NO_DEBUG_ALL
        struct if_link_node *oif_iln = oif_idx ? avl_find_item(&if_link_tree, &oif_idx) : NULL;

        dbgf_track( DBGT_INFO, "cmd=%s %s dst=%s iif=%s table=%d prio=%d oifIdx=%d oif=%s via=%s src=%s metric=%d",
                trackt2str(cmd), del2str(del), netAsStr(dst),
                iifname ? iifname->str : NULL, table, prio, oif_idx, oif_iln ? oif_iln->name.str : "???",
                via ? ipXAsStr(dst->af, via) : DBG_NIL, src ? ipXAsStr(dst->af, src) : DBG_NIL, metric);
#endif

        memset(&req, 0, sizeof (req));

        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_pid = My_pid;

        req.rtm.rtm_family = dst->af;
        req.rtm.rtm_table = table;

        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        if (cmd > IP_ROUTES && cmd < IP_ROUTE_MAX) {

                if ( cmd == IP_ROUTE_FLUSH_ALL ) {

                        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
                        req.nlh.nlmsg_type = RTM_GETROUTE;
                        req.rtm.rtm_scope = RTN_UNICAST;
                } else if (del) {
                        req.nlh.nlmsg_type = RTM_DELROUTE;
                        req.rtm.rtm_scope = RT_SCOPE_NOWHERE;
                } else {
                        req.nlh.nlmsg_flags = req.nlh.nlmsg_flags | NLM_F_CREATE | NLM_F_EXCL; //| NLM_F_REPLACE;
                        req.nlh.nlmsg_type = RTM_NEWROUTE;
                        req.rtm.rtm_scope = ((cmd == IP_ROUTE_HNA || cmd == IP_ROUTE_HOST) && llocal) ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
                        req.rtm.rtm_protocol = RTPROT_STATIC;
                        req.rtm.rtm_type = (cmd == IP_THROW_MY_HNA || cmd == IP_THROW_MY_NET) ? RTN_THROW : RTN_UNICAST;
                }

                if (is_ip_set(&dst->ip)) {
                        req.rtm.rtm_dst_len = dst->mask;
                        add_rtattr(&req.nlh, RTA_DST, (char*) &dst->ip, sizeof (IPX_T), dst->af);
                }

                if (via && !llocal)
                        add_rtattr(&req.nlh, RTA_GATEWAY, (char*) via, sizeof (IPX_T), dst->af);

                if (oif_idx)
                        add_rtattr(&req.nlh, RTA_OIF, (char*) & oif_idx, sizeof (oif_idx), 0);

                if (src)
                        add_rtattr(&req.nlh, RTA_PREFSRC, (char*) src, sizeof (IPX_T), dst->af);



        } else if (cmd > IP_RULES && cmd < IP_RULE_MAX) {

                if (del) {
                        req.nlh.nlmsg_type = RTM_DELRULE;
                        req.rtm.rtm_scope = RT_SCOPE_NOWHERE;
                } else {
                        req.nlh.nlmsg_flags = req.nlh.nlmsg_flags | NLM_F_CREATE | NLM_F_EXCL;
                        req.nlh.nlmsg_type = RTM_NEWRULE;
                        req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
                        req.rtm.rtm_protocol = RTPROT_STATIC;
                        req.rtm.rtm_type = RTN_UNICAST;
                }

                if (is_ip_set(&dst->ip)) {
                        req.rtm.rtm_src_len = dst->mask;
                        add_rtattr(&req.nlh, RTA_SRC, (char*) &dst->ip, sizeof (IPX_T), dst->af);
                }

                if (iifname)
                        add_rtattr(&req.nlh, RTA_IIF, iifname->str, strlen(iifname->str) + 1, 0);

        } else {

                cleanup_all(-500628);
        }


        if (prio)
                add_rtattr(&req.nlh, RTA_PRIORITY, (char*) & prio, sizeof (prio), 0);

        if (metric)
                add_rtattr(&req.nlh, RTA_PRIORITY, (char*) & metric, sizeof (metric), 0);

        errno = 0;

        return rtnl_talk(&req, req.nlh.nlmsg_len, dst->af, cmd, del, quiet, &dst->ip, dst->mask, via, table_macro);
}




STATIC_FUNC
void check_proc_sys_net(char *file, int32_t desired, int32_t *backup)
{
	TRACE_FUNCTION_CALL;
        FILE *f;
	int32_t state = 0;
	char filename[MAX_PATH_SIZE];

	sprintf( filename, "/proc/sys/net/%s", file );

	if((f = fopen(filename, "r" )) == NULL) {

		dbgf_sys(DBGT_ERR, "can't open %s for reading! retry later..", filename );

		return;
	}

	if(fscanf(f, "%d", &state) < 0 ) {
                 dbgf_track(DBGT_WARN, "%s", strerror(errno));
        }
	fclose(f);

	if ( backup )
		*backup = state;

	// other routing protocols are probably not able to handle this therefore
	// it is probably better to leave the routing configuration operational as it is!
	if ( !backup  &&  !Pedantic_cleanup   &&  state != desired ) {

		dbgf_mute( 50, DBGL_SYS, DBGT_INFO,
		          "NOT restoring %s to NOT mess up other routing protocols. "
		          "Use --%s=1 to enforce proper cleanup",
		          file, ARG_PEDANTIC_CLEANUP );

		return;
	}


	if ( state != desired ) {

		dbgf_sys(DBGT_INFO, "changing %s from %d to %d", filename, state, desired );

		if((f = fopen(filename, "w" )) == NULL) {

                        dbgf_sys(DBGT_ERR, "can't open %s for writing! retry later...", filename);
			return;
		}

		fprintf(f, "%d", desired?1:0 );
		fclose(f);

	}
}

void sysctl_restore(struct dev_node *dev)
{
        TRACE_FUNCTION_CALL;

        if (dev && AF_CFG == AF_INET) {

		char filename[100];

		if (dev->ip4_rp_filter_orig > -1) {
			sprintf( filename, "ipv4/conf/%s/rp_filter", dev->name_phy_cfg.str);
			check_proc_sys_net( filename, dev->ip4_rp_filter_orig, NULL );
		}

		dev->ip4_rp_filter_orig = -1;


		if (dev->ip4_send_redirects_orig > -1) {
			sprintf( filename, "ipv4/conf/%s/send_redirects", dev->name_phy_cfg.str);
			check_proc_sys_net( filename, dev->ip4_send_redirects_orig, NULL );
		}

		dev->ip4_send_redirects_orig = -1;

        } else if (dev && AF_CFG == AF_INET6) {

                // nothing to restore
        }
        
        if (!dev) {

		if( if4_rp_filter_all_orig != -1 )
			check_proc_sys_net( "ipv4/conf/all/rp_filter", if4_rp_filter_all_orig, NULL );

		if4_rp_filter_all_orig = -1;

		if( if4_rp_filter_default_orig != -1 )
			check_proc_sys_net( "ipv4/conf/default/rp_filter", if4_rp_filter_default_orig,  NULL );

		if4_rp_filter_default_orig = -1;

		if( if4_send_redirects_all_orig != -1 )
			check_proc_sys_net( "ipv4/conf/all/send_redirects", if4_send_redirects_all_orig, NULL );

		if4_send_redirects_all_orig = -1;

		if( if4_send_redirects_default_orig != -1 )
			check_proc_sys_net( "ipv4/conf/default/send_redirects", if4_send_redirects_default_orig, NULL );

		if4_send_redirects_default_orig = -1;

		if( if4_forward_orig != -1 )
			check_proc_sys_net( "ipv4/ip_forward", if4_forward_orig, NULL );

		if4_forward_orig = -1;


                if (if6_forward_orig != -1)
                        check_proc_sys_net("ipv6/conf/all/forwarding", if6_forward_orig, NULL);

                if6_forward_orig = -1;

	}
}

// TODO: check for further traps: http://lwn.net/Articles/45386/
void sysctl_config( struct dev_node *dev )
{
        TRACE_FUNCTION_CALL;

        static TIME_T ipv4_timestamp = -1;
        static TIME_T ipv6_timestamp = -1;
        char filename[100];

        if (!(dev->active && dev->if_llocal_addr && dev->if_llocal_addr->iln->flags && IFF_UP))
                return;


        if (dev && AF_CFG == AF_INET) {

		sprintf( filename, "ipv4/conf/%s/rp_filter", dev->name_phy_cfg.str);
		check_proc_sys_net( filename, 0, &dev->ip4_rp_filter_orig );

		sprintf( filename, "ipv4/conf/%s/send_redirects", dev->name_phy_cfg.str);
		check_proc_sys_net( filename, 0, &dev->ip4_send_redirects_orig );

                if (ipv4_timestamp != bmx_time) {

                        check_proc_sys_net("ipv4/conf/all/rp_filter", 0, &if4_rp_filter_all_orig);
                        check_proc_sys_net("ipv4/conf/default/rp_filter", 0, &if4_rp_filter_default_orig);
                        check_proc_sys_net("ipv4/conf/all/send_redirects", 0, &if4_send_redirects_all_orig);
                        check_proc_sys_net("ipv4/conf/default/send_redirects", 0, &if4_send_redirects_default_orig);
                        check_proc_sys_net("ipv4/ip_forward", 1, &if4_forward_orig);

                        ipv4_timestamp = bmx_time;
                }

        } else if (dev && AF_CFG == AF_INET6) {


                if (ipv6_timestamp != bmx_time) {

                        check_proc_sys_net("ipv6/conf/all/forwarding", 1, &if6_forward_orig);

                        ipv6_timestamp = bmx_time;
                }
        }
}





STATIC_FUNC
int8_t dev_bind_sock(int32_t sock, IFNAME_T *name)
{
	errno=0;

        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, name->str, strlen(name->str) + 1) < 0) {
                dbgf_sys(DBGT_ERR, "Can not bind socket to device %s : %s", name->str, strerror(errno));
                return FAILURE;
        }

        return SUCCESS;
}


STATIC_FUNC
void dev_reconfigure_soft(struct dev_node *dev)
{
        TRACE_FUNCTION_CALL;

        assertion(-500611, (dev->active));
        assertion(-500612, (dev->if_llocal_addr));
        assertion(-500613, IMPLIES(dev->announce, dev->if_global_addr));
        assertion(-500614, IMPLIES(dev == primary_dev, dev->if_global_addr));
        assertion(-500615, IMPLIES(dev->linklayer == TYP_DEV_LL_LO, dev->if_global_addr));
        
        if (!initializing) {
                dbgf_sys(DBGT_INFO, "%s soft interface configuration changed", dev->label_cfg.str);
        }

        assertion(-501029, (dev->linklayer == TYP_DEV_LL_WIFI || dev->linklayer == TYP_DEV_LL_LAN || dev->linklayer == TYP_DEV_LL_LO));
        assertion(-501030, (DEF_DEV_BITRATE_MAX_WIFI > DEF_DEV_BITRATE_MIN_WIFI));
        assertion(-501031, (DEF_DEV_BITRATE_MAX_LAN >= DEF_DEV_BITRATE_MIN_LAN));

        // STRANGE! But  if (dev->umetric_max_conf != ((UMETRIC_T)-1)) does not work! !!!!
        static const UMETRIC_T UMETRIC_UNDEFINED  = OPT_CHILD_UNDEFINED;

        if (dev->umetric_max_conf != UMETRIC_UNDEFINED) {
                dev->umetric_max = dev->umetric_max_conf;
        } else {
                if (dev->linklayer == TYP_DEV_LL_WIFI) {
                        dev->umetric_max = DEF_DEV_BITRATE_MAX_WIFI;
                } else if (dev->linklayer == TYP_DEV_LL_LAN) {
                        dev->umetric_max = DEF_DEV_BITRATE_MAX_LAN;
                } else if (dev->linklayer == TYP_DEV_LL_LO) {
                        dev->umetric_max = UMETRIC_MAX;//umetric(0, 0);
                }
        }

        if (dev->umetric_min_conf != UMETRIC_UNDEFINED && dev->umetric_min_conf < dev->umetric_max) {
                dev->umetric_min = dev->umetric_min_conf;
        } else {
                if (dev->linklayer == TYP_DEV_LL_WIFI) {
                        dev->umetric_min = (dev->umetric_max / (DEF_DEV_BITRATE_MAX_WIFI / DEF_DEV_BITRATE_MIN_WIFI));
                } else if (dev->linklayer == TYP_DEV_LL_LAN) {
                        dev->umetric_min = (dev->umetric_max / (DEF_DEV_BITRATE_MAX_LAN / DEF_DEV_BITRATE_MIN_LAN));
                } else if (dev->linklayer == TYP_DEV_LL_LO) {
                        dev->umetric_min = UMETRIC_MAX;//umetric(0, 0);
                }
        }




        if (dev->channel_conf != OPT_CHILD_UNDEFINED) {
                dev->channel = dev->channel_conf;
        } else {
                if (dev->linklayer == TYP_DEV_LL_WIFI) {
                        dev->channel = TYP_DEV_CHANNEL_SHARED;
                } else if (dev->linklayer == TYP_DEV_LL_LAN) {
                        dev->channel = TYP_DEV_CHANNEL_EXCLUSIVE;
                } else if (dev->linklayer == TYP_DEV_LL_LO) {
                        dev->channel = DEF_DEV_CHANNEL;
                }
        }

        dbgf(initializing ? DBGL_SYS : DBGL_CHANGES, DBGT_INFO,
                "enabled %s umin=%s umax=%s umax=%ju umax_conf=%ju undef=%ju %s=%s MAC: %s link-local %s/%d global %s/%d brc %s",
                dev->linklayer == TYP_DEV_LL_LO ? "loopback" : (
                dev->linklayer == TYP_DEV_LL_WIFI ? "wireless" : (
                dev->linklayer == TYP_DEV_LL_LAN ? "ethernet" : ("ILLEGAL"))),
                umetric_to_human(dev->umetric_min), umetric_to_human(dev->umetric_max), dev->umetric_max, dev->umetric_max_conf, ((UMETRIC_T) OPT_CHILD_UNDEFINED),
                ARG_DEV,
                dev->label_cfg.str, macAsStr(&dev->mac),
                dev->ip_llocal_str, dev->if_llocal_addr->ifa.ifa_prefixlen,
                dev->ip_global_str, dev->if_global_addr ? dev->if_global_addr->ifa.ifa_prefixlen : 0,
                dev->ip_brc_str);

        update_my_dev_adv();

	dev->soft_conf_changed = NO;

}


STATIC_FUNC
void dev_deactivate( struct dev_node *dev )
{
        TRACE_FUNCTION_CALL;

        dbgf_sys(DBGT_WARN, "deactivating %s=%s llocal=%s global=%s",
                ARG_DEV, dev->label_cfg.str, dev->ip_llocal_str, dev->ip_global_str);

        if (!is_ip_set(&dev->llocal_ip_key)) {
                dbgf_sys(DBGT_ERR, "no address given to remove in dev_ip_tree!");
        } else if (!avl_find(&dev_ip_tree, &dev->llocal_ip_key)) {
                dbgf_sys(DBGT_ERR, "%s not in dev_ip_tree!", ipFAsStr(&dev->llocal_ip_key));
        } else {
                avl_remove(&dev_ip_tree, &dev->llocal_ip_key, -300192);
                dev->llocal_ip_key = ZERO_IP;
        }


        if (dev->active) {
                dev->active = NO;
                cb_plugin_hooks(PLUGIN_CB_BMX_DEV_EVENT, dev);
        }

	if ( dev->linklayer != TYP_DEV_LL_LO ) {

                purge_link_route_orig_nodes(dev, NO);

                purge_tx_task_list(dev->tx_task_lists, NULL, NULL);

                struct avl_node *an;
                struct link_dev_node *lndev;
                for (an = NULL; (lndev = avl_iterate_item(&link_dev_tree, &an));) {
                        purge_tx_task_list(lndev->tx_task_lists, NULL, dev);
                }


		if (dev->unicast_sock) {
			close(dev->unicast_sock);
                        dev->unicast_sock = 0;
                }

		if (dev->rx_mcast_sock) {
			close(dev->rx_mcast_sock);
                        dev->rx_mcast_sock = 0;
                }

                if (dev->rx_fullbrc_sock) {
                        close(dev->rx_fullbrc_sock);
                        dev->rx_fullbrc_sock = 0;
                }

                dev->dev_adv_idx = DEVADV_IDX_INVALID;
        }


        if (dev->tx_task) {
                task_remove(dev->tx_task, dev);
                dev->tx_task = NULL;
        }

        if (!dev_ip_tree.items)
                task_remove(tx_packets, NULL); //TODO: remove_task() should be reentrant save if called by task_next()!!



	sysctl_restore ( dev );

	change_selects();

	dbgf_all( DBGT_WARN, "Interface %s deactivated", dev->label_cfg.str );

        if (dev->dev_adv_msg > DEVADV_MSG_IGNORED)
                update_my_dev_adv();

        if (dev->announce)
                my_description_changed = YES;

        if (dev == primary_dev && !terminating) {
                dbgf_mute(30, DBGL_SYS, DBGT_WARN,
                        "Using an IP on the loopback device as primary interface ensures reachability under your primary IP!");
        }

        if (dev == primary_dev || dev == primary_phy) {
                struct avl_node *an = NULL;
                struct dev_node *ipdev;

                if (dev == primary_dev) {
                        primary_dev = NULL;
                        self->primary_ip = ZERO_IP;
                        ipFToStr(&ZERO_IP, self->primary_ip_str);
                }

                if (dev == primary_phy)
                        primary_phy = NULL;

                while ((ipdev = avl_iterate_item(&dev_ip_tree, &an))) {
                        if (ipdev->active && ipdev->announce && ipdev->if_global_addr) {
                                if(!primary_dev) {
                                        primary_dev = ipdev;
                                        self->primary_ip = ipdev->if_global_addr->ip_addr;
                                        ipFToStr(&ipdev->if_global_addr->ip_addr, self->primary_ip_str);
                                }

                                if (!primary_phy && ipdev->linklayer != TYP_DEV_LL_LO)
                                        primary_phy = ipdev;
                        }

                }
        }

        if (dev->autoIP6Configured.mask && !dev->activate_again) {
                //if (dev->if_llocal_addr && dev->if_llocal_addr->iln->flags & IFF_UP)
                ipaddr(DEL, dev->autoIP6IfIndex, AF_INET6, &dev->autoIP6Configured.ip, dev->autoIP6Configured.mask, NO /*deprecated*/);
                dev->autoIP6Configured = ZERO_NET6_KEY;
                dev->autoIP6IfIndex = 0;
        }



}


STATIC_FUNC
void set_sockaddr_storage(struct sockaddr_storage *ss, IPX_T *ipx)
{
        TRACE_FUNCTION_CALL;
        memset(ss, 0, sizeof ( struct sockaddr_storage));

        ss->ss_family = AF_CFG;

        if (AF_CFG == AF_INET) {
                struct sockaddr_in *in = (struct sockaddr_in*) ss;
                in->sin_port = htons(base_port);
                in->sin_addr.s_addr = ipXto4(*ipx);
        } else {
                struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ss;
                in6->sin6_port = htons(base_port);
                in6->sin6_addr = *ipx;
        }
}


STATIC_FUNC
IDM_T dev_init_sockets(struct dev_node *dev)
{

        TRACE_FUNCTION_CALL;
        assertion(-500618, (dev->linklayer != TYP_DEV_LL_LO));

        int set_on = 1;
        int sock_opts;
        int pf_domain = AF_CFG == AF_INET ? PF_INET : PF_INET6;

        if ((dev->unicast_sock = socket(pf_domain, SOCK_DGRAM, 0)) < 0) {

                dbgf_sys(DBGT_ERR, "can't create send socket: %s", strerror(errno));
                return FAILURE;
        }

        set_sockaddr_storage(&dev->llocal_unicast_addr, &dev->if_llocal_addr->ip_addr);

        if (AF_CFG == AF_INET) {
                if (setsockopt(dev->unicast_sock, SOL_SOCKET, SO_BROADCAST, &set_on, sizeof (set_on)) < 0) {
                        dbgf_sys(DBGT_ERR, "can't enable broadcasts on unicast socket: %s", strerror(errno));
                        return FAILURE;
                }
        } else {
                struct ipv6_mreq mreq6;

                mreq6.ipv6mr_multiaddr = dev->if_llocal_addr->ip_mcast;

                mreq6.ipv6mr_interface = dev->if_llocal_addr->iln->index;//0 corresponds to any interface

/*
                if (setsockopt(dev->unicast_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &set_on, sizeof (set_on)) < 0) {
                        dbgf_sys(DBGT_ERR, "can't set IPV6_MULTICAST_LOOP:: on unicast socket: %s", strerror(errno));
                        return FAILURE;
                }
*/
                if (setsockopt(dev->unicast_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &set_on, sizeof (set_on)) < 0) {
                        dbgf_sys(DBGT_ERR, "can't set IPV6_MULTICAST_HOPS on unicast socket: %s", strerror(errno));
                        return FAILURE;
                }

                if (setsockopt(dev->unicast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof (mreq6)) < 0) {
                        dbgf_sys(DBGT_ERR, "can't set IPV6_ADD_MEMBERSHIP on unicast socket: %s", strerror(errno));
                        return FAILURE;
                }
        }

        // bind send socket to interface name
        if (dev_bind_sock(dev->unicast_sock, &dev->name_phy_cfg) < 0)
                return FAILURE;

        // bind send socket to address
        if (bind(dev->unicast_sock, (struct sockaddr *) & dev->llocal_unicast_addr, sizeof (dev->llocal_unicast_addr)) < 0) {
                dbgf_sys(DBGT_ERR, "can't bind unicast socket to IP=%s : %s (retrying later...)",
                        ipFAsStr(&dev->if_llocal_addr->ip_addr), strerror(errno));

                dev->activate_again = YES;
                return FAILURE;
        }

        // make udp send socket non blocking
        sock_opts = fcntl(dev->unicast_sock, F_GETFL, 0);
        fcntl(dev->unicast_sock, F_SETFL, sock_opts | O_NONBLOCK);

#ifdef SO_TIMESTAMP
        if (setsockopt(dev->unicast_sock, SOL_SOCKET, SO_TIMESTAMP, &set_on, sizeof (set_on))) {
                dbgf_sys(DBGT_WARN, "No SO_TIMESTAMP support, despite being defined, falling back to SIOCGSTAMP");
        }
#else
        dbgf_sys(DBGT_WARN, "No SO_TIMESTAMP support, falling back to SIOCGSTAMP");
#endif


        set_sockaddr_storage(&dev->tx_netwbrc_addr, &dev->if_llocal_addr->ip_mcast);




        // get netwbrc recv socket
        if ((dev->rx_mcast_sock = socket(pf_domain, SOCK_DGRAM, 0)) < 0) {
                dbgf_track(DBGT_ERR, "can't create network-broadcast socket: %s", strerror(errno));
                return FAILURE;
        }

        // bind recv socket to interface name
        if (dev_bind_sock(dev->rx_mcast_sock, &dev->name_phy_cfg) < 0)
                return FAILURE;


        struct sockaddr_storage rx_netwbrc_addr;

        if (AF_CFG == AF_INET && ipXto4(dev->if_llocal_addr->ip_mcast) == 0xFFFFFFFF) {
                // if the mcast address is the full-broadcast address
                // we'll listen on the network-broadcast address :
                IPX_T brc = ip4ToX(ipXto4(dev->if_llocal_addr->ip_addr) | htonl(~(0XFFFFFFFF << dev->if_llocal_addr->ifa.ifa_prefixlen)));
                set_sockaddr_storage(&rx_netwbrc_addr, &brc);
        } else {
                set_sockaddr_storage(&rx_netwbrc_addr, &dev->if_llocal_addr->ip_mcast);
        }


        if (bind(dev->rx_mcast_sock, (struct sockaddr *) & rx_netwbrc_addr, sizeof (rx_netwbrc_addr)) < 0) {
                char ip6[IP6_ADDR_LEN];

                if (AF_CFG == AF_INET)
                        inet_ntop(AF_CFG, &((struct sockaddr_in*) (&rx_netwbrc_addr))->sin_addr, ip6, sizeof (ip6));
                else
                        inet_ntop(AF_CFG, &((struct sockaddr_in6*) (&rx_netwbrc_addr))->sin6_addr, ip6, sizeof (ip6));

                dbgf_sys(DBGT_ERR, "can't bind network-broadcast socket to %s: %s",
                        ip6, strerror(errno));
                return FAILURE;
        }

        if (AF_CFG == AF_INET) {
                // we'll always listen on the full-broadcast address
                struct sockaddr_storage rx_fullbrc_addr;
                IPX_T brc = ip4ToX(0XFFFFFFFF);
                set_sockaddr_storage(&rx_fullbrc_addr, &brc);

                // get fullbrc recv socket
                if ((dev->rx_fullbrc_sock = socket(pf_domain, SOCK_DGRAM, 0)) < 0) {
                        dbgf_sys(DBGT_ERR, "can't create full-broadcast socket: %s",
                                strerror(errno));
                        return FAILURE;
                }

                // bind recv socket to interface name
                if (dev_bind_sock(dev->rx_fullbrc_sock, &dev->name_phy_cfg) < 0)
                        return FAILURE;


                // bind recv socket to address
                if (bind(dev->rx_fullbrc_sock, (struct sockaddr *) & rx_fullbrc_addr, sizeof (rx_fullbrc_addr)) < 0) {
                        dbgf_sys(DBGT_ERR, "can't bind full-broadcast socket: %s", strerror(errno));
                        return FAILURE;
                }

        }

        return SUCCESS;
}

STATIC_FUNC
DEVADV_IDX_T get_free_devidx(void)
{
        static uint16_t idx = DEVADV_IDX_MIN;
        uint16_t tries = DEVADV_IDX_MAX - DEVADV_IDX_MIN;

        struct avl_node *an;
        struct dev_node *dev;

        while ((--tries)) {

                idx = ((idx + 1) > DEVADV_IDX_MAX ? DEVADV_IDX_MIN : (idx + 1));

                for (an = NULL; ((dev = avl_iterate_item(&dev_ip_tree, &an)));) {
                        if (dev->dev_adv_idx == idx)
                                break;
                }

                if (dev == NULL)
                        return idx;
        }
        return DEVADV_IDX_INVALID;
}


STATIC_FUNC
void dev_activate( struct dev_node *dev )
{
        TRACE_FUNCTION_CALL;

        assertion(-500575, (dev && !dev->active && dev->if_llocal_addr && dev->if_llocal_addr->iln->flags & IFF_UP));
        assertion(-500593, (AF_CFG == dev->if_llocal_addr->ifa.ifa_family));
        assertion(-500599, (is_ip_set(&dev->if_llocal_addr->ip_addr) && dev->if_llocal_addr->ifa.ifa_prefixlen));

        dbgf_sys(DBGT_WARN, "%s=%s", ARG_DEV, dev->label_cfg.str);

	if ( wordsEqual( DEV_LO, dev->name_phy_cfg.str ) ) {

		dev->linklayer = TYP_DEV_LL_LO;

                if (!dev->if_global_addr) {
                        dbgf_mute(30, DBGL_SYS, DBGT_WARN, "loopback dev %s MUST be given with global address",
                                dev->label_cfg.str);

                        cleanup_all(-500621);
                }

                uint8_t prefixlen = ((AF_CFG == AF_INET) ? IP4_MAX_PREFIXLEN : IP6_MAX_PREFIXLEN);

                if (!dev->if_global_addr || dev->if_global_addr->ifa.ifa_prefixlen != prefixlen) {
                        dbgf_mute(30, DBGL_SYS, DBGT_WARN,
                                "prefix length of loopback interface is %d but SHOULD be %d and global",
                                dev->if_global_addr->ifa.ifa_prefixlen, prefixlen);
                }


	} else {

                if (dev->linklayer_conf != OPT_CHILD_UNDEFINED) {

                        dev->linklayer = dev->linklayer_conf;

                } else /* check if interface is a wireless interface */ {

                        struct ifreq int_req;
                        char *dot_ptr;

                        // if given interface is a vlan then truncate to physical interface name:
                        if ((dot_ptr = strchr(dev->name_phy_cfg.str, '.')) != NULL)
                                *dot_ptr = '\0';

                        if (get_if_req(&dev->name_phy_cfg, &int_req, SIOCGIWNAME) == SUCCESS)
                                dev->linklayer = TYP_DEV_LL_WIFI;
                        else
                                dev->linklayer = TYP_DEV_LL_LAN;

                        if (dot_ptr)
                                *dot_ptr = '.';
                }
        }



        if (dev->linklayer != TYP_DEV_LL_LO) {

                dev->mac = *((MAC_T*)&(dev->if_llocal_addr->iln->addr));

                if (dev_init_sockets(dev) == FAILURE)
                        goto error;

                if ((dev->dev_adv_idx = get_free_devidx()) == DEVADV_IDX_INVALID)
                        goto error;

                if (my_local_id == LOCAL_ID_INVALID && new_local_id(dev) == LOCAL_ID_INVALID)
                        goto error;

                sysctl_config(dev);
        }

        // from here on, nothing should fail anymore !!:


        assertion(-500592, (!avl_find(&dev_ip_tree, &dev->if_llocal_addr->ip_addr)));
        dev->llocal_ip_key = dev->if_llocal_addr->ip_addr;
        avl_insert(&dev_ip_tree, dev, -300151);


        ipFToStr(&dev->if_llocal_addr->ip_addr, dev->ip_llocal_str);

        if ( dev->if_global_addr)
                ipFToStr(&dev->if_global_addr->ip_addr, dev->ip_global_str);

        ipFToStr(&dev->if_llocal_addr->ip_mcast, dev->ip_brc_str);

        if (!primary_dev && dev->announce && dev->if_global_addr) {
                primary_dev = dev;
                self->primary_ip = dev->if_global_addr->ip_addr;
                ipFToStr(&dev->if_global_addr->ip_addr, self->primary_ip_str);
        }

        if (!primary_phy && dev->linklayer != TYP_DEV_LL_LO && dev->announce && dev->if_global_addr)
                primary_phy = dev;



        dev->active = YES;
        dev->activate_again = NO;

//        assertion(-500595, (primary_dev_cfg));

        if (!(dev->link_hello_sqn )) {
                dev->link_hello_sqn = ((HELLO_SQN_MASK) & rand_num(HELLO_SQN_MAX));
        }

/*
        int i;
        for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {
                LIST_INIT_HEAD(dev->tx_task_lists[i], struct tx_task_node, list, list);
        }

        AVL_INIT_TREE(dev->tx_task_interval_tree, struct tx_task_node, task);
*/

        if (dev_ip_tree.items == 1)
                task_register(rand_num(bmx_time ? 0 : DEF_TX_DELAY), tx_packets, NULL, -300350);


//        if (dev->announce)
                my_description_changed = YES;


        dev->soft_conf_changed = YES;

	//activate selector for active interfaces
	change_selects();

	//trigger plugins interested in changed interface configuration
        cb_plugin_hooks(PLUGIN_CB_BMX_DEV_EVENT, dev);
//        cb_plugin_hooks(PLUGIN_CB_CONF, NULL);

	return;

error:
        dbgf_sys(DBGT_ERR, "error intitializing %s=%s", ARG_DEV, dev->label_cfg.str);

        ipFToStr( &ZERO_IP, dev->ip_llocal_str);
        ipFToStr( &ZERO_IP, dev->ip_brc_str);

        dev_deactivate(dev);
}


STATIC_FUNC
void ip_flush_routes(uint8_t family)
{
	TRACE_FUNCTION_CALL;

        assertion(-501128, (AF_CFG || policy_routing == POLICY_RT_ENABLED));

        int8_t table_macro;
        struct net_key net = family == AF_INET ? ZERO_NET4_KEY : ZERO_NET6_KEY;


        for (table_macro = RT_TABLE_MIN; table_macro <= RT_TABLE_MAX; table_macro++) {
                ip(IP_ROUTE_FLUSH_ALL, DEL, YES/*quiet*/, &net, table_macro, 0, 0, 0, 0, 0, 0);
        }

}

STATIC_FUNC
void ip_flush_rules(uint8_t family)
{
	TRACE_FUNCTION_CALL;

        assertion(-501129, (AF_CFG || policy_routing == POLICY_RT_ENABLED));

        int8_t table_macro;
        struct net_key net = family == AF_INET ? ZERO_NET4_KEY : ZERO_NET6_KEY;

        for (table_macro = RT_TABLE_MIN; table_macro <= RT_TABLE_MAX; table_macro++) {

                if (table_macro_to_table(table_macro) == DEF_IP_TABLE_MAIN)
                        continue;

                while (ip(IP_RULE_FLUSH, DEL, YES, &net, table_macro, 0, 0, 0, 0, 0, 0) == SUCCESS) {

                        dbgf_sys(DBGT_ERR, "removed orphan %s rule to table %d", family2Str(AF_CFG), table_macro);

                }
        }
}



STATIC_FUNC
void ip_flush_tracked( uint8_t cmd )
{
	TRACE_FUNCTION_CALL;
        struct avl_node *an;
        struct track_node *tn;
        struct net_key net;

        for (an = NULL; (tn = avl_iterate_item(&iptrack_tree, &an));) {

                if (!(cmd == tn->cmd ||
                        (cmd == IP_ROUTE_FLUSH && tn->k.cmd_type == IP_ROUTES) ||
                        (cmd == IP_RULE_FLUSH && tn->k.cmd_type == IP_RULES)))
                        continue;

                setNet(&net, tn->k.family, tn->k.mask, &tn->k.net);
                ip(tn->cmd, DEL, NO, &net, tn->k.table_macro, tn->k.prio_macro, &tn->k.iif, 0, 0, 0, tn->k.metric);

                an = NULL;
        }
}



STATIC_FUNC
int update_interface_rules(void)
{
	TRACE_FUNCTION_CALL;
        assertion(-501130, (policy_routing != POLICY_RT_UNSET));

//        ip_flush_tracked(IP_THROW_MY_HNA);
        ip_flush_tracked(IP_THROW_MY_NET);

        struct avl_node *lan = NULL;
        struct if_link_node *iln;

        while (policy_routing == POLICY_RT_ENABLED && ip_throw_rules_cfg &&
                (iln = avl_iterate_item(&if_link_tree, &lan))) {

                if (!((iln->flags & IFF_UP)))
                        continue;

                struct avl_node *aan;
                struct if_addr_node *ian;

                for (aan = NULL; (ian = avl_iterate_item(&iln->if_addr_tree, &aan));) {

                        assertion(-500609, is_ip_set(&ian->ip_addr));

/*
                        if (ian->ifa.ifa_family != AF_CFG)
                                continue;
*/

                        if (!ian->ifa.ifa_prefixlen)
                                continue;

                        if (is_ip_net_equal(&ian->ip_addr, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))
                                continue;

                        struct avl_node *dan;
                        struct dev_node *dev = NULL;

                        for (dan = NULL; (dev = avl_iterate_item(&dev_ip_tree, &dan));) {

                                if (!dev->if_global_addr /*||  ian->ifa.ifa_family != af_cfg*/)
                                        continue;

                                if (is_ip_net_equal(&ian->ip_addr, &dev->if_global_addr->ip_addr, ian->ifa.ifa_prefixlen, AF_CFG))
                                        break;

                        }

                        if (dev)
                                continue;

                        struct net_key throw;
                        setNet(&throw, ian->ifa.ifa_family, ian->ifa.ifa_prefixlen, &ian->ip_addr);
                        ip_netmask_validate(&throw.ip, throw.mask, throw.af, YES);

                        ip(IP_THROW_MY_NET, ADD, NO, &throw, RT_TABLE_HNA, RT_PRIO_HNA, 0, (throw.af == AF_INET6 ? dev_lo_idx : 0), 0, 0, 0);
                        ip(IP_THROW_MY_NET, ADD, NO, &throw, RT_TABLE_TUN, RT_PRIO_TUNS, 0, (throw.af == AF_INET6 ? dev_lo_idx : 0), 0, 0, 0);

                }
        }

#ifdef ADJ_PATCHED_NETW
        struct list_node *throw_pos;
	struct throw_node *throw_node;

        list_for_each(throw_pos, &throw4_list) {

                throw_node = list_entry(throw_pos, struct throw_node, list);

                IPX_T throw6 = ip4ToX(throw_node->addr);

                configure_route(&throw6, AF_INET, throw_node->netmask, 0, 0, 0, 0, RT_TABLE_HOSTS, RTN_THROW, ADD, IP_THROW_MY_NET);
                configure_route(&throw6, AF_INET, throw_node->netmask, 0, 0, 0, 0, RT_TABLE_HNA, RTN_THROW, ADD, IP_THROW_MY_NET);
                configure_route(&throw6, AF_INET, throw_node->netmask, 0, 0, 0, 0, RT_TABLE_TUN, RTN_THROW, ADD, IP_THROW_MY_NET);

        }
#endif
	return SUCCESS;
}


struct net_key bmx6AutoEUI64Ip6(struct dev_node *dev, struct net_key *prefix)
{
        struct net_key autoPrefix = ZERO_NET6_KEY;

        if (dev && prefix->mask && prefix->mask <= 64 && /*dev->linklayer != TYP_DEV_LL_LO &&*/
                dev->if_link && !is_zero(&dev->if_link->addr, sizeof (dev->if_link->addr))) {

                autoPrefix = *prefix;

                autoPrefix.ip.s6_addr[8 ] = dev->if_link->addr.u8[0];
                autoPrefix.ip.s6_addr[9 ] = dev->if_link->addr.u8[1];
                autoPrefix.ip.s6_addr[10] = dev->if_link->addr.u8[2];
                autoPrefix.ip.s6_addr[11] = 0xFF;
                autoPrefix.ip.s6_addr[12] = 0xFE;
                autoPrefix.ip.s6_addr[13] = dev->if_link->addr.u8[3];
                autoPrefix.ip.s6_addr[14] = dev->if_link->addr.u8[4];
                autoPrefix.ip.s6_addr[15] = dev->if_link->addr.u8[5];

                // toggle the U/L bit (  http://en.wikipedia.org/wiki/IPv6_address#Modified_EUI-64 )
                autoPrefix.ip.s6_addr[8 ] |= 2;
        }

        dbgf_track(DBGT_INFO, "%s returnPrefix=%s (prefix=%s dev->if_link_addr=%s)",
                dev->label_cfg.str, netAsStr(&autoPrefix), netAsStr(prefix),
                (dev->if_link ? memAsHexString(&dev->if_link->addr, sizeof (dev->if_link->addr)) : "--"));

        return autoPrefix;
}

STATIC_INLINE_FUNC
void dev_if_fix(void)
{
	TRACE_FUNCTION_CALL;
        struct if_link_node *iln = avl_first_item(&if_link_tree);
        struct avl_node *lan;
        struct dev_node *dev;
        struct avl_node *dan;

        for (dan = NULL; (dev = avl_iterate_item(&dev_name_tree, &dan));) {
                if (dev->hard_conf_changed) {
                        dev->if_link = NULL;
                        if (dev->if_llocal_addr) {
                                dev->if_llocal_addr->dev = NULL;
                                dev->if_llocal_addr = NULL;
                        }
                        if (dev->if_global_addr) {
                                dev->if_global_addr->dev = NULL;
                                dev->if_global_addr = NULL;
                        }
                }
        }


        for (lan = NULL; (iln = avl_iterate_item(&if_link_tree, &lan));) {

                struct dev_node *dev = dev_get_by_name(iln->name.str);

                if (dev && dev->hard_conf_changed && (iln->flags & IFF_UP))
                        dev->if_link = iln;
        }


        for (dan = NULL; (dev = avl_iterate_item(&dev_name_tree, &dan));) {

                if (!(dev->hard_conf_changed && dev->if_link && (dev->if_link->flags & IFF_UP)))
                        continue;

                assertion( -500620, (!dev->if_llocal_addr && !dev->if_global_addr ));

                struct if_addr_node *ian;
                struct avl_node *aan;
                struct net_key autoIP6 = ZERO_NET6_KEY;

                if (!global_prefix_cfg.mask && !dev->global_prefix_conf_.mask && autoconf_prefix_cfg.mask)
                        autoIP6 = bmx6AutoEUI64Ip6(dev, &autoconf_prefix_cfg);


                for (aan = NULL; (ian = avl_iterate_item(&dev->if_link->if_addr_tree, &aan));) {

                        if (AF_CFG != ian->ifa.ifa_family || strcmp(dev->label_cfg.str, ian->label.str))
                                continue;

                        dbgf_all(DBGT_INFO, "testing %s=%s %s", ARG_DEV, ian->label.str, ipFAsStr(&ian->ip_addr));

                        if (AF_CFG == AF_INET6 && is_ip_net_equal(&ian->ip_addr, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6)) {

                                dbgf_all(DBGT_INFO, "skipping multicast");
                                continue;
                        }

                        IDM_T is_ip6llocal = is_ip_net_equal(&ian->ip_addr, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6);

                        if (!dev->if_llocal_addr && (AF_CFG == AF_INET || is_ip6llocal)) {

                                if (dev->llocal_prefix_conf_.mask &&
                                        is_ip_net_equal(&dev->llocal_prefix_conf_.ip, &ian->ip_addr, dev->llocal_prefix_conf_.mask, dev->llocal_prefix_conf_.af)) {

                                        dev->if_llocal_addr = ian;

                                } else if (!dev->llocal_prefix_conf_.mask && llocal_prefix_cfg.mask &&
                                        is_ip_net_equal(&llocal_prefix_cfg.ip, &ian->ip_addr, llocal_prefix_cfg.mask, llocal_prefix_cfg.af)) {

                                        dev->if_llocal_addr = ian;

                                } else if (!dev->llocal_prefix_conf_.mask && !llocal_prefix_cfg.mask &&
                                        (AF_CFG == AF_INET || is_ip6llocal)) {
                                        
                                        dev->if_llocal_addr = ian;

                                }
                        }

                        if (!dev->if_global_addr && dev->announce) {

                                if ((AF_CFG == AF_INET6 && !is_ip6llocal) && autoIP6.mask) {

                                        if (is_ip_equal(&autoIP6.ip, &ian->ip_addr) && autoIP6.mask == ian->ifa.ifa_prefixlen) {

                                                dev->if_global_addr = ian;
                                        }

                                } else if ((AF_CFG == AF_INET || !is_ip6llocal) && !autoIP6.mask) {

                                        if (dev->global_prefix_conf_.mask &&
                                                is_ip_net_equal(&dev->global_prefix_conf_.ip, &ian->ip_addr, dev->global_prefix_conf_.mask, dev->global_prefix_conf_.af)) {

                                                dev->if_global_addr = ian;

                                        } else if (!dev->global_prefix_conf_.mask && global_prefix_cfg.mask &&
                                                is_ip_net_equal(&global_prefix_cfg.ip, &ian->ip_addr, global_prefix_cfg.mask, global_prefix_cfg.af)) {

                                                dev->if_global_addr = ian;

                                        } else if (!dev->global_prefix_conf_.mask && !global_prefix_cfg.mask) {

                                                dev->if_global_addr = ian;
                                        }
                                }
                        }
                }

                if (AF_CFG == AF_INET6 && autoIP6.mask && dev->announce && !dev->if_global_addr) {

                        ipaddr(ADD, dev->if_link->index, AF_INET6, &autoIP6.ip, autoIP6.mask, NO /*deprecated*/);
                        dev->autoIP6Configured = autoIP6;
                        dev->autoIP6IfIndex = dev->if_link->index;
                }


                if (wordsEqual(DEV_LO, dev->name_phy_cfg.str)) {
                        // the loopback interface usually does not need a link-local address, BUT BMX needs one
                        // And it MUST have a global one.
                        if (!dev->if_global_addr)
                                dev->if_llocal_addr = NULL;
                        else if (!dev->if_llocal_addr)
                                dev->if_llocal_addr = dev->if_global_addr;
                }

                if (dev->if_llocal_addr) {
                        dev->if_llocal_addr->dev = dev;
                } else {
                        dbgf_mute(30, DBGL_SYS, DBGT_ERR, "No link-local IP for %s=%s !", ARG_DEV, dev->label_cfg.str);
                }

                if (dev->if_global_addr && dev->if_llocal_addr) {

                        dev->if_global_addr->dev = dev;

                } else if (dev->if_global_addr && !dev->if_llocal_addr) {

                        dev->if_global_addr = NULL;

                } else {
                        if (/*dev == primary_dev_cfg ||*/ dev->announce) {

                                dbgf_mute(30, DBGL_SYS, DBGT_ERR,
                                        "No global IP for %s=%s ! DEACTIVATING !!!", ARG_DEV, dev->label_cfg.str);

                                if (dev->if_llocal_addr) {
                                        dev->if_llocal_addr->dev = NULL;
                                        dev->if_llocal_addr = NULL;
                                }
                        }
                }
        }
}


static void dev_check(IDM_T kernel_ip_config_changed)
{
	TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct dev_node *dev;

	dbgf_all( DBGT_INFO, " " );
/*

	if ( !dev_name_tree.items ) {
                dbgf_sys(DBGT_ERR, "No interfaces specified");
		cleanup_all( CLEANUP_FAILURE );
        }
*/



        // fix all dev->.._ian stuff here:
        dev_if_fix();

        for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));) {

                if (dev->hard_conf_changed) {

                        dev->activate_again = NO;

                        if (dev->active) {
                                dbgf_sys(DBGT_WARN, "detected changed but used %sprimary dev=%s ! Deactivating now...",
                                        (dev == primary_dev ? "" : "non-"), dev->label_cfg.str);

                                dev_deactivate(dev);
                        }
                }

                IDM_T iff_up = dev->if_llocal_addr && (dev->if_llocal_addr->iln->flags & IFF_UP);

                assertion(-500895, (!(dev->active && !iff_up) == IMPLIES(dev->active, iff_up)));
                assertion(-500896, (IMPLIES(dev->active, iff_up)));
                assertion(-500897, (!(dev->active && !iff_up)));

                assertion(-500898, (!(dev->active && iff_up && dev->hard_conf_changed) == IMPLIES(dev->active, (!iff_up || !dev->hard_conf_changed))));
                assertion(-500901, (IMPLIES(dev->active, (!dev->hard_conf_changed))));
                assertion(-500899, (IMPLIES(dev->active ,(!iff_up || !dev->hard_conf_changed))));
                assertion(-500900, (!(dev->active && iff_up && dev->hard_conf_changed)));

                assertion(-500598, (!(dev->active && !iff_up) && !(dev->active && iff_up && dev->hard_conf_changed)));

                if (!dev->active && iff_up && (dev->hard_conf_changed || dev->activate_again)) {

                        struct dev_node *tmp_dev = avl_find_item(&dev_ip_tree, &dev->if_llocal_addr->ip_addr);

                        if (tmp_dev && !wordsEqual(tmp_dev->name_phy_cfg.str, dev->name_phy_cfg.str)) {

                                dbgf_sys(DBGT_ERR, "%s=%s IP %-15s already used for IF %s",
                                       ARG_DEV, dev->label_cfg.str, dev->ip_llocal_str, tmp_dev->label_cfg.str);

                        } else if (dev->announce && !dev->if_global_addr) {

                                dbgf_sys(DBGT_ERR,
                                        "%s=%s %s but no global addr", ARG_DEV, dev->label_cfg.str, "to-be announced");

                        } else if (dev == primary_dev && !dev->if_global_addr) {

                                dbgf_sys(DBGT_ERR,
                                        "%s=%s %s but no global addr", ARG_DEV, dev->label_cfg.str, "primary dev");

                        } else if (wordsEqual(DEV_LO, dev->name_phy_cfg.str) && !dev->if_global_addr) {

                                dbgf_sys(DBGT_ERR,
                                        "%s=%s %s but no global addr", ARG_DEV, dev->label_cfg.str, "loopback");

                        } else if (dev_ip_tree.items == DEVADV_IDX_MAX) {

                                dbgf_sys(DBGT_ERR, "too much active interfaces");

                        } else  {

                                dbgf_sys(DBGT_WARN, "detected valid but disabled dev=%s ! Activating now...",
                                        dev->label_cfg.str);

                                dev_activate(dev);
			}
                }

                if (!dev->active) {

/*
                        if (initializing && dev == primary_dev_cfg) {
				dbgf_sys(DBGT_ERR,
                                        "at least primary %s=%s MUST be operational at startup! "
                                        "Use loopback (e.g. ip addr add fd01:2345::6789/128 dev lo) if nothing else is available!",
                                        ARG_DEV, dev->label_cfg.str);

				cleanup_all( CLEANUP_FAILURE );
                        }
*/

                        dbgf_sys(DBGT_WARN, "not using interface %s (retrying later): %s %s ila=%d iln=%d",
                                dev->label_cfg.str, iff_up ? "UP" : "DOWN",
                                dev->hard_conf_changed ? "CHANGED" : "UNCHANGED",
                                dev->if_llocal_addr ? 1 : 0, dev->if_llocal_addr && dev->if_llocal_addr->iln ? 1 : 0);

                }

                dev->hard_conf_changed = NO;

                if (dev->active && dev->soft_conf_changed) {

			dev_reconfigure_soft( dev );
                }
        }

        if (kernel_ip_config_changed) {

                update_interface_rules();

                cb_plugin_hooks(PLUGIN_CB_SYS_DEV_EVENT, NULL);
        }

//        cb_plugin_hooks(PLUGIN_CB_CONF, NULL);
}



static void recv_ifevent_netlink_sk(int sk)
{
        TRACE_FUNCTION_CALL;
	char buf[4096]; //test this with a very small value !!
	struct sockaddr_nl sa;
        struct iovec iov;

        dbgf_track(DBGT_INFO, "detected changed interface status! Going to check interfaces!");

        memset(&iov, 0, sizeof (struct iovec));

        iov.iov_base = buf;
        iov.iov_len = sizeof (buf);

        struct msghdr msg; // = {(void *) & sa, sizeof (sa), &iov, 1, NULL, 0, 0};
        memset( &msg, 0, sizeof( struct msghdr));
        msg.msg_name = (void *)&sa;
        msg.msg_namelen = sizeof(sa); /* Length of address data.  */
        msg.msg_iov = &iov; /* Vector of data to send/receive into.  */
        msg.msg_iovlen = 1; /* Number of elements in the vector.  */

	//so fare I just want to consume the pending message...
	while( recvmsg (sk, &msg, 0) > 0 );

        //do NOT delay checking of interfaces to not miss ifdown/up of interfaces !!
        if (kernel_if_config() == YES) //just call if changed!
                dev_check(YES);

}


static int open_ifevent_netlink_sk(void)
{
	struct sockaddr_nl sa;
	int32_t unix_opts;
	memset (&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups |= RTMGRP_IPV4_IFADDR /*| RTMGRP_IPV4_MROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_RULE*/;
        sa.nl_groups |= RTMGRP_IPV6_IFADDR /*| RTMGRP_IPV6_MROUTE | RTMGRP_IPV6_ROUTE */| RTMGRP_IPV6_IFINFO | RTMGRP_IPV6_PREFIX;
	sa.nl_groups |= RTMGRP_LINK; // (this can result in select storms with buggy wlan devices


	if ( ( ifevent_sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) ) < 0 ) {
		dbgf_sys(DBGT_ERR, "can't create af_netlink socket for reacting on if up/down events: %s",
		     strerror(errno) );
		ifevent_sk = 0;
		return -1;
	}


	unix_opts = fcntl( ifevent_sk, F_GETFL, 0 );
	fcntl( ifevent_sk, F_SETFL, unix_opts | O_NONBLOCK );

	if ( ( bind( ifevent_sk, (struct sockaddr*)&sa, sizeof(sa) ) ) < 0 ) {
		dbgf_sys(DBGT_ERR, "can't bind af_netlink socket for reacting on if up/down events: %s",
		     strerror(errno) );
		ifevent_sk = 0;
		return -1;
        }

        set_fd_hook(ifevent_sk, recv_ifevent_netlink_sk, ADD);

	return ifevent_sk;
}

static void close_ifevent_netlink_sk(void)
{
        set_fd_hook(ifevent_sk, recv_ifevent_netlink_sk, DEL);

	if ( ifevent_sk > 0 )
		close( ifevent_sk );

	ifevent_sk = 0;
}

STATIC_FUNC
IDM_T is_policy_rt_supported(void)
{
        static IDM_T tested_policy_rt = POLICY_RT_UNSET;
        static uint8_t tested_family = 0;
        struct net_key net = ZERO_NETCFG_KEY;

        if (net.af == tested_family) {
                assertion(-501132, (tested_policy_rt != POLICY_RT_UNSET));
                return tested_policy_rt;
        }

        tested_family = net.af;

        if (ip(IP_RULE_TEST, ADD, YES, &net, RT_TABLE_HNA, RT_PRIO_HNA, 0, 0, 0, 0, 0) == SUCCESS) {

                ip(IP_RULE_TEST, DEL, YES, &net, RT_TABLE_HNA, RT_PRIO_HNA, 0, 0, 0, 0, 0);

                return (tested_policy_rt = YES);

        } else {

                dbgf_sys(DBGT_ERR, "Disabled policy-routing for IPv%d! (Kernel requires %s,...)",
                        net.af == AF_INET ? 4 : 6,
                        net.af == AF_INET ? "IP_MULTIPLE_TABLES" : "CONFIG_IPV6_MULTIPLE_TABLES");

                return ( tested_policy_rt = NO);
        }
}

uint8_t _af_cfg(const char *func)
{
        _af_cfg_read = func;
        return __af_cfg;
}

struct net_key _ZERO_NETCFG_KEY(const char *func)
{
        struct net_key key = ZERO_NET_KEY;
        key.af = _af_cfg(func);
        return key;
}



STATIC_FUNC
int32_t opt_ip_version(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;


        if (cmd == OPT_CHECK) {

                if (!initializing)
                        return FAILURE;

                uint8_t ip_tmp = (patch->diff == ADD) ? strtol(patch->val, NULL, 10) : 0;

                if (ip_tmp != 4 && ip_tmp != 6)
                        return FAILURE;

                //if (__af_cfg == AF_INET && ip_tmp == 6)
                if (__af_cfg != DEF_IP_FAMILY && __af_cfg != ((ip_tmp == 4) ? AF_INET : AF_INET6))
                        return FAILURE;

                if (_af_cfg_read && __af_cfg != ((ip_tmp == 4) ? AF_INET : AF_INET6)) {
                        dbgf_sys(DBGT_ERR, "Non-default %s=%d configured! Prefix your args with --%s=%d",
                                ARG_IP, ip_tmp, ARG_IP, ip_tmp);
                        return FAILURE;
                }


                __af_cfg = (ip_tmp == 4) ? AF_INET : AF_INET6;
                __ZERO_NETCFG_KEY.af = __af_cfg;

                //assertion_dbg(-501282, !_af_cfg_read, "af_cfg() already read by %s!", _af_cfg_read);

                struct opt_child *c = NULL;
                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!c->val)
                                continue;

                        int32_t val = strtol(c->val, NULL, 10);

                        if (val) {

                                if (!is_policy_rt_supported()) {

                                        dbgf_sys(DBGT_ERR, "Kernel policy-routing support required for %s=%d %c%s=%d",
                                                ARG_IP, ip_tmp, LONG_OPT_ARG_DELIMITER_CHAR, c->opt->name, val);

                                        if (!strcmp(c->opt->name, ARG_IP_POLICY_ROUTING))
                                                return FAILURE;
                                }
                        }

                        if (!strcmp(c->opt->name, ARG_IP_POLICY_ROUTING))
                                ip_policy_rt_cfg = val;
                        else if (!strcmp(c->opt->name, ARG_IP_THROW_RULES))
                                ip_throw_rules_cfg = val;
                        else if (!strcmp(c->opt->name, ARG_IP_PRIO_RULES))
                                ip_prio_rules_cfg = val;
                        else if (!strcmp(c->opt->name, ARG_IP_RULE_HNA))
                                ip_prio_hna_cfg = val;
                        else if (!strcmp(c->opt->name, ARG_IP_RULE_TUN))
                                ip_prio_tun_cfg = val;
                        else if (!strcmp(c->opt->name, ARG_IP_TABLE_HNA))
                                ip_table_hna_cfg = val;
                        else if (!strcmp(c->opt->name, ARG_IP_TABLE_TUN))
                                ip_table_tun_cfg = val;

                }


        } else if (cmd == OPT_SET_POST && initializing) {

                policy_routing = (ip_policy_rt_cfg && is_policy_rt_supported()) ? POLICY_RT_ENABLED : POLICY_RT_DISABLED;


//        } else if (cmd == OPT_POST && initializing) {

                assertion(-501131, (policy_routing != POLICY_RT_UNSET));

                dbgf_track(DBGT_INFO, "%s=%d policy_routing=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d",
                        ARG_IP, (AF_CFG == AF_INET ? 4 : 6), (policy_routing == POLICY_RT_ENABLED),
                        ARG_IP_POLICY_ROUTING, ip_policy_rt_cfg,
                        ARG_IP_THROW_RULES, ip_throw_rules_cfg,
                        ARG_IP_PRIO_RULES, ip_prio_rules_cfg,
                        ARG_IP_RULE_HNA,ip_prio_hna_cfg,
                        ARG_IP_RULE_TUN,ip_prio_tun_cfg,
                        ARG_IP_TABLE_HNA, ip_table_hna_cfg,
                        ARG_IP_TABLE_TUN, ip_table_tun_cfg

                        );

		// add rule for hosts and announced interfaces and networks
                if (policy_routing == POLICY_RT_ENABLED && ip_prio_rules_cfg /*&& primary_dev_cfg*/) {

                        ip_flush_routes(AF_INET);
                        ip_flush_rules(AF_INET);

                        ip(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET4_KEY, RT_TABLE_HNA, RT_PRIO_HNA, 0, 0, 0, 0, 0);
                        ip(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET4_KEY, RT_TABLE_TUN, RT_PRIO_TUNS, 0, 0, 0, 0, 0);

                        if (AF_CFG == AF_INET6) {
                                
                                ip_flush_routes(AF_INET6);
                                ip_flush_rules(AF_INET6);

                                ip(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET6_KEY, RT_TABLE_HNA, RT_PRIO_HNA, 0, 0, 0, 0, 0);
                                ip(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET6_KEY, RT_TABLE_TUN, RT_PRIO_TUNS, 0, 0, 0, 0, 0);
                        }

		}

        }

	return SUCCESS;
}

struct dev_status {
        char* devName;
        DEVADV_IDX_T devIdx;
        char *state;
        char *type;
        UMETRIC_T rateMin;
        UMETRIC_T rateMax;
        char llocalIp[IPX_PREFIX_STR_LEN];
        char globalIp[IPX_PREFIX_STR_LEN];
        char *multicastIp;
        HELLO_SQN_T helloSqn;
        uint8_t primary;
        uint8_t announced;
};

static const struct field_format dev_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,              dev_status, devName,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, devIdx,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,              dev_status, state,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,              dev_status, type,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,                   dev_status, rateMin,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,                   dev_status, rateMax,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,               dev_status, llocalIp,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,               dev_status, globalIp,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,              dev_status, multicastIp, 1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, helloSqn,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, primary,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, announced,   1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_END
};

static int32_t dev_status_creator(struct status_handl *handl, void* data)
{
        struct avl_node *it = NULL;
        struct dev_node *dev;
        uint32_t status_size = dev_name_tree.items * sizeof (struct dev_status);
        uint32_t i = 0;
        struct dev_status *status = ((struct dev_status*) (handl->data = debugRealloc(handl->data, status_size, -300367)));
        memset(status, 0, status_size);

        while ((dev = avl_iterate_item(&dev_name_tree, &it))) {

                IDM_T iff_up = dev->if_llocal_addr && (dev->if_llocal_addr->iln->flags & IFF_UP);


                status[i].devName = dev->label_cfg.str;
                status[i].devIdx = dev->dev_adv_idx;
                status[i].state = iff_up ? "UP":"DOWN";
                status[i].type = !dev->active ? "INACTIVE" :
                        (dev->linklayer == TYP_DEV_LL_LO ? "loopback" :
                        (dev->linklayer == TYP_DEV_LL_LAN ? "ethernet" :
                        (dev->linklayer == TYP_DEV_LL_WIFI ? "wireless" : "???")));
                status[i].rateMin = dev->umetric_min;
                status[i].rateMax = dev->umetric_max;
                sprintf(status[i].llocalIp, "%s/%d", dev->ip_llocal_str, dev->if_llocal_addr ? dev->if_llocal_addr->ifa.ifa_prefixlen : -1);
                sprintf(status[i].globalIp, "%s/%d", dev->ip_global_str, dev->if_global_addr ? dev->if_global_addr->ifa.ifa_prefixlen : -1);
                status[i].multicastIp = dev->ip_brc_str;
                status[i].helloSqn = dev->link_hello_sqn;
                status[i].primary = (dev == primary_dev);
                status[i].announced = dev->announce;

                i++;
        }
        return status_size;
}





STATIC_FUNC
int32_t opt_dev_prefix(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;


        if ((cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY)) {

                IDM_T is_global_prefix = !strcmp(opt->name, ARG_GLOBAL_PREFIX);
                struct net_key prefix = ZERO_NETCFG_KEY;

                if (patch->diff == ADD) {

                        if (str2netw(patch->val, &prefix.ip, cn, &prefix.mask, &prefix.af, NO) == FAILURE ||
                                (!is_ip_valid(&prefix.ip, prefix.af)) ||
                                (prefix.af == AF_INET6 && (
                                (is_ip_net_equal(&prefix.ip, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6)) ||
                                (XOR(is_global_prefix, !is_ip_net_equal(&prefix.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)))
                                ))) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s invalid prefix %s",
                                        opt->name, patch->val, netAsStr(&prefix));

                                return FAILURE;
                        }

                        set_opt_parent_val(patch, netAsStr(&prefix));
                }


                if (cmd == OPT_APPLY) {

                        struct avl_node *an = NULL;
                        struct dev_node *dev;

                        while ((dev = avl_iterate_item(&dev_name_tree, &an))) {

                                if (is_global_prefix ? !dev->global_prefix_conf_.mask : !dev->llocal_prefix_conf_.mask) {

                                        //mark all dev that are note specified more precise:
                                        dbgf_track(DBGT_INFO, "applying %s %s=%s %s",
                                                dev->label_cfg.str, opt->name, patch->val, netAsStr(&prefix));

                                        dev->hard_conf_changed = YES;
                                        opt_dev_changed = YES;
                                }
                        }

                        if (is_global_prefix)
                                global_prefix_cfg = prefix;
                        else
                                llocal_prefix_cfg = prefix;

                }
        }

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_auto_prefix(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;


        if ((cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY)) {

                struct net_key prefix = ZERO_NET6_KEY;
                str2netw(DEF_AUTO_IP6_PREFIX, &prefix.ip, NULL, &prefix.mask, &prefix.af, NO);

                if (patch->diff == ADD) {

                        if (str2netw(patch->val, &prefix.ip, cn, &prefix.mask, &prefix.af, NO) == FAILURE ||
                                (prefix.mask != DEF_AUTO_MASK_DISABLED && !is_ip_valid(&prefix.ip, prefix.af)) ||
                                (prefix.af != AF_INET6) ||
                                (is_ip_net_equal(&prefix.ip, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6)) ||
                                (is_ip_net_equal(&prefix.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)) ||
                                (prefix.mask != DEF_AUTO_IP6_MASK && prefix.mask != DEF_AUTO_MASK_DISABLED)
                                ) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s invalid prefix %s",
                                        opt->name, patch->val, netAsStr(&prefix));

                                return FAILURE;
                        }

                        set_opt_parent_val(patch, netAsStr(&prefix));
                }


                if (cmd == OPT_APPLY) {

                        if (!strcmp(opt->name, ARG_AUTO_IP6_PREFIX) && !is_ip_equal(&autoconf_prefix_cfg.ip, &prefix.ip)) {

                                struct avl_node *an = NULL;
                                struct dev_node *dev;

                                while ((dev = avl_iterate_item(&dev_name_tree, &an))) {

                                        if (!global_prefix_cfg.mask && !dev->global_prefix_conf_.mask) {

                                                //mark all dev that are note specified more precise:
                                                dbgf_track(DBGT_INFO, "applying %s %s=%s %s",
                                                        dev->label_cfg.str, opt->name, patch->val, netAsStr(&prefix));

                                                dev->hard_conf_changed = YES;
                                                opt_dev_changed = YES;
                                        }
                                }

                                autoconf_prefix_cfg = prefix;

                        } else if (!strcmp(opt->name, ARG_AUTO_REMOTE_PREFIX)) {

                                remote_prefix_cfg = prefix;

                                my_description_changed = YES;

                        }

                }
        }

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_dev(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

	struct dev_node *dev = NULL;

        if (cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) {

		if ( strlen(patch->val) >= IFNAMSIZ ) {
			dbgf_cn( cn, DBGL_SYS, DBGT_ERR, "dev name MUST be smaller than %d chars", IFNAMSIZ );
			return FAILURE;
                }

                char *colon_ptr;
                char phy_name[IFNAMSIZ] = {0};
                strcpy(phy_name, patch->val);

                // if given interface is an alias then truncate to physical interface name:
                if ((colon_ptr = strchr(phy_name, ':')) != NULL)
                        *colon_ptr = '\0';


                dev = dev_get_by_name(phy_name);

                if ( dev && strcmp(dev->label_cfg.str, patch->val)) {
                        dbgf_cn(cn, DBGL_SYS, DBGT_ERR,
                                "%s=%s (%s) already used for %s=%s %s!",
                                opt->name, patch->val, phy_name, opt->name, dev->label_cfg.str, dev->ip_llocal_str);

                        return FAILURE;
                }

		if ( patch->diff == DEL ) {

/*
                        if (dev && dev == primary_dev_cfg) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR,
                                        "primary interface %s %s can not be removed!",
                                        dev->label_cfg.str, dev->ip_llocal_str);

				return FAILURE;

                        } else
*/
                                if (dev && cmd == OPT_APPLY) {

                                opt_dev_changed = YES;

                                if (dev->active)
                                        dev_deactivate(dev);

                                avl_remove(&dev_name_tree, &dev->name_phy_cfg, -300205);

                                uint16_t i;
                                for (i = 0; i < plugin_data_registries[PLUGIN_DATA_DEV]; i++) {
                                        assertion(-500767, (!dev->plugin_data[i]));
                                }

                                debugFree(dev, -300048);

                                return SUCCESS;


                        } else if (!dev) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "Interface does not exist!");
                                return FAILURE;
                        }
                }

                if (!dev && cmd == OPT_APPLY) {

                        dbgf_track(DBGT_INFO, "cmd: %s opt: %s  %s instance %s",
                                opt_cmd2str[cmd], opt->name, family2Str(AF_CFG), patch ? patch->val : "");

                        uint32_t dev_size = sizeof (struct dev_node) + (sizeof (void*) * plugin_data_registries[PLUGIN_DATA_DEV]);
                        dev = debugMalloc(dev_size, -300002);
                        memset(dev, 0, dev_size);

/*
                        if (!primary_dev_cfg)
                                primary_dev_cfg = dev;
*/

                        strcpy(dev->label_cfg.str, patch->val);
                        strcpy(dev->name_phy_cfg.str, phy_name);

                        int i;
                        for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {
                                LIST_INIT_HEAD(dev->tx_task_lists[i], struct tx_task_node, list, list);
                        }

                        AVL_INIT_TREE(dev->tx_task_interval_tree, struct tx_task_node, task);


                        avl_insert(&dev_name_tree, dev, -300144);

/*
                        if (dev == primary_dev_cfg)
                                dev->announce = YES;
                        else
*/
                                dev->announce = DEF_DEV_ANNOUNCE;

                        // some configurable interface values - initialized to unspecified:
                        dev->linklayer_conf = OPT_CHILD_UNDEFINED;
                        dev->channel_conf = OPT_CHILD_UNDEFINED;
                        dev->umetric_max_conf = (UMETRIC_T) OPT_CHILD_UNDEFINED;
                        dev->umetric_min_conf = (UMETRIC_T) OPT_CHILD_UNDEFINED;
                        dev->global_prefix_conf_ = ZERO_NETCFG_KEY;
                        dev->llocal_prefix_conf_ = ZERO_NETCFG_KEY;

                        //dev->umetric_max = DEF_DEV_BITRATE_MAX;

                        dev->dummy_lndev.key.dev = dev;
                        
                        /*
                         * specifying the outgoing src address for IPv6 seems not working
                         * http://www.ureader.de/msg/12621915.aspx
                         * http://www.davidc.net/networking/ipv6-source-address-selection-linux
                         * http://etherealmind.com/ipv6-which-address-multiple-ipv6-address-default-address-selection/
                         * http://marc.info/?l=linux-net&m=127811438206347&w=2
                         */
                        dev->hard_conf_changed = YES;
                        dbgf_all(DBGT_INFO, "assigned dev %s physical name %s", dev->label_cfg.str, dev->name_phy_cfg.str);
                }

                if (cmd == OPT_APPLY)
                        opt_dev_changed = dev->soft_conf_changed = YES;
                

                struct opt_child *c = NULL;
                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_DEV_GLOBAL_PREFIX) || !strcmp(c->opt->name, ARG_DEV_LLOCAL_PREFIX)) {

                                IDM_T is_global_prefix = (!strcmp(c->opt->name, ARG_DEV_GLOBAL_PREFIX));
                                struct net_key prefix = ZERO_NETCFG_KEY;

                                if (c->val) {

                                        if (str2netw(c->val, &prefix.ip, cn, &prefix.mask, &prefix.af, NO) == FAILURE || !is_ip_valid(&prefix.ip, prefix.af) ||
                                                (prefix.af == AF_INET6 && (
                                                is_ip_net_equal(&prefix.ip, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6) ||
                                                XOR(is_global_prefix, !is_ip_net_equal(&prefix.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))))
                                                ) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid interface prefix %s", netAsStr(&prefix));
                                                return FAILURE;
                                        }

                                        set_opt_child_val(c, netAsStr(&prefix));
                                }

                                if (cmd == OPT_APPLY) {

                                        dbgf_track(DBGT_INFO, "applying %s %s=%s hard_conf_changed=%d",
                                                dev->label_cfg.str, c->opt->name, c->val, dev->hard_conf_changed);

                                        if (is_global_prefix) {
                                                if (c->val)
                                                        dev->global_prefix_conf_ = prefix;
                                                else
                                                        dev->global_prefix_conf_ = ZERO_NETCFG_KEY;
                                                
                                        } else {
                                                if (c->val)
                                                        dev->llocal_prefix_conf_ = prefix;
                                                else
                                                        dev->llocal_prefix_conf_ = ZERO_NETCFG_KEY;

                                        }

                                        dev->hard_conf_changed = YES;
                                }

                        } else if (!strcmp(c->opt->name, ARG_DEV_LL) && cmd == OPT_APPLY) {

                                dev->linklayer_conf = c->val ? strtol(c->val, NULL, 10) : OPT_CHILD_UNDEFINED;

                                dev->hard_conf_changed = YES;

                        } else if (!strcmp(c->opt->name, ARG_DEV_CHANNEL) && cmd == OPT_APPLY) {

                                dev->channel_conf = c->val ? strtol(c->val, NULL, 10) : OPT_CHILD_UNDEFINED;

                        } else if (!strcmp(c->opt->name, ARG_DEV_BITRATE_MAX) && cmd == OPT_APPLY) {

                                if (c->val) {
                                        char *endptr;
                                        unsigned long long ull = strtoul(c->val, &endptr, 10);

                                        if (ull > UMETRIC_MAX || ull < UMETRIC_FM8_MIN || *endptr != '\0') {

                                                dbgf_sys(DBGT_ERR, "%s %c%s MUST be within [%ju ... %ju]",
                                                        dev->label_cfg.str, LONG_OPT_ARG_DELIMITER_CHAR, c->opt->name, UMETRIC_FM8_MIN, UMETRIC_MAX);

                                                return FAILURE;
                                        }

                                        

                                        dev->umetric_max_conf = ull;
                                } else {
                                        dev->umetric_max_conf = (UMETRIC_T) OPT_CHILD_UNDEFINED;
                                }


                        } else if (!strcmp(c->opt->name, ARG_DEV_BITRATE_MIN) && cmd == OPT_APPLY) {

                                if (c->val) {
                                        char *endptr;
                                        unsigned long long ull = strtoul(c->val, &endptr, 10);

                                        if (ull > UMETRIC_MAX || ull < UMETRIC_FM8_MIN || *endptr != '\0') {

                                                dbgf_sys(DBGT_ERR, "%s %c%s given with illegal value",
                                                        dev->label_cfg.str, LONG_OPT_ARG_DELIMITER_CHAR, c->opt->name);

                                                return FAILURE;
                                        }

                                        dev->umetric_min_conf = ull;
                                } else {
                                        dev->umetric_min_conf = OPT_CHILD_UNDEFINED;
                                }


                        } else if (!strcmp(c->opt->name, ARG_DEV_ANNOUNCE) && cmd == OPT_APPLY) {

                                if (c->val)
                                        dev->announce = strtol(c->val, NULL, 10);

                                dev->hard_conf_changed = YES;
                        }
                }

/*
        } else if (cmd == OPT_POST && !primary_dev_cfg) {

                dbgf_sys(DBGT_ERR, "No interface configured!");

                cleanup_all( CLEANUP_FAILURE );
*/

        } else if (cmd == OPT_POST /*&& af_cfg == family && opt && !opt->parent_name*/ && opt_dev_changed) {

                opt_dev_changed = NO;

                // will always be called whenever a dev-parameter is changed (due to OPT_POST and opt_dev_changed)
                // is it needed by another option ?
                dev_check(initializing ? kernel_if_config() == YES : NO);

        }

	return SUCCESS;
}



static struct opt_type ip_options[]=
{
//        ord parent long_name          shrt, order, relevance, Attributes...	*ival		min		max		default		*func,*syntax,*help
	{ODI,0,ARG_IP,	                'I',3,2, A_PS1N,A_ADM,A_INI,A_CFA,A_ANY,	NULL,    0,0,0,/*MIN_IP_VERSION, MAX_IP_VERSION,*/ DEF_IP_VERSION,  opt_ip_version,
			ARG_VALUE_FORM,	"select ip protocol Version 4 or 6"}
        ,

	{ODI,ARG_IP,ARG_IP_POLICY_ROUTING,0,3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_policy_rt_cfg,0, 		1,		DEF_IP_POLICY_ROUTING,0,opt_ip_version,
			ARG_VALUE_FORM,	"disable policy routing (throw and priority rules)"}
        ,
	{ODI,ARG_IP,ARG_IP_THROW_RULES,	 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_throw_rules_cfg,0, 		1,		DEF_IP_THROW_RULES,0,opt_ip_version,
			ARG_VALUE_FORM,	"disable/enable default throw rules"}
        ,
	{ODI,ARG_IP,ARG_IP_PRIO_RULES,	 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_prio_rules_cfg, 0, 		1,		DEF_IP_PRIO_RULES,0, opt_ip_version,
			ARG_VALUE_FORM,	"disable/enable default priority rules"}
        ,
	{ODI,ARG_IP,ARG_IP_RULE_HNA,	 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_prio_hna_cfg,	MIN_IP_RULE_HNA,MAX_IP_RULE_HNA,DEF_IP_RULE_HNA,0,opt_ip_version,
			ARG_VALUE_FORM,	"specify iproute2 rule preference offset for hna networks"},
	{ODI,ARG_IP,ARG_IP_RULE_TUN,	 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_prio_tun_cfg,	MIN_IP_RULE_TUN,MAX_IP_RULE_TUN,DEF_IP_RULE_TUN,0,opt_ip_version,
			ARG_VALUE_FORM,	"specify iproute2 rule preference offset for tunnel networks"}
        ,
	{ODI,ARG_IP,ARG_IP_TABLE_HNA, 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_table_hna_cfg,	MIN_IP_TABLE_HNA,   MAX_IP_TABLE_HNA,   DEF_IP_TABLE_HNA,0,     opt_ip_version,
			ARG_VALUE_FORM,	"specify iproute2 table for hna networks"},
	{ODI,ARG_IP,ARG_IP_TABLE_TUN, 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_table_tun_cfg,	MIN_IP_TABLE_TUN,   MAX_IP_TABLE_TUN,   DEF_IP_TABLE_TUN,0,     opt_ip_version,
			ARG_VALUE_FORM,	"specify iproute2 table for tunnel networks"}

#ifdef WITH_UNUSED
        ,
        {ODI,0,"lo_rule",		0,  4,0,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	&Lo_rule,	0, 		1,		DEF_LO_RULE,0,	0,
			ARG_VALUE_FORM,	"disable/enable autoconfiguration of lo rule"}
#endif
        ,
	{ODI,0,ARG_INTERFACES,	        0,  9,2,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show interfaces\n"}
        ,

	{ODI,0,ARG_GLOBAL_PREFIX,	0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_dev_prefix,
			ARG_PREFIX_FORM,HLP_GLOBAL_PREFIX}
        ,
	{ODI,0,ARG_LLOCAL_PREFIX,	0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_dev_prefix,
			ARG_PREFIX_FORM,HLP_LLOCAL_PREFIX}
        ,
	{ODI,0,ARG_AUTO_IP6_PREFIX,     0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,      	0,      	0,              0,DEF_AUTO_IP6_PREFIX,opt_auto_prefix,
			ARG_VALUE_FORM,	HLP_AUTO_IP6_PREFIX}
        ,
	{ODI,0,ARG_AUTO_REMOTE_PREFIX,  0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,      	0,      	0,              0,DEF_AUTO_REMOTE_PREFIX,opt_auto_prefix,
			ARG_VALUE_FORM,	HLP_AUTO_REMOTE_PREFIX}
        ,
	{ODI,0,ARG_DEV,		        'i',9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0,0, 		opt_dev,
			"<interface-name>", HLP_DEV}
        ,
	{ODI,ARG_DEV,ARG_DEV_ANNOUNCE,  'a',9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		1,		DEF_DEV_ANNOUNCE,0,opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_ANNOUNCE}
        ,
	{ODI,ARG_DEV,ARG_DEV_LL,	 'l',9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		MIN_DEV_LL,	MAX_DEV_LL,     DEF_DEV_LL,0,	opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_LL}
        ,
	{ODI,ARG_DEV,ARG_DEV_GLOBAL_PREFIX,0, 9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,		0,              0,              0,0,              opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_GLOBAL_PREFIX}
        ,
	{ODI,ARG_DEV,ARG_DEV_LLOCAL_PREFIX,0, 9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,		0,              0,              0,0,              opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_LLOCAL_PREFIX}
        ,
	{ODI,ARG_DEV,ARG_DEV_BITRATE_MAX,'r',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,              0,              0,0,              opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_BITRATE_MAX}
        ,
	{ODI,ARG_DEV,ARG_DEV_BITRATE_MIN, 0, 9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,              0,              0,0,              opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_BITRATE_MIN}

        ,
	{ODI,0,ARG_PEDANTIC_CLEANUP,	  0, 9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&Pedantic_cleanup,0,		1,		DEF_PEDANTIC_CLEANUP,0,0,
			ARG_VALUE_FORM,	"disable/enable pedantic cleanup of system configuration (like ip_forward,..) \n"
			"	at program termination. Its generally safer to keep this disabled to not mess up \n"
			"	with other routing protocols"}

};




void init_ip(void)
{
        assertion(-500894, is_zero(((char*)&ZERO_IP), sizeof (ZERO_IP)));
        assertion(-501254, is_zero((void*) &ZERO_NET_KEY, sizeof (ZERO_NET_KEY)));
        assertion(-501336, is_zero((void*) &llocal_prefix_cfg, sizeof (llocal_prefix_cfg)));
        assertion(-501337, is_zero((void*) &global_prefix_cfg, sizeof (global_prefix_cfg)));
        assertion(-501395, is_zero((void*) &autoconf_prefix_cfg, sizeof (autoconf_prefix_cfg)));

        remote_prefix_cfg = ZERO_NET6_KEY;
        autoconf_prefix_cfg = ZERO_NET6_KEY;
        str2netw(DEF_AUTO_IP6_PREFIX, &autoconf_prefix_cfg.ip, NULL, &autoconf_prefix_cfg.mask, &autoconf_prefix_cfg.af, NO);
        str2netw(DEF_AUTO_REMOTE_PREFIX, &remote_prefix_cfg.ip, NULL, &remote_prefix_cfg.mask, &remote_prefix_cfg.af, NO);

        memset(&default_tun_in, 0, sizeof (default_tun_in));
        default_tun_in.tun6Id = -1;


        if (rtnl_open(&ip_rth) != SUCCESS) {
                dbgf_sys(DBGT_ERR, "failed opening rtnl socket");
                cleanup_all( -500561 );
        }

        errno=0;
	if ( !rt_sock  &&  (rt_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		dbgf_sys(DBGT_ERR, "can't create routing socket %s:",  strerror(errno) );
		cleanup_all( -500021 );
	}

        if( ( nlsock_default = open_netlink_socket()) <= 0 )
		cleanup_all( -500067 );

        if ((nlsock_flush_all = open_netlink_socket()) <= 0)
		cleanup_all( -500658 );

        if (open_ifevent_netlink_sk() < 0)
                cleanup_all(-500150);

        register_options_array(ip_options, sizeof ( ip_options), CODE_CATEGORY_NAME);

        register_status_handl(sizeof (struct dev_status), 1, dev_status_format, ARG_INTERFACES, dev_status_creator);


//        InitSha(&ip_sha);
}

void cleanup_ip(void)
{

        close_ifevent_netlink_sk();

        // if ever started succesfully in daemon mode...
        if (policy_routing == POLICY_RT_ENABLED && ip_prio_rules_cfg) {

                ip_flush_tracked( IP_ROUTE_FLUSH );
                ip_flush_routes(AF_CFG);
                if (AF_CFG == AF_INET6)
                        ip_flush_routes(AF_INET);


                ip_flush_tracked( IP_RULE_FLUSH );
                ip_flush_rules(AF_CFG);
                if (AF_CFG == AF_INET6)
                        ip_flush_rules(AF_INET);

        }

        kernel_if_fix(YES,0);


        sysctl_restore(NULL);


        while (dev_name_tree.items) {

                struct dev_node *dev = dev_name_tree.root->item;

                if (dev->active)
                        dev_deactivate(dev);

                avl_remove(&dev_name_tree, &dev->name_phy_cfg, -300204);

                debugFree(dev, -300046);
        }


        if (ip_rth.fd >= 0) {
                close(ip_rth.fd);
                ip_rth.fd = -1;
        }


        if ( rt_sock ) {
                close(rt_sock);
                rt_sock = 0;
        }


        if( nlsock_default > 0 ) {
                close(nlsock_default);
                nlsock_default = 0;
        }


        if (nlsock_flush_all > 0) {
                close(nlsock_flush_all);
                nlsock_flush_all = 0;
        }



}

