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
#include <linux/if_tun.h> /* TUNSETPERSIST, ... */
#include <linux/if.h>     /* ifr_if, ifr_tun */

#include <sys/types.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "ip.h"
#include "schedule.h"
#include "plugin.h"
#include "tools.h"
#include "iptools.h"
#include "allocate.h"

#define CODE_CATEGORY_NAME "ip"

uint8_t __af_cfg = DEF_IP_FAMILY;
struct net_key __ZERO_NETCFG_KEY = {.af = DEF_IP_FAMILY};



const IFNAME_T ZERO_IFNAME = {{0}};


//TODO: remove me!!??
int dev_lo_idx = 0;



int32_t ip_prio_hna_cfg = DEF_IP_RULE_HNA;
static int32_t ip_prio_tun_cfg = DEF_IP_RULE_TUN;
int32_t ip_table_hna_cfg = DEF_IP_TABLE_HNA;
int32_t ip_table_tun_cfg = DEF_IP_TABLE_TUN;
int32_t ip_prio_rules_cfg = DEF_IP_PRIO_RULES;
int32_t ip_throw_rules_cfg = DEF_IP_THROW_RULES;
int32_t ip_policy_rt_cfg = DEF_IP_POLICY_ROUTING;


int32_t policy_routing = POLICY_RT_UNSET;

static int32_t base_port = DEF_BASE_PORT;


//TODO: make this configurable
static struct net_key llocal_prefix_cfg;
struct net_key autoconf_prefix_cfg;


//#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
//#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
//const IP6_T IP6_LOOPBACK_ADDR = { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } };


//const IP6_T   IP6_ALLROUTERS_MC_ADDR = {.s6_addr[0] = 0xFF, .s6_addr[1] = 0x02, .s6_addr[15] = 0x02};
const IP6_T   IP6_ALLROUTERS_MC_ADDR = {{{0xFF,0x02,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x02}}};

//const IP6_T   IP6_LINKLOCAL_UC_PREF = {.s6_addr[0] = 0xFE, .s6_addr[1] = 0x80};
const IP6_T   IP6_LINKLOCAL_UC_PREF = {{{0xFE,0x80,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}}};
const uint8_t IP6_LINKLOCAL_UC_PLEN = 10;

//const IP6_T   IP6_MC_PREF = {.s6_addr[0] = 0xFF};
const IP6_T   IP6_MC_PREF = {{{0xFF,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}}};
const uint8_t IP6_MC_PLEN = 8;


// static int nlsock_default = -1;

static int io_sock = 0;

struct rtnl_handle ip_rth = { .fd = -1 };
struct rtnl_handle ip_rth2 = { .fd = -1 };

static IDM_T opt_dev_changed = YES;


AVL_TREE(if_link_tree, struct if_link_node, index);

AVL_TREE(dev_ip_tree, struct dev_node, llip_key);
AVL_TREE(dev_name_tree, struct dev_node, name_phy_cfg);
AVL_TREE(tun_name_tree, struct ifname, str);

AVL_TREE(iptrack_tree, struct track_node, k);


static int ifevent_sk = -1;


//static Sha ip_sha;



static int32_t Pedantic_cleanup = DEF_PEDANTIC_CLEANUP;
static int32_t if6_forward_orig = -1;
static int32_t if4_forward_orig = -1;
static int32_t if4_rp_filter_all_orig = -1;
static int32_t if4_rp_filter_default_orig = -1;
static int32_t if4_send_redirects_all_orig = -1;
static int32_t if4_send_redirects_default_orig = -1;

static void dev_check(void *kernel_ip_config_changed);
static void (*ipexport) (int8_t del, const struct net_key *dst, uint32_t oif_idx, IPX_T *via, uint32_t metric, uint8_t distance) = NULL;

struct sys_route_dict bmx6_rt_dict[BMX6_ROUTE_MAX];


STATIC_FUNC
int rtnl_open(struct rtnl_handle *rth)
{
        unsigned subscriptions = 0;
        int protocol = NETLINK_ROUTE;
	socklen_t addr_len;
//	int sndbuf = 32768;
//        int rcvbuf = 1024 * 1024;

	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (rth->fd < 0) {
                dbgf_sys(DBGT_ERR, "Cannot open netlink socket");
		return FAILURE;
	}

/*
        if ( fcntl( rth->fd, F_SETFL, O_NONBLOCK) < 0 ) {
		dbgf_sys(DBGT_ERR, "can't set netlink socket nonblocking : (%s)",  strerror(errno));
		close(rth->fd);
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
*/

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
	rth->seq = rand_num(UINT32_MAX);
	return SUCCESS;
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
        if ( ioctl( io_sock, siocgi_req, if_req ) < 0 ) {

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
uint32_t prio_macro_to_prio(int32_t prio_macro)
{
        assertion(-501100, (IMPLIES(prio_macro<0, (prio_macro >= RT_PRIO_MIN && prio_macro <= RT_PRIO_MAX))));

        if (policy_routing == POLICY_RT_DISABLED)
                return 0;

	else if (prio_macro>=0)
		return prio_macro;

        else if (prio_macro == RT_PRIO_HNA)
		return ip_prio_hna_cfg;

        else if (prio_macro == RT_PRIO_TUNS)
		return ip_prio_tun_cfg;

	return 0;
}


STATIC_FUNC
uint32_t table_macro_to_table(int32_t table_macro)
{
        assertion(-501101, (IMPLIES(table_macro<0, (table_macro >= RT_TABLE_MIN && table_macro <= RT_TABLE_MAX))));

        if (policy_routing == POLICY_RT_DISABLED)
                return 0;

	else if (table_macro>=0)
		return table_macro;

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

        else if (cmd == IP_LINK_DEL)
                return "LINK_DEL";

        else if (cmd == IP_LINK_GET)
                return "LINK_GET";

        else if (cmd == IP_ADDR_GET)
                return "ADDR_GET";

        else if (cmd == IP_ROUTE_GET)
                return "ROUTE_GET";


        else if ( cmd == IP_ADDRESS_SET )
		return "ADDRESS_SET";


        else if ( cmd == IP_RULE_FLUSH )
		return "RULE_FLUSH";

        else if ( cmd == IP_RULE_DEFAULT )
		return "RULE_DEFAULT";

        else if ( cmd == IP_RULE_TEST )
		return "RULE_TEST";


        else if (cmd == IP_ROUTE_FLUSH)
                return "ROUTE_FLUSH";

        else if ( cmd == IP_THROW_MY_HNA )
		return "THROW_MY_HNA";

	else if ( cmd == IP_THROW_MY_NET )
		return "THROW_MY_NET";

	else if ( cmd == IP_THROW_MY_TUNS )
		return "THROW_MY_TUNS";

	else if ( cmd == IP_ROUTE_HOST )
		return "ROUTE_HOST";

	else if ( cmd == IP_ROUTE_HNA )
		return "ROUTE_HNA";

        else if(cmd == IP_ROUTE_TUNS )
                return "ROUTE_TUNS";

	else if ( cmd > IP_ROUTE_TUNS && cmd < IP_ROUTE_MAX ) {

                return bmx6_rt_dict[ (cmd - IP_ROUTE_TUNS) ].sys2Name;

	} 

        return "TRACK_ILLEGAL";
}


STATIC_FUNC
struct dev_node * dev_get_by_name(char *name)
{
        IFNAME_T key = ZERO_IFNAME;

        strcpy(key.str, name);

        return avl_find_item(&dev_name_tree, &key);
}

IDM_T rtnl_rcv( int fd, uint32_t pid, uint32_t seq, uint8_t cmd, uint8_t quiet, void (*func) (struct nlmsghdr *nh, void *data) ,void *data)
{
        int max_retries = 10;
        uint8_t more_data;

        //TODO: see ip/libnetlink.c rtnl_talk() for HOWTO
        do {
                char buf[4096]; // less causes lost messages !!??
                memset(buf, 0, sizeof(buf));

                struct iovec iov = {.iov_base = buf, .iov_len = sizeof (buf)};
                struct sockaddr_nl nla = {.nl_family = AF_NETLINK }; //{.nl_family = AF_NETLINK}; //TODO: not sure here, maybe only for cmd==IP_ADDR_GET and IP_LINK_GET
                struct msghdr msg = {.msg_name = (void *)&nla, .msg_namelen = sizeof(nla), .msg_iov = &iov, .msg_iovlen = 1};
                struct nlmsghdr *nh;

                more_data = NO;

		errno=0;
		int status = recvmsg( fd, &msg, 0 );
                int err = errno;

                if (err) {
                        dbgf(DBGL_CHANGES, DBGT_INFO, "rcvd %s status=%d err=%d %s",
                                trackt2str(cmd), status, err, strerror(err));
                }


		if ( status < 0 ) {

                        dbgf_sys(DBGT_ERR, "%s", strerror(err));

                        if ( (err == EINTR || err == EWOULDBLOCK || err == EAGAIN ) && max_retries-- > 0 ) {
                                usleep(500);
				upd_time( NULL );
                                more_data = YES;
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


		for ( nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)status); nh = NLMSG_NEXT(nh, status) ) {

                        if (nla.nl_pid || (pid && nh->nlmsg_pid != pid) || (seq && nh->nlmsg_seq != seq)) {

                                dbgf_sys(DBGT_ERR, "pid/sqn mismatch: status=%d  "
                                        "nl_pid=%d ==0!?  nlmsg_pid=%d == local.nl_pid=%d!? "
                                        "nlmsg_seq=%d == ip_rth.dump=%d!?",
                                        status, nla.nl_pid, nh->nlmsg_pid, pid, nh->nlmsg_seq, seq);

                                assertion(-501495, (0)); //continue;
                        }

                        if (nh->nlmsg_flags & NLM_F_MULTI) {
                                dbgf_all( DBGT_INFO, "NLM_F_MULTI");
                                more_data = YES;
                        }

                        if (nh->nlmsg_type == NLMSG_DONE) {
                                dbgf_track(DBGT_INFO, "NLMSG_DONE");
                                more_data = NO;
                                break;

                        } else if (nh->nlmsg_type == NLMSG_ERROR && ((struct nlmsgerr*) NLMSG_DATA(nh))->error) {

                                dbgf(quiet ? DBGL_ALL : DBGL_SYS, quiet ? DBGT_INFO : DBGT_ERR, "%s error=%s",
                                        trackt2str(cmd), strerror(-((struct nlmsgerr*) NLMSG_DATA(nh))->error));

                                return FAILURE;
                        }


                        if (func)
                                (*func)(nh, data);
		}

        } while (more_data);

        return SUCCESS;
}

STATIC_FUNC
IDM_T rtnl_talk(struct rtnl_handle *iprth, struct nlmsghdr *nlh, uint8_t cmd, uint8_t quiet, void (*func) (struct nlmsghdr *nh, void *data) ,void *data)
{

        // DONT USE setNet() here (because return pointer is static)!!!!!!!!!!!!!

        assertion(-501494, (!iprth->busy));
        iprth->busy = 1;

	nlh->nlmsg_pid = My_pid;
	nlh->nlmsg_seq = ++(iprth->seq);

        errno = 0;
        if (send(iprth->fd, nlh, nlh->nlmsg_len, 0) < 0) {
                dbgf_sys(DBGT_ERR, "can't send netlink message to kernel: %s", strerror(errno));
                iprth->busy = 0;
                EXITERROR(-501095, (0));
		return FAILURE;
        }



	IDM_T result = rtnl_rcv( iprth->fd, iprth->local.nl_pid, iprth->seq, cmd, quiet, func, data );

	iprth->busy = 0;
	return result;
}


STATIC_FUNC
IDM_T kernel_get_if_config_post(IDM_T purge_all, uint16_t curr_sqn)
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

                        if ( purge_all || curr_sqn != ian->update_sqn || curr_sqn != iln->update_sqn) {

                                dbgf_track(DBGT_WARN, "addr index %d %s addr %s REMOVED",
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

                        dbgf_track(DBGT_WARN, "link index %d %s addr %s REMOVED",
                                iln->index, iln->name.str, memAsHexString(&iln->addr, iln->alen));

                        avl_remove(&if_link_tree, &iln->index, -300232);
                        avl_remove(&if_link_tree, &iln->name, -300521);
                        debugFree(iln, -300230);
                        changed++;


                } else if (iln->changed || (addr_changed && dev && !dev->if_llocal_addr && !dev->if_global_addr)) {

                        if (dev)
                                dev->hard_conf_changed = YES;

                        changed += iln->changed;

                        dbgf_track(DBGT_WARN, "link=%s dev=%s configuration CHANGED",
                                iln->name.str, dev ? dev->label_cfg.str : "ERROR");

                }
        }

        if (changed) {
                dbgf_track(DBGT_WARN, "network configuration CHANGED");
                return YES;
        } else {
                dbgf_all(DBGT_INFO, "network configuration UNCHANGED");
                return NO;
        }
}


STATIC_FUNC
void kernel_get_if_addr_config(struct nlmsghdr *nh, void *index_sqnp)
{
        TRACE_FUNCTION_CALL;
        uint16_t index_sqn = *((uint16_t*) index_sqnp);
        struct ifaddrmsg *if_addr = NLMSG_DATA(nh);
        int index = if_addr->ifa_index;
        int family = if_addr->ifa_family;
        struct if_link_node *iln = avl_find_item(&if_link_tree, &index);

        if (!iln)
                return;

        if (family != AF_INET && family != AF_INET6)
                return;

        if (nh->nlmsg_type != RTM_NEWADDR)
                return;

        assertion(-501496, (nh->nlmsg_len >= (int) NLMSG_LENGTH(sizeof (*if_addr))));

        struct rtattr * rta_tb[IFA_MAX + 1];

        parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(if_addr), nh->nlmsg_len - NLMSG_LENGTH(sizeof (*if_addr)));


        if (!rta_tb[IFA_LOCAL])
                rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];

        if (!rta_tb[IFA_LOCAL] || !if_addr)
                return;

        IPX_T ip_addr = ZERO_IP;

        uint32_t alen = XMIN(sizeof (ip_addr), RTA_PAYLOAD(rta_tb[IFA_LOCAL]));

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

                if (nh->nlmsg_len > old_ian->nlmsghdr->nlmsg_len) {

                        if (old_ian->dev) {
                                old_ian->dev->hard_conf_changed = YES;
                                old_ian->dev->if_llocal_addr = NULL;
                                old_ian->dev->if_global_addr = NULL;
                        }

                        avl_remove(&iln->if_addr_tree, &ip_addr, -300239);
                        dbgf_sys(DBGT_ERR, "new size");

                } else if (memcmp(nh, old_ian->nlmsghdr, nh->nlmsg_len)) {

                        if (nh->nlmsg_len != old_ian->nlmsghdr->nlmsg_len) {
                                dbgf_sys(DBGT_ERR, "different data and size %d != %d",
                                        nh->nlmsg_len, old_ian->nlmsghdr->nlmsg_len);
                        }

                        memcpy(old_ian->nlmsghdr, nh, nh->nlmsg_len);
                        new_ian = old_ian;

                } else {
                        new_ian = old_ian;
                }

        }

        if (!new_ian) {
                new_ian = debugMallocReset(sizeof (struct if_addr_node) + nh->nlmsg_len, -300522);
                memcpy(new_ian->nlmsghdr, nh, nh->nlmsg_len);
                new_ian->ip_addr = ip_addr;
                new_ian->iln = iln;
                avl_insert(&iln->if_addr_tree, new_ian, -300520);
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
                //old_ian->ifa.ifa_flags != if_addr->ifa_flags ||
                old_ian->ifa.ifa_prefixlen != if_addr->ifa_prefixlen ||
                old_ian->ifa.ifa_scope != if_addr->ifa_scope ||
                old_ian->ifa.ifa_index != if_addr->ifa_index ||
                memcmp(&old_ian->label, &label, sizeof (label)) ||
                //                                                memcmp(&old_ian->ip_any, &ip_any, alen) ||
                memcmp(&old_ian->ip_mcast, &ip_mcast, alen)
                ) {

                dbgf_track(DBGT_INFO, "%s addr %s CHANGED old=%d", label.str, ipXAsStr(family, &ip_addr), old_ian?1:0);

                if(old_ian) {
                        dbgf_track(DBGT_INFO, "fa=%d|%d flags=%X|%X plen=%d|%d scope=%d|%d idx=%d|%d label=%s|%s mcast=%s|%s )",
                                old_ian->ifa.ifa_family, if_addr->ifa_family,
                                old_ian->ifa.ifa_flags, if_addr->ifa_flags,
                                old_ian->ifa.ifa_prefixlen, if_addr->ifa_prefixlen,
                                old_ian->ifa.ifa_scope,if_addr->ifa_scope,
                                old_ian->ifa.ifa_index,if_addr->ifa_index,
                                old_ian->label.str, label.str,
                                memAsHexString(&old_ian->ip_mcast, alen), memAsHexString(&ip_mcast, alen));
                }


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

	checkIntegrity();
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

STATIC_FUNC
void kernel_get_if_link_config(struct nlmsghdr *nh, void *update_sqnp)
{
	TRACE_FUNCTION_CALL;

        uint16_t update_sqn = *((uint16_t*) update_sqnp);

	struct ifinfomsg *if_link_info = NLMSG_DATA(nh);
	//struct idxmap *im, **imp;
	struct rtattr *tb[IFLA_MAX+1];

        uint16_t changed = 0;

	if (nh->nlmsg_type != RTM_NEWLINK)
		return;

        assertion(-501497, (nh->nlmsg_len >= NLMSG_LENGTH(sizeof(*if_link_info))));

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(if_link_info), IFLA_PAYLOAD(nh));

        if (!tb[IFLA_IFNAME])
                return;

        int index = if_link_info->ifi_index;
        struct if_link_node *new_ilx = NULL;
        struct if_link_node *old_ilx = avl_find_item(&if_link_tree, &index);

        if (old_ilx) {

                if (old_ilx->update_sqn == update_sqn) {
                        dbgf_sys(DBGT_ERR, "ifi %d found several times!", old_ilx->index);
                }

                assertion(-500902, (nh->nlmsg_len >= sizeof (struct nlmsghdr)));

                if (nh->nlmsg_len > old_ilx->nlmsghdr->nlmsg_len) {

                        avl_remove(&if_link_tree, &index, -300240);
                        dbgf_all(DBGT_INFO, "CHANGED and MORE nlmsg_len");

                } else if (memcmp(nh, old_ilx->nlmsghdr, nh->nlmsg_len)) {

                        dbgf_all(DBGT_INFO, "CHANGED nlmsg_len new=%d  old=%d",
                                nh->nlmsg_len, old_ilx->nlmsghdr->nlmsg_len);
                        
                        memcpy(old_ilx->nlmsghdr, nh, nh->nlmsg_len);
                        new_ilx = old_ilx;
                
                } else {
                        new_ilx = old_ilx;
                }
        }

        if (!new_ilx) {
                new_ilx = debugMallocReset(sizeof (struct if_link_node) + nh->nlmsg_len, -300231);
                new_ilx->index = if_link_info->ifi_index;
                AVL_INIT_TREE(new_ilx->if_addr_tree, struct if_addr_node, ip_addr);
                avl_insert(&if_link_tree, new_ilx, -300233);
                memcpy(new_ilx->nlmsghdr, nh, nh->nlmsg_len);
        }

        IFNAME_T devname = ZERO_IFNAME;
        strcpy(devname.str, RTA_DATA(tb[IFLA_IFNAME]));

        if (!strcmp(devname.str, DEV_LO)) {
                assertion(-501346, IMPLIES(dev_lo_idx, dev_lo_idx == if_link_info->ifi_index));
                dev_lo_idx = if_link_info->ifi_index;
        }

        int32_t alen = (tb[IFLA_ADDRESS]) ? RTA_PAYLOAD(tb[IFLA_ADDRESS]) : 0;
        ADDR_T addr = {{0}};
        memcpy(&addr, RTA_DATA(tb[IFLA_ADDRESS]), XMIN(alen, (int)sizeof (addr)));

        if (!old_ilx ||
                old_ilx->type != if_link_info->ifi_type ||
                old_ilx->flags != if_link_info->ifi_flags ||
                old_ilx->alen != alen /*(int)RTA_PAYLOAD(tb[IFLA_ADDRESS])*/ ||
                memcmp(&old_ilx->addr, RTA_DATA(tb[IFLA_ADDRESS]), XMIN(alen, (int)sizeof(old_ilx->addr))) ||
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

	return;
}






static IDM_T kernel_get_if_config(void)
{
	TRACE_FUNCTION_CALL;

        static uint16_t index_sqn = 0;
        int ai;

        index_sqn++;
        dbgf_all( DBGT_INFO, "%d", index_sqn);

#define LINK_INFO 0
#define ADDR_INFO 1

        for (ai = LINK_INFO; ai <= ADDR_INFO; ai++) {

                struct ip_req req;


                memset(&req, 0, sizeof (req));

		req.nlh.nlmsg_len = sizeof(req);

                req.nlh.nlmsg_type = ai ? RTM_GETADDR : RTM_GETLINK;
                req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;

                req.rtg.rtgen_family = AF_UNSPEC;

                rtnl_talk(&ip_rth, &req.nlh, (ai ? IP_ADDR_GET : IP_LINK_GET), NO,
                        (ai ? kernel_get_if_addr_config : kernel_get_if_link_config), &index_sqn);
        }

        return kernel_get_if_config_post(NO, index_sqn);
}



IDM_T kernel_set_addr(IDM_T del, uint32_t if_index, uint8_t family, IPX_T *ipX, uint8_t prefixlen, IDM_T deprecated)
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

        return rtnl_talk(&ip_rth, &req.nlh, IP_ADDRESS_SET, NO, NULL, NULL);
}


IDM_T kernel_set_flags(char *name, int fd, int get_req, int set_req, uint16_t up_flags, uint16_t down_flags)
{
        struct ifreq req;
	memset(&req, 0, sizeof (req));
	strncpy(req.ifr_name, name, IFNAMSIZ);
	if (get_req && (ioctl(fd ? fd : io_sock, get_req, &req))) {
		dbgf_sys(DBGT_ERR, "getting dev=%s request=%d flags up=%X down=%X %s", name, get_req, up_flags, down_flags, strerror(errno));
		return FAILURE;
	}

	req.ifr_flags &= ~down_flags;
	req.ifr_flags |= up_flags;

	if ((ioctl(fd ? fd : io_sock, set_req, &req))) {
		dbgf_sys(DBGT_ERR, "setting dev=%s request=%d flags up=%X down=%X %s", name, set_req, up_flags, down_flags, strerror(errno));
		return FAILURE;
	}
	return SUCCESS;
}


int32_t kernel_get_ifidx( char *name )
{
        struct ifreq req;
	memset(&req, 0, sizeof (req));
	strncpy(req.ifr_name, name, IFNAMSIZ);

	if ( ioctl( io_sock, SIOCGIFINDEX, &req ) < 0 ) {
		dbgf_sys(DBGT_ERR, "getting idx for dev=%s %s", name, strerror(errno));
		return FAILURE;
	}

	return req.ifr_ifindex;
}


IDM_T kernel_link_del(char *name)
{
        dbgf_track(DBGT_INFO, "name=%s", name);
	struct iplink_req req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifinfomsg));

	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_type = RTM_DELLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = kernel_get_ifidx(name);

	if (rtnl_talk(&ip_rth, &req.nlh, IP_LINK_DEL, NO, NULL, NULL) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed removing link=%s", name);
		return FAILURE;
	}
	return SUCCESS;
}



IDM_T kernel_dev_exists(char *name)
{
        dbgf_track(DBGT_INFO, "name=%s tun_name_tree.items=%d", name, tun_name_tree.items);

	IFNAME_T tnKey = {{0}};
	strcpy(tnKey.str, name);

	if (avl_find(&tun_name_tree, tnKey.str))
		return YES;

	struct if_link_node *iln = NULL;
	struct avl_node *an = NULL;

	while ((iln = avl_iterate_item(&if_link_tree, &an))) {
		if (!strcmp(iln->name.str, tnKey.str))
			return YES;
	}

	return NO;
}

void kernel_dev_tun_del( char *name, int32_t fd ) {

        dbgf_track(DBGT_INFO, "name=%s tun_name_tree.items=%d fd=%d ", name, tun_name_tree.items, fd);

	IFNAME_T tnKey = {{0}};
	strcpy(tnKey.str,name);
	IFNAME_T *tn;
	if ((tn = avl_find_item(&tun_name_tree, tnKey.str))) {
		avl_remove(&tun_name_tree, tn->str, -300538);
		debugFree(tn, -300539);
	}
	assertion(-501498, (initializing || tn));


	if ( DEF_TUN_OUT_PERSIST && ioctl( fd, TUNSETPERSIST, 0 ) < 0 ) {

		dbg( DBGL_SYS, DBGT_ERR, "can't delete catch_all tunnel device: %s", strerror(errno) );
		assertion(-501499,(0));
		return;
	}

	dbgf( DBGL_SYS, DBGT_INFO, "closing catch_all tunnel!" );

	close( fd );

	return;
}


int32_t kernel_dev_tun_add( char *name, int32_t *fdp, IDM_T accept_local_ipv4 )
{
	int32_t sock_opts;
	int32_t ifidx;
	int32_t fd;

        dbgf_track(DBGT_INFO, "name=%s tun_name_tree.items=%d", name, tun_name_tree.items);

	IFNAME_T *tn = 	debugMalloc(sizeof(IFNAME_T), -300540);
	memset(tn, 0, sizeof(IFNAME_T));
	strcpy(tn->str,name);
	assertion(-501500, (!avl_find_item(&tun_name_tree, tn->str)));
	avl_insert(&tun_name_tree, tn, -300541);


	if ( ( fd = open( "/dev/net/tun", O_RDWR ) ) < 0 ) {
		dbg( DBGL_SYS, DBGT_ERR, "can't open tun device (/dev/net/tun): %s", strerror(errno) );
		return FAILURE;
	}

	if ( kernel_set_flags( name, fd, 0, TUNSETIFF, IFF_TUN | IFF_NO_PI, -1)  == FAILURE )
		goto kernel_dev_tun_add_error;

	if( DEF_TUN_OUT_PERSIST && ioctl( fd, TUNSETPERSIST, 1 ) < 0 ) {
		dbg( DBGL_SYS, DBGT_ERR, "can't set tun device (TUNSETPERSIST): %s", strerror(errno) );
		close(fd);
		return FAILURE;
	}

	if ( kernel_set_flags( name, 0, SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP|IFF_RUNNING, 0) == FAILURE )
		goto kernel_dev_tun_add_error;


	/* make tun socket non blocking */
	sock_opts = fcntl( fd, F_GETFL, 0 );
	if (fcntl( fd, F_SETFL, sock_opts | O_NONBLOCK ) < 0 ) {
		dbg_sys(DBGT_ERR, "Failed set tunnel dev=%s sock O_NONBLOCK: %s", name, strerror(errno));
		goto kernel_dev_tun_add_error;
	}

	if ((ifidx = kernel_get_ifidx( name )) == FAILURE)
		goto kernel_dev_tun_add_error;

	if (accept_local_ipv4) {
		char filename[100];
		int32_t dummy;
		sprintf(filename,"ipv4/conf/%s/accept_local", name);
		if (check_proc_sys_net(filename, 1, &dummy)==FAILURE)
			goto kernel_dev_tun_add_error;
	}


	if (fdp)
		*fdp = fd;

	return ifidx;

kernel_dev_tun_add_error:

	if ( fd > -1 )
		kernel_dev_tun_del(name, fd );

	if (fdp)
		*fdp = 0;

	return FAILURE;
}


IDM_T kernel_tun_del(char *name)
{

        dbgf_track(DBGT_INFO, "name=%s tun_name_tree.items=%d", name, tun_name_tree.items);

	IFNAME_T tnKey = {{0}};
	strcpy(tnKey.str,name);
	IFNAME_T *tn;
	if ((tn = avl_find_item(&tun_name_tree, tnKey.str))) {
		avl_remove(&tun_name_tree, tn->str, -300542);
		debugFree(tn, -300543);
	}
	assertion(-501501, (initializing || tn));

        struct ifreq req;

        assertion(-501526, (name && strlen(name)));


        memset(&req, 0, sizeof (req));
        strncpy(req.ifr_name, name, IFNAMSIZ);

        if ((ioctl(io_sock, SIOCDELTUNNEL, &req))) {
                dbgf_sys(DBGT_ERR, "Failed deleting tunnel dev=%s %s", name, strerror(errno));
                return FAILURE;
        }

        return SUCCESS;
}


int32_t kernel_tun_add(char *name, uint8_t proto, IPX_T *local, IPX_T *remote)
{

        dbgf_track(DBGT_INFO, "name=%s tun_name_tree.items=%d proto=%d local=%s remote=%s",
		name, tun_name_tree.items, proto, ip6AsStr(local), ip6AsStr(remote));

	IFNAME_T *tn = 	debugMalloc(sizeof(IFNAME_T), -300544);
	memset(tn, 0, sizeof(IFNAME_T));
	strcpy(tn->str,name);
	assertion(-501502, (!avl_find_item(&tun_name_tree, tn->str)));
	avl_insert(&tun_name_tree, tn, -300545);


        struct ifreq req;
	struct ip6_tnl_parm p;
	int32_t idx;

        assertion(-501527, (name && strlen(name)));


        memset(&req, 0, sizeof (req));
        strncpy(req.ifr_name, "ip6tnl0", IFNAMSIZ);

	memset(&p, 0, sizeof (p));
	strncpy(p.name, name, IFNAMSIZ);
	p.flags |= IP6_TNL_F_IGN_ENCAP_LIMIT;
	p.hop_limit = DEFAULT_TNL_HOP_LIMIT;
	//        p.encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
	p.proto = proto;

	if(remote)
		p.raddr = *remote;
	if(local)
		p.laddr = *local;
	req.ifr_ifru.ifru_data = &p;

        if ((ioctl(io_sock, SIOCADDTUNNEL, &req))) {
                dbgf_sys(DBGT_ERR, "Failed adding tunnel dev=%s %s", name, strerror(errno));
                return FAILURE;
        }

	if ( kernel_set_flags( name, 0, SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP, 0 ) != SUCCESS ||
		(idx = kernel_get_ifidx( name )) <= 0) {
		IDM_T result = kernel_tun_del(name);
		assertion(-501502, (result==SUCCESS));
		return FAILURE;
	}

	return idx;
}


uint32_t kernel_get_mtu(char *name)
{
	struct ifreq req;
        memset(&req, 0, sizeof (req));
	req.ifr_addr.sa_family = AF_INET;
	strcpy(req.ifr_name, name);

	if (ioctl(io_sock, SIOCGIFMTU, (caddr_t)&req) < 0) {
        	dbgf_sys(DBGT_ERR, "Can't read MTU from device=%s: %s", name, strerror(errno));
        	return FAILURE;
	}

        dbgf_all(DBGT_INFO, "Get device=%s mtu=%d", name, req.ifr_mtu);

	return req.ifr_mtu;
}


IDM_T kernel_set_mtu(char *name, uint16_t mtu)
{
	struct ifreq req;
        memset(&req, 0, sizeof (req));
	req.ifr_addr.sa_family = AF_INET;
	strcpy(req.ifr_name, name);

/*
	if (ioctl(io_sock, SIOCGIFMTU, (caddr_t)&req) < 0) {
        	dbgf_sys(DBGT_ERR, "Can't read MTU from device=%s: %s", name, strerror(errno));
        	return FAILURE;
	}
*/
    
	req.ifr_mtu = mtu;
    	if (ioctl(io_sock, SIOCSIFMTU, (caddr_t)&req) < 0) {
        	dbgf_sys(DBGT_ERR, "Can't set MTU=%d from device=%s: %s", mtu, name, strerror(errno));
                return FAILURE;

	}

        dbgf_track(DBGT_INFO, "Set device=%s mtu=%d", name, mtu);

	return SUCCESS;
}




IDM_T kernel_get_route(uint8_t quiet, uint8_t family, uint32_t table, void (*func) (struct nlmsghdr *nh, void *data) )
{

        struct rtmsg_req req;
        memset(&req, 0, sizeof (req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

        req.rtm.rtm_family = family;
        req.rtm.rtm_table = table;

        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.nlh.nlmsg_type = RTM_GETROUTE;
        req.rtm.rtm_scope = RTN_UNICAST;

        return rtnl_talk(&ip_rth2, &req.nlh, IP_ROUTE_GET, quiet, func, &table);
}


STATIC_FUNC
IDM_T kernel_set_route(uint8_t cmd, int8_t del, uint8_t quiet, const struct net_key *dst,
        uint32_t table, uint32_t prio, int oif_idx, IPX_T *via, IPX_T *src, uint32_t metric)
{

        dbgf_all(DBGT_INFO, "1");

        struct rtmsg_req req;
        IDM_T llocal = (via && is_ip_equal(via, &dst->ip)) ? YES : NO;

        memset(&req, 0, sizeof (req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

        req.rtm.rtm_family = dst->af;
        req.rtm.rtm_table = table;

        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        if (cmd > IP_ROUTES && cmd < IP_ROUTE_MAX) {

                if (del) {
                        req.nlh.nlmsg_type = RTM_DELROUTE;
                        req.rtm.rtm_scope = RT_SCOPE_NOWHERE;
                } else {
                        req.nlh.nlmsg_flags = req.nlh.nlmsg_flags | NLM_F_CREATE | NLM_F_EXCL; //| NLM_F_REPLACE;
                        req.nlh.nlmsg_type = RTM_NEWROUTE;
                        req.rtm.rtm_scope = ((cmd == IP_ROUTE_HNA || cmd == IP_ROUTE_HOST) && llocal) ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
                        req.rtm.rtm_protocol = RTPROT_STATIC;
                        req.rtm.rtm_type = (cmd == IP_THROW_MY_HNA || cmd == IP_THROW_MY_NET || cmd == IP_THROW_MY_TUNS) ? RTN_THROW : RTN_UNICAST;
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

        } else {

                cleanup_all(-500628);
        }


        if (prio)
                add_rtattr(&req.nlh, RTA_PRIORITY, (char*) & prio, sizeof (prio), 0);

        if (metric)
                add_rtattr(&req.nlh, RTA_PRIORITY, (char*) & metric, sizeof (metric), 0);

        return rtnl_talk(&ip_rth, &req.nlh, cmd, quiet, NULL, NULL);
}


void set_ipexport( void (*func) (int8_t del, const struct net_key *dst, uint32_t oif_idx, IPX_T *via, uint32_t metric, uint8_t distance) )
{
        assertion(-501506, (func ? !ipexport : !!ipexport ));

        ipexport = func;


        struct avl_node *an = NULL;
        struct track_node *tn;

        while ((tn = avl_iterate_item(&iptrack_tree, &an))) {

                assertion(-501507, (tn->rt_exp.exportDistance <= MAX_EXPORT_DISTANCE));

                if (tn->rt_exp.exportDistance == TYP_EXPORT_DISTANCE_INFINITE)
                        continue;

                assertion(-501508, (tn->cmd >= IP_ROUTE_TUNS && tn->cmd < IP_ROUTE_MAX && tn->items == 1));

                IPX_T *via = is_ip_set(&tn->via) ? &tn->via : NULL;
                IPX_T *src = is_ip_set(&tn->src) ? &tn->src : NULL;

                if (func) {
                        assertion(-501509, (!tn->rt_exp.ipexport));

                        if(tn->rt_exp.exportOnly)
                                kernel_set_route(tn->cmd, DEL, NO, &tn->k.net, tn->k.table, tn->k.prio, tn->oif_idx, via, src, tn->k.metric);

                        (*func)(ADD, &tn->k.net, tn->oif_idx, via, tn->k.metric, tn->rt_exp.exportDistance);

                        tn->rt_exp.ipexport = 1;

                } else {
                        assertion(-501510, (tn->rt_exp.ipexport));

                        if(tn->rt_exp.exportOnly)
                                kernel_set_route(tn->cmd, ADD, NO, &tn->k.net, tn->k.table, tn->k.prio, tn->oif_idx, via, src, tn->k.metric);

                        tn->rt_exp.ipexport = 0;
                }
        }
}




STATIC_FUNC
IDM_T iptrack(const struct net_key *net, uint8_t cmd, uint8_t quiet, int8_t del, uint32_t table, uint32_t prio,
        int oif_idx, IPX_T *via, IPX_T *src, uint32_t metric, struct route_export *rte)
{

        // DONT USE setNet() here (because return pointer is static)!!!!!!!!!!!!!

	TRACE_FUNCTION_CALL;
        assertion(-501232, (net));
        assertion(-500628, (cmd != IP_NOP));
        assertion(-500629, (cmd != IP_ROUTE_FLUSH && cmd != IP_RULE_FLUSH && cmd != IP_RULE_TEST));
        assertion(-501511, ((cmd > IP_ROUTES && cmd < IP_ROUTE_MAX) || (cmd > IP_RULES && cmd < IP_RULE_MAX)));

        static struct track_node ts;
        memset(&ts, 0, sizeof (ts));
        ts.k.net = *net;
        ts.k.prio = prio;
        ts.k.table = table;
        ts.k.metric = metric;
        ts.k.cmd_type = (cmd > IP_ROUTES && cmd < IP_ROUTE_MAX) ? IP_ROUTES :IP_RULES;

        int found = 0;
        struct track_node *exact = NULL;
        struct avl_node *an = avl_find(&iptrack_tree, &ts.k);
        struct track_node *tn = an ? an->item : NULL;

        while (tn) {
                assertion(-501512, IMPLIES(exact, (tn->cmd != cmd)));

                if (!exact && tn->cmd == cmd)
                        exact = tn;

                found += tn->items;

                tn = (tn = avl_iterate_item(&iptrack_tree, &an)) && !memcmp(&ts.k, &tn->k, sizeof (ts.k)) ? tn : NULL;
        }

        if ((del && !exact) || (del && found != 1) || (!del && found > 0)) {
                dbgf(
                        quiet ? DBGL_ALL : (del && !exact) ? DBGL_SYS : DBGL_CHANGES,
                        quiet ? DBGT_INFO : (del && !exact) ? DBGT_ERR : DBGT_INFO,
                        "   %s cmd=%s net=%s table=%d  prio=%d exists=%d exact_match=%d",
                        del2str(del), trackt2str(cmd), netAsStr(net), table, prio,
                        /*iif ? iif->str : NULL,*/ found, exact ? exact->items : 0);

                EXITERROR(-500700, (!(!quiet && (del && !exact))));
        }

        assertion(-501513, IMPLIES(!del && (cmd >= IP_ROUTE_TUNS && cmd < IP_ROUTE_MAX), found == 0 && !exact));
        assertion(-501514, IMPLIES(del && (cmd >= IP_ROUTE_TUNS && cmd < IP_ROUTE_MAX), found == 1 && exact));
        assertion(-501515, IMPLIES(exact, exact->rt_exp.exportOnly == (rte ? rte->exportOnly : 0) ));
        assertion(-501516, IMPLIES(exact, exact->rt_exp.exportDistance == (rte ? rte->exportDistance : TYP_EXPORT_DISTANCE_INFINITE)));
        assertion(-501517, IMPLIES(exact, exact->rt_exp.ipexport == (rte ? rte->ipexport : 0 )));


        if (del) {

                if (!exact) {

                        assertion(-500883, (0));

                } else if (exact->items == 1) {

                        struct track_node *rem_tn = avl_remove(&iptrack_tree, &exact->k, -300250);
                        assertion(-501233, (rem_tn));
                        //assertion(-500882, (rem_tn == first_tn));
                        if (rem_tn != exact) {
                                // if first_tn is not the first track_node of searched key then
                                // first_tn and rem_tn are different and first_tn an be reused as rem_tn:
                                assertion(-501425, (!memcmp(&exact->k, &rem_tn->k, sizeof (ts.k))));
                                memcpy(exact, rem_tn, sizeof(*exact));
                        }
                        debugFree(rem_tn, -300072);

                } else if (exact->items > 1) {

                        exact->items--;
                }

                if ( found != 1 )
                        return NO;

	} else {

                if (exact) {

                        exact->items++;

                } else {

                        struct track_node *tn = debugMallocReset(sizeof ( struct track_node), -300030);
                        tn->k = ts.k;
                        tn->items = 1;
                        tn->cmd = cmd;
                        tn->rt_exp.exportOnly = rte ? rte->exportOnly : 0;
                        tn->rt_exp.exportDistance = rte ? rte->exportDistance : TYP_EXPORT_DISTANCE_INFINITE;
                        tn->rt_exp.ipexport = rte ? rte->ipexport : 0;

                        if (cmd >= IP_ROUTE_TUNS && cmd < IP_ROUTE_MAX) {
                                tn->oif_idx = oif_idx;
                                tn->src = src ? *src : ZERO_IP;
                                tn->via = via ? *via : ZERO_IP;
                        }

                        avl_insert(&iptrack_tree, tn, -300251);
                }

                if (found > 0)
                        return NO;

	}

        return YES;
}



IDM_T iproute(uint8_t cmd, int8_t del, uint8_t quiet, const struct net_key *dst, int32_t table_macro, int32_t prio_macro,
        int oif_idx, IPX_T *via, IPX_T *src, uint32_t metric, struct route_export *rte)
{
        // DONT USE setNet() here (because return pointer is static)!!!!!!!!!!!!!

	TRACE_FUNCTION_CALL;
        assertion(-501518, (cmd != IP_RULE_FLUSH && cmd != IP_ROUTE_FLUSH && cmd != IP_RULE_TEST));
        assertion(-501234, (dst));
        assertion(-500650, IMPLIES(is_ip_set(&dst->ip), is_ip_valid(&dst->ip, dst->af)));
        assertion(-500651, IMPLIES(via, is_ip_valid(via, dst->af)));
        assertion(-500652, IMPLIES(src, is_ip_valid(src, dst->af)));
        assertion(-500653, (dst->af == AF_INET || dst->af == AF_INET6));
        assertion(-500672, (ip_netmask_validate((IPX_T*) &dst->ip, dst->mask, dst->af, NO) == SUCCESS));
        assertion(-501519, IMPLIES(rte, !rte->ipexport));

        uint32_t prio = prio_macro_to_prio(prio_macro);
        uint32_t table = table_macro_to_table(table_macro);

        dbgf_all(DBGT_INFO, "1");

        if(rte && rte->exportDistance != TYP_EXPORT_DISTANCE_INFINITE && ipexport)
                rte->ipexport = YES;


        if ((cmd == IP_THROW_MY_HNA || cmd == IP_THROW_MY_NET || cmd == IP_THROW_MY_TUNS) &&
                (policy_routing != POLICY_RT_ENABLED || !ip_throw_rules_cfg))
		return SUCCESS;

        if (cmd == IP_RULE_DEFAULT && (table == DEF_IP_TABLE_MAIN || policy_routing != POLICY_RT_ENABLED || !ip_prio_rules_cfg ))
                return SUCCESS;


        if (iptrack(dst, cmd, quiet, del, table, prio, oif_idx, via, src, metric, rte) == NO)
                return SUCCESS;

#ifdef DEBUG_ALL
        struct if_link_node *oif_iln = oif_idx ? avl_find_item(&if_link_tree, &oif_idx) : NULL;

        dbgf_all( DBGT_INFO, "cmd=%s %s dst=%s table=%d prio=%d oifIdx=%d oif=%s via=%s src=%s metric=%d",
                trackt2str(cmd), del2str(del), netAsStr(dst),
                table, prio, oif_idx, oif_iln ? oif_iln->name.str : "???",
                via ? ipXAsStr(dst->af, via) : DBG_NIL, src ? ipXAsStr(dst->af, src) : DBG_NIL, metric);
#endif

        if(rte && rte->ipexport)
                (*ipexport)(del, dst, oif_idx, via, metric, rte->exportDistance);

        if(!rte || !rte->ipexport || !rte->exportOnly)
                return kernel_set_route(cmd, del, quiet, dst, table, prio, oif_idx, via, src, metric);

        return SUCCESS;
}






IDM_T check_proc_sys_net(char *file, int32_t desired, int32_t *backup)
{
	TRACE_FUNCTION_CALL;
        FILE *f;
	int32_t state = 0;
	char filename[MAX_PATH_SIZE];

	sprintf( filename, "/proc/sys/net/%s", file );

	if((f = fopen(filename, "r" )) == NULL) {

		dbgf_sys(DBGT_ERR, "can't open %s for reading! retry later..", filename );
		return FAILURE;
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

		return FAILURE;
	}


	if ( state != desired ) {

		dbgf_sys(DBGT_INFO, "changing %s from %d to %d", filename, state, desired );

		if((f = fopen(filename, "w" )) == NULL) {

                        dbgf_sys(DBGT_ERR, "can't open %s for writing! retry later...", filename);
			return FAILURE;
		}

		fprintf(f, "%d", desired?1:0 );
		fclose(f);
	}
	return SUCCESS;
}

void sysctl_restore(struct dev_node *dev)
{
        TRACE_FUNCTION_CALL;
        
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

        static TIME_T ipv6_timestamp = -1;

        if (!(dev->active && dev->if_llocal_addr && dev->if_llocal_addr->iln->flags && IFF_UP))
                return;


        if (dev) {

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
        assertion(-500613, (dev->if_global_addr));
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

        if (!is_ip_set(&dev->llip_key.ip)) {
                dbgf_sys(DBGT_ERR, "no address given to remove in dev_ip_tree!");
        } else if (!avl_find(&dev_ip_tree, &dev->llip_key)) {
                dbgf_sys(DBGT_ERR, "%s not in dev_ip_tree!", ip6AsStr(&dev->llip_key.ip));
        } else {
                avl_remove(&dev_ip_tree, &dev->llip_key, -300192);
                dev->llip_key.ip = ZERO_IP;
        }


        if (dev->active) {
                dev->active = NO;
                cb_plugin_hooks(PLUGIN_CB_BMX_DEV_EVENT, dev);
        }

	if ( dev->linklayer != TYP_DEV_LL_LO ) {


		purge_linkDevs(NULL, dev, NO);

                purge_tx_task_list(dev->tx_task_lists, NULL, NULL);

                struct avl_node *an;
		LinkNode *link;
                for (an = NULL; (link = avl_iterate_item(&link_tree, &an));) {
                        assertion(-502212, (!purge_tx_task_list(link->tx_task_lists, NULL, dev)));
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

                dev->llip_key.idx = DEVADV_IDX_INVALID;
        }


        if (dev->tx_task) {
                task_remove(dev->tx_task, dev);
                dev->tx_task = NULL;
        }


	sysctl_restore ( dev );

	change_selects();

	dbgf_all( DBGT_WARN, "Interface %s deactivated", dev->label_cfg.str );

        if (dev->dev_adv_msg > DEVADV_MSG_IGNORED)
                update_my_dev_adv();

	my_description_changed = YES;

        if (dev->autoIP6Configured.mask && !dev->activate_again) {
                //if (dev->if_llocal_addr && dev->if_llocal_addr->iln->flags & IFF_UP)
                kernel_set_addr(DEL, dev->autoIP6IfIndex, AF_INET6, &dev->autoIP6Configured.ip, dev->autoIP6Configured.mask, NO /*deprecated*/);
                dev->autoIP6Configured = ZERO_NET6_KEY;
                dev->autoIP6IfIndex = 0;
                dev->activate_cancelled = 1;
        }



}


struct sockaddr_storage set_sockaddr_storage(uint8_t af, IPX_T *ipx, int32_t port)
{
        TRACE_FUNCTION_CALL;

	union {
		struct sockaddr_storage sosa;
		struct sockaddr_in soin4;
		struct sockaddr_in6 soin6;
	} s;

        memset(&s, 0, sizeof (s));

	s.sosa.ss_family = af;//AF_CFG
	s.soin6.sin6_port = htons(port/*base_port*/);
	s.soin6.sin6_addr = *ipx;

	return s.sosa;
}


STATIC_FUNC
IDM_T dev_init_sockets(struct dev_node *dev)
{

        TRACE_FUNCTION_CALL;
        assertion(-500618, (dev->linklayer != TYP_DEV_LL_LO));

        int set_on = 1;
        int sock_opts;
        int pf_domain = PF_INET6;

        if ((dev->unicast_sock = socket(pf_domain, SOCK_DGRAM, 0)) < 0) {

                dbgf_sys(DBGT_ERR, "can't create send socket: %s", strerror(errno));
                return FAILURE;
        }

        dev->llocal_unicast_addr = set_sockaddr_storage(AF_INET6, &dev->if_llocal_addr->ip_addr, base_port);

	if (setsockopt(dev->unicast_sock, SOL_SOCKET, SO_BROADCAST, &set_on, sizeof (set_on)) < 0) {
		dbgf_sys(DBGT_ERR, "can't enable broadcasts on unicast socket: %s", strerror(errno));
		return FAILURE;
	}

        // bind send socket to interface name
        if (dev_bind_sock(dev->unicast_sock, &dev->name_phy_cfg) < 0)
                return FAILURE;

        // bind send socket to address
        if (bind(dev->unicast_sock, (struct sockaddr *) & dev->llocal_unicast_addr, sizeof (dev->llocal_unicast_addr)) < 0) {
                dbgf_sys(DBGT_ERR, "can't bind unicast socket to IP=%s : %s (retrying later...)",
                        ip6AsStr(&dev->if_llocal_addr->ip_addr), strerror(errno));

                dev->activate_again = YES;
                task_remove(dev_check, NULL);
                task_register(1000, dev_check, NULL, -300523);
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


        dev->tx_netwbrc_addr = set_sockaddr_storage(AF_INET6, &dev->if_llocal_addr->ip_mcast, base_port);




        // get netwbrc recv socket
        if ((dev->rx_mcast_sock = socket(pf_domain, SOCK_DGRAM, 0)) < 0) {
                dbgf_track(DBGT_ERR, "can't create network-broadcast socket: %s", strerror(errno));
                return FAILURE;
        }

        // bind recv socket to interface name
        if (dev_bind_sock(dev->rx_mcast_sock, &dev->name_phy_cfg) < 0)
                return FAILURE;


        struct sockaddr_storage rx_netwbrc_addr;

	rx_netwbrc_addr = set_sockaddr_storage(AF_INET6, &dev->if_llocal_addr->ip_mcast, base_port);


        if (bind(dev->rx_mcast_sock, (struct sockaddr *) & rx_netwbrc_addr, sizeof (rx_netwbrc_addr)) < 0) {
                char ip6[IP6_ADDR_LEN];

		inet_ntop(AF_INET6, &((struct sockaddr_in6*) (&rx_netwbrc_addr))->sin6_addr, ip6, sizeof (ip6));

                dbgf_sys(DBGT_ERR, "can't bind network-broadcast socket to %s: %s",
                        ip6, strerror(errno));
                return FAILURE;
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
                        if (dev->llip_key.idx == idx)
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
        assertion(-500593, (AF_INET6 == dev->if_llocal_addr->ifa.ifa_family));
        assertion(-500599, (is_ip_set(&dev->if_llocal_addr->ip_addr) && dev->if_llocal_addr->ifa.ifa_prefixlen));

        dbgf_sys(DBGT_WARN, "%s=%s", ARG_DEV, dev->label_cfg.str);

	if ( wordsEqual( DEV_LO, dev->name_phy_cfg.str ) ) {

		dev->linklayer = TYP_DEV_LL_LO;

                if (!dev->if_global_addr) {
                        dbgf_mute(30, DBGL_SYS, DBGT_WARN, "loopback dev %s MUST be given with global address",
                                dev->label_cfg.str);

                        cleanup_all(-500621);
                }

                if (!dev->if_global_addr || dev->if_global_addr->ifa.ifa_prefixlen != IP6_MAX_PREFIXLEN) {
                        dbgf_mute(30, DBGL_SYS, DBGT_WARN,
                                "prefix length of loopback interface is %d but SHOULD be %d and global",
                                dev->if_global_addr->ifa.ifa_prefixlen, IP6_MAX_PREFIXLEN);
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

                if ((dev->llip_key.idx = get_free_devidx()) == DEVADV_IDX_INVALID)
                        goto error;

                sysctl_config(dev);
        }

        // from here on, nothing should fail anymore !!:


        dev->llip_key.ip = dev->if_llocal_addr->ip_addr;
        assertion(-500592, (!avl_find(&dev_ip_tree, &dev->llip_key)));
        avl_insert(&dev_ip_tree, dev, -300151);


        ip6ToStr(&dev->if_llocal_addr->ip_addr, dev->ip_llocal_str);

        if ( dev->if_global_addr)
                ip6ToStr(&dev->if_global_addr->ip_addr, dev->ip_global_str);

        ip6ToStr(&dev->if_llocal_addr->ip_mcast, dev->ip_brc_str);

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

        ip6ToStr( &ZERO_IP, dev->ip_llocal_str);
        ip6ToStr( &ZERO_IP, dev->ip_brc_str);

        dev_deactivate(dev);
}



void del_route_list_nlhdr(struct nlmsghdr *nh, void *tablep )
{

	uint32_t table = *((uint32_t*)tablep);
        struct rtmsg *rtm = (struct rtmsg *) NLMSG_DATA(nh);
        struct rtattr *rtap = (struct rtattr *) RTM_RTA(rtm);
        int rtl = RTM_PAYLOAD(nh);

        while (RTA_OK(rtap, rtl)) {

		if (rtap->rta_type==RTA_DST && rtm->rtm_table == table) {

			struct net_key net = {
				.af=rtm->rtm_family,
				.mask=rtm->rtm_dst_len,
				.ip=(rtm->rtm_family==AF_INET6) ? *((IPX_T *) RTA_DATA(rtap)) : ip4ToX(*((IP4_T *) RTA_DATA(rtap)))
			};

			kernel_set_route(IP_ROUTE_FLUSH, DEL, NO, &net, table, 0, 0, NULL, NULL, 0);
				dbgf_sys(DBGT_ERR, "removed orphan %s route=%s table=%d", family2Str(net.af), netAsStr(&net), table);
		}

                rtap = RTA_NEXT(rtap, rtl);
        }
}


void ip_flush_routes(uint8_t family, int32_t table_macro)
{
	TRACE_FUNCTION_CALL;

	uint32_t table = table_macro_to_table(table_macro);

	if (table == DEF_IP_TABLE_MAIN || policy_routing != POLICY_RT_ENABLED || !ip_prio_rules_cfg)
		return;

	kernel_get_route(NO, family, table, del_route_list_nlhdr);
}



void ip_flush_rules(uint8_t family, int32_t table_macro)
{
	TRACE_FUNCTION_CALL;

        struct net_key net = family == AF_INET ? ZERO_NET4_KEY : ZERO_NET6_KEY;

	uint32_t table = table_macro_to_table(table_macro);

	if (table == DEF_IP_TABLE_MAIN || table == DEF_IP_TABLE_DEFAULT || policy_routing != POLICY_RT_ENABLED || !ip_prio_rules_cfg)
		return;

	while (kernel_set_route(IP_RULE_FLUSH, DEL, YES, &net, table, 0, 0, NULL, NULL, 0) == SUCCESS) {
		dbgf_sys(DBGT_ERR, "removed orphan %s rule to table %d", family2Str(family), table);
	}
}



STATIC_FUNC
void ip_flush_tracked( uint8_t cmd )
{
	TRACE_FUNCTION_CALL;
        struct avl_node *an;
        struct track_node *tn;

        for (an = NULL; (tn = avl_iterate_item(&iptrack_tree, &an));) {

                if (cmd == tn->cmd ||
                        (cmd == IP_ROUTE_FLUSH && tn->k.cmd_type == IP_ROUTES) ||
                        (cmd == IP_RULE_FLUSH && tn->k.cmd_type == IP_RULES)) {

                        struct track_key tk = tn->k;
                        iproute(tn->cmd, DEL, NO, &tk.net, tk.table, tk.prio, 0, 0, 0, tk.metric, NULL);

                        an = NULL;
                }
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

                                if (is_ip_net_equal(&ian->ip_addr, &dev->if_global_addr->ip_addr, ian->ifa.ifa_prefixlen, AF_INET6))
                                        break;

                        }

                        if (dev)
                                continue;

                        struct net_key throw;
                        setNet(&throw, ian->ifa.ifa_family, ian->ifa.ifa_prefixlen, &ian->ip_addr);
                        ip_netmask_validate(&throw.ip, throw.mask, throw.af, YES);

			//TODO: Fix (set oif_idx=0) as soon as this becomes mainline: http://permalink.gmane.org/gmane.linux.network/242277
                        iproute(IP_THROW_MY_NET, ADD, NO, &throw, RT_TABLE_HNA, 0, (throw.af == AF_INET6 ? iln->index : 0), 0, 0, 0, NULL);
                        //iproute(IP_THROW_MY_NET, ADD, NO, &throw, RT_TABLE_TUN, 0, (throw.af == AF_INET6 ? iln->index : 0), 0, 0, 0, NULL);

                }
        }
	return SUCCESS;
}

#ifdef WITH_UNUSED
STATIC_FUNC
struct net_key bmx6AutoEUI64Ip6(ADDR_T mac, struct net_key *prefix)
{
        struct net_key autoPrefix = ZERO_NET6_KEY;

        if (prefix->mask && prefix->mask <= 64 && !is_zero(&mac, sizeof (ADDR_T))) {

                autoPrefix = *prefix;

                autoPrefix.ip.s6_addr[8 ] = mac.u8[0];
                autoPrefix.ip.s6_addr[9 ] = mac.u8[1];
                autoPrefix.ip.s6_addr[10] = mac.u8[2];
                autoPrefix.ip.s6_addr[11] = 0xFF;
                autoPrefix.ip.s6_addr[12] = 0xFE;
                autoPrefix.ip.s6_addr[13] = mac.u8[3];
                autoPrefix.ip.s6_addr[14] = mac.u8[4];
                autoPrefix.ip.s6_addr[15] = mac.u8[5];

                // toggle the U/L bit (  http://en.wikipedia.org/wiki/IPv6_address#Modified_EUI-64 )
                autoPrefix.ip.s6_addr[8 ] |= 2;
        }

        dbgf_track(DBGT_INFO, "returnPrefix=%s prefix=%s mac=%s",
                netAsStr(&autoPrefix), netAsStr(prefix),memAsHexString(&mac, sizeof (ADDR_T)));

        return autoPrefix;
}
#endif

STATIC_INLINE_FUNC
void dev_if_fix(void)
{
	TRACE_FUNCTION_CALL;

	assertion(-502042, (self && is_ip_set(&self->primary_ip)));

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


                for (aan = NULL; (ian = avl_iterate_item(&dev->if_link->if_addr_tree, &aan));) {

                        if (AF_INET6 != ian->ifa.ifa_family || strcmp(dev->label_cfg.str, ian->label.str))
                                continue;

                        dbgf_all(DBGT_INFO, "testing %s=%s %s", ARG_DEV, ian->label.str, ip6AsStr(&ian->ip_addr));

                        if (is_ip_net_equal(&ian->ip_addr, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6)) {

                                dbgf_all(DBGT_INFO, "skipping multicast");
                                continue;
                        }

                        IDM_T is_ip6llocal = is_ip_net_equal(&ian->ip_addr, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6);

                        if (!dev->if_llocal_addr && is_ip6llocal) {

                                if (dev->llocal_prefix_conf_.mask &&
                                        is_ip_net_equal(&dev->llocal_prefix_conf_.ip, &ian->ip_addr, dev->llocal_prefix_conf_.mask, dev->llocal_prefix_conf_.af)) {

                                        dev->if_llocal_addr = ian;

                                } else if (!dev->llocal_prefix_conf_.mask && llocal_prefix_cfg.mask &&
                                        is_ip_net_equal(&llocal_prefix_cfg.ip, &ian->ip_addr, llocal_prefix_cfg.mask, llocal_prefix_cfg.af)) {

                                        dev->if_llocal_addr = ian;

                                } else if (!dev->llocal_prefix_conf_.mask && !llocal_prefix_cfg.mask && is_ip6llocal) {
                                        
                                        dev->if_llocal_addr = ian;

                                }
                        }

			if (!is_ip6llocal && DEF_AUTO_IP6_DEVMASK) {

				if (is_ip_equal(&self->primary_ip, &ian->ip_addr) && DEF_AUTO_IP6_DEVMASK == ian->ifa.ifa_prefixlen) {

					dev->if_global_addr = ian;
				}
			}
                }

                if (DEF_AUTO_IP6_DEVMASK && !dev->if_global_addr) {

			dbgf_sys(DBGT_INFO, "Autoconfiguring dev=%s idx=%d ip=%s", dev->label_cfg.str, dev->if_link->index, self->primary_ip_str);

                        kernel_set_addr(ADD, dev->if_link->index, AF_INET6, &self->primary_ip, DEF_AUTO_IP6_DEVMASK, NO /*deprecated*/);
                        dev->autoIP6Configured.ip = self->primary_ip;
			dev->autoIP6Configured.mask = DEF_AUTO_IP6_DEVMASK;
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
			dbgf_mute(30, DBGL_SYS, DBGT_ERR,
				"No global IP for %s=%s ! DEACTIVATING !!!", ARG_DEV, dev->label_cfg.str);

			if (dev->if_llocal_addr) {
				dev->if_llocal_addr->dev = NULL;
				dev->if_llocal_addr = NULL;
			}
		}
        }
}


static void dev_check(void *kernel_ip_config_changed)
{
	TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct dev_node *dev;

	dbgf_all( DBGT_INFO, " " );

        task_remove( dev_check, NULL);

        // fix all dev->.._ian stuff here:
        dev_if_fix();

        for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));) {

                dev->activate_cancelled = 0;

                if (dev->hard_conf_changed)
                        dev->activate_again = NO;

                if (dev->hard_conf_changed && dev->active) {

                        dbgf_sys(DBGT_WARN, "detected changed but used dev=%s ! Deactivating now!", dev->label_cfg.str);

                        dev_deactivate(dev);
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

                if (iff_up && !dev->active && (dev->hard_conf_changed || dev->activate_again)) {

			struct dev_ip_key devip_key = { .ip = dev->if_llocal_addr->ip_addr, .idx=0 };
                        struct dev_node *tmp_dev = avl_find_item(&dev_ip_tree, &devip_key);

                        while ((tmp_dev || (tmp_dev = avl_next_item(&dev_ip_tree, &devip_key)))
				&& is_ip_equal(&tmp_dev->llip_key.ip, &dev->if_llocal_addr->ip_addr)) {

				devip_key = tmp_dev->llip_key;

				if (!wordsEqual(tmp_dev->name_phy_cfg.str, dev->name_phy_cfg.str)) {

					dbgf_sys(DBGT_WARN, "%s=%s llocal=%s already used for dev=%s idx=0x%X",
						ARG_DEV, dev->label_cfg.str, ip6AsStr(&dev->if_llocal_addr->ip_addr),
						tmp_dev->label_cfg.str, tmp_dev->llip_key.idx);
				}
				tmp_dev = NULL;
			}

			if (dev->activate_cancelled) {

                                dbgf_sys(DBGT_ERR, "%s=%s activation delayed", ARG_DEV, dev->label_cfg.str);

                        } else if (!dev->if_global_addr) {

                                dbgf_sys(DBGT_ERR, "%s=%s %s but no global addr", ARG_DEV, dev->label_cfg.str, "to-be announced");

                        } else if (wordsEqual(DEV_LO, dev->name_phy_cfg.str) && !dev->if_global_addr) {

                                dbgf_sys(DBGT_ERR, "%s=%s %s but no global addr", ARG_DEV, dev->label_cfg.str, "loopback");

                        } else if (dev_ip_tree.items == DEVADV_IDX_MAX) {

                                dbgf_sys(DBGT_ERR, "too much active interfaces");

                        } else  {

                                dbgf_sys(DBGT_WARN, "detected valid but disabled dev=%s ! Activating now...",
                                        dev->label_cfg.str);

                                dev_activate(dev);
                        }
                }


                if (!dev->active) {
                        dbgf_sys(DBGT_WARN, "not using interface %s (retrying later): %s %s ila=%d iln=%d",
                                dev->label_cfg.str, iff_up ? "UP" : "DOWN",
                                dev->hard_conf_changed ? "CHANGED" : "UNCHANGED",
                                dev->if_llocal_addr ? 1 : 0, dev->if_llocal_addr && dev->if_llocal_addr->iln ? 1 : 0);
                }

                dev->hard_conf_changed = NO;

                if (dev->active && dev->soft_conf_changed)
			dev_reconfigure_soft( dev );

        }

        if (kernel_ip_config_changed && (*((IDM_T*)kernel_ip_config_changed))) {

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
        struct iovec iov = {.iov_base = buf, .iov_len = sizeof (buf)};

        dbgf_track(DBGT_INFO, "detected changed interface status! Going to check interfaces!");

        struct msghdr msg; // = {(void *) & sa, sizeof (sa), &iov, 1, NULL, 0, 0};
        memset( &msg, 0, sizeof( struct msghdr));
        msg.msg_name = (void *)&sa;
        msg.msg_namelen = sizeof(sa); /* Length of address data.  */
        msg.msg_iov = &iov; /* Vector of data to send/receive into.  */
        msg.msg_iovlen = 1; /* Number of elements in the vector.  */

	int rcvd;

	//so fare I just want to consume the pending message...
	while( (rcvd=recvmsg (sk, &msg, 0)) > 0 ){
		dbgf_track(DBGT_INFO, "rcvd %d bytes", rcvd);

	}

        //do NOT delay checking of interfaces to not miss ifdown/up of interfaces !!
        if (kernel_get_if_config() == YES) //just call if changed!
                dev_check((void*)&CONST_YES);

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
	uint32_t prio = prio_macro_to_prio(RT_PRIO_HNA);
        uint32_t table = table_macro_to_table(RT_TABLE_HNA);

        if (net.af == tested_family) {
                assertion(-501132, (tested_policy_rt != POLICY_RT_UNSET));
                return tested_policy_rt;
        }

        tested_family = net.af;

        assertion(-501521, IMPLIES(policy_routing == POLICY_RT_UNSET, (initializing)));

        if (kernel_set_route(IP_RULE_TEST, ADD, YES, &net, table, prio, 0, NULL, NULL, 0) == SUCCESS) {
                kernel_set_route(IP_RULE_TEST, DEL, YES, &net, table, prio, 0, NULL, NULL, 0);

                return (tested_policy_rt = YES);

        } else {
                dbgf_sys(DBGT_ERR, "Disabled policy-routing for IPv%d! (Kernel requires %s,...)",
                        net.af == AF_INET ? 4 : 6,
                        net.af == AF_INET ? "IP_MULTIPLE_TABLES" : "CONFIG_IPV6_MULTIPLE_TABLES");

                return (tested_policy_rt = NO);
        }

}



STATIC_FUNC
int32_t opt_ip_version(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;


        if (cmd == OPT_CHECK) {

                if (!initializing)
                        return FAILURE;

                uint8_t ip_tmp = (patch->diff == ADD) ? strtol(patch->val, NULL, 10) : 0;

                if (ip_tmp != 6)
                        return FAILURE;

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

                dbgf_track(DBGT_INFO, "%s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d",
                        ARG_IP, 6,
                        "policy_routing", (policy_routing == POLICY_RT_ENABLED),
                        ARG_IP_POLICY_ROUTING, ip_policy_rt_cfg,
                        ARG_IP_THROW_RULES, ip_throw_rules_cfg,
                        ARG_IP_PRIO_RULES, ip_prio_rules_cfg,
                        ARG_IP_RULE_HNA,ip_prio_hna_cfg,
                        ARG_IP_RULE_TUN,ip_prio_tun_cfg,
                        ARG_IP_TABLE_HNA, ip_table_hna_cfg,
                        ARG_IP_TABLE_TUN, ip_table_tun_cfg

                        );

		// add rule for hosts and announced interfaces and networks

		//ip_flush_routes(AF_INET, RT_TABLE_HNA);
		//ip_flush_rules(AF_INET, RT_TABLE_HNA);

		//iproute(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET4_KEY, RT_TABLE_HNA, RT_PRIO_HNA, 0, 0, 0, 0, NULL);
		//iproute(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET4_KEY, RT_TABLE_TUN, RT_PRIO_TUNS, 0, 0, 0, 0, NULL);

		ip_flush_routes(AF_INET6, RT_TABLE_HNA);
		ip_flush_rules(AF_INET6, RT_TABLE_HNA);

		iproute(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET6_KEY, RT_TABLE_HNA, RT_PRIO_HNA, 0, 0, 0, 0, NULL);
		//iproute(IP_RULE_DEFAULT, ADD, NO, &ZERO_NET6_KEY, RT_TABLE_TUN, RT_PRIO_TUNS, 0, 0, 0, 0, NULL);



        }

	return SUCCESS;
}

static int32_t nextDevStatPeriod = DEF_DEVSTAT_PERIOD;
static int32_t currDevStatPeriod = DEF_DEVSTAT_PERIOD;
static int32_t prevDevStatPeriod = DEF_DEVSTAT_PERIOD;

STATIC_FUNC
void update_devStatistic_task(void *data)
{
        struct dev_node *dev;
        struct avl_node *an = NULL;

	prevDevStatPeriod = currDevStatPeriod;
	currDevStatPeriod = nextDevStatPeriod;

        while ((dev = avl_iterate_item(&dev_name_tree, &an))) {

		dev->udpInPrevBytes = dev->udpInCurrBytes;
		dev->udpInPrevPackets = dev->udpInCurrPackets;
		dev->udpOutPrevBytes = dev->udpOutCurrBytes;
		dev->udpOutPrevPackets = dev->udpOutCurrPackets;
		dev->udpInCurrBytes = dev->udpInCurrPackets = dev->udpOutCurrBytes = dev->udpOutCurrPackets = 0;
        }

        task_register(currDevStatPeriod, update_devStatistic_task, NULL, -300000);
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
	uint32_t outPps;
	uint32_t outBps;
	uint32_t inPps;
	uint32_t inBps;

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
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,              dev_status, multicastIp, 1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, helloSqn,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, outPps,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, outBps,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, inPps,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,                      dev_status, inBps,       1, FIELD_RELEVANCE_MEDI),
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
                status[i].devIdx = dev->llip_key.idx;
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
		status[i].outBps = (1000 * dev->udpOutPrevBytes) / prevDevStatPeriod;
		status[i].outPps = (1000 * dev->udpOutPrevPackets) / prevDevStatPeriod;
		status[i].inBps = (1000 * dev->udpInPrevBytes) / prevDevStatPeriod;
		status[i].inPps = (1000 * dev->udpInPrevPackets) / prevDevStatPeriod;

                i++;
        }
        return status_size;
}





STATIC_FUNC
int32_t opt_dev_prefix(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;


        if ((cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY)) {

                struct net_key prefix = ZERO_NETCFG_KEY;

                if (patch->diff == ADD) {

                        if (str2netw(patch->val, &prefix.ip, cn, &prefix.mask, &prefix.af, NO) == FAILURE ||
                                (!is_ip_valid(&prefix.ip, prefix.af)) ||
                                (prefix.af == AF_INET6 && (
                                (is_ip_net_equal(&prefix.ip, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6)) ||
                                (is_ip_net_equal(&prefix.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))
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

                                if (!dev->llocal_prefix_conf_.mask) {

                                        //mark all dev that are note specified more precise:
                                        dbgf_track(DBGT_INFO, "applying %s %s=%s %s",
                                                dev->label_cfg.str, opt->name, patch->val, netAsStr(&prefix));

                                        dev->hard_conf_changed = YES;
                                        opt_dev_changed = YES;
                                }
                        }

			llocal_prefix_cfg = prefix;
                }
        }

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_auto_prefix(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;


        if (cmd == OPT_REGISTER) {

		autoconf_prefix_cfg = ZERO_NET6_KEY;
		str2netw(DEF_AUTO_IP6_PREFIX, &autoconf_prefix_cfg.ip, NULL, &autoconf_prefix_cfg.mask, &autoconf_prefix_cfg.af, NO);

        } else if ((cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY)) {

                struct net_key prefix = ZERO_NET6_KEY;
                str2netw(DEF_AUTO_IP6_PREFIX, &prefix.ip, NULL, &prefix.mask, &prefix.af, NO);

                if (patch->diff == ADD) {

                        if (str2netw(patch->val, &prefix.ip, cn, &prefix.mask, &prefix.af, NO) == FAILURE ||
                                prefix.mask < DEF_AUTO_MASK_MIN || prefix.mask > DEF_AUTO_MASK_MAX ||
				prefix.mask % DEF_AUTO_MASK_MOD || !is_ip_valid(&prefix.ip, prefix.af) ||
				! prefix.ip.s6_addr[prefix.mask/8] /* as long as dummy tun6 src addresses are used */||
                                (is_ip_net_equal(&prefix.ip, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6)) ||
                                (is_ip_net_equal(&prefix.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))
                                ) {

                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s=%s invalid prefix %s",
                                        opt->name, patch->val, netAsStr(&prefix));

                                return FAILURE;
                        }

                        set_opt_parent_val(patch, netAsStr(&prefix));
                }


                if (cmd == OPT_APPLY)
			autoconf_prefix_cfg = prefix;

        } else if (cmd == OPT_SET_POST && initializing ) {

		assertion(-502043, (self));
		assertion(-502044, (!is_zero(&self->nodeId, sizeof(self->nodeId))));
		self->primary_ip = autoconf_prefix_cfg.ip;
		memcpy(&self->primary_ip.s6_addr[(autoconf_prefix_cfg.mask/8)], &self->nodeId, ((128-autoconf_prefix_cfg.mask)/8));

/*		if (is_zero(&self->global_id.pkid, sizeof(self->global_id.pkid)/2))
			memcpy(&self->primary_ip.s6_addr[(autoconf_prefix_cfg.mask/8)], &self->global_id.pkid.u8[sizeof(self->global_id.pkid)/2],
				XMIN((128-autoconf_prefix_cfg.mask)/8, sizeof(self->global_id.pkid)/2));
*/
		ip6ToStr(&self->primary_ip, self->primary_ip_str);
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

                        dbgf_track(DBGT_INFO, "cmd: %s opt:  %s instance %s",
                                opt_cmd2str[cmd], opt->name, patch ? patch->val : "");

                        uint32_t dev_size = sizeof (struct dev_node) + (sizeof (void*) * plugin_data_registries[PLUGIN_DATA_DEV]);
                        dev = debugMallocReset(dev_size, -300002);

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

                        // some configurable interface values - initialized to unspecified:
                        dev->linklayer_conf = OPT_CHILD_UNDEFINED;
                        dev->channel_conf = OPT_CHILD_UNDEFINED;
                        dev->umetric_max_conf = (UMETRIC_T) OPT_CHILD_UNDEFINED;
                        dev->umetric_min_conf = (UMETRIC_T) OPT_CHILD_UNDEFINED;
                        dev->llocal_prefix_conf_ = ZERO_NETCFG_KEY;

                        //dev->umetric_max = DEF_DEV_BITRATE_MAX;

                        dev->dummyLink.k.myDev = dev;
                        
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

                        if (!strcmp(c->opt->name, ARG_DEV_LLOCAL_PREFIX)) {

                                struct net_key prefix = ZERO_NETCFG_KEY;

                                if (c->val) {

                                        if (str2netw(c->val, &prefix.ip, cn, &prefix.mask, &prefix.af, NO) == FAILURE || !is_ip_valid(&prefix.ip, prefix.af) ||
                                                (prefix.af == AF_INET6 && (
                                                is_ip_net_equal(&prefix.ip, &IP6_MC_PREF, IP6_MC_PLEN, AF_INET6) ||
                                                is_ip_net_equal(&prefix.ip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)))
                                                ) {

                                                dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid interface prefix %s", netAsStr(&prefix));
                                                return FAILURE;
                                        }

                                        set_opt_child_val(c, netAsStr(&prefix));
                                }

                                if (cmd == OPT_APPLY) {

                                        dbgf_track(DBGT_INFO, "applying %s %s=%s hard_conf_changed=%d",
                                                dev->label_cfg.str, c->opt->name, c->val, dev->hard_conf_changed);

					if (c->val)
                                                        dev->llocal_prefix_conf_ = prefix;
                                                else
                                                        dev->llocal_prefix_conf_ = ZERO_NETCFG_KEY;

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
                                        unsigned long long int ull = strtoull(c->val, &endptr, 10);

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
                                        unsigned long long int ull = strtoull(c->val, &endptr, 10);

                                        if (ull > UMETRIC_MAX || ull < UMETRIC_FM8_MIN || *endptr != '\0') {

                                                dbgf_sys(DBGT_ERR, "%s %c%s given with illegal value",
                                                        dev->label_cfg.str, LONG_OPT_ARG_DELIMITER_CHAR, c->opt->name);

                                                return FAILURE;
                                        }

                                        dev->umetric_min_conf = ull;
                                } else {
                                        dev->umetric_min_conf = OPT_CHILD_UNDEFINED;
                                }
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
                dev_check( initializing ? (void*)&CONST_YES : (void*)&CONST_NO );
//                dev_check((initializing && kernel_get_if_config()) ? (void*)&CONST_YES : (void*)&CONST_NO);

        }

	return SUCCESS;
}



static struct opt_type ip_options[]=
{
//        ord parent long_name          shrt, order, relevance, Attributes...	*ival		min		max		default		*func,*syntax,*help
	{ODI,0,ARG_IP,	                'I',3,2, A_PS1N,A_ADM,A_INI,A_CFA,A_ANY,	NULL,    0,0,0,/*MIN_IP_VERSION, MAX_IP_VERSION,*/ DEF_IP_VERSION,  opt_ip_version,
			ARG_VALUE_FORM,	"select ip protocol Version 4 or 6"},

	{ODI,ARG_IP,ARG_IP_POLICY_ROUTING,0,3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_policy_rt_cfg,0, 		1,		DEF_IP_POLICY_ROUTING,0,opt_ip_version,
			ARG_VALUE_FORM,	"disable policy routing (throw and priority rules)"},

	{ODI,ARG_IP,ARG_IP_THROW_RULES,	 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_throw_rules_cfg,0, 		1,		DEF_IP_THROW_RULES,0,opt_ip_version,
			ARG_VALUE_FORM,	"disable/enable default throw rules"},

	{ODI,ARG_IP,ARG_IP_PRIO_RULES,	 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_prio_rules_cfg, 0, 		1,		DEF_IP_PRIO_RULES,0, opt_ip_version,
			ARG_VALUE_FORM,	"disable/enable default priority rules"},

	{ODI,ARG_IP,ARG_IP_RULE_HNA,	 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_prio_hna_cfg,	MIN_IP_RULE_HNA,MAX_IP_RULE_HNA,DEF_IP_RULE_HNA,0,opt_ip_version,
			ARG_VALUE_FORM,	"specify iproute2 rule preference offset for hna networks"},

	{ODI,ARG_IP,ARG_IP_TABLE_HNA, 0, 3,1,A_CS1,A_ADM,A_INI,A_CFA,A_ANY,	&ip_table_hna_cfg,	MIN_IP_TABLE_HNA,   MAX_IP_TABLE_HNA,   DEF_IP_TABLE_HNA,0,     opt_ip_version,
			ARG_VALUE_FORM,	"specify iproute2 table for hna networks"},


	{ODI,0,ARG_INTERFACES,	        0,  9,2,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show interfaces\n"},
	{ODI,0,ARG_DEVSTAT_PERIOD,      0, 9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,   &nextDevStatPeriod,MIN_DEVSTAT_PERIOD,MAX_DEVSTAT_PERIOD,DEF_DEVSTAT_PERIOD,0,0,
			ARG_VALUE_FORM,	HLP_DEVSTAT_PERIOD},

	{ODI,0,ARG_LLOCAL_PREFIX,	0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_dev_prefix,
			ARG_NETW_FORM,HLP_LLOCAL_PREFIX},
//order must be after ARG_HOSTNAME (which initializes self via init_self(), called from opt_hostname):
	{ODI,0,ARG_AUTO_IP6_PREFIX,     0,  6,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,      	0,      	0,              0,DEF_AUTO_IP6_PREFIX,opt_auto_prefix,
			ARG_VALUE_FORM,	HLP_AUTO_IP6_PREFIX},

	{ODI,0,ARG_DEV,		        'i',9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0,0, 		opt_dev,
			"<interface-name>", HLP_DEV},

	{ODI,ARG_DEV,ARG_DEV_LL,	 'l',9,0,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		MIN_DEV_LL,	MAX_DEV_LL,     DEF_DEV_LL,0,	opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_LL},

	{ODI,ARG_DEV,ARG_DEV_LLOCAL_PREFIX,0, 9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,		0,              0,              0,0,              opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_LLOCAL_PREFIX},

	{ODI,ARG_DEV,ARG_DEV_BITRATE_MAX,'r',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,              0,              0,0,              opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_BITRATE_MAX},

	{ODI,ARG_DEV,ARG_DEV_BITRATE_MIN, 0, 9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,              0,              0,0,              opt_dev,
			ARG_VALUE_FORM,	HLP_DEV_BITRATE_MIN},

#ifndef LESS_OPTIONS
	{ODI,0,ARG_PEDANTIC_CLEANUP,	  0, 9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&Pedantic_cleanup,0,		1,		DEF_PEDANTIC_CLEANUP,0,0,
			ARG_VALUE_FORM,	"disable/enable pedantic cleanup of system configuration (like ip_forward,..) \n"
			"	at program termination. Its generally safer to keep this disabled to not mess up \n"
			"	with other routing protocols"}
#endif
};




void init_ip(void)
{
        assertion(-500894, is_zero(((char*)&ZERO_IP), sizeof (ZERO_IP)));
        assertion(-501254, is_zero((void*) &ZERO_NET_KEY, sizeof (ZERO_NET_KEY)));
        assertion(-501336, is_zero((void*) &llocal_prefix_cfg, sizeof (llocal_prefix_cfg)));
        assertion(-501395, is_zero((void*) &autoconf_prefix_cfg, sizeof (autoconf_prefix_cfg)));

        memset(&bmx6_rt_dict, 0, sizeof(bmx6_rt_dict));
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_UNSPEC,  'u', ARG_ROUTE_UNSPEC,   BMX6_ROUTE_UNSPEC);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_REDIRECT,'r', ARG_ROUTE_REDIRECT, BMX6_ROUTE_REDIRECT);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_KERNEL,  'k', ARG_ROUTE_KERNEL,   BMX6_ROUTE_KERNEL);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_BOOT,    't', ARG_ROUTE_BOOT,     BMX6_ROUTE_BOOT);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_STATIC,  's', ARG_ROUTE_STATIC,   BMX6_ROUTE_STATIC);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_GATED,   'g', ARG_ROUTE_GATED,    BMX6_ROUTE_GATED);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_RA,      'a', ARG_ROUTE_RA,       BMX6_ROUTE_RA);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_MRT,     'm', ARG_ROUTE_MRT,      BMX6_ROUTE_MRT);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_ZEBRA,   'z', ARG_ROUTE_ZEBRA,    BMX6_ROUTE_ZEBRA);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_BIRD,    'd', ARG_ROUTE_BIRD,     BMX6_ROUTE_BIRD);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_DNROUTED,'n', ARG_ROUTE_DNROUTED, BMX6_ROUTE_DNROUTED);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_XORP,    'p', ARG_ROUTE_XORP,     BMX6_ROUTE_XORP);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_NTK,     'k', ARG_ROUTE_NTK,      BMX6_ROUTE_NTK);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_DHCP,    'd', ARG_ROUTE_DHCP,     BMX6_ROUTE_DHCP);

        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_SYSTEM,  'X', ARG_ROUTE_SYSTEM,   BMX6_ROUTE_SYSTEM);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_CONNECT, 'C', ARG_ROUTE_CONNECT,  BMX6_ROUTE_CONNECT);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_RIP,     'R', ARG_ROUTE_RIP,      BMX6_ROUTE_RIP);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_RIPNG,   'R', ARG_ROUTE_RIPNG,    BMX6_ROUTE_RIPNG);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_OSPF,    'O', ARG_ROUTE_OSPF,     BMX6_ROUTE_OSPF);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_OSPF6,   'O', ARG_ROUTE_OSPF6,    BMX6_ROUTE_OSPF6);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_ISIS,    'I', ARG_ROUTE_ISIS,     BMX6_ROUTE_ISIS);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_BGP,     'B', ARG_ROUTE_BGP,      BMX6_ROUTE_BGP);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_BABEL,   'A', ARG_ROUTE_BABEL,    BMX6_ROUTE_BABEL);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_HSLS,    'H', ARG_ROUTE_HSLS,     BMX6_ROUTE_HSLS);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_OLSR,    'o', ARG_ROUTE_OLSR,     BMX6_ROUTE_OLSR);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_BMX6,    'x', ARG_ROUTE_BMX6,     BMX6_ROUTE_BMX6);
        set_rt_dict(bmx6_rt_dict, BMX6_ROUTE_BATMAN,  'b', ARG_ROUTE_BATMAN,   BMX6_ROUTE_BATMAN);



        if (rtnl_open(&ip_rth) != SUCCESS) {
                dbgf_sys(DBGT_ERR, "failed opening rtnl socket");
                cleanup_all( -500561 );
        }

	if (rtnl_open(&ip_rth2) != SUCCESS) {
                dbgf_sys(DBGT_ERR, "failed opening rtnl2 socket");
                cleanup_all( -501605 );
        }

        errno=0;
	if ( !io_sock  &&  (io_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		dbgf_sys(DBGT_ERR, "can't create io socket %s:",  strerror(errno) );
		cleanup_all( -500021 );
	}

        if (open_ifevent_netlink_sk() < 0)
                cleanup_all(-500150);

        register_options_array(ip_options, sizeof ( ip_options), CODE_CATEGORY_NAME);

        register_status_handl(sizeof (struct dev_status), 1, dev_status_format, ARG_INTERFACES, dev_status_creator);

	task_register(currDevStatPeriod, update_devStatistic_task, NULL, -300000);

        kernel_get_if_config();

//        InitSha(&ip_sha);
}

void cleanup_ip(void)
{

        task_remove( dev_check, NULL);

        close_ifevent_netlink_sk();

        // if ever started succesfully in daemon mode...
	// flush default routes installed by bmx6:
	ip_flush_tracked( IP_ROUTE_FLUSH );

	// flush all routes in this bmx6 tables (there should be NOTHING!):
	ip_flush_routes(AF_INET6, RT_TABLE_HNA);
	//ip_flush_routes(AF_INET, RT_TABLE_HNA);

	// flush default routes installed by bmx6:
	ip_flush_tracked( IP_RULE_FLUSH );


	// flush all rules pointing to bmx6 tables (there should be NOTHING!):
	ip_flush_rules(AF_INET6, RT_TABLE_HNA);
	//ip_flush_rules(AF_INET, RT_TABLE_HNA);


        kernel_get_if_config_post(YES,0);


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

        if (ip_rth2.fd >= 0) {
                close(ip_rth2.fd);
                ip_rth2.fd = -1;
        }

        if ( io_sock ) {
                close(io_sock);
                io_sock = 0;
        }

}
