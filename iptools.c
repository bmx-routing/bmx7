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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <glob.h>
#include <limits.h>
#include <unistd.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "tools.h"
#include "allocate.h"
#include "iptools.h"


const IP6_T IP6_LOOPBACK_ADDR = { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } };

IDM_T str2netw(char* args, IPX_T *ipX, struct ctrl_node *cn, uint8_t *maskp, uint8_t *familyp, uint8_t is_addr)
{

	const char delimiter = '/';
	char *slashptr = NULL;
	uint8_t family;

	char switch_arg[IP6NET_STR_LEN] = { 0 };

	if (wordlen(args) < 1 || wordlen(args) >= IP6NET_STR_LEN)
		return FAILURE;

	wordCopy(switch_arg, args);
	switch_arg[wordlen(args)] = '\0';

	if (maskp) {

		if ((slashptr = strchr(switch_arg, delimiter))) {
			char *end = NULL;

			*slashptr = '\0';

			errno = 0;
			int mask = strtol(slashptr + 1, &end, 10);

			if ((errno == ERANGE) || mask > 128 || mask < 0) {

				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid argument %s %s",
					args, strerror(errno));

				return FAILURE;

			} else if (end == slashptr + 1 || wordlen(end)) {

				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid argument trailer %s", end);
				return FAILURE;
			}

			*maskp = mask;

		} else {

			dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid argument %s! Fix you parameters!", switch_arg);
			return FAILURE;
		}
	}

	errno = 0;

	struct in_addr in4;
	struct in6_addr in6;

	if ((inet_pton(AF_INET, switch_arg, &in4) == 1) && (!maskp || *maskp <= 32)) {

		*ipX = ip4ToX(in4.s_addr);
		family = AF_INET;

	} else if ((inet_pton(AF_INET6, switch_arg, &in6) == 1) && (!maskp || *maskp <= 128)) {

		*ipX = in6;
		family = AF_INET6;

	} else {

		dbgf_all(DBGT_WARN, "invalid argument: %s: %s", args, strerror(errno));
		return FAILURE;

	}

	if (is_addr) {
		IPX_T netw = *ipX;
		if ((ip_netmask_validate(&netw, (maskp ? *maskp : (family == AF_INET ? 32 : 128)), family, YES) == FAILURE) ||
			(maskp && *maskp != (family == AF_INET ? 32 : 128) && !memcmp(&netw, ipX, sizeof(netw)))) {
			dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "Address required! NOT network!");
			return FAILURE;
		}

	} else {
		if (ip_netmask_validate(ipX, (maskp ? *maskp : (family == AF_INET ? 32 : 128)), family, NO) == FAILURE) {
			dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "Network required! NOT address!");
			return FAILURE;
		}
	}

	if (familyp && (*familyp == AF_INET || *familyp == AF_INET6) && *familyp != family) {
		dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "%s required!", family2Str(*familyp));
	}

	if (familyp)
		*familyp = family;

	return SUCCESS;

}

char *family2Str(uint8_t family)
{
	static char b[B64_SIZE];

	switch (family) {
	case AF_INET:
		return "IPv4";
	case AF_INET6:
		return "IPv6";
	default:
		sprintf(b, "%d ???", family);
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

void ip6ToStr(const IPX_T *addr, char *str)
{
	ipXToStr(AF_INET6, addr, str);
}

IPX_T ip4ToX(IP4_T ip4)
{
	IPX_T ip = ZERO_IP;
	ip.s6_addr32[3] = ip4;
	return ip;
}

char *ipXAsStr(int family, const IPX_T *addr)
{
	static uint8_t c = 0;
	static char str[IP2S_ARRAY_LEN][INET6_ADDRSTRLEN];

	c = (c + 1) % IP2S_ARRAY_LEN;

	ipXToStr(family, addr, str[c]);

	return str[c];
}

char *ip4AsStr(IP4_T addr)
{

	static uint8_t c = 0;
	static char str[IP2S_ARRAY_LEN][INET_ADDRSTRLEN];

	c = (c + 1) % IP2S_ARRAY_LEN;

	inet_ntop(AF_INET, &addr, str[c], INET_ADDRSTRLEN);

	return str[c];
}

char *netAsStr(const struct net_key *net)
{
	static uint8_t c = 0;
	static char str[IP2S_ARRAY_LEN][IPXNET_STR_LEN];

	c = (c + 1) % IP2S_ARRAY_LEN;

	if (net) {
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
	return strToLower(memAsHexStringSep(mac, MAC_ADDR_LEN, 1, ":"));
}

IDM_T is_mac_equal(const MAC_T *a, const MAC_T *b)
{
	return(a->u16[2] == b->u16[2] &&
		a->u16[1] == b->u16[1] &&
		a->u16[0] == b->u16[0]);

}

IDM_T is_ip_equal(const IPX_T *a, const IPX_T *b)
{
	return(a->s6_addr32[3] == b->s6_addr32[3] &&
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
	return(ip && !is_ip_equal(ip, &ZERO_IP));
}

IDM_T is_ip_valid(const IPX_T *ip, const uint8_t family)
{
	TRACE_FUNCTION_CALL;

	if (!is_ip_set(ip))
		return NO;

	if (family != (is_zero((void*) ip, sizeof( IPX_T) - sizeof(IP4_T)) ? AF_INET : AF_INET6))
		return NO;

	if (family == AF_INET6) {

		if (!is_ip_equal(ip, &IP6_LOOPBACK_ADDR))
			return YES;


	} else if (family == AF_INET) {

		if (ipXto4(*ip) != INADDR_LOOPBACK && ipXto4(*ip) != INADDR_NONE)
			return YES;
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

		if (force) {

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

/* recurse down layer-2 interfaces until we hit a layer-1 interface using Linux' sysfs */
int interface_get_lowest(char *hwifname, const char *ifname)
{
	glob_t globbuf = { .gl_offs = 1 };
	char *lowentry = NULL;
	char *fnamebuf = debugMalloc(1 + strlen(VIRTIF_PREFIX) + IF_NAMESIZE + strlen(LOWERGLOB_SUFFIX), -300840);
	char path[PATH_MAX];

	sprintf(fnamebuf, "%s%s%s", VIRTIF_PREFIX, ifname, LOWERGLOB_SUFFIX);
	glob(fnamebuf, GLOB_NOSORT | GLOB_NOESCAPE, NULL, &globbuf);

	if (globbuf.gl_pathc == 1) {
		lowentry = debugMalloc(1 + strlen(globbuf.gl_pathv[0]), -300841);
		strncpy(lowentry, globbuf.gl_pathv[0], 1 + strlen(globbuf.gl_pathv[0]));
	}

	globfree(&globbuf);
	debugFree(fnamebuf, -300842);

	if (lowentry) {
		ssize_t len;
		/* lower interface found, recurse down */

		len = readlink(lowentry, path, PATH_MAX - 1);
		debugFree(lowentry, -300846);

		if (len != -1 && strncmp(path, "../", 3) == 0) {
			path[len] = '\0';
			return interface_get_lowest(hwifname, strrchr(path, '/') + 1);
		}

	} else {
		/* no lower interface found, check if physical interface exists */
		sprintf(path, "%s%s", NETIF_PREFIX, ifname);

		if (access(path, F_OK) == 0) {
			strncpy(hwifname, ifname, IF_NAMESIZE - 1);
			dbgf_track(DBGT_INFO, "got %s", hwifname);
			return SUCCESS;
		}
	}

	return FAILURE;
}
