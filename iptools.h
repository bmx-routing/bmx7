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

#define IP2S_ARRAY_LEN 10

#define IP6NET_STR_LEN (INET6_ADDRSTRLEN+4)  // eg ::1/128
#define IPXNET_STR_LEN IP6NET_STR_LEN
#define B64_SIZE 64

#define IP4_MAX_PREFIXLEN 32
#define IP6_MAX_PREFIXLEN 128

extern const IP6_T   IP6_LOOPBACK_ADDR;


IDM_T str2netw(char* args, IPX_T *ipX, struct ctrl_node *cn, uint8_t *maskp, uint8_t *familyp, uint8_t is_addr);

char *family2Str(uint8_t family);


char *ipXAsStr(int family, const IPX_T *addr);
char *ip4AsStr( IP4_T addr );
void  ipXToStr(int family, const IPX_T *addr, char *str);
void ip6ToStr(const IPX_T *addr, char *str);
char *netAsStr(const struct net_key *net);


#define ipXto4( ipx ) ((ipx).s6_addr32[3])
IPX_T ip4ToX(IP4_T ip4);

char* macAsStr(const MAC_T* mac);

#define ip6AsStr( addr_ptr ) ipXAsStr( AF_INET6, addr_ptr)

struct net_key * setNet(struct net_key *netp, uint8_t family, uint8_t prefixlen, IPX_T *ip);


IDM_T is_mac_equal(const MAC_T *a, const MAC_T *b);

IDM_T is_ip_equal(const IPX_T *a, const IPX_T *b);
IDM_T is_ip_set(const IPX_T *ip);

IDM_T is_ip_valid( const IPX_T *ip, const uint8_t family );

IDM_T ip_netmask_validate(IPX_T *ipX, uint8_t mask, uint8_t family, uint8_t force);

IDM_T is_ip_net_equal(const IPX_T *netA, const IPX_T *netB, const uint8_t plen, const uint8_t family);

