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



#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <netinet/in.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "ip.h"
#include "hna.h"
#include "redist.h"
#include "allocate.h"
#include "quagga.h"



#define CODE_CATEGORY_NAME "quagga"

char *zebraCmd2Str[ZEBRA_MESSAGE_MAX + 1] = {
        "ZERO",
        "INTERFACE_ADD",
        "INTERFACE_DELETE",
        "INTERFACE_ADDRESS_ADD",
        "INTERFACE_ADDRESS_DELETE",
        "INTERFACE_UP",
        "INTERFACE_DOWN",
        "IPV4_ROUTE_ADD",
        "IPV4_ROUTE_DELETE",
        "IPV6_ROUTE_ADD",
        "IPV6_ROUTE_DELETE",
        "REDISTRIBUTE_ADD",
        "REDISTRIBUTE_DELETE",
        "REDISTRIBUTE_DEFAULT_ADD",
        "REDISTRIBUTE_DEFAULT_DELETE",
        "IPV4_NEXTHOP_LOOKUP",
        "IPV6_NEXTHOP_LOOKUP",
        "IPV4_IMPORT_LOOKUP",
        "IPV6_IMPORT_LOOKUP",
        "INTERFACE_RENAME",
        "ROUTER_ID_ADD",
        "ROUTER_ID_DELETE",
        "ROUTER_ID_UPDATE",
        "HELLO",
        "MESSAGE_MAX"
};

int32_t nothing = 0;

static LIST_SIMPEL(zsock_write_list, struct zsock_write_node, list, list);
static LIST_SIMPEL(zdata_read_list, struct zdata, list, list);

static AVL_TREE(zroute_tree, struct redist_in_node, k);
static AVL_TREE(redist_opt_tree, struct redistr_opt_node, nameKey);
static AVL_TREE(redist_out_tree, struct redist_out_node, k);

//static AVL_TREE(export_opt_tree, struct export_opt_node, nameKey);

struct tunXin6_net_adv_node *quagga_net_adv_list = NULL;

static struct zebra_cfg zcfg;

static struct sys_route_dict zapi_rt_dict[BMX6_ROUTE_MAX_SUPP+1];


STATIC_FUNC void zsock_write(void* zpacket);
STATIC_FUNC int zsock_read(char* buff, int max);
STATIC_FUNC void zsock_disconnect(void);
STATIC_FUNC void zsock_connect(void *nothing);

uint8_t* zdata_get_ptr(struct zdata *zd, uint32_t *offset, ssize_t size)
{
        uint8_t *zp = (uint8_t*) zd->hdr;
        uint8_t* ret;

        if (*offset + size <= zd->len)
                ret = &(zp[*offset]);
        else
                ret = NULL;

        *offset += size;

        return ret;
}


void mem_cpy(uint8_t *dst, uint8_t *src, ssize_t size)
{
        if (dst && size) {

                if(src)
                        memcpy(dst, src, size);
                else
                        memset(dst, 0, size);
        }
}

uint8_t zdata_get_u8(struct zdata *zd, uint32_t *offset)
{
        uint8_t *ret = zdata_get_ptr(zd, offset, sizeof(uint8_t));
        return ret ? *ret : 0;
}

uint16_t zdata_get_u16(struct zdata *zd, uint32_t *offset)
{
        uint16_t *ret = (uint16_t*)zdata_get_ptr(zd, offset, sizeof(uint16_t));
        return ret ? *ret : 0;
}

uint32_t zdata_get_u32(struct zdata *zd, uint32_t *offset)
{
        uint32_t *ret = (uint32_t*)zdata_get_ptr(zd, offset, sizeof(uint32_t));
        return ret ? *ret : 0;
}




STATIC_FUNC
void zdata_parse_route(struct zdata *zd)
{
        dbgf_all(DBGT_INFO," ");

        assertion(-501402, ( zd->len >= sizeof (struct zapiV2_header) && zd->hdr->version == ZEBRA_VERSION2));
        assertion(-501445, (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV4_ROUTE_DELETE ||
                        zd->cmd == ZEBRA_IPV6_ROUTE_ADD || zd->cmd == ZEBRA_IPV6_ROUTE_DELETE));

        uint32_t ofs = sizeof (struct zapiV2_header);
        struct redist_in_node zrn;
        memset(&zrn, 0, sizeof (zrn));

        zrn.k.net.af = (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV4_ROUTE_DELETE) ? AF_INET : AF_INET6;

        zrn.k.inType = zdata_get_u8(zd, &ofs);
        zrn.flags = zdata_get_u8(zd, &ofs);
        zrn.message = zdata_get_u8(zd, &ofs);
        zrn.k.net.mask = zdata_get_u8(zd, &ofs);
        mem_cpy((uint8_t*) &(zrn.k.net.ip.s6_addr32[(zrn.k.net.af == AF_INET) ? 3 : 0]),
                zdata_get_ptr(zd, &ofs, ((zrn.k.net.mask + 7) / 8)), ((zrn.k.net.mask + 7) / 8));

        if (zrn.message & ZAPI_MESSAGE_NEXTHOP) {
                uint8_t idxnum = zdata_get_u8(zd, &ofs);

                if (zrn.k.net.af == AF_INET)
                        zrn.k.via = ip4ToX(zdata_get_u32(zd, &ofs));
                else
                        mem_cpy((uint8_t*) & zrn.k.via, zdata_get_ptr(zd, &ofs, sizeof (zrn.k.via)), sizeof (zrn.k.via));

                assertion(-501403, (idxnum == 1));
        }

        if (zrn.message & ZAPI_MESSAGE_IFINDEX) {
                uint8_t idxnum = zdata_get_u8(zd, &ofs);
                zrn.k.ifindex = ntohl(zdata_get_u32(zd, &ofs));
                assertion(-501404, (idxnum == 1));
        }

        if (zrn.message & ZAPI_MESSAGE_DISTANCE)
                zrn.distance = zdata_get_u8(zd, &ofs);
        
        if (zrn.message & ZAPI_MESSAGE_METRIC)
                zrn.metric = ntohl(zdata_get_u32(zd, &ofs));

        assertion(-501405, (zd->len == ofs));

        struct redist_in_node *tmp = avl_find_item(&zroute_tree, &zrn.k);

        if (tmp) {
                tmp->cnt += (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV6_ROUTE_ADD) ? (+1) : (-1);
                redist_dbg(DBGL_CHANGES, DBGT_INFO, __FUNCTION__, tmp, zapi_rt_dict, zebraCmd2Str[zd->cmd], "OLD");
        } else {
                tmp = debugMallocReset(sizeof (zrn), -300472);
                *tmp = zrn;
                tmp->cnt += 1;
                redist_dbg(DBGL_CHANGES, DBGT_INFO, __FUNCTION__, tmp, zapi_rt_dict, zebraCmd2Str[zd->cmd], "NEW");
                assertion(-501406, (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV6_ROUTE_ADD));
                avl_insert(&zroute_tree, tmp, -300473);
        }

}



STATIC_FUNC
void zdata_parse(void)
{
        dbgf_track(DBGT_INFO, " ");

        struct zdata * zd;
        uint8_t changed_routes = NO;
        
        while ((zd = list_del_head(&zdata_read_list))) {

                if (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV4_ROUTE_DELETE ||
                        zd->cmd == ZEBRA_IPV6_ROUTE_ADD || zd->cmd == ZEBRA_IPV6_ROUTE_DELETE) {

                        zdata_parse_route(zd);
                        changed_routes = YES;

                } else {
                        dbgf_sys(DBGT_WARN, "Unknown command=%d", zd->cmd);
                }

                debugFree(zd->hdr, -300474);
                debugFree(zd, -300475);
        }


        if (changed_routes) {

                changed_routes = NO;

                struct redist_in_node *zrn;
                struct redist_in_node zri;
                memset(&zri, 0, sizeof (zri));
                while ((zrn = avl_next_item(&zroute_tree, &zri.k))) {
                        zri = *zrn;

//                        zroute_dbg(DBGL_CHANGES, DBGT_INFO, __FUNCTION__, zrn, "", "");

                        if (zrn->old != zrn->cnt)
                                changed_routes = YES;

                        if (zrn->cnt > 1 || zrn->cnt < 0) {
                                zsock_disconnect();
                                return;
                        }

                        if (zrn->cnt == 0) {
                                struct redist_in_node *tmp = avl_remove(&zroute_tree, &zrn->k, -300476);
                                assertion(-501427, (tmp == zrn));
                                debugFree(zrn, -300477);
                                continue;
                        }

                        zrn->old = 1;
                }

                if (changed_routes) {
                        if ( redistribute_routes(&redist_out_tree, &zroute_tree, &redist_opt_tree, zapi_rt_dict) )
				update_tunXin6_net_adv_list(&redist_out_tree, &quagga_net_adv_list);
		}
        }
}

STATIC_FUNC
void zsock_read_handler(void * nothing)
{
        assertion(-501407, (zcfg.socket > 0));

        dbgf_track(DBGT_INFO," ");

        task_remove(zsock_read_handler, NULL);
        int ret = 1;
        static int no_data_cnt = 0;

        while (ret > 0) {
                // read lenght field:
                const uint16_t max = sizeof (((struct zapiV2_header *) NULL)->length);

                if (zcfg.zread_buff_len == 0) {
                        zcfg.zread_buff = debugMalloc(max, -300478);
                        zcfg.zread_buff_len = max;
                        zcfg.zread_len = 0;
                }

                while (zcfg.zread_len < max && (ret = zsock_read(zcfg.zread_buff + zcfg.zread_len, (max - zcfg.zread_len))) > 0)
                        zcfg.zread_len += ret;

                if (ret == 0 && (++no_data_cnt) >= 2)
                        zsock_disconnect();
                else if (ret > 0)
                        no_data_cnt = 0;


                if (zcfg.zread_len >= max) {

                        // read rest of packet:
                        uint16_t zpl = ntohs(((struct zapiV2_header *) zcfg.zread_buff)->length);

                        if (zcfg.zread_buff_len == max) {
                                zcfg.zread_buff = debugRealloc(zcfg.zread_buff, zpl, -300489);
                                zcfg.zread_buff_len = zpl;
                        }

                        while (zcfg.zread_len < zpl && (ret = zsock_read(zcfg.zread_buff + zcfg.zread_len, (zpl - zcfg.zread_len))) > 0)
                                zcfg.zread_len += ret;

                        if (zcfg.zread_len >= zpl) {

                                if (zcfg.zread_len == zpl && zcfg.zread_len >= sizeof (struct zapiV2_header) &&
                                        ((struct zapiV2_header *) zcfg.zread_buff)->marker == ZEBRA_HEADER_MARKER &&
                                        ((struct zapiV2_header *) zcfg.zread_buff)->version == ZEBRA_VERSION2) {

                                        struct zdata *zd = debugMalloc(sizeof (struct zdata), -300480);
                                        zd->hdr = (struct zapiV2_header *) zcfg.zread_buff;
                                        zd->len = zpl;
                                        zd->cmd = ntohs(zd->hdr->command);

                                        list_add_tail(&zdata_read_list, &zd->list);

                                        dbgf_all(DBGT_INFO, "full ZAPI len=%d data=%s",
                                                zcfg.zread_buff_len, memAsHexStringSep(zcfg.zread_buff, zcfg.zread_buff_len, 4, NULL));

                                } else {
                                        dbgf_sys(DBGT_ERR, "Invalid ZAPI len=%d data=%s",
                                                zcfg.zread_buff_len, memAsHexStringSep(zcfg.zread_buff, zcfg.zread_buff_len, 4, NULL));

                                        debugFree(zcfg.zread_buff, -300481);
                                }

                                zcfg.zread_buff = NULL;
                                zcfg.zread_buff_len = 0;
                                zcfg.zread_len = 0;
                        }
                }
        }

        if (zdata_read_list.items && zcfg.zread_len == 0 /*finished zsock reading*/)
                zdata_parse();

}


STATIC_FUNC
void zsock_fd_handler(int fd)
{
        assertion(-501408, (fd == zcfg.socket));
        zsock_read_handler(NULL);
}





STATIC_FUNC
uint8_t* zsock_put_hdr(uint8_t *d, uint16_t cmd, uint16_t len)
{
        struct zapiV2_header *hdr = (struct zapiV2_header*) d;
        hdr->version = ZEBRA_VERSION2;
        hdr->marker = ZEBRA_HEADER_MARKER;
        hdr->command = htons(cmd);
        hdr->length = htons(len);

        return d + sizeof (struct zapiV2_header);
}

STATIC_FUNC
uint8_t* zsock_put_mem(uint8_t *d, uint8_t * mem, uint16_t len)
{
        memcpy(d, mem, len);
        return d + len;
}

STATIC_FUNC
uint8_t* zsock_put_u8(uint8_t *d, uint8_t val)
{
        *((uint8_t*) d) = val;
        return d + sizeof (val);
}

STATIC_FUNC
uint8_t* zsock_put_u16(uint8_t *d, uint16_t val)
{
        *((uint16_t*) d) = val;
        return d + sizeof (val);
}

STATIC_FUNC
uint8_t* zsock_put_u32(uint8_t *d, uint32_t val)
{
        *((uint32_t*) d) = val;
        return d + sizeof (val);
}

STATIC_FUNC
void zsock_send_cmd_typeU8(uint16_t cmd, uint8_t type)
{
        assertion(-501410, (zcfg.socket > 0));
        assertion(-501411, (cmd < ZEBRA_MESSAGE_MAX));
        assertion(-501412, (type < ZEBRA_ROUTE_MAX));

        uint16_t len = sizeof (struct zapiV2_header) + sizeof (type);
        uint8_t *d = debugMalloc(len, -300524), *p = d;
        d = zsock_put_hdr(d, cmd, len);
        d = zsock_put_u8(d, type);

        dbgf_track(DBGT_INFO, "cmd=%s type=%s len=%d", zebraCmd2Str[cmd], zapi_rt_dict[type].sys2Name, len);

        zsock_write(p);
}


STATIC_FUNC
void zsock_send_redist_request(void)
{
        assertion(-501413, (zcfg.socket > 0));

        int route_type;
        for (route_type = 0; route_type <= BMX6_ROUTE_MAX_KNOWN; route_type++) {

                uint8_t new = bit_get((uint8_t*) & zcfg.bmx6_redist_bits_new, (sizeof (zcfg.bmx6_redist_bits_new) * 8), route_type);
                uint8_t old = bit_get((uint8_t*) & zcfg.bmx6_redist_bits_old, (sizeof (zcfg.bmx6_redist_bits_old) * 8), route_type);

                if (new && !old)
                        zsock_send_cmd_typeU8(ZEBRA_REDISTRIBUTE_ADD, zapi_rt_dict[route_type].bmx2sys);
                else if (!new && old)
                        zsock_send_cmd_typeU8(ZEBRA_REDISTRIBUTE_DELETE, zapi_rt_dict[route_type].bmx2sys);

        }
        zcfg.bmx6_redist_bits_old = zcfg.bmx6_redist_bits_new;
}


STATIC_FUNC
void zsock_send_route(int8_t del, const struct net_key *dst, uint32_t oif_idx, IPX_T *via, uint32_t metric, uint8_t distance)
{
        dbgf_track(DBGT_INFO, "del=%d dst=%s idx=%d via=%s metric=%d distance=%d",
                del, netAsStr(dst), oif_idx, ipXAsStr(dst->af, via), metric, distance);

        uint8_t len =
                sizeof (struct zapiV2_header) +
                1 + // uint8_t type;
                1 + // uint8_t flags;
                1 + // uint8_t message;
                2 + // uint16_t safi; // zclient.h uses uint8_t here  !! This field only exist in quagga/zebra/zserv.c:zread_ipvX_add/del()
                1 + // uint8_t prefixlen;
                ((dst->mask + 7) / 8) + // uint8_t prefix[];
                1 + // uint8_t nexthop_num;
                (via ? 1 : 0) + // uint8_t nexthop_type_af;
                (via ? (dst->af == AF_INET ? sizeof (IP4_T) : sizeof (IPX_T)) : 0) + // IP4/6_T nexthop;
                1 + // uint8_t nexthop_type_ifidx;
                4 + // uint32_t ifidx;
                1 + // uint8_t distance;
                4 + // uint32_t metric;
                0;

        uint8_t *d = debugMallocReset(len, -300511), *p = d;

        d = zsock_put_hdr(d, (dst->af == AF_INET ? (del ? ZEBRA_IPV4_ROUTE_DELETE : ZEBRA_IPV4_ROUTE_ADD) : (del ? ZEBRA_IPV6_ROUTE_DELETE : ZEBRA_IPV6_ROUTE_ADD)), len);
        d = zsock_put_u8(d, ZEBRA_ROUTE_BMX6); // type
        d = zsock_put_u8(d, 0); // flags
        d = zsock_put_u8(d, ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_METRIC | ZAPI_MESSAGE_DISTANCE); // message
        d = zsock_put_u16(d, htons(SAFI_UNICAST)); //safi
        d = zsock_put_u8(d, dst->mask);
        d = zsock_put_mem(d, (uint8_t*) & dst->ip.s6_addr32[(dst->af == AF_INET) ? 3 : 0], ((dst->mask + 7) / 8));

        if (via) {
                d = zsock_put_u8(d, 2);
                *(d++) = 2;
                d = zsock_put_mem(d, (uint8_t*) & via->s6_addr32[(dst->af == AF_INET) ? 3 : 0], (dst->af == AF_INET) ? 4 : 16);
        } else {
                d = zsock_put_u8(d, 1);
        }

        d = zsock_put_u8(d, ZEBRA_NEXTHOP_IFINDEX);
        d = zsock_put_u32(d, htonl(oif_idx)); //if_index
        d = zsock_put_u8(d, distance); // distance
        d = zsock_put_u32(d, htonl(metric)); //metric

        assertion(-501428, (d == p + len));

        zsock_write(p);
}




STATIC_FUNC
void zsock_disconnect(void)
{

        dbgf_sys(DBGT_WARN, " ");

        if (zcfg.socket > 0) {
                set_fd_hook(zcfg.socket, zsock_fd_handler, DEL);
                close(zcfg.socket);
                zcfg.socket = 0;
        }



        //zsock_write_flush();

        struct zsock_write_node *zwn;

        while ((zwn = list_del_head(&zsock_write_list))) {
                debugFree(zwn->zpacket, -300482);
                debugFree(zwn, -300483);
        }

        task_remove(zsock_write, NULL);


        //zsock_read_flush();

        if (zcfg.zread_buff) {
                debugFree(zcfg.zread_buff, -300484);
                zcfg.zread_buff = NULL;
                zcfg.zread_buff_len = 0;
                zcfg.zread_len = 0;
        }
        assertion(-501409, (!zcfg.zread_len));

        struct zdata *zd;

        while ((zd = list_del_head(&zdata_read_list))) {
                debugFree(zd->hdr, -300485);
                debugFree(zd, -300486);
        }

        while (zroute_tree.items)
                debugFree(avl_remove_first_item(&zroute_tree, -300487), -300488);

        task_remove(zsock_read_handler, NULL);

        if (!terminating) {
                task_remove(zsock_connect, NULL);
                task_register(0, zsock_connect, NULL, -300512);
        }

        while (redist_out_tree.items) {
                debugFree(avl_remove_first_item(&redist_out_tree, -300513), -300514);
                my_description_changed = YES;
        }

        if (quagga_net_adv_list) {
                debugFree(quagga_net_adv_list, -300515);
		quagga_net_adv_list = NULL;
        }

        set_ipexport( NULL );
}


STATIC_FUNC
void zsock_connect(void *nothing)
{

        task_remove(zsock_connect, NULL);

        assertion(-501414, (!zcfg.socket));

        if (zcfg.port) {

                assertion(-501415, IMPLIES(is_ip_set(&zcfg.ipX), is_ip_valid(&zcfg.ipX, AF_CFG)));

                if ((zcfg.socket = socket(AF_CFG, SOCK_STREAM, 0)) < 0)
                        goto zsock_connect_error;


                if (AF_CFG == AF_INET) {
                        struct sockaddr_in sin;
                        memset(&sin, 0, sizeof (sin));
                        sin.sin_family = AF_INET;
                        sin.sin_port = htons(zcfg.port);
                        sin.sin_addr.s_addr = is_ip_set(&zcfg.ipX) ? ipXto4(zcfg.ipX) : INADDR_LOOPBACK;

                        if (connect(zcfg.socket, (struct sockaddr *) &sin, sizeof sin) < 0)
                                goto zsock_connect_error;

                } else {
                        struct sockaddr_in6 sin6;
                        memset(&sin6, 0, sizeof (sin6));
                        sin6.sin6_family = AF_INET6;
                        sin6.sin6_port = htons(zcfg.port);
                        sin6.sin6_addr = is_ip_set(&zcfg.ipX) ? zcfg.ipX : in6addr_loopback;

                        if (connect(zcfg.socket, (struct sockaddr *) &sin6, sizeof sin6) < 0)
                                goto zsock_connect_error;
                }

        } else {
                struct sockaddr_un sun;
                memset(&sun, 0, sizeof (sun));

                if (check_file(zcfg.unix_path, NO/*regular*/, NO/*read*/, NO/*wirtable*/, NO/*executable*/) == FAILURE)
                        goto zsock_connect_error;

                if ((zcfg.socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
                        goto zsock_connect_error;

                fcntl(zcfg.socket, F_SETFL, fcntl(zcfg.socket, F_GETFL, 0) | O_NONBLOCK);

                sun.sun_family = AF_UNIX;
                strcpy(sun.sun_path, zcfg.unix_path);

                if( connect(zcfg.socket, (struct sockaddr *) &sun, sizeof sun) < 0 )
                        goto zsock_connect_error;

        }

        if (fcntl(zcfg.socket, F_SETFL, fcntl(zcfg.socket, F_GETFL, 0) | O_NONBLOCK))
                goto zsock_connect_error;

        dbgf_all(DBGT_INFO, "opened zapi socket %d", zcfg.socket);

        set_fd_hook( zcfg.socket, zsock_fd_handler, ADD);

        zsock_send_cmd_typeU8(ZEBRA_HELLO, ZEBRA_ROUTE_BMX6);
        zcfg.bmx6_redist_bits_old = 0;
        zsock_send_redist_request();

        set_ipexport( zsock_send_route );


        return;

        
zsock_connect_error:

        if (zcfg.socket > 0)
                close(zcfg.socket);

        zcfg.socket = 0;

        dbgf_mute(25, DBGL_SYS, DBGT_WARN, "failed, retrying in %d sec", ZSOCK_RECONNECT_TO / 1000);

        task_register(ZSOCK_RECONNECT_TO, zsock_connect, NULL, -300490);

        return;
}


STATIC_FUNC
int zsock_read(char* buff, int max)
{
        assertion(-501417, (zcfg.socket > 0));
        assertion(-501418, (buff));
        assertion(-501419, (max > 0));

        errno = 0;
        int rlen = read(zcfg.socket, buff, max);
        int err = errno;

        if (rlen >= 0) {
                dbgf_all(DBGT_INFO, "read len=%d data=%s", rlen, memAsHexStringSep(buff, rlen, 4, NULL));

        } else {

                if (err == EAGAIN || err == EWOULDBLOCK)
                        return 0;

                dbgf_sys(DBGT_ERR, "rlen=%d errno=%d error=%s", rlen, err, strerror(err));

                if (err == EINTR)
                        task_register(1, zsock_read_handler, NULL, -300491);
                else
                        zsock_disconnect();
        }

        return rlen;
}





STATIC_FUNC
void zsock_write( void* zpacket )
{
        char *zp = zpacket;
        struct zsock_write_node *zwn;
        static uint8_t writing = 0;

        assertion(-501420, (zcfg.socket > 0));

        task_remove(zsock_write, NULL);

        dbgf_track(DBGT_INFO, "write len=%d", zp ? ntohs(((struct zapiV2_header *) zp)->length): 0);

        if (zp) {
                zwn = debugMalloc(sizeof (struct zsock_write_node), -300492);
                zwn->zpacket = zp;
                zwn->send = 0;
                list_add_tail(&zsock_write_list, &zwn->list);
        }

        assertion(-501429, (!writing));

        if (writing)
                return;
        else
                writing = 1;

        while ((zwn = list_get_first(&zsock_write_list))) {

                struct zapiV2_header *hdr = (struct zapiV2_header *) zwn->zpacket;
                uint16_t len = ntohs(hdr->length);

                assertion(-501421, (len > zwn->send));
                assertion(-501422, (len >= sizeof (struct zapiV2_header)));

                do {
                        assertion(-501423, (zwn->send < len));

                        int ret = 0;
                        errno = 0;

                        dbgf_track(DBGT_INFO, "write len=%d tot=%d data=%s",
                                len - zwn->send, len, memAsHexStringSep(zwn->zpacket + zwn->send, len - zwn->send, 4, NULL));

                        if ((ret = write(zcfg.socket, zwn->zpacket + zwn->send, len - zwn->send)) < 0) {

                                if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                                        dbgf_sys(DBGT_WARN, "failed, errno: %s! retrying...", strerror(errno));
                                        task_register(0, zsock_write, NULL, -300493);
                                        writing = 0;
                                        return;
                                } else {
                                        dbgf_sys(DBGT_WARN, "disconneced, errno: %s!", strerror(errno));
                                        zsock_disconnect();
                                        break;
                                }
                        }
                        zwn->send += ret;

                } while (zwn->send != len);

                if (zwn->send == len) {
                        dbgf_track(DBGT_INFO, "written len=%d bytes", len);
                        list_del_head(&zsock_write_list);
                        debugFree(zwn->zpacket, -300494);
                        debugFree(zwn, -300495);
                }
        }

        writing = 0;
        return;
}


STATIC_FUNC
int32_t opt_zsock_path(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

                if (wordlen(patch->val) + 1 >= MAX_PATH_SIZE || patch->val[0] != '/')
                        return FAILURE;

                if (check_file(patch->val, NO/*regular*/, NO/*read*/, NO/*writable*/, NO/*executable*/) == FAILURE)
			return FAILURE;

		snprintf( zcfg.unix_path, wordlen(patch->val)+1, "%s", patch->val );
        }

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_redistribute(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        struct redistr_opt_node *rdn = NULL;
        static uint8_t changed = NO;

	int32_t redist = opt_redist(cmd, _save, opt, patch, cn, &redist_opt_tree, &changed);

	if (redist!=SUCCESS)
		return redist;

	if (cmd == OPT_SET_POST) {

                struct avl_node *an = NULL;

                zcfg.bmx6_redist_bits_new = 0;
                
                while ((rdn = avl_iterate_item(&redist_opt_tree, &an)))
                        zcfg.bmx6_redist_bits_new |= rdn->bmx6_redist_bits;

                if (initializing) {
                        task_register(0, zsock_connect, NULL, -300500);

                } else if (changed) {

                        zsock_send_redist_request();
			if ( redistribute_routes(&redist_out_tree, &zroute_tree, &redist_opt_tree, zapi_rt_dict) )
				update_tunXin6_net_adv_list(&redist_out_tree, &quagga_net_adv_list);
                }

                changed = NO;
        }

        return SUCCESS;
}


static struct opt_type quagga_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,ARG_ZAPI_DIR,		0,  2,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,ZEBRA_SERV_PATH,opt_zsock_path,
			ARG_DIR_FORM,	"" },
 	{ODI,0,ARG_REDIST,     	          0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_redistribute,
		        ARG_NAME_FORM,  HLP_REDIST},
	{ODI,ARG_REDIST,ARG_REDIST_NET, 'n',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,              0,              0,              0,0,            opt_redistribute,
			ARG_ADDR_FORM, HLP_REDIST_NET},
	{ODI,ARG_REDIST,ARG_REDIST_PREFIX_MIN,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_PREFIX,MAX_REDIST_PREFIX,DEF_REDIST_PREFIX_MIN,0,opt_redistribute,
			ARG_VALUE_FORM, HLP_REDIST_PREFIX_MIN},
	{ODI,ARG_REDIST,ARG_REDIST_PREFIX_MAX,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_PREFIX,MAX_REDIST_PREFIX,DEF_REDIST_PREFIX_MAX,0,opt_redistribute,
			ARG_VALUE_FORM, HLP_REDIST_PREFIX_MAX},
	{ODI,ARG_REDIST,ARG_TUN_DEV,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,		0,              0,              0,0,            opt_redistribute,
			ARG_NAME_FORM,	HLP_TUN_IN_DEV},
	{ODI,ARG_REDIST,ARG_REDIST_AGGREGATE,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_AGGREGATE,MAX_REDIST_AGGREGATE,DEF_REDIST_AGGREGATE,0,opt_redistribute,
			ARG_VALUE_FORM, HLP_REDIST_AGGREGATE},
	{ODI,ARG_REDIST,ARG_REDIST_BW,  'b',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,	        0,              0,0,            opt_redistribute,
			ARG_VALUE_FORM,	HLP_REDIST_BW},
	{ODI,ARG_REDIST,ARG_ROUTE_SYSTEM, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_KERNEL, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_CONNECT,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_RIP,    0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_RIPNG,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_OSPF,   0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_OSPF6,  0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_ISIS,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_BGP,    0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_BABEL,  0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_HSLS,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_OLSR,   0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	{ODI,ARG_REDIST,ARG_ROUTE_BATMAN, 0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_VALUE_FORM, HLP_ROUTE_TYPE},
	
};


static void quagga_cleanup( void )
{
        if (zcfg.socket)
                zsock_disconnect();

        set_tunXin6_net_adv_list(DEL, &quagga_net_adv_list);

}



static int32_t quagga_init( void )
{

        assertion(-501424, (ZEBRA_ROUTE_MAX <= BMX6_ROUTE_MAX_KNOWN));
	memset(&zapi_rt_dict, 0, sizeof(zapi_rt_dict));

	set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_SYSTEM,  'X', ARG_ROUTE_SYSTEM, BMX6_ROUTE_SYSTEM);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_KERNEL,  'K', ARG_ROUTE_KERNEL, BMX6_ROUTE_KERNEL);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_CONNECT, 'C', ARG_ROUTE_CONNECT, BMX6_ROUTE_CONNECT);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_STATIC,  'S', ARG_ROUTE_STATIC, BMX6_ROUTE_STATIC);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_RIP,     'R', ARG_ROUTE_RIP, BMX6_ROUTE_RIP);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_RIPNG,   'R', ARG_ROUTE_RIPNG, BMX6_ROUTE_RIPNG);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_OSPF,    'O', ARG_ROUTE_OSPF, BMX6_ROUTE_OSPF);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_OSPF6,   'O', ARG_ROUTE_OSPF6, BMX6_ROUTE_OSPF6);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_ISIS,    'I', ARG_ROUTE_ISIS, BMX6_ROUTE_ISIS);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_BGP,     'B', ARG_ROUTE_BGP, BMX6_ROUTE_BGP);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_BABEL,   'A', ARG_ROUTE_BABEL, BMX6_ROUTE_BABEL);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_BMX6,    'x', ARG_ROUTE_BMX6, BMX6_ROUTE_BMX6);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_HSLS,    'H', ARG_ROUTE_HSLS, BMX6_ROUTE_HSLS);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_OLSR,    'o', ARG_ROUTE_OLSR, BMX6_ROUTE_OLSR);
        set_rt_dict(zapi_rt_dict, ZEBRA_ROUTE_BATMAN,  'b', ARG_ROUTE_BATMAN, BMX6_ROUTE_BATMAN);


        memset(&zcfg, 0, sizeof (zcfg));
        strcpy(zcfg.unix_path, ZEBRA_SERV_PATH);

        register_options_array(quagga_options, sizeof ( quagga_options), CODE_CATEGORY_NAME);

        set_tunXin6_net_adv_list(ADD, &quagga_net_adv_list);


	return SUCCESS;
}


struct plugin* get_plugin( void ) {
	
	static struct plugin quagga_plugin;
	
	memset( &quagga_plugin, 0, sizeof ( struct plugin ) );
	

	quagga_plugin.plugin_name = CODE_CATEGORY_NAME;
	quagga_plugin.plugin_size = sizeof ( struct plugin );
	quagga_plugin.cb_init = quagga_init;
	quagga_plugin.cb_cleanup = quagga_cleanup;

	return &quagga_plugin;
}


