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


#include "bmx.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "metrics.h"
#include "ip.h"
#include "hna.h"
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

static AVL_TREE(zroute_tree, struct zroute_node, k);
static AVL_TREE(redist_opt_tree, struct redistr_opt_node, nameKey);
static AVL_TREE(redist_out_tree, struct redist_out_node, k);

static LIST_SIMPEL(tunXin6_net_adv_list, struct tunXin6_net_adv_node, list, list);

static struct zebra_cfg zcfg;

static struct quagga_rt_dict zroute_dict[BMX6_ROUTE_MAX];


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

void zroute_dbg(int8_t dbgl, int8_t dbgt, const char *func, struct zroute_node *zrn)
{
        dbgf(dbgl, dbgt, "%s old=%d cnt=%d %s route=%s via=%s type=%s ifidx=%d metric=%d distance=%d flags=%X message=%X",
                func, zrn->old, zrn->cnt,
                (zrn->cnt > 1 || zrn->cnt < 0) ? "INVALID" : (zrn->old != zrn->cnt) ? "CHANGED" : "UNCHANGED",
                netAsStr(&zrn->k.net), ipXAsStr(zrn->k.net.af, &zrn->k.via),
                zrn->k.ztype < ZEBRA_ROUTE_MAX ? zroute_dict[zroute_dict[zrn->k.ztype].zebra2Bmx].bmx2Name : memAsHexStringSep(&zrn->k.ztype, 1, 0),
                zrn->k.ifindex, zrn->k.metric, zrn->k.distance, zrn->flags, zrn->message);
}

STATIC_FUNC
void zdata_parse_route(struct zdata *zd)
{
        dbgf_track(DBGT_INFO,"");

        assertion(-501402, ( zd->len >= sizeof (struct zapiV1_header) && zd->hdr->version == ZEBRA_VERSION));


        uint32_t ofs = sizeof (struct zapiV1_header);
        struct zroute_node zrn;
        memset(&zrn, 0, sizeof (zrn));

        zrn.k.net.af = (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV4_ROUTE_DELETE) ? AF_INET : AF_INET6;

        zrn.k.ztype = zdata_get_u8(zd, &ofs);
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
                zrn.k.distance = zdata_get_u8(zd, &ofs);
        
        if (zrn.message & ZAPI_MESSAGE_METRIC) {
                uint32_t metric = ntohl(zdata_get_u32(zd, &ofs));
                if (zrn.k.ztype != ZEBRA_ROUTE_CONNECT)
                        zrn.k.metric = metric;
        }

        assertion(-501405, (zd->len == ofs));

        struct zroute_node *tmp = avl_find_item(&zroute_tree, &zrn.k);

        dbgf_track(DBGT_INFO, "%s %s",
                zd->cmd < ZEBRA_MESSAGE_MAX ? zebraCmd2Str[zd->cmd] : memAsHexStringSep(&zd->cmd, 1, 0), (tmp ? "old" : "new"));

        if (tmp) {
                tmp->cnt += (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV6_ROUTE_ADD) ? (+1) : (-1);
        } else {
                assertion(-501406, (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV6_ROUTE_ADD));
                tmp = debugMalloc(sizeof (zrn), -300472);
                memset(tmp, 0, sizeof (*tmp));
                *tmp = zrn;
                avl_insert(&zroute_tree, tmp, -300473);
                tmp->cnt += 1;
        }

        zroute_dbg(DBGL_CHANGES, DBGT_INFO, __FUNCTION__, tmp);
}

STATIC_FUNC
void redist_rm_overlapping(void)
{

        dbgf_track(DBGT_INFO, "");

        struct redist_out_node *routn;
        struct avl_node *an = NULL;

        while ((routn = avl_iterate_item(&redist_out_tree, &an))) {

                if (!routn->new)
                        continue;

                // find overlapping route entry:
                if (routn->minAggregatePrefixLen != MAX_REDIST_AGGREGATE) {
                        struct redist_out_node *ovlp = NULL;
                        struct redist_out_node t = {.k =
                                {.bandwidth = routn->k.bandwidth, .bmx6_route_type = routn->k.bmx6_route_type, .net =
                                        {.af = routn->k.net.af}}};

                        while ((ovlp = avl_next_item(&redist_out_tree, ovlp ? &ovlp->k : &t.k))) {

                                if (ovlp->k.bandwidth.val.u8 != routn->k.bandwidth.val.u8 ||
                                        ovlp->k.bmx6_route_type != routn->k.bmx6_route_type ||
                                        ovlp->k.net.af != routn->k.net.af ||
                                        ovlp->k.net.mask >= routn->k.net.mask)
                                        break;

                                if (!ovlp->new || ovlp->k.net.mask < routn->minAggregatePrefixLen)
                                        continue;

                                if (is_ip_net_equal(&ovlp->k.net.ip, &routn->k.net.ip, ovlp->k.net.mask, routn->k.net.af)) {
                                        routn->new = 0;
                                        ovlp->minAggregatePrefixLen = MAX(ovlp->minAggregatePrefixLen, routn->minAggregatePrefixLen);
                                        dbgf_track(DBGT_INFO, "disable overlapping net=%s in favor of net=%s",
                                                netAsStr(&routn->k.net), netAsStr(&ovlp->k.net));
                                        break;
                                }
                        }
                }
        }
}

STATIC_FUNC
void redist_rm_aggregatable(void)
{
        dbgf_track(DBGT_INFO, "");

        struct redist_out_node *r1;
        struct avl_node *an = NULL;

        struct redist_out_node rtn;
        memset(&rtn, 0, sizeof (rtn));

        uint8_t more = YES;

        while (more) {

                more = NO;

                while ((r1 = avl_iterate_item(&redist_out_tree, &an))) {

                        uint8_t v4 = (r1->k.net.af == AF_INET);

                        if (!r1->new || !r1->k.net.mask || r1->k.net.mask <= r1->minAggregatePrefixLen)
                                continue;


                        if (bit_get((uint8_t*)&(r1->k.net.ip), v4 ? 32 : 128, r1->k.net.mask + (v4 ? 96 : 0))) {

                                struct redist_out_node s0 = *r1;
                                bit_set((uint8_t*)&(s0.k.net.ip), v4 ? 32 : 128, s0.k.net.mask + (v4 ? 96 : 0), 0);

                                struct redist_out_node *r0 = avl_find_item(&redist_out_tree, &s0.k);

                                if (r0 && r0->new && r0->k.net.mask > r0->minAggregatePrefixLen) {

                                        struct redist_out_node *ra;

                                        s0.k.net.mask--;

                                        if ((ra = avl_find_item(&redist_out_tree, &s0.k))) {
                                                assertion(-500000, (!ra->new));
                                        } else {
                                                ra = debugMalloc(sizeof (s0), -300000);
                                                *ra = s0;
                                                avl_insert(&redist_out_tree, ra, -300000);
                                        }

                                        ra->new = 1;
                                        r0->new = 0;
                                        r1->new = 0;
                                        ra->minAggregatePrefixLen = MAX(r0->minAggregatePrefixLen, r1->minAggregatePrefixLen);
                                        more = YES;

                                        dbgf_track(DBGT_INFO, "aggregate neighboring net0=%s net1=%s into new=%s",
                                                netAsStr(&r0->k.net), netAsStr(&r1->k.net), netAsStr(&ra->k.net));

                                }
                        }
                }
        }
}

STATIC_FUNC
void redistribute_routes(void)
{

        dbgf_track(DBGT_INFO, "");

        struct zroute_node *zrn;
        struct avl_node *zri;

        struct redistr_opt_node *roptn;
        struct avl_node *ropti;

        struct redist_out_node *routn;
        struct avl_node *routi;

        struct redist_out_node routf;

        for (routi = NULL; (routn = avl_iterate_item(&redist_out_tree, &routi));) {
                routn->new = 0;
                routn->minAggregatePrefixLen = 0;
        }

        for (zri = NULL; (zrn = avl_iterate_item(&zroute_tree, &zri));) {

                zroute_dbg(DBGL_CHANGES, DBGT_INFO, "parsing", zrn);

                for (ropti = NULL; (roptn = avl_iterate_item(&redist_opt_tree, &ropti));) {

                        if (roptn->net.af && roptn->net.af != zrn->k.net.af) {
                                dbgf_track(DBGT_INFO, "skipping A");
                                continue;
                        }

                        if (roptn->bandwidth.val.u8 == 0) {
                                dbgf_track(DBGT_INFO, "skipping B");
                                continue;
                        }

                        if (roptn->bmx6_redist_bits &&
                                !bit_get(((uint8_t*) & roptn->bmx6_redist_bits),
                                sizeof (&roptn->bmx6_redist_bits)*8, zroute_dict[zrn->k.ztype].zebra2Bmx)) {
                                
                                dbgf_track(DBGT_INFO, "skipping C");
                                continue;
                        }

                        if ((roptn->net.mask != MIN_REDIST_PREFIX ||
                                roptn->netPrefixMin != DEF_REDIST_PREFIX_MIN ||
                                roptn->netPrefixMax != DEF_REDIST_PREFIX_MAX)
                                && !(
                                (roptn->netPrefixMax == TYP_REDIST_PREFIX_NET ?
                                roptn->net.mask >= zrn->k.net.mask : roptn->netPrefixMax >= zrn->k.net.mask) &&
                                (roptn->netPrefixMin == TYP_REDIST_PREFIX_NET ?
                                roptn->net.mask <= zrn->k.net.mask : roptn->netPrefixMin <= zrn->k.net.mask) &&
                                is_ip_net_equal(&roptn->net.ip, &zrn->k.net.ip, MIN(roptn->net.mask, zrn->k.net.mask), roptn->net.af))) {

                                dbgf_track(DBGT_INFO, "skipping D");
                                continue;
                        }

                        memset(&routf, 0, sizeof (routf));

                        routf.k.bmx6_route_type = zroute_dict[zrn->k.ztype].zebra2Bmx;
                        routf.k.net = roptn->net.mask >= zrn->k.net.mask ? roptn->net : zrn->k.net;
                        routf.k.bandwidth = roptn->bandwidth;
                        routf.k.must_be_one = 1; // to let alv_next_item find the first one
                        routf.minAggregatePrefixLen = roptn->minAggregatePrefixLen;

                        if (!(routn = avl_find_item(&redist_out_tree, &routf.k))) {
                                *(routn = debugMalloc(sizeof (routf), -300000)) = routf;
                                avl_insert(&redist_out_tree, routn, -300000);
                                dbgf_track(DBGT_INFO, "addding");
                        } else {
                                dbgf_track(DBGT_INFO, "reusing");
                        }

                        routn->new = 1;
                        routn->minAggregatePrefixLen = MAX(routn->minAggregatePrefixLen, roptn->minAggregatePrefixLen);

                        break;
                }
        }
        
        redist_rm_overlapping();

        redist_rm_aggregatable();


        // remove_old_routes:
        uint8_t redist_changed = NO;

        memset(&routf, 0, sizeof (routf));
        while ((routn = avl_next_item(&redist_out_tree, &routf.k))) {
                routf = *routn;

                dbgf_track(DBGT_INFO, "old=%d new=%d rtype=%d bandwith=%d net=%s",
                        routn->old, routn->new, routn->k.bmx6_route_type, routn->k.bandwidth.val.u8, netAsStr(&routn->k.net));

                if (routn->new != routn->old) // 10, 11, 01, 00
                        redist_changed = YES;

                if (!routn->new) {
                        avl_remove(&redist_out_tree, &routn->k, -300000);
                        debugFree(routn, -300000);
                        continue;
                }

                routn->new = 0;
                routn->old = 1;
        }

        if (redist_changed) {

                dbgf_track(DBGT_INFO, "redist changed");

                struct avl_node *ran = NULL;

                while (tunXin6_net_adv_list.items) {
                        struct tunXin6_net_adv_node *tn = list_del_head(&tunXin6_net_adv_list);
                        debugFree(tn, -300000);
                }

                while ((routn = avl_iterate_item(&redist_out_tree, &ran))) {
                        struct tunXin6_net_adv_node *tn = debugMalloc(sizeof (struct tunXin6_net_adv_node), -300000);
                        memset(tn, 0, sizeof (*tn));
                        tn->bandwidth = routn->k.bandwidth;
                        tn->bmx6_route_type = routn->k.bmx6_route_type;
                        tn->net = routn->k.net;
                        list_add_tail(&tunXin6_net_adv_list, &tn->list);
                }

                my_description_changed = YES;
        }
}

STATIC_FUNC
void zdata_parse(void)
{
        dbgf_track(DBGT_INFO, "");

        struct zdata * zd;
        uint8_t new_routes = 0;
        
        while ((zd = list_del_head(&zdata_read_list))) {

                if (zd->cmd == ZEBRA_IPV4_ROUTE_ADD || zd->cmd == ZEBRA_IPV4_ROUTE_DELETE ||
                        zd->cmd == ZEBRA_IPV6_ROUTE_ADD || zd->cmd == ZEBRA_IPV6_ROUTE_DELETE) {

                        zdata_parse_route(zd);
                        new_routes = 1;

                } else {
                        dbgf_sys(DBGT_WARN, "Unknown command=%d", zd->cmd);
                }

                debugFree(zd->hdr, -300474);
                debugFree(zd, -300475);
        }


        if (new_routes) {

                new_routes = 0;

                struct zroute_node *zrn;
                struct zroute_node zri;
                memset(&zri, 0, sizeof (zri));
                while ((zrn = avl_next_item(&zroute_tree, &zri.k))) {
                        zri = *zrn;

                        zroute_dbg(DBGL_CHANGES, DBGT_INFO, __FUNCTION__, zrn);

                        if (zrn->old != zrn->cnt)
                                new_routes = 1;

                        if (zrn->cnt > 1 || zrn->cnt < 0) {
                                zsock_disconnect();
                                return;
                        }

                        if (zrn->cnt == 0) {
                                struct zroute_node *tmp = avl_remove(&zroute_tree, &zrn->k, -300476);
                                assertion(-500000, (tmp == zrn));
                                debugFree(zrn, -300477);
                                continue;
                        }

                        zrn->old = 1;
                }

                if (new_routes)
                        redistribute_routes();
        }
}

STATIC_FUNC
void zsock_read_handler(void * nothing)
{
        assertion(-501407, (zcfg.socket > 0));

        dbgf_track(DBGT_INFO,"");

        task_remove(zsock_read_handler, NULL);
        int ret = 1;
        static int no_data_cnt = 0;

        while (ret > 0) {
                // read lenght field:
                const uint16_t max = sizeof (((struct zapiV1_header *) NULL)->length);

                if (zcfg.zread_buff_len == 0) {
                        zcfg.zread_buff = debugMalloc(max, -300478);
                        zcfg.zread_buff_len = max;
                        zcfg.zread_len = 0;
                }

                while (zcfg.zread_len < max && (ret = zsock_read(zcfg.zread_buff + zcfg.zread_len, (max - zcfg.zread_len))) > 0)
                        zcfg.zread_len += ret;

                if (ret == 0 && (++no_data_cnt) >= 2)
                        zsock_disconnect();
                else
                        no_data_cnt = 0;


                if (zcfg.zread_len >= max) {

                        // read rest of packet:
                        uint16_t zpl = ntohs(((struct zapiV1_header *) zcfg.zread_buff)->length);

                        if (zcfg.zread_buff_len == max) {
                                zcfg.zread_buff = debugRealloc(zcfg.zread_buff, zpl, -300489);
                                zcfg.zread_buff_len = zpl;
                        }

                        while (zcfg.zread_len < zpl && (ret = zsock_read(zcfg.zread_buff + zcfg.zread_len, (zpl - zcfg.zread_len))) > 0)
                                zcfg.zread_len += ret;

                        if (zcfg.zread_len >= zpl) {

                                if (zcfg.zread_len == zpl && zcfg.zread_len >= sizeof (struct zapiV1_header) &&
                                        ((struct zapiV1_header *) zcfg.zread_buff)->marker == ZEBRA_HEADER_MARKER &&
                                        ((struct zapiV1_header *) zcfg.zread_buff)->version == ZEBRA_VERSION) {

                                        struct zdata *zd = debugMalloc(sizeof (struct zdata), -300480);
                                        zd->hdr = (struct zapiV1_header *) zcfg.zread_buff;
                                        zd->len = zpl;
                                        zd->cmd = ntohs(zd->hdr->command);

                                        list_add_tail(&zdata_read_list, &zd->list);

                                        dbgf_track(DBGT_INFO, "full ZAPI len=%d data=%s",
                                                zcfg.zread_buff_len, memAsHexStringSep(zcfg.zread_buff, zcfg.zread_buff_len, 4));

                                } else {
                                        dbgf_sys(DBGT_ERR, "Invalid ZAPI len=%d data=%s",
                                                zcfg.zread_buff_len, memAsHexStringSep(zcfg.zread_buff, zcfg.zread_buff_len, 4));

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
void zsock_disconnect(void)
{

        dbgf_sys(DBGT_WARN, "");

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
                task_register(0, zsock_connect, NULL, -300000);
        }

        while (redist_out_tree.items) {
                debugFree(avl_remove_first_item(&redist_out_tree, -300000), -300000);
                my_description_changed = YES;
        }

        while (tunXin6_net_adv_list.items) {
                struct tunXin6_net_adv_node *tn = list_del_head(&tunXin6_net_adv_list);
                debugFree(tn, -300000);
        }

}


STATIC_FUNC
char* zsock_put_hdr(char *packet, uint16_t cmd, uint8_t data_len)
{
        struct zapiV1_header *hdr = (struct zapiV1_header*) packet;
        hdr->version = ZEBRA_VERSION;
        hdr->marker = ZEBRA_HEADER_MARKER;
        hdr->command = htons(cmd);
        hdr->length = htons(sizeof (struct zapiV1_header) +data_len);

        return packet + sizeof (struct zapiV1_header);
}


STATIC_FUNC
void zsock_send_cmd_typeU8(uint16_t cmd, uint8_t type)
{
        assertion(-501410, (zcfg.socket > 0));
        assertion(-501411, (cmd < ZEBRA_MESSAGE_MAX));
        assertion(-501412, (type < ZEBRA_ROUTE_MAX));

        uint16_t len = sizeof (struct zapiV1_header) + sizeof (type);
        char *p = debugMalloc(len, -300489);
        char *d = zsock_put_hdr(p, cmd, sizeof (type));
        *d = type;

        dbgf_track(DBGT_INFO, "cmd=%s type=%s", zebraCmd2Str[cmd], zroute_dict[zroute_dict[type].zebra2Bmx].bmx2Name);

        zsock_write(p);
}


STATIC_FUNC
void zsock_send_redist_request(void)
{
        assertion(-501413, (zcfg.socket > 0));

        int route_type;
        for (route_type = 0; route_type < BMX6_ROUTE_MAX; route_type++) {

                uint8_t new = bit_get((uint8_t*) & zcfg.bmx6_redist_bits_new, (sizeof (zcfg.bmx6_redist_bits_new) * 8), route_type);
                uint8_t old = bit_get((uint8_t*) & zcfg.bmx6_redist_bits_old, (sizeof (zcfg.bmx6_redist_bits_old) * 8), route_type);

                if (new && !old)
                        zsock_send_cmd_typeU8(ZEBRA_REDISTRIBUTE_ADD, zroute_dict[route_type].bmx2Zebra);
                else if (!new && old)
                        zsock_send_cmd_typeU8(ZEBRA_REDISTRIBUTE_DELETE, zroute_dict[route_type].bmx2Zebra);

        }
        zcfg.bmx6_redist_bits_old = zcfg.bmx6_redist_bits_new;
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

        return;

        
zsock_connect_error:

        if (zcfg.socket > 0)
                close(zcfg.socket);

        zcfg.socket = 0;

        dbgf_sys(DBGT_WARN, "failed, retrying in %d sec", ZSOCK_RECONNECT_TO / 1000);

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
                dbgf_track(DBGT_INFO, "read len=%d data=%s", rlen, memAsHexStringSep(buff, rlen, 4));

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


        if (zp) {
                zwn = debugMalloc(sizeof (struct zsock_write_node), -300492);
                zwn->zpacket = zp;
                zwn->send = 0;
                list_add_tail(&zsock_write_list, &zwn->list);
        }

        assertion(-500000, (!writing));

        if (writing)
                return;
        else
                writing = 1;

        while ((zwn = list_get_first(&zsock_write_list))) {

                struct zapiV1_header *hdr = (struct zapiV1_header *) zwn->zpacket;
                uint16_t len = ntohs(hdr->length);

                assertion(-501421, (len > zwn->send));
                assertion(-501422, (len >= sizeof (struct zapiV1_header)));

                do {
                        assertion(-501423, (zwn->send < len));

                        int ret = 0;
                        errno = 0;

                        dbgf_track(DBGT_INFO, "write len=%d data=%s",
                                len - zwn->send, memAsHexStringSep(zwn->zpacket + zwn->send, len - zwn->send, 4));

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

                rdn = avl_find_item(&redist_opt_tree, name);

                struct net_key net = ZERO_NET_KEY;
                net.af = rdn ? rdn->net.af : 0; // family of ARG_TUN_SEARCH_NETWORK and ARG_TUN_SEARCH_SRC must be the same!!!

                if (cmd == OPT_APPLY) {

                        changed = YES;

                        //unlink_tun_net(NULL, NULL, NULL);

                        if (!rdn && patch->diff != DEL) {
                                rdn = debugMalloc(sizeof (struct redistr_opt_node), -300496);
                                memset(rdn, 0, sizeof (struct redistr_opt_node));
                                strcpy(rdn->nameKey, name);
                                avl_insert(&redist_opt_tree, rdn, -300497);

                                rdn->hysteresis = DEF_REDIST_HYSTERESIS;
                                rdn->netPrefixMin = DEF_REDIST_PREFIX_MIN;
                                rdn->netPrefixMax = DEF_REDIST_PREFIX_MAX;
                        } else if (rdn && patch->diff == DEL) {
                                avl_remove(&redist_opt_tree, &rdn->nameKey, -300498);
                                debugFree(rdn, -300499);
                        }
                }

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_REDIST_NET)) {

                                if (c->val) {

                                        if (str2netw(c->val, &net.ip, cn, &net.mask, &net.af, NO) == FAILURE)
                                                return FAILURE;

                                        set_opt_child_val(c, netAsStr(&net));

                                        if (cmd == OPT_APPLY && rdn)
                                                rdn->net = net;
                                        

                                } else if (cmd == OPT_APPLY && rdn) {
                                        setNet(&rdn->net, net.af, 0, NULL);
                                }

                        } else if (!strcmp(c->opt->name, ARG_REDIST_BW)) {

                                if (c->val) {
                                        char *endptr;
                                        unsigned long long ull = strtoul(c->val, &endptr, 10);

                                        if (ull > UMETRIC_MAX || ull < UMETRIC_FM8_MIN || *endptr != '\0')
                                                return FAILURE;

                                        assertion(-500000, (sizeof (ull) == sizeof (UMETRIC_T)));

                                        if (cmd == OPT_APPLY && rdn)
                                                rdn->bandwidth = umetric_to_fmu8((UMETRIC_T*) & ull);

                                } else if (cmd == OPT_APPLY && rdn) {
                                        rdn->bandwidth.val.u8 = 0;
                                }


                        } else if (cmd == OPT_APPLY && rdn) {

                                if (!strcmp(c->opt->name, ARG_REDIST_PREFIX_MIN)) {
                                        rdn->netPrefixMin = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_PREFIX_MIN;

                                } else if (!strcmp(c->opt->name, ARG_REDIST_PREFIX_MAX)) {
                                        rdn->netPrefixMax = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_PREFIX_MAX;

                                } else if (!strcmp(c->opt->name, ARG_REDIST_AGGREGATE)) {
                                        rdn->minAggregatePrefixLen = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_AGGREGATE;

                                } else if (!strcmp(c->opt->name, ARG_REDIST_HYSTERESIS)) {
                                        rdn->hysteresis = c->val ? strtol(c->val, NULL, 10) : DEF_REDIST_HYSTERESIS;

                                } else {
                                        uint8_t t;
                                        for (t = 0; t < BMX6_ROUTE_MAX; t++) {
                                                if (!strcmp(c->opt->name, zroute_dict[t].bmx2Name)) {
                                                        bit_set((uint8_t*) &rdn->bmx6_redist_bits,
                                                                sizeof (rdn->bmx6_redist_bits) * 8,
                                                                t, (c->val && strtol(c->val, NULL, 10) == 1));
                                                }
                                        }
                                }
                        }
                }


        } else if (cmd == OPT_SET_POST) {

                struct avl_node *an = NULL;

                zcfg.bmx6_redist_bits_new = 0;
                
                while ((rdn = avl_iterate_item(&redist_opt_tree, &an)))
                        zcfg.bmx6_redist_bits_new |= rdn->bmx6_redist_bits;

                if (initializing) {
                        task_register(0, zsock_connect, NULL, -300500);

                } else if (changed) {

                        zsock_send_redist_request();
                        redistribute_routes();
                }

                changed = NO;


        } else if (cmd == OPT_UNREGISTER) {

                struct avl_node *an = NULL;
                
                while ((rdn = avl_iterate_item(&redist_opt_tree, &an))) {
                        avl_remove(&redist_opt_tree, &rdn->nameKey, -300501);
                        debugFree(rdn, -300502);
                }

        }

        return SUCCESS;

}


static struct opt_type quagga_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,ARG_ZAPI_DIR,		0,  2,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,ZEBRA_SERV_PATH,opt_zsock_path,
			ARG_DIR_FORM,	"" },

	{ODI,0,ARG_REDIST,     	          0,9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_redistribute,
		        ARG_NAME_FORM,  "arbitrary but unique name for redistributed network(s) depending on sub criterias"},
	{ODI,ARG_REDIST,ARG_REDIST_NET, 'n',9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,  0,              0,              0,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"network permit filter (optional)"},
	{ODI,ARG_REDIST,ARG_REDIST_PREFIX_MIN,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_PREFIX,MAX_REDIST_PREFIX,DEF_REDIST_PREFIX_MIN,0,opt_redistribute,
			ARG_VALUE_FORM, "minumum prefix len to accept for redistribution (129 = network prefix len)"},
	{ODI,ARG_REDIST,ARG_REDIST_PREFIX_MAX,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_PREFIX,MAX_REDIST_PREFIX,DEF_REDIST_PREFIX_MAX,0,opt_redistribute,
			ARG_VALUE_FORM, "maximum prefix len to accept for redistribution (129 = network prefix len)"},
	{ODI,ARG_REDIST,ARG_REDIST_AGGREGATE,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,MIN_REDIST_AGGREGATE,MAX_REDIST_AGGREGATE,DEF_REDIST_AGGREGATE,0,opt_redistribute,
			ARG_VALUE_FORM, "maximum prefix len to accept for redistribution"},
	{ODI,ARG_REDIST,ARG_REDIST_BW,    0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,0,		0,	        0,              0,0,            opt_redistribute,
			ARG_VALUE_FORM,	"bandwidth to network as bits/sec (mandatory)"},
	{ODI,ARG_REDIST,ARG_ROUTE_SYSTEM, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_KERNEL, 0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_CONNECT,0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_RIP,    0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_RIPNG,  0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_OSPF,   0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_OSPF6,  0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_ISIS,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_BGP,    0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_BABEL,  0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_HSLS,   0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_OLSR,   0,9,2,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	{ODI,ARG_REDIST,ARG_ROUTE_BATMAN, 0,9,1,A_CS1,A_ADM,A_DYI,A_CFA,A_ANY,   0,              0,              1,              0,0,            opt_redistribute,
			ARG_PREFIX_FORM,"redistribute route type"},
	
};


static void quagga_cleanup( void )
{
        if (zcfg.socket)
                zsock_disconnect();

        set_tunXin6_net_adv_list(DEL, &tunXin6_net_adv_list);

}



static int32_t quagga_init( void )
{

        assertion(-501424, (ZEBRA_ROUTE_MAX == BMX6_ROUTE_MAX));
        set_rt_dict(BMX6_ROUTE_SYSTEM, ZEBRA_ROUTE_SYSTEM, ARG_ROUTE_SYSTEM);
        set_rt_dict(BMX6_ROUTE_KERNEL, ZEBRA_ROUTE_KERNEL, ARG_ROUTE_KERNEL);
        set_rt_dict(BMX6_ROUTE_CONNECT, ZEBRA_ROUTE_CONNECT, ARG_ROUTE_CONNECT);
        set_rt_dict(BMX6_ROUTE_STATIC, ZEBRA_ROUTE_STATIC, ARG_ROUTE_STATIC);
        set_rt_dict(BMX6_ROUTE_RIP, ZEBRA_ROUTE_RIP, ARG_ROUTE_RIP);
        set_rt_dict(BMX6_ROUTE_RIPNG, ZEBRA_ROUTE_RIPNG, ARG_ROUTE_RIPNG);
        set_rt_dict(BMX6_ROUTE_OSPF, ZEBRA_ROUTE_OSPF, ARG_ROUTE_OSPF);
        set_rt_dict(BMX6_ROUTE_OSPF6, ZEBRA_ROUTE_OSPF6, ARG_ROUTE_OSPF6);
        set_rt_dict(BMX6_ROUTE_ISIS, ZEBRA_ROUTE_ISIS, ARG_ROUTE_ISIS);
        set_rt_dict(BMX6_ROUTE_BGP, ZEBRA_ROUTE_BGP, ARG_ROUTE_BGP);
        set_rt_dict(BMX6_ROUTE_BABEL, ZEBRA_ROUTE_BABEL, ARG_ROUTE_BABEL);
        set_rt_dict(BMX6_ROUTE_BMX6, ZEBRA_ROUTE_BMX6, ARG_ROUTE_BMX6);
        set_rt_dict(BMX6_ROUTE_HSLS, ZEBRA_ROUTE_HSLS, ARG_ROUTE_HSLS);
        set_rt_dict(BMX6_ROUTE_OLSR, ZEBRA_ROUTE_OLSR, ARG_ROUTE_OLSR);
        set_rt_dict(BMX6_ROUTE_BATMAN, ZEBRA_ROUTE_BATMAN, ARG_ROUTE_BATMAN);


        memset(&zcfg, 0, sizeof (zcfg));
        strcpy(zcfg.unix_path, ZEBRA_SERV_PATH);

        register_options_array(quagga_options, sizeof ( quagga_options), CODE_CATEGORY_NAME);

        set_tunXin6_net_adv_list(ADD, &tunXin6_net_adv_list);

	return SUCCESS;
}


struct plugin* get_plugin( void ) {
	
	static struct plugin quagga_plugin;
	
	memset( &quagga_plugin, 0, sizeof ( struct plugin ) );
	

	quagga_plugin.plugin_name = CODE_CATEGORY_NAME;
	quagga_plugin.plugin_size = sizeof ( struct plugin );
        quagga_plugin.plugin_code_version = CODE_VERSION;
	quagga_plugin.cb_init = quagga_init;
	quagga_plugin.cb_cleanup = quagga_cleanup;

	return &quagga_plugin;
}


