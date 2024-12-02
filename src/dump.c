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
#include <string.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "ip.h"
#include "iptools.h"
#include "dump.h"
#include "schedule.h"
#include "plugin.h"
#include "tools.h"
#include "allocate.h"
#include "prof.h"

#define CODE_CATEGORY_NAME "traffic"

#define IMPROVE_ROUNDOFF 10

static int64_t curr_dump_period = DEF_DUMP_PERIOD;
static int32_t next_dump_period = DEF_DUMP_PERIOD;
static int32_t prev_dump_period = DEF_DUMP_PERIOD;

static uint32_t dump_iteration = 0;

static IDM_T dump_terminating = NO;
static int32_t data_dev_plugin_registry = FAILURE;

enum {
    DUMP_DIRECTION_TX,
    DUMP_DIRECTION_RX,
    DUMP_DIRECTION_ARRSZ,
};

enum {
    DUMP_BC,
    DUMP_UC,
    DUMP_BCUC_ARRSZ
};


enum {
    DUMP_TYPE_IP6_PACKETS,
    DUMP_TYPE_IP6_LOAD,
    DUMP_TYPE_IP6_HEADER,
    DUMP_TYPE_UDP_HEADER,
    DUMP_TYPE_BMX_HEADER,
//  DUMP_TYPE_FRAME_HEADER,
    DUMP_TYPE_ARRSZ
};

char * dump_type_names[DUMP_TYPE_ARRSZ] = {
    "IP6_PACKETS",
    "IP6_LOAD",
    "IP6_HEADER",
    "UDP_HEADER",
    "BMX7_HEADER"
};

struct dump_data {
    uint32_t tmp_frame[DUMP_DIRECTION_ARRSZ][DUMP_BCUC_ARRSZ][FRAME_TYPE_ARRSZ];
    uint32_t pre_frame[DUMP_DIRECTION_ARRSZ][DUMP_BCUC_ARRSZ][FRAME_TYPE_ARRSZ];
    uint32_t avg_frame[DUMP_DIRECTION_ARRSZ][DUMP_BCUC_ARRSZ][FRAME_TYPE_ARRSZ];

    int32_t tmp_all[DUMP_DIRECTION_ARRSZ][DUMP_BCUC_ARRSZ][DUMP_TYPE_ARRSZ];
    int32_t pre_all[DUMP_DIRECTION_ARRSZ][DUMP_BCUC_ARRSZ][DUMP_TYPE_ARRSZ];
    int32_t avg_all[DUMP_DIRECTION_ARRSZ][DUMP_BCUC_ARRSZ][DUMP_TYPE_ARRSZ];
};


static struct dump_data all_devs_data;

STATIC_FUNC
void update_traffic_statistics_data(struct dump_data *data)
{
	uint16_t i,c, t;

	for (i = 0; i < DUMP_DIRECTION_ARRSZ; i++) {

      for (c = 0; c < DUMP_BCUC_ARRSZ; c++) {

		for (t = 0; t < DUMP_TYPE_ARRSZ; t++) {
			data->pre_all[i][c][t] = (((int64_t) (data->tmp_all[i][c][t])) * 1000) / curr_dump_period;

			data->avg_all[i][c][t] -= (data->avg_all[i][c][t] / devStatRegression);
			data->avg_all[i][c][t] += ((data->pre_all[i][c][t]) / devStatRegression);
			data->tmp_all[i][c][t] = 0;
		}


		for (t = 0; t < FRAME_TYPE_ARRSZ; t++) {
			data->pre_frame[i][c][t] = (((int64_t) (data->tmp_frame[i][c][t])) * 1000) / curr_dump_period;

			data->avg_frame[i][c][t] -= (data->avg_frame[i][c][t] / devStatRegression);
			data->avg_frame[i][c][t] += ((data->pre_frame[i][c][t]) / devStatRegression);
			data->tmp_frame[i][c][t] = 0;
		}
      }
	}
}

STATIC_FUNC
void update_traffic_statistics_task(void *data)
{
	prof_start(update_traffic_statistics_task, main);

	struct dev_node *dev;
	struct avl_node *an = NULL;

	dump_iteration++;
	curr_dump_period = prev_dump_period;

	update_traffic_statistics_data(&all_devs_data);

	while ((dev = avl_iterate_item(&dev_name_tree, &an))) {

		struct dump_data **dump_dev_plugin_data = (struct dump_data **) (get_plugin_data(dev, PLUGIN_DATA_DEV, data_dev_plugin_registry));

		if (*dump_dev_plugin_data)
			update_traffic_statistics_data(*dump_dev_plugin_data);

	}

	task_register(next_dump_period, update_traffic_statistics_task, NULL, -300348);
	prev_dump_period = next_dump_period;

	prof_stop();
}

STATIC_FUNC
void dump(struct packet_buff *pb)
{

	assertion(-500760, (XOR((pb->i.oif), (pb->i.iif))));

	IDM_T direction = pb->i.iif ? DUMP_DIRECTION_RX : DUMP_DIRECTION_TX;
	struct dev_node *dev = pb->i.iif ? pb->i.iif : pb->i.oif;
	struct packet_header *phdr = (struct packet_header *) pb->p.data;

	struct dump_data **this_dev_data = (struct dump_data **) (get_plugin_data(dev, PLUGIN_DATA_DEV, data_dev_plugin_registry));

	assertion(-500761, (*this_dev_data));

	uint16_t plength = pb->i.length;
	uint8_t unicast = pb->i.unicast;
    uint8_t cast = (unicast ? DUMP_UC : DUMP_BC);

	dbgf(DBGL_DUMP, DBGT_NONE, "%s dev=%-12s unicast=%d src=%-16s dst=%-16s udpPayload=%-d",
		direction == DUMP_DIRECTION_RX ? "in " : "out", dev->ifname_label.str, unicast, pb->i.llip_str,
		pb->i.dst ? ip6AsStr( &(((struct sockaddr_in6*)pb->i.dst)->sin6_addr) ): "", plength);

	dbgf(DBGL_DUMP, DBGT_NONE, "%s data: %s",
		direction == DUMP_DIRECTION_RX ? "in " : "out", memAsHexString(((uint8_t*) phdr), plength));

    dbgf(DBGL_DUMP, DBGT_NONE, "%s       headerVersion=%-2d reserved=%-2X headerSize=%-4zu",
        direction == DUMP_DIRECTION_RX ? "in " : "out", phdr->comp_version, phdr->reserved, sizeof(struct packet_header));

//  for ( cast=DUMP_BCUC_BROADCAST; cast <= (unicast ? DUMP_BCUC_UNICAST : DUMP_BCUC_BROADCAST); cast++ ) {
    (*this_dev_data)->tmp_all[direction][cast][DUMP_TYPE_IP6_PACKETS] += (100 << IMPROVE_ROUNDOFF);
    (&all_devs_data)->tmp_all[direction][cast][DUMP_TYPE_IP6_PACKETS] += (100 << IMPROVE_ROUNDOFF);
    (*this_dev_data)->tmp_all[direction][cast][DUMP_TYPE_IP6_LOAD] += ((plength + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) << IMPROVE_ROUNDOFF);
    (&all_devs_data)->tmp_all[direction][cast][DUMP_TYPE_IP6_LOAD] += ((plength + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) << IMPROVE_ROUNDOFF);
    (*this_dev_data)->tmp_all[direction][cast][DUMP_TYPE_IP6_HEADER] += (sizeof(struct ip6_hdr) << IMPROVE_ROUNDOFF);
    (&all_devs_data)->tmp_all[direction][cast][DUMP_TYPE_IP6_HEADER] += (sizeof(struct ip6_hdr) << IMPROVE_ROUNDOFF);
    (*this_dev_data)->tmp_all[direction][cast][DUMP_TYPE_UDP_HEADER] += (sizeof(struct udphdr) << IMPROVE_ROUNDOFF);
    (&all_devs_data)->tmp_all[direction][cast][DUMP_TYPE_UDP_HEADER] += (sizeof(struct udphdr) << IMPROVE_ROUNDOFF);
    (*this_dev_data)->tmp_all[direction][cast][DUMP_TYPE_BMX_HEADER] += (sizeof(struct packet_header) << IMPROVE_ROUNDOFF);
    (&all_devs_data)->tmp_all[direction][cast][DUMP_TYPE_BMX_HEADER] += (sizeof(struct packet_header) << IMPROVE_ROUNDOFF);
//  }

	struct rx_frame_iterator it = {
		.caller = __func__, .op = 0,
		.db = packet_frame_db, .process_filter = FRAME_TYPE_PROCESS_NONE,
		.f_type = -1, .frames_in = (((uint8_t*) phdr) + sizeof(struct packet_header)),
		.frames_length = (plength - sizeof(struct packet_header)), ._f_pos_next = 0
	};

	int32_t result;
	uint16_t pkt_pos = sizeof(struct packet_header);

	while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

		char tnum[8];
		char *tname;
		int16_t frame_msgs = -1;

		if (!(tname = it.db->handls[it.f_type].name)) {
			sprintf(tnum, "%d", it.f_type);
			tname = tnum;
		}

		if (it.db->handls[it.f_type].fixed_msg_size) {
			frame_msgs = it.f_msgs_len / it.db->handls[it.f_type].min_msg_size;
		}


		dbgf(DBGL_DUMP, DBGT_NONE, "%s             frame_type=%-12s data_header_size=%-3d msgs=%-3d frame_length=%-4d",
			direction == DUMP_DIRECTION_RX ? "in " : "out", tname,
			it.db->handls[it.f_type].data_header_size, frame_msgs, it._f_len);

		dbgf(DBGL_DUMP, DBGT_NONE, "%s         data [%3d...%3d]:%s",
			direction == DUMP_DIRECTION_RX ? "in  hex" : "out hex",
			pkt_pos, pkt_pos + it._f_len - 1, memAsHexString(((uint8_t*) phdr) + pkt_pos, it._f_len));

		//assertion(-500991, (it.hands->hands[it.frame_type].min_msg_size));
		assertion(-500992, (it.f_msgs_len >= 0));

//	    for ( cast=DUMP_BCUC_BROADCAST; cast <= (unicast ? DUMP_BCUC_UNICAST : DUMP_BCUC_BROADCAST); cast++ ) {
	        (*this_dev_data)->tmp_frame[direction][cast][it.f_type] += (it._f_len << IMPROVE_ROUNDOFF);
	        (&all_devs_data)->tmp_frame[direction][cast][it.f_type] += (it._f_len << IMPROVE_ROUNDOFF);

//	        (*this_dev_data)->tmp_all[direction][cast][DUMP_TYPE_FRAME_HEADER] += ((it._f_len - it.f_dlen) << IMPROVE_ROUNDOFF);
//	        (&all_devs_data)->tmp_all[direction][cast][DUMP_TYPE_FRAME_HEADER] += ((it._f_len - it.f_dlen) << IMPROVE_ROUNDOFF);
//	    }

		pkt_pos += it._f_len;
	}

	if (result != TLV_RX_DATA_DONE) {

		dbgf(DBGL_DUMP, DBGT_NONE, "%s             ERROR frame_type=%d frame_length=%d frame_data_length=%d result=%s - ignoring further frames!!",
			direction == DUMP_DIRECTION_RX ? "in " : "out", it.f_type, it._f_len, it.f_dlen, tlv_rx_result_str(result));

		dbgf(DBGL_DUMP, DBGT_NONE, "%s         data [%3d...%3d]:%s",
			direction == DUMP_DIRECTION_RX ? "in  hex" : "out hex",
			pkt_pos, pkt_pos + it._f_len - 1, memAsHexString(((uint8_t*) phdr) + pkt_pos, it._f_len));
	}

	assertion(-500990, (IMPLIES(direction == DUMP_DIRECTION_TX, result == TLV_RX_DATA_DONE)));

}

STATIC_FUNC
void dbg_traffic_statistics(struct dump_data *data, struct ctrl_node *cn, char* dbg_name)
{

	uint16_t t;
	int32_t secIp6BcRx = data->pre_all[DUMP_DIRECTION_RX][DUMP_BC][DUMP_TYPE_IP6_LOAD];
    int32_t secIp6UcRx = data->pre_all[DUMP_DIRECTION_RX][DUMP_UC][DUMP_TYPE_IP6_LOAD];
    int32_t secIp6BcTx = data->pre_all[DUMP_DIRECTION_TX][DUMP_BC][DUMP_TYPE_IP6_LOAD];
    int32_t secIp6UcTx = data->pre_all[DUMP_DIRECTION_TX][DUMP_UC][DUMP_TYPE_IP6_LOAD];
//    int32_t secIp6 = secIp6Rx + secIp6Tx;
	int32_t avgIp6BcRx = data->avg_all[DUMP_DIRECTION_RX][DUMP_BC][DUMP_TYPE_IP6_LOAD];
    int32_t avgIp6UcRx = data->avg_all[DUMP_DIRECTION_RX][DUMP_UC][DUMP_TYPE_IP6_LOAD];
    int32_t avgIp6BcTx = data->avg_all[DUMP_DIRECTION_TX][DUMP_BC][DUMP_TYPE_IP6_LOAD];
    int32_t avgIp6UcTx = data->avg_all[DUMP_DIRECTION_TX][DUMP_UC][DUMP_TYPE_IP6_LOAD];
//    int32_t avgIp6 = avgIp6Rx + avgIp6Tx;

	for (t = 0; t < DUMP_TYPE_ARRSZ; t++) {
//		dbg_printf(cn, "%-11s %13s  %5d %3d  %5d %3d  %5d %3d  %5d %3d  %5d %3d | %5d %3d  %5d %3d  %5d %3d  %5d %3d  %5d %3d\n", dbg_name, dump_type_names[t],
	    dbg_printf(cn, "%-11s %13s  %5d %3d  %5d %3d  %5d %3d  %5d %3d | %5d %3d  %5d %3d  %5d %3d  %5d %3d\n", dbg_name, dump_type_names[t],
/*
			((data->pre_all[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->pre_all[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t] +
			  data->pre_all[DUMP_DIRECTION_IN][DUMP_BCUC_UNICAST][t]   + data->pre_all[DUMP_DIRECTION_OUT][DUMP_BCUC_UNICAST][t]     ) >> IMPROVE_ROUNDOFF),
			(secUdp ? ((( data->pre_all[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->pre_all[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t] +
			              data->pre_all[DUMP_DIRECTION_IN][DUMP_BCUC_UNICAST][t]   + data->pre_all[DUMP_DIRECTION_OUT][DUMP_BCUC_UNICAST][t]     )*100) / secUdp) : -1),
*/

			((data->pre_all[DUMP_DIRECTION_RX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
			(secIp6BcRx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->pre_all[DUMP_DIRECTION_RX][DUMP_BC][t]*100) / secIp6BcRx) : -1),

            ((data->pre_all[DUMP_DIRECTION_RX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
            (secIp6UcRx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->pre_all[DUMP_DIRECTION_RX][DUMP_UC][t]*100) / secIp6UcRx) : -1),

            ((data->pre_all[DUMP_DIRECTION_TX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
			(secIp6BcTx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->pre_all[DUMP_DIRECTION_TX][DUMP_BC][t]*100) / secIp6BcTx) : -1),

            ((data->pre_all[DUMP_DIRECTION_TX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
            (secIp6UcTx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->pre_all[DUMP_DIRECTION_TX][DUMP_UC][t]*100) / secIp6UcTx) : -1),


/*
			((data->avg_all[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->avg_all[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t]) >> IMPROVE_ROUNDOFF),
			(avgUdp ? (((data->avg_all[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->avg_all[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t])*100) / avgUdp) : 0),
*/

			((data->avg_all[DUMP_DIRECTION_RX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
			(avgIp6BcRx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->avg_all[DUMP_DIRECTION_RX][DUMP_BC][t]*100) / avgIp6BcRx) : -1),

            ((data->avg_all[DUMP_DIRECTION_RX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
            (avgIp6UcRx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->avg_all[DUMP_DIRECTION_RX][DUMP_UC][t]*100) / avgIp6UcRx) : -1),

            ((data->avg_all[DUMP_DIRECTION_TX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
            (avgIp6BcTx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->avg_all[DUMP_DIRECTION_TX][DUMP_BC][t]*100) / avgIp6BcTx) : -1),

            ((data->avg_all[DUMP_DIRECTION_TX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
            (avgIp6UcTx && (t!=DUMP_TYPE_IP6_PACKETS) ? ((data->avg_all[DUMP_DIRECTION_TX][DUMP_UC][t]*100) / avgIp6UcTx) : -1)

			);
	}

	for (t = 0; t < FRAME_TYPE_NOP; t++) {

		if (packet_frame_db->handls[t].name || data->avg_frame[DUMP_DIRECTION_RX][DUMP_BC][t] || data->avg_frame[DUMP_DIRECTION_TX][DUMP_BC][t]) {

			char tnum[4];
			char *tname = packet_frame_db->handls[t].name;
			if (!tname) {
				sprintf(tnum, "%d", t);
				tname = tnum;
			}

//			dbg_printf(cn, "%-11s %13s  %5d %3d  %5d %3d  %5d %3d  %5d %3d  %5d %3d | %5d %3d  %5d %3d  %5d %3d  %5d %3d  %5d %3d\n", dbg_name, tname,
            dbg_printf(cn, "%-11s %13s  %5d %3d  %5d %3d  %5d %3d  %5d %3d | %5d %3d  %5d %3d  %5d %3d  %5d %3d\n", dbg_name, tname,
/*
				((data->pre_frame[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->pre_frame[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t]) >> IMPROVE_ROUNDOFF),
				(secUdp ? (((data->pre_frame[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->pre_frame[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t])*100) / secUdp) : 0),
*/
				((data->pre_frame[DUMP_DIRECTION_RX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
				(secIp6BcRx ? ((data->pre_frame[DUMP_DIRECTION_RX][DUMP_BC][t]*100) / secIp6BcRx): 0),

                ((data->pre_frame[DUMP_DIRECTION_RX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
                (secIp6UcRx ? ((data->pre_frame[DUMP_DIRECTION_RX][DUMP_UC][t]*100) / secIp6UcRx): 0),

                ((data->pre_frame[DUMP_DIRECTION_TX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
                (secIp6BcTx ? ((data->pre_frame[DUMP_DIRECTION_TX][DUMP_BC][t]*100) / secIp6BcTx) : 0),

                ((data->pre_frame[DUMP_DIRECTION_TX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
                (secIp6UcTx ? ((data->pre_frame[DUMP_DIRECTION_TX][DUMP_UC][t]*100) / secIp6UcTx) : 0),

/*
				((data->avg_frame[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->avg_frame[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t]) >> IMPROVE_ROUNDOFF),
				(avgUdp ? (((data->avg_frame[DUMP_DIRECTION_IN][DUMP_BCUC_BROADCAST][t] + data->avg_frame[DUMP_DIRECTION_OUT][DUMP_BCUC_BROADCAST][t])*100) / avgUdp) : 0),
*/
                ((data->avg_frame[DUMP_DIRECTION_RX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
                (avgIp6BcRx ? ((data->avg_frame[DUMP_DIRECTION_RX][DUMP_BC][t]*100) / avgIp6BcRx) : 0),

				((data->avg_frame[DUMP_DIRECTION_RX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
				(avgIp6UcRx ? ((data->avg_frame[DUMP_DIRECTION_RX][DUMP_UC][t]*100) / avgIp6UcRx) : 0),

                ((data->avg_frame[DUMP_DIRECTION_TX][DUMP_BC][t]) >> IMPROVE_ROUNDOFF),
                (avgIp6BcTx ? ((data->avg_frame[DUMP_DIRECTION_TX][DUMP_BC][t]*100) / avgIp6BcTx) : 0),

				((data->avg_frame[DUMP_DIRECTION_TX][DUMP_UC][t]) >> IMPROVE_ROUNDOFF),
				(avgIp6UcTx ? ((data->avg_frame[DUMP_DIRECTION_TX][DUMP_UC][t]*100) / avgIp6UcTx) : 0)

				);
		}
	}
}

STATIC_FUNC
int32_t opt_traffic_statistics(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd == OPT_APPLY) {

		struct dev_node *dev;
		struct avl_node *an = NULL;

		dbg_printf(cn, "TRAFFIC (iteration=%d as [B/s], averaged over %.1fs and weighted averages):\n",
			dump_iteration, (float) curr_dump_period / 1000);

//		dbg_printf(cn, "dev %16s type    all _%%_     Rx _%%_     Tx _%%_   UcRx _%%_   UcTx _%%_ |   all _%%_     Rx _%%_     Tx _%%_   UcRx _%%_   UcTx _%%_\n", "");
        dbg_printf(cn, "dev %16s type   BcRx _%%_   UcRx _%%_   BcTx _%%_   UcTx _%%_ |  BcRx _%%_   UcRx _%%_   BcTx _%%_   UcTx _%%_\n", "");

		if (patch->val && (!strcmp(patch->val, ARG_DUMP_ALL) || !strcmp(patch->val, ARG_DUMP_SUMMARY)))
			dbg_traffic_statistics(&all_devs_data, cn, ARG_DUMP_ALL);

		while ((dev = avl_iterate_item(&dev_name_tree, &an))) {

			if (!patch->val || !strcmp(patch->val, ARG_DUMP_ALL) || !strcmp(patch->val, ARG_DUMP_DEV) || !strcmp(patch->val, dev->ifname_label.str)) {

				struct dump_data **this_dev_data = (struct dump_data **) (get_plugin_data(dev, PLUGIN_DATA_DEV, data_dev_plugin_registry));

				if (dev->active && *this_dev_data)
					dbg_traffic_statistics(*this_dev_data, cn, dev->ifname_label.str);
			}
		}
	}
	return SUCCESS;
}


STATIC_FUNC
	struct opt_type dump_options[] ={
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

        {ODI, 0, ARG_DUMP_PERIOD,          0,  9,1, A_PS1, A_ADM, A_DYI, A_ARG, A_ANY, &next_dump_period,    MIN_DUMP_PERIOD,    MAX_DUMP_PERIOD,   DEF_DUMP_PERIOD,0,   0,
			ARG_VALUE_FORM,	"set duration in ms for how long traffic is measured for calculating interval averages"}
	,
	{ODI, 0, ARG_DUMP,     	           0,  9,2, A_PS1, A_USR, A_DYN, A_ARG, A_ANY, 0,                 0,                  0,                 0,0,                  opt_traffic_statistics,
			"<DEV>",		"show traffic statistics for given device name, summary, or all\n"}
};

STATIC_FUNC
void init_cleanup_dev_traffic_data(int32_t cb_id, void* devp)
{

	struct dev_node *dev;
	struct avl_node *an;


	for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));) {

		struct dump_data **dump_dev_plugin_data = (struct dump_data **) (get_plugin_data(dev, PLUGIN_DATA_DEV, data_dev_plugin_registry));

		if (dump_terminating || (!dev->active && *dump_dev_plugin_data)) {

			if (*dump_dev_plugin_data)
				debugFree(*dump_dev_plugin_data, -300305);

			*dump_dev_plugin_data = NULL;


		} else if (dev->active && !(*dump_dev_plugin_data)) {

			*dump_dev_plugin_data = debugMallocReset(sizeof(struct dump_data), -300306);
		}
	}
}

STATIC_FUNC
void cleanup_dump(void)
{
	dump_terminating = YES;
	init_cleanup_dev_traffic_data(0, NULL);
	set_packet_hook(dump, DEL);
}

STATIC_FUNC
int32_t init_dump(void)
{
	memset(&all_devs_data, 0, sizeof(struct dump_data));

	data_dev_plugin_registry = get_plugin_data_registry(PLUGIN_DATA_DEV);

	register_options_array(dump_options, sizeof( dump_options), CODE_CATEGORY_NAME);

	task_register(next_dump_period, update_traffic_statistics_task, NULL, -300349);

	set_packet_hook(dump, ADD);

	return SUCCESS;
}

struct plugin *dump_get_plugin(void)
{

	static struct plugin dump_plugin;
	memset(&dump_plugin, 0, sizeof( struct plugin));

	dump_plugin.plugin_name = CODE_CATEGORY_NAME;
	dump_plugin.plugin_size = sizeof( struct plugin);
	dump_plugin.cb_init = init_dump;
	dump_plugin.cb_cleanup = cleanup_dump;
	dump_plugin.cb_plugin_handler[PLUGIN_CB_BMX_DEV_EVENT] = init_cleanup_dev_traffic_data;

	return &dump_plugin;
}
