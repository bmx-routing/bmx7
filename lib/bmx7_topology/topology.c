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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/inotify.h>



#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "link.h"
#include "ogm.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "ip.h"
#include "allocate.h"
#include "topology.h"
#include "prof.h"


#define CODE_CATEGORY_NAME "topology"


AVL_TREE(local_topology_tree, struct local_topology_node, k);

int32_t my_topology_hysteresis = DEF_TOPOLOGY_HYSTERESIS;
int32_t my_topology_period_sec = DEF_TOPOLOGY_PERIOD;

struct description_msg_topology *topology_msg;
uint32_t topology_msgs;


struct topology_status {
        GLOBAL_ID_T *id;
        char* name;
        IPX_T *primaryIp;
	DEVIDX_T idx;

        GLOBAL_ID_T *neighId;
	DESC_SQN_T neighDescSqnDiff;
        char* neighName;
        IPX_T *neighIp;
	DEVIDX_T neighIdx;

	uint32_t lastDesc;
	int8_t signal;
	int8_t noise;
	int8_t snr;
	uint8_t channel;
	uint8_t rq;
	uint8_t tq;
        UMETRIC_T rxRate;
        UMETRIC_T txRate;
};

static const struct field_format topology_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, topology_status, id,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      topology_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             topology_status, primaryIp,     1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, idx,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, topology_status, neighId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, neighDescSqnDiff,1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      topology_status, neighName,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             topology_status, neighIp,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, neighIdx,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, lastDesc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_INT,               topology_status, signal,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_INT,               topology_status, noise,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_INT,               topology_status, snr,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, channel,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, rq,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, tq,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           topology_status, rxRate,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           topology_status, txRate,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};



static int32_t topology_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *it = NULL;
        struct orig_node *on;
        uint32_t stsize = 0;
        uint32_t i = 0;
        struct topology_status *status = NULL;

        while (data ? (on = data) : (on = avl_iterate_item(&orig_tree, &it))) {

		topology_msgs = 0;
		topology_msg = NULL;
		uint32_t m = 0;
		process_description_tlvs(NULL, on, NULL, on->dc, TLV_OP_CUSTOM_TOPOLOGY, BMX_DSC_TLV_TOPOLOGY);

		for (m=0; topology_msg && m < topology_msgs; m++) {

			struct orig_node *non;
			struct avl_node *nan = NULL;
			while ((non = avl_iterate_item(&orig_tree, &nan)) && memcmp(&non->k.nodeId, &topology_msg[m].nbId, sizeof(GLOBAL_ID_T)));

			if (non) {
				stsize += sizeof(struct topology_status);
				status = ((struct topology_status*) (handl->data = debugRealloc(handl->data, stsize, -300366)));

				memset(&status[i], 0, sizeof(struct topology_status));
				status[i].id = &on->k.nodeId;
				status[i].name = on->k.hostname;
				status[i].primaryIp = &on->primary_ip;
				status[i].idx = topology_msg[m].idx;

				status[i].lastDesc = (bmx_time - on->updated_timestamp) / 1000;
				status[i].txRate = fmetric_u8_to_umetric(topology_msg[m].txBw);
				status[i].rxRate = fmetric_u8_to_umetric(topology_msg[m].rxBw);
				status[i].tq = ((((uint32_t) topology_msg[m].tq) * 100) / LQ_MAX);
				status[i].rq = ((((uint32_t) topology_msg[m].rq) * 100) / LQ_MAX);
				status[i].signal = topology_msg[m].signal;
				status[i].noise = topology_msg[m].noise;
				status[i].snr = (topology_msg[m].signal - topology_msg[m].noise);
				status[i].channel = topology_msg[m].channel;
				status[i].neighId = &non->k.nodeId;
				status[i].neighDescSqnDiff = non->dc->descSqn - ntohl(topology_msg[m].nbDescSqn);
				status[i].neighName = non->k.hostname;
				status[i].neighIp = &non->primary_ip;
				status[i].neighIdx = topology_msg[m].nbIdx;

				i++;
			}
		}

                if(data)
                        break;

        }
        return stsize;
}



STATIC_FUNC
int process_description_topology(struct rx_frame_iterator *it)
{

	struct description_hdr_topology *hdr = (struct description_hdr_topology *)it->f_data;

	if (it->op == TLV_OP_CUSTOM_TOPOLOGY && 
		it->f_dlen > (int)sizeof(struct description_hdr_topology) &&
		hdr->type == 0 &&
		it->f_msgs_len && 
		(it->f_msgs_len % sizeof(struct description_msg_topology)) == 0) {

		topology_msgs = it->f_msgs_len / it->f_handl->min_msg_size;
		topology_msg = &hdr->msg[0];
	}

	return it->f_msgs_len;
}



STATIC_FUNC
int check_value_deviation(uint64_t a, uint64_t b, int32_t percent, int32_t absolute)
{
	if (percent >= 0 && ((((a * (100+percent)) / 100) < b) || (((b * (100+percent)) / 100) < a)))
		return YES;

	if (absolute >= 0 && ((XMAX(a,b) - XMIN(a,b)) > ((uint32_t)absolute)))
		return YES;

	return NO;
}

STATIC_FUNC
void set_local_topology_node(struct local_topology_node *ltn, LinkNode *link)
{
	assertion(-502523, (ltn));
	assertion(-502524, (link));

	ltn->txBw = link->wifiStats.txRateAvg ? link->wifiStats.txRateAvg : ((link->k.myDev->umetric_max * ((UMETRIC_T)link->timeaware_tq_probe))/LQ_MAX);
	ltn->rxBw = ((((UMETRIC_T)link->timeaware_rq_probe) * (link->wifiStats.rxRate ? link->wifiStats.rxRate : link->k.myDev->umetric_max)) / LQ_MAX);
//	ltn->rxBw = ((link->k.myDev->umetric_max * ((UMETRIC_T)link->timeaware_rq_probe))/LQ_MAX);
	ltn->tq = link->timeaware_tq_probe;
	ltn->rq = link->timeaware_rq_probe;
	ltn->signal = link->wifiStats.signal;
	ltn->noise = link->wifiStats.noise;
	ltn->channel = link->k.myDev->channel;
}

STATIC_FUNC
void check_local_topology_cache(void *nothing)
{
	prof_start(check_local_topology_cache, main);
	assertion(-502532, (my_topology_period_sec > MIN_TOPOLOGY_PERIOD));

	uint32_t m = 0;
	struct avl_node *an;
	LinkNode *link;
	static uint8_t sqn;

	sqn++;

//	for (local_it = NULL; (local = avl_iterate_item(&local_tree, &local_it));) {
	for (an = NULL; (link = avl_iterate_item(&link_tree, &an));) {

		if (link->timeaware_tq_probe) {

			struct local_topology_key key = {
				.nbId = link->k.linkDev->key.local->local_id,
				.myIdx = link->k.myDev->llipKey.devIdx,
				.nbIdx = link->k.linkDev->key.devIdx
			};

			struct local_topology_node *ltn = avl_find_item(&local_topology_tree, &key);
			struct local_topology_node tmp;

			set_local_topology_node(&tmp, link);

			if (!ltn && check_value_deviation(0, tmp.tq, -1, my_topology_hysteresis)) {

				my_description_changed = YES;
				goto finish;

			} else {

				if (
					check_value_deviation(ltn->txBw, tmp.txBw, my_topology_hysteresis, -1) ||
					check_value_deviation(ltn->rxBw, tmp.rxBw, my_topology_hysteresis, -1) ||
					check_value_deviation(ltn->tq, tmp.tq, -1, my_topology_hysteresis) ||
					check_value_deviation(ltn->rq, tmp.rq, -1, my_topology_hysteresis) ||
					check_value_deviation(ltn->signal - ltn->noise, tmp.signal - tmp.noise, my_topology_hysteresis, -1) ||
					check_value_deviation(ltn->channel, tmp.channel, -1, 0)
					) {
					my_description_changed = YES;
					goto finish;;
				}

				ltn->sqn = sqn;
				m++;
			}
		}
        }

	if (local_topology_tree.items != m) {
		struct local_topology_node *ltn;
		for (an = NULL; (ltn = avl_iterate_item(&local_topology_tree, &an));) {
			if (ltn->sqn != sqn && check_value_deviation(ltn->tq, 0, -1, my_topology_hysteresis)) {

				my_description_changed = YES;
				goto finish;
			}
		}
	}

	task_register((my_topology_period_sec*1000), check_local_topology_cache, NULL, -300782);

finish:
	prof_stop();

}

STATIC_FUNC
void destroy_local_topology_cache(void)
{

	struct local_topology_node *ltn;

	while ((ltn = avl_remove_first_item(&local_topology_tree, -300783)))
		debugFree(ltn, -300784);

}

STATIC_FUNC
int create_description_topology(struct tx_frame_iterator *it)
{
        struct avl_node *link_it = NULL;
        LinkNode *link;
        int32_t m = 0;

	struct description_hdr_topology *hdr = (struct description_hdr_topology *) tx_iterator_cache_hdr_ptr(it);
	struct description_msg_topology *msg = (struct description_msg_topology *) tx_iterator_cache_msg_ptr(it);

	destroy_local_topology_cache();

	if (my_topology_period_sec <= MIN_TOPOLOGY_PERIOD)
		return TLV_TX_DATA_IGNORED;

	task_remove(check_local_topology_cache, NULL);
	task_register(rand_num((my_topology_period_sec * 1000) / 10) +
		((bmx_time < ((TIME_T) (my_topology_period_sec * 1000) / 10)) ? ((TIME_T)(((my_topology_period_sec * 1000) / 10) - bmx_time)) : ((TIME_T)(my_topology_period_sec * 1000))),
		check_local_topology_cache, NULL, -300785);

	hdr->reserved = 0;
	hdr->type = 0;

	while ((link = avl_iterate_item(&link_tree, &link_it)) && tx_iterator_cache_data_space_pref(it, ((m + 1) * sizeof(struct description_msg_topology)), 0)) {

		if (link->tq_probe) {

			struct local_topology_node *ltn = debugMallocReset(sizeof(struct local_topology_node), -300786);

			set_local_topology_node(ltn, link);
			ltn->k.nbId = link->k.linkDev->key.local->local_id;
			ltn->k.myIdx = link->k.myDev->llipKey.devIdx;
			ltn->k.nbIdx = link->k.linkDev->key.devIdx;
			avl_insert(&local_topology_tree, ltn, -300787);

			msg[m].nbId = ltn->k.nbId;
			msg[m].nbDescSqn = htonl(link->k.linkDev->key.local->on->dc->descSqn);
			msg[m].nbIdx = ltn->k.nbIdx;
			msg[m].idx = ltn->k.myIdx;
			msg[m].txBw = umetric_to_fmu8( &ltn->txBw);
			msg[m].rxBw = umetric_to_fmu8(&ltn->rxBw);
			msg[m].tq = ltn->tq;
			msg[m].rq = ltn->rq;
			msg[m].signal = ltn->signal;
			msg[m].noise = ltn->noise;
			msg[m].channel = ltn->channel;

			m++;
		}
        }

	if (m)
		return m * sizeof(struct description_msg_topology);

        return TLV_TX_DATA_IGNORED;
}

STATIC_FUNC
int32_t opt_topology(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	static int32_t scheduled_period = MIN_TOPOLOGY_PERIOD;

        if (!terminating && cmd == OPT_POST && my_topology_period_sec != scheduled_period) {

		task_remove(check_local_topology_cache, NULL);

		if (my_topology_period_sec > MIN_TOPOLOGY_PERIOD)
			task_register(0, check_local_topology_cache, NULL, -300788);

		scheduled_period = my_topology_period_sec;
	}

	if (cmd == OPT_UNREGISTER && scheduled_period > MIN_TOPOLOGY_PERIOD) {
		task_remove(check_local_topology_cache, NULL);
		scheduled_period = MIN_TOPOLOGY_PERIOD;
	}

	return SUCCESS;
}

static struct opt_type topology_options[]=
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	{ODI,0,ARG_TOPOLOGY,	        0, 9,2,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show topology\n"}
	,
	{ODI,0,ARG_TOPOLOGY_HYSTERESIS, 0, 9,2, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_topology_hysteresis, MIN_TOPOLOGY_HYSTERESIS, MAX_TOPOLOGY_HYSTERESIS, DEF_TOPOLOGY_HYSTERESIS,0, NULL,
			ARG_VALUE_FORM,	"set hysteresis for creating topology (description) updates due to changed local topology statistics"}
	,
	{ODI,0,ARG_TOPOLOGY_PERIOD,     0, 9,2, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_topology_period_sec, MIN_TOPOLOGY_PERIOD, MAX_TOPOLOGY_PERIOD, DEF_TOPOLOGY_PERIOD,0, opt_topology,
			ARG_VALUE_FORM,	"set min periodicity for creating topology (description) updates due to changed local topology statistics"}
};


static void topology_cleanup( void )
{

	destroy_local_topology_cache();
}



static int32_t topology_init( void ) {

        static const struct field_format topology_format[] = DESCRIPTION_MSG_TOPOLOGY_FORMAT;
        struct frame_handl tlv_handl;

        memset( &tlv_handl, 0, sizeof(tlv_handl));
	tlv_handl.data_header_size = sizeof (struct description_hdr_topology);
        tlv_handl.min_msg_size = sizeof (struct description_msg_topology);
        tlv_handl.fixed_msg_size = 0;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;
        tlv_handl.name = "TOPOLOGY_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_topology;
        tlv_handl.rx_frame_handler = process_description_topology;
        tlv_handl.msg_format = topology_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_TOPOLOGY, &tlv_handl);
	register_status_handl(sizeof (struct topology_status), 1, topology_status_format, ARG_TOPOLOGY, topology_status_creator);
        register_options_array(topology_options, sizeof ( topology_options), CODE_CATEGORY_NAME);

	return SUCCESS;
}


struct plugin* get_plugin( void ) {
	
	static struct plugin topology_plugin;
	
	memset( &topology_plugin, 0, sizeof ( struct plugin ) );

	topology_plugin.plugin_name = CODE_CATEGORY_NAME;
	topology_plugin.plugin_size = sizeof ( struct plugin );
	topology_plugin.cb_init = topology_init;
	topology_plugin.cb_cleanup = topology_cleanup;

	return &topology_plugin;
}


