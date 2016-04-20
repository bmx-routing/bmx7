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


#define CODE_CATEGORY_NAME "topology"


AVL_TREE(local_topology_tree, struct local_topology_node, k);

int32_t my_topology_hysteresis = DEF_TOPOLOGY_HYSTERESIS;
int32_t my_topology_period = DEF_TOPOLOGY_PERIOD;

struct description_msg_topology *topology_msg;
uint32_t topology_msgs;


struct topology_status {
        GLOBAL_ID_T *id;
        char* name;
        IPX_T *primaryIp;
        IPX_T *llIp;
	DEVIDX_T idx;

        GLOBAL_ID_T *neighId;
	DESC_SQN_T neighDescSqnDiff;
        char* neighName;
        IPX_T *neighIp;
        IPX_T *neighLlIp;
	DEVIDX_T neighIdx;

	uint32_t lastDesc;

	uint8_t rq;
	uint8_t tq;
        UMETRIC_T rxRate;
        UMETRIC_T txRate;
};

static const struct field_format topology_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, topology_status, id,            1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      topology_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             topology_status, primaryIp,     1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             topology_status, llIp,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, idx,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, topology_status, neighId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, neighDescSqnDiff,1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      topology_status, neighName,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             topology_status, neighIp,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX6P,             topology_status, neighLlIp,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, neighIdx,      1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              topology_status, lastDesc,      1, FIELD_RELEVANCE_HIGH),
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
				status[i].llIp = (contents_dlen(on->dc, BMX_DSC_TLV_LLIP) >= ((topology_msg[m].idx * sizeof(struct dsc_msg_llip)))) ?
					&((((struct dsc_msg_llip*) contents_data(on->dc, BMX_DSC_TLV_LLIP))[topology_msg[m].idx]).ip6) : NULL;

				status[i].lastDesc = (bmx_time - on->updated_timestamp) / 1000;
				status[i].txRate = fmetric_u8_to_umetric(topology_msg[m].txBw);
				status[i].rxRate = fmetric_u8_to_umetric(topology_msg[m].rxBw);
				status[i].tq = ((((uint32_t) topology_msg[m].tq) * 100) / LQ_MAX);
				status[i].rq = ((((uint32_t) topology_msg[m].rq) * 100) / LQ_MAX);
				status[i].neighId = &non->k.nodeId;
				status[i].neighDescSqnDiff = non->dc->descSqn - ntohl(topology_msg[m].nbDescSqn);
				status[i].neighName = non->k.hostname;
				status[i].neighIp = &non->primary_ip;
				status[i].neighIdx = topology_msg[m].nbIdx;
				status[i].neighLlIp = (non->dc->descSqn == ntohl(topology_msg[m].nbDescSqn)) && (contents_dlen(non->dc, BMX_DSC_TLV_LLIP) >= ((topology_msg[m].nbIdx * sizeof(struct dsc_msg_llip)))) ?
					&((((struct dsc_msg_llip*) contents_data(non->dc, BMX_DSC_TLV_LLIP))[topology_msg[m].nbIdx]).ip6) : NULL;

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
UMETRIC_T tp_umetric_multiply_normalized(UMETRIC_T *a, UMETRIC_T *b)
{
	UMETRIC_T um;

        if (*b < UMETRIC_MULTIPLY_MAX)
                um = (*a * *b) / UMETRIC_MAX;
        else
                um = (*a * ((*b << UMETRIC_SHIFT_MAX) / UMETRIC_MAX)) >> UMETRIC_SHIFT_MAX;

	dbgf_track(DBGT_INFO, "a=%ju b=%ju ab=%ju magicAB=%ju", *a, *b, ((*a * *b) / UMETRIC_MAX), ((*a * ((*b << UMETRIC_SHIFT_MAX) / UMETRIC_MAX)) >> UMETRIC_SHIFT_MAX));

	return um;
}


STATIC_FUNC
int check_value_deviation(UMETRIC_T a, UMETRIC_T b, UMETRIC_T percent)
{
	if ((((a * (100+percent)) / 100) < b) || (((b * (100+percent)) / 100) < a))
		return YES;

	return NO;
}

STATIC_FUNC
void set_local_topology_node(struct local_topology_node *ltn, LinkNode *link)
{
	assertion(-502523, (ltn));
	assertion(-502524, (link));

	ltn->txBw = (link->k.myDev->umetric_max * ((UMETRIC_T)link->timeaware_tq_probe))/LQ_MAX;
	ltn->rxBw = (link->k.myDev->umetric_max * ((UMETRIC_T)link->timeaware_rq_probe))/LQ_MAX;
	ltn->tq = link->timeaware_tq_probe;
	ltn->rq = link->timeaware_rq_probe;
}

STATIC_FUNC
void check_local_topology_cache(void *nothing)
{
	assertion(-502532, (my_topology_period < MAX_TOPOLOGY_PERIOD));

	uint32_t m = 0;
	struct avl_node *link_it;
	LinkNode *link;

//	for (local_it = NULL; (local = avl_iterate_item(&local_tree, &local_it));) {
	for (link_it = NULL; (link = avl_iterate_item(&link_tree, &link_it));) {

		if (link->timeaware_tq_probe) {

			struct local_topology_key key = {.nbId = link->k.linkDev->key.local->local_id, .myIdx = link->k.myDev->llipKey.devIdx, .nbIdx = link->k.linkDev->key.devIdx};

			struct local_topology_node *ltn = avl_find_item(&local_topology_tree, &key);
			struct local_topology_node tmp;

			if (!ltn) {
				my_description_changed = YES;
				return;
			}

			set_local_topology_node(&tmp, link);

			if ( (bmx_time - myKey->on->updated_timestamp) > ((uint32_t)my_topology_period * 100) && (
				check_value_deviation(ltn->txBw, tmp.txBw, 0) ||
				check_value_deviation(ltn->rxBw, tmp.rxBw, 0) ||
				check_value_deviation(ltn->tq, tmp.tq, 0) ||
				check_value_deviation(ltn->rq, tmp.rq, 0) )
				) {

				my_description_changed = YES;
				return;

			} else if (
				check_value_deviation(ltn->txBw, tmp.txBw, my_topology_hysteresis) ||
				check_value_deviation(ltn->rxBw, tmp.rxBw, my_topology_hysteresis) ||
				check_value_deviation(ltn->tq, tmp.tq, my_topology_hysteresis) ||
				check_value_deviation(ltn->rq, tmp.rq, my_topology_hysteresis)
				) {
				my_description_changed = YES;
				return;
			}

			m++;
		}
        }

	if (local_topology_tree.items != m) {
		my_description_changed = YES;
		return;
	}

	task_register(my_topology_period, check_local_topology_cache, NULL, -300782);
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

	if (my_topology_period >= MAX_TOPOLOGY_PERIOD)
		return TLV_TX_DATA_IGNORED;

	task_remove(check_local_topology_cache, NULL);
	task_register(((bmx_time < ((TIME_T)my_topology_period/10)) ? (my_topology_period/10) : my_topology_hysteresis), check_local_topology_cache, NULL, -300785);

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

	static int32_t scheduled_period = MAX_TOPOLOGY_PERIOD;

        if (!terminating && cmd == OPT_POST && my_topology_period != scheduled_period) {

		task_remove(check_local_topology_cache, NULL);

		if (my_topology_period < MAX_TOPOLOGY_PERIOD)
			task_register(my_topology_period/10, check_local_topology_cache, NULL, -300788);

		scheduled_period = my_topology_period;
	}

	if (cmd == OPT_UNREGISTER && scheduled_period < MAX_TOPOLOGY_PERIOD) {
		task_remove(check_local_topology_cache, NULL);
		scheduled_period = MAX_TOPOLOGY_PERIOD;
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
	{ODI,0,ARG_TOPOLOGY_PERIOD,     0, 9,2, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_topology_period, MIN_TOPOLOGY_PERIOD, MAX_TOPOLOGY_PERIOD, DEF_TOPOLOGY_PERIOD,0, opt_topology,
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


