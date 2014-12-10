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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "sec.h"
#include "metrics.h"
#include "msg.h"
#include "z.h"
#include "ip.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"
#include "prof.h"

#define CODE_CATEGORY_NAME "message"

static int32_t drop_all_frames = DEF_DROP_ALL_FRAMES;
static int32_t drop_all_packets = DEF_DROP_ALL_PACKETS;

static int32_t pref_udpd_size = DEF_UDPD_SIZE;
static int32_t desc_size_out = DEF_DESC_SIZE;
static int32_t vrt_frame_data_size_out = DEF_VRT_FRAME_DATA_SIZE;
static int32_t vrt_frame_data_size_in =  DEF_VRT_FRAME_DATA_SIZE;
static int32_t vrt_desc_size_out =       DEF_VRT_DESC_SIZE;
static int32_t vrt_desc_size_in =        DEF_VRT_DESC_SIZE;

static int32_t ogmSqnRange = DEF_OGM_SQN_RANGE;

static int32_t ogm_adv_tx_iters = DEF_OGM_TX_ITERS;
static int32_t ogm_ack_tx_iters = DEF_OGM_ACK_TX_ITERS;

static int32_t desc_req_tx_iters = DEF_DESC_REQ_TX_ITERS;
static int32_t desc_adv_tx_iters = DEF_DESC_ADV_TX_ITERS;

int32_t desc_adv_tx_unsolicited = DEF_DESC_ADV_UNSOLICITED;

static int32_t dref_adv_tx_unsolicited = DEF_DREF_ADV_UNSOLICITED;

static int32_t dhash_req_tx_iters = DEF_DHASH_REQ_TX_ITERS;
static int32_t dhash_adv_tx_iters = DEF_DHASH_ADV_TX_ITERS;
int32_t dhash_adv_tx_unsolicited = DEF_DHASH_ADV_UNSOLICITED;


static int32_t dev_req_tx_iters = DEF_DEV_REQS_TX_ITERS;
static int32_t dev_adv_tx_iters = DEF_DEV_ADVS_TX_ITERS;
static int32_t dev_adv_tx_unsolicited = DEF_DEV_ADV_UNSOLICITED;

static int32_t link_req_tx_iters = DEF_LINK_REQS_TX_ITERS;
static int32_t link_adv_tx_iters = DEF_LINK_ADVS_TX_ITERS;
static int32_t link_adv_tx_unsolicited = DEF_LINK_ADV_UNSOLICITED;

static int32_t dextReferencing = DEF_FREF;
static int32_t dextCompression = DEF_FZIP;

int32_t processDescriptionsViaUnverifiedLink = 1;

union schedule_hello_info {
        uint8_t u8[2];
        uint16_t u16;
};


static AVL_TREE( description_cache_tree, struct description_cache_node, dhash );

AVL_TREE(ref_tree, struct ref_node, rhash);
int32_t ref_tree_items_used = 0;

const int32_t always_fref = TYP_FREF_DO;
const int32_t never_fref = TYP_FREF_DONT;
const int32_t dflt_fref = TYP_FREF_DFLT;

const int32_t never_fzip = TYP_FZIP_DONT;
const int32_t dflt_fzip = TYP_FZIP_DFLT;


int32_t ref_nodes_max_unused = 200;
int32_t ref_nodes_purge_to = 60000;

//int my_desc0_tlv_len = 0;

IID_T myIID4me = IID_RSVD_UNUSED;
TIME_T myIID4me_timestamp = 0;


static PKT_SQN_T my_packet_sqn = 0;
static IDM_T first_packet = YES;

static struct msg_dev_adv *my_dev_adv_buff = NULL;
static DEVADV_SQN_T my_dev_adv_sqn = 0;
static uint16_t my_dev_adv_msgs_size = 0;

static int32_t msg_dev_req_enabled = NO;


static struct msg_link_adv *my_link_adv_buff = NULL;
static LINKADV_SQN_T my_link_adv_sqn = 0;
//static int32_t my_link_adv_msgs_size = 0;
static int32_t my_link_adv_msgs = 0;




static LIST_SIMPEL( ogm_aggreg_list, struct ogm_aggreg_node, list, sqn );
uint32_t ogm_aggreg_pending = 0;
static AGGREG_SQN_T ogm_aggreg_sqn_max;

//static struct dhash_node* DHASH_NODE_FAILURE = (struct dhash_node*) & DHASH_NODE_FAILURE;

STATIC_FUNC
struct desc_extension * dext_resolve(struct packet_buff *pb, struct description_cache_node *desc, struct desc_extension *dext);

STATIC_FUNC
int32_t resolve_ref_frame(struct packet_buff *pb, uint8_t *data, uint32_t dlen, struct desc_extension *dext, uint8_t rf_type, uint8_t compression, uint8_t nest_level );

STATIC_FUNC
int32_t tx_frame_iterate_finish(struct tx_frame_iterator *it);


const void* REJECTED_PTR = (void*) & REJECTED_PTR;
const void* UNRESOLVED_PTR = (void*) & UNRESOLVED_PTR;
const void* FAILURE_PTR = (void*) & FAILURE_PTR;


/***********************************************************
  The core frame/message structures and handlers
 ************************************************************/

char *tlv_rx_result_str(int32_t r)
{
        switch (r) {
        case TLV_RX_DATA_FAILURE:
                return "TLV_FAILURE";
        case TLV_RX_DATA_REJECTED:
                return "TLV_REJECTED";
        case TLV_RX_DATA_REBOOTED:
                return "TLV_REBOOTED";
        case TLV_RX_DATA_DONE:
                return "TLV_DONE";
        case TLV_RX_DATA_BLOCKED:
                return "TLV_BLOCKED";
        case TLV_RX_DATA_PROCESSED:
                return "TLV_PROCESSED";
        }

	if (r > TLV_RX_DATA_PROCESSED)
		return "TLV_PROCESSED++";

        return "TLV_ILLEGAL";
}

char *tlv_tx_result_str(int32_t r)
{
        switch (r) {
        case TLV_TX_DATA_FAILURE:
                return "TLV_FAILURE";
        case TLV_TX_DATA_FULL:
                return "TLV_FULL";
        case TLV_TX_DATA_DONE:
                return "TLV_DONE";
        case TLV_TX_DATA_IGNORED:
                return "TLV_IGNORED";
        case TLV_TX_DATA_PROCESSED:
                return "TLV_PROCESSED";
        }

	if (r > TLV_TX_DATA_PROCESSED)
		return "TLV_PROCESSED++";

        return "TLV_ILLEGAL";
}

char *tlv_op_str(uint8_t op)
{
        switch (op) {
        case TLV_OP_DEL:
                return "TLV_OP_DEL";
        case TLV_OP_TEST:
                return "TLV_OP_TEST";
        case TLV_OP_NEW:
                return "TLV_OP_NEW";
        case TLV_OP_DEBUG:
                return "TLV_OP_DEBUG";
        default:
                if (op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX)
                        return "TLV_OP_CUSTOM";

                if (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX)
                        return "TLV_OP_PLUGIN";

                return "TLV_OP_ILLEGAL";
        }

        return "TLV_OP_ERROR";
}

struct frame_db *packet_frame_db = NULL;
struct frame_db *packet_desc_db = NULL;
struct frame_db *description_tlv_db = NULL;
struct frame_db *description_names_db = NULL;




struct tlv_hdr tlvSetBigEndian(int16_t type, int16_t length)
{
	assertion(-502044, (type >= 0 && type <= FRAME_TYPE_MASK));
	assertion(-502045, (length > 0 && length < (int)(MAX_UDPD_SIZE - sizeof(struct packet_header))));

	struct tlv_hdr tlv = {.u.tlv = {.type = type, .length = length } };
	tlv.u.u16 = htons(tlv.u.u16);
	
//	dbgf_sys(DBGT_INFO, "type=%d=0x%X length=%d=0x%X tlv=%s u16=0x%X",
//	type, type, length, length, memAsHexString(&tlv, sizeof(tlv)), ntohs(tlv.u.u16));
	
	return tlv;
}


STATIC_FUNC
struct frame_db *init_frame_db(uint8_t handlSz, uint8_t processUnVerifiedLinks, char *name) {

	struct frame_db *db = debugMallocReset(sizeof(struct frame_db) + (handlSz * sizeof(struct frame_handl)), -300622);

	db->handl_max = handlSz -1;
	db->rx_processUnVerifiedLink = processUnVerifiedLinks;
	db->name = name;

	return db;
}

STATIC_FUNC
void free_frame_db(struct frame_db **db) {
	debugFree(*db, -300623);
	db = NULL;
}

void register_frame_handler(struct frame_db *db, int pos, struct frame_handl *handl)
{
        TRACE_FUNCTION_CALL;
        
        assertion(-500659, (pos <= db->handl_max));
        assertion(-500660, (!db->handls[pos].name)); // the pos MUST NOT be used yet
        assertion(-500661, (handl && handl->name));
        assertion(-500806, (XOR(handl->rx_frame_handler, handl->rx_msg_handler) && XOR(handl->tx_frame_handler, handl->tx_msg_handler)));
	assertion(-502046, IMPLIES(handl->rx_msg_handler, handl->fixed_msg_size));
        assertion(-500975, (handl->tx_task_interval_min <= CONTENT_MIN_TX_INTERVAL_MAX));

        assertion(-501213, IMPLIES(handl->msg_format && handl->min_msg_size, handl->min_msg_size ==
                fields_dbg_lines(NULL, FIELD_RELEVANCE_LOW, 0, NULL, handl->min_msg_size, handl->msg_format)));
/*
	assertion(-501611, IMPLIES(array==description_tlv_handl && pos!=BMX_DSC_TLV_RHASH_ADV, !handl->data_header_size));
	// this is mandatory to let
	assertion(-501612, TEST_VALUE(BMX_DSC_TLV_RHASH_ADV));
	// messages to point and allow unambiguous concatenation of
	assertion(-501613, TEST_VALUE(FRAME_TYPE_REF_ADV));
	// into
	assertion(-501614, TEST_STRUCT(struct tlv_hdr_virtual));
	// and
	assertion(-501615, TEST_STRUCT(struct desc_extension));
	// without potentially conflicting message headers (frame data headers)
*/

        db->handls[pos] = *handl;

        memset(handl, 0, sizeof ( struct frame_handl ) );
}



STATIC_FUNC
void del_cached_description(DHASH_T *dhash)
{
        TRACE_FUNCTION_CALL;

        struct description_cache_node *dcn;

        if ((dcn = avl_find_item(&description_cache_tree, dhash))) {
		avl_remove(&description_cache_tree, &dcn->dhash, -300206);
		debugFree(dcn, -300108);
	}
}


struct description_cache_node *purge_cached_descriptions(DHASH_T *onlyDhash, GLOBAL_ID_T *onlyGlobalId, IDM_T onlyExpired)
{
        TRACE_FUNCTION_CALL;
        struct description_cache_node *dcn;
        struct description_cache_node *dcn_min = NULL;
        DHASH_T tmp_dhash;
        memset( &tmp_dhash, 0, sizeof(DHASH_T));

        dbgf_all( DBGT_INFO, "%s", onlyExpired ? "purge_all" : "only_expired");

	while ((dcn = onlyDhash ?
		avl_find_item(&description_cache_tree, onlyDhash) :
		avl_next_item(&description_cache_tree, &tmp_dhash))) {

		tmp_dhash = dcn->dhash;

		if (onlyGlobalId && !cryptShasEqual(onlyGlobalId, nodeIdFromDescAdv(dcn->desc_frame)))
			continue;

                if (!onlyExpired || ((TIME_T) (bmx_time - dcn->timestamp)) > DEF_DESC0_CACHE_TO) {

                        avl_remove(&description_cache_tree, &dcn->dhash, -300208);
                        debugFree(dcn->desc_frame, -300100);
                        debugFree(dcn, -300101);

                } else {

                        if (!dcn_min || U32_LT(dcn->timestamp, dcn_min->timestamp))
                                dcn_min = dcn;
                }

		if (onlyDhash)
			break;
        }

        return dcn_min;
}

STATIC_FUNC
void cache_description(uint8_t *desc, uint16_t desc_len, DHASH_T *dhash)
{
        TRACE_FUNCTION_CALL;
        struct description_cache_node *dcn;

	IDM_T TODO_only_chache_if_signature_and_sqn_match;

        if ((dcn = avl_find_item(&description_cache_tree, dhash))) {
                dcn->timestamp = bmx_time;
                return;
        }

        dbgf_all( DBGT_INFO, "%8X..", dhash->h.u32[0]);

        assertion(-500261, (description_cache_tree.items <= DEF_DESC0_CACHE_SIZE));

        if ( description_cache_tree.items == DEF_DESC0_CACHE_SIZE ) {


                struct description_cache_node *dcn_min = purge_cached_descriptions( NULL, NULL, YES );

                dbgf_sys(DBGT_WARN, "desc0_cache_tree reached %d items! cleaned up %d items!",
                        DEF_DESC0_CACHE_SIZE, DEF_DESC0_CACHE_SIZE - description_cache_tree.items);

                if (description_cache_tree.items == DEF_DESC0_CACHE_SIZE) {
                        avl_remove(&description_cache_tree, &dcn_min->dhash, -300209);
                        debugFree(dcn_min->desc_frame, -300102);
                        debugFree(dcn_min, -300103);
                }
        }

        dcn = debugMalloc(sizeof ( struct description_cache_node), -300104);
        dcn->desc_frame = debugMalloc(desc_len, -300105);
	dcn->desc_frame_len = desc_len;
        memcpy(dcn->desc_frame, desc, desc_len);
        dcn->dhash = *dhash;
        dcn->timestamp = bmx_time;
        avl_insert(&description_cache_tree, dcn, -300145);
}


IDM_T process_description_tlvs(struct packet_buff *pb, struct orig_node *onOld, struct dhash_node *dhnNew, uint8_t op, uint8_t filter)
{
        TRACE_FUNCTION_CALL;
        assertion(-500370, (op == TLV_OP_DEL || op == TLV_OP_TEST || op == TLV_OP_NEW || op == TLV_OP_DEBUG ||
                (op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX)));

        assertion(-500590, IMPLIES(onOld == self, (op == TLV_OP_DEBUG || op == TLV_OP_TEST ||
                (op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX))));

        assertion(-500807, (dhnNew && dhnNew->desc_frame && dhnNew->dext));
	assertion(-502047, IMPLIES(op == TLV_OP_DEL || op == TLV_OP_NEW,onOld));
        assertion(-501354, IMPLIES(op == TLV_OP_DEL, onOld->added));

        int32_t result;
	int8_t blocked = NO;
	struct frame_db *db = description_tlv_db;

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .op = op, .pb = pb, .db = db, .process_filter = filter,
		.onOld = onOld, .dhnNew = dhnNew,
		.frame_type = -1, .frames_length = dhnNew->dext->dlen, .frames_in = dhnNew->dext->data 
	};

	if (filter <= db->handl_max) {
		if (dext_dptr(dhnNew->dext, filter)) {
			it.frame_type    = filter-1;
			it.frames_length = dhnNew->dext->dtd[filter].len + sizeof(struct tlv_hdr_virtual);
			it.frames_in     = ((uint8_t*)dext_dptr(dhnNew->dext, filter)) - sizeof(struct tlv_hdr_virtual);
		} else {
			return TLV_RX_DATA_DONE;
		}
	}

        dbgf_track(DBGT_INFO, "op=%s nodeId=%s size=%d, filter=%d",
                tlv_op_str(op), nodeIdAsStringFromDescAdv(dhnNew->desc_frame), dhnNew->dext->dlen, filter);


        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {
		
		if (result == TLV_RX_DATA_BLOCKED)
			blocked = YES;
	}

	assertion( -502048, (result==TLV_RX_DATA_DONE || result==TLV_RX_DATA_REBOOTED || result==TLV_RX_DATA_REJECTED || result==TLV_RX_DATA_FAILURE));

        if ((op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX))
                return result;

        if (result==TLV_RX_DATA_REBOOTED || result==TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_FAILURE || blocked) {

                assertion(-501355, (op == TLV_OP_TEST));

                dbgf_sys(DBGT_WARN, "problematic description_ltv from %s, near type=%d=%s frame_data_length=%d  pos=%d %s %s",
                        pb ? pb->i.llip_str : DBG_NIL,
			it.frame_type, (((uint8_t)it.frame_type) <= db->handl_max) ? db->handls[it.frame_type].name : "",
                        it.frame_data_length, it.frames_pos, blocked ? "BLOCKED" : "", tlv_rx_result_str(result));

		if (result==TLV_RX_DATA_REBOOTED || result==TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_FAILURE)
			return result;
		else
			return TLV_RX_DATA_BLOCKED;
        }

	if (filter == FRAME_TYPE_PROCESS_ALL && (op == TLV_OP_NEW || op == TLV_OP_DEL)) {

		if (filter == FRAME_TYPE_PROCESS_ALL && op == TLV_OP_NEW)
			onOld->added = YES;
		else if (filter == FRAME_TYPE_PROCESS_ALL && op == TLV_OP_DEL)
			onOld->added = NO;
	}

        return TLV_RX_DATA_DONE;
}



int purge_tx_task_list(struct list_head *tx_task_lists, LinkDevNode *onlyLinkDev, struct dev_node *only_dev)
{
        TRACE_FUNCTION_CALL;
        int i, removed=0;
        assertion(-500845, (tx_task_lists));

        for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {

                struct list_node *lpos, *tpos, *lprev = (struct list_node*) & tx_task_lists[i];

                list_for_each_safe(lpos, tpos, &tx_task_lists[i])
                {
                        struct tx_task_node * tx_task = list_entry(lpos, struct tx_task_node, list);

//			assertion(-502151, IMPLIES(only_dev, only_dev == tx_task->task.dev));
//			assertion(-502152, (only_dev = tx_task->task.dev));

                        if ((!onlyLinkDev || onlyLinkDev == tx_task->task.linkDev) &&
                                (!only_dev || only_dev == tx_task->task.dev)) {

                                if (packet_frame_db->handls[tx_task->task.type].tx_task_interval_min) {
                                        avl_remove(&tx_task->task.dev->tx_task_interval_tree, &tx_task->task, -300313);
                                }

                                list_del_next(&tx_task_lists[i], lprev);

                                dbgf_all(DBGT_INFO, "removed frame_type=%d ln=%s dev=%s tx_tasks_list.items=%d",
                                        tx_task->task.type,
                                        ip6AsStr(tx_task->task.linkDev ? &tx_task->task.linkDev->link_ip : &ZERO_IP),
                                        tx_task->task.dev->label_cfg.str, tx_task_lists[tx_task->task.type].items);

                                debugFree(tx_task, -300066);
				removed++;
                                continue;
                        }

                        lprev = lpos;
                }
        }
	return removed;
}


STATIC_FUNC
IDM_T freed_tx_task_node(struct tx_task_node *tx_task, struct list_head *tx_task_list, struct list_node *lprev)
{
        TRACE_FUNCTION_CALL;
        assertion(-500372, (tx_task && tx_task->task.dev));
        assertion(-500539, lprev);

        if (tx_task->tx_iterations <= 0) {

                if (packet_frame_db->handls[tx_task->task.type].tx_task_interval_min) {
                        avl_remove(&tx_task->task.dev->tx_task_interval_tree, &tx_task->task, -300314);
                }

                list_del_next(tx_task_list, lprev);

                debugFree(tx_task, -300169);

                return YES;
        }

        return NO;
}


STATIC_FUNC
IDM_T tx_task_obsolete(struct tx_task_node *tx_task)
{
        TRACE_FUNCTION_CALL;
        struct dhash_node *dhn = NULL;
        char *reason = NULL;
        IDM_T problem;

	if (packet_frame_db->handls[tx_task->task.type].tx_task_interval_min &&
                ((TIME_T) (bmx_time - tx_task->send_ts) < packet_frame_db->handls[tx_task->task.type].tx_task_interval_min)) {

                reason = "RECENTLY SEND";
                problem = TLV_TX_DATA_IGNORED;

        } else {

//                tx_task->send_ts = bmx_time;

//		self->dhn->referred_by_me_timestamp = bmx_time;

                if (dhn)
                        dhn->referred_by_me_timestamp = bmx_time;

                return TLV_TX_DATA_PROCESSED;
        }


        dbgf_track(DBGT_INFO,
                "%s type=%s dev=%s local_id=%s dev_idx=0x%X name=%s or send just %d ms ago",
                reason,
                packet_frame_db->handls[tx_task->task.type].name, tx_task->task.dev->name_phy_cfg.str,
                tx_task->task.linkDev ? cryptShaAsString(&tx_task->task.linkDev->key.local_id) : 0,
                tx_task->task.linkDev ? tx_task->task.linkDev->key.dev_idx : 0,
                (dhn && dhn->on) ? cryptShaAsString(&dhn->on->nodeId) : "???", (bmx_time - tx_task->send_ts));


        return problem;
}



STATIC_FUNC
struct tx_task_node *tx_task_new(LinkNode *destLink, struct tx_task_node *test)
{
        assertion(-500909, (destLink));
	assertion(-502153, (destLink->k.myDev == test->task.dev));

        struct frame_handl *handl = &packet_frame_db->handls[test->task.type];
        struct tx_task_node *ttn = NULL;

        if (handl->tx_task_interval_min) {

                if ((ttn = avl_find_item(&test->task.dev->tx_task_interval_tree, &test->task))) {

                        ttn->frame_msgs_length = test->frame_msgs_length;
                        ttn->tx_iterations = XMAX(ttn->tx_iterations, test->tx_iterations);

                        // then it is already scheduled
                        return ttn;
                }
        }

        ttn = debugMalloc(sizeof ( struct tx_task_node), -300026);
        memcpy(ttn, test, sizeof ( struct tx_task_node));
        ttn->send_ts = ((TIME_T) (bmx_time - handl->tx_task_interval_min));


        if (handl->tx_task_interval_min) {

                avl_insert(&ttn->task.dev->tx_task_interval_tree, ttn, -300315);

                if (ttn->task.dev->tx_task_interval_tree.items > DEF_TX_TS_TREE_SIZE) {
                        dbg_mute(20, DBGL_SYS, DBGT_WARN,
                                "%s tx_ts_tree reached %d %s data=%s",
                                ttn->task.dev->name_phy_cfg.str, ttn->task.dev->tx_task_interval_tree.items,
				handl->name, memAsHexString(ttn->task.data, TX_TASK_MAX_DATA_LEN));
                }
        }


        if (destLink->k.linkDev) {
                // this is NOT a dummy dest_lndev!!!:

                list_add_tail(&(destLink->tx_task_lists[ttn->task.type]), &ttn->list);

                dbgf_track(DBGT_INFO, "added %s to lndev local_id=%s link_ip=%s dev=%s tx_tasks_list.items=%d",
                        handl->name, cryptShaAsString(&destLink->k.linkDev->key.local_id),
                        ip6AsStr(&destLink->k.linkDev->link_ip),
                        destLink->k.myDev->label_cfg.str, destLink->tx_task_lists[ttn->task.type].items);

        } else {

                list_add_tail(&(ttn->task.dev->tx_task_lists[ttn->task.type]), &ttn->list);
        }

        return ttn;
}

void schedule_tx_task(LinkNode *destLink, uint16_t frame_type, int16_t frame_msgs_len, void *data, uint32_t dlen)
{
        TRACE_FUNCTION_CALL;
        struct frame_handl *handl = &packet_frame_db->handls[frame_type];

        if (!destLink)
                return;

        if (destLink->k.myDev->linklayer == TYP_DEV_LL_LO)
                return;

        assertion(-501047, (!cleaning_up)); // this function MUST NOT be called during cleanup
        assertion(-500756, (destLink && destLink->k.myDev));
//        ASSERTION(-500713, (initializing || iid_get_node_by_myIID4x(myIID4me)));
        assertion(-501090, (frame_msgs_len >= SCHEDULE_MIN_MSG_SIZE));
        assertion(-501091, (destLink->k.myDev->active));
        assertion(-501092, (destLink->k.myDev->linklayer != TYP_DEV_LL_LO));
	assertion(-501573, (dlen <= TX_TASK_MAX_DATA_LEN));

        // ensure, if is a real destLink (NOT a dummy) then exists in link_tree:
	ASSERTION(-500976, (IMPLIES(destLink->k.linkDev, (destLink == avl_find_item(&link_tree, &destLink->k)))));

        if (handl->tx_iterations && !(*handl->tx_iterations))
                return;


        dbgf((( /* debug interesting frame types: */
                frame_type == FRAME_TYPE_DHASH_REQ || frame_type == FRAME_TYPE_DHASH_ADV ||
                frame_type == FRAME_TYPE_DESC_REQ ||frame_type == FRAME_TYPE_DESC_ADVS ||
                frame_type == FRAME_TYPE_LINK_REQ || frame_type == FRAME_TYPE_LINK_ADV ||
                frame_type == FRAME_TYPE_DEV_REQ || frame_type == FRAME_TYPE_DEV_ADV)
                ? DBGL_CHANGES : DBGL_ALL), DBGT_INFO,
                 "%s to NB=%s local_id=%s via dev=%s frame_msgs_len=%d data=%s",
                handl->name,
                destLink->k.linkDev ? ip6AsStr(&destLink->k.linkDev->link_ip) : DBG_NIL,
                destLink->k.linkDev ? cryptShaAsString(&destLink->k.linkDev->local->local_id) : 0,
                destLink->k.myDev->label_cfg.str, frame_msgs_len, memAsHexString(data, dlen));

        if (handl->tx_tp_min && *(handl->tx_tp_min) > destLink->timeaware_tx_probe) {

                dbgf_track(DBGT_INFO, "NOT sending %s (via dev=%s data=%s) tp=%ju < %ju",
                        handl->name, destLink->k.myDev->label_cfg.str, memAsHexString(data, dlen),
                        destLink->timeaware_tx_probe, *(handl->tx_tp_min));
                return;
        }

        if (handl->tx_rp_min && *(handl->tx_rp_min) > destLink->timeaware_rx_probe) {

                dbgf_track(DBGT_INFO, "NOT sending %s (via dev=%s data=%s) rp=%ju < %ju",
                        handl->name, destLink->k.myDev->label_cfg.str, memAsHexString(data, dlen),
                        destLink->timeaware_rx_probe, *(handl->tx_rp_min));
                return;
        }

        struct tx_task_node test_task;
        memset(&test_task, 0, sizeof (test_task));
	if( data && dlen)
		memcpy(test_task.task.data, data, dlen);
        test_task.task.dev = destLink->k.myDev;
	test_task.task.linkDev = destLink->k.linkDev;
        test_task.task.type = frame_type;
        test_task.tx_iterations = handl->tx_iterations ? *handl->tx_iterations : 1;
        test_task.considered_ts = bmx_time - 1;
        test_task.frame_msgs_length = frame_msgs_len == SCHEDULE_MIN_MSG_SIZE ? handl->min_msg_size : frame_msgs_len;


        assertion(-500371, IMPLIES(handl->fixed_msg_size && handl->min_msg_size, !(test_task.frame_msgs_length % handl->min_msg_size)));
        assertion(-500371, IMPLIES(handl->fixed_msg_size && !handl->min_msg_size, !test_task.frame_msgs_length));

        tx_task_new(destLink, &test_task);
}





OGM_SQN_T set_ogmSqn_toBeSend_and_aggregated(struct orig_node *on, UMETRIC_T um, OGM_SQN_T to_be_send, OGM_SQN_T aggregated)
{
        TRACE_FUNCTION_CALL;

        to_be_send &= OGM_SQN_MASK;
        aggregated &= OGM_SQN_MASK;

        if (UXX_GT(OGM_SQN_MASK, to_be_send, aggregated)) {

                if (UXX_LE(OGM_SQN_MASK, on->ogmSqn_next, on->ogmSqn_send))
                        ogm_aggreg_pending++;

        } else {

                assertion(-500830, (UXX_LE(OGM_SQN_MASK, to_be_send, aggregated)));

                if (UXX_GT(OGM_SQN_MASK, on->ogmSqn_next, on->ogmSqn_send))
                        ogm_aggreg_pending--;
        }

        on->ogmMetric_next = um;
        on->ogmSqn_next = to_be_send;
        on->ogmSqn_send = aggregated;

        return on->ogmSqn_next;
}


STATIC_FUNC
IID_T create_ogm(struct orig_node *on, IID_T prev_ogm_iid, struct msg_ogm_adv *ogm)
{
        TRACE_FUNCTION_CALL;
        assertion(-501064, (on->ogmMetric_next <= UMETRIC_MAX));
        assertion(-501066, (on->ogmMetric_next > UMETRIC_INVALID));
        assertion_dbg(-501063, ((((OGM_SQN_MASK) & (on->ogmSqn_next - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize)),
                "orig=%s next=%d min=%d size=%d", on==self ? "self" : cryptShaAsString(&on->nodeId),
                on->ogmSqn_next, on->ogmSqn_rangeMin, on->ogmSqn_rangeSize);

        FMETRIC_U16_T fm = umetric_to_fmetric(on->ogmMetric_next);

        if (UXX_GT(OGM_SQN_MASK, on->ogmSqn_next, on->ogmSqn_send + 1)) {

                dbgf_track(DBGT_WARN, "id=%s delayed %d < %d", cryptShaAsString(&on->nodeId), on->ogmSqn_send, on->ogmSqn_next);
        } else {

                dbgf_all(DBGT_INFO, "id=%s in-time %d < %d", cryptShaAsString(&on->nodeId), on->ogmSqn_send, on->ogmSqn_next);
        }

        set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_next, on->ogmSqn_next);

        on->dhn->referred_by_me_timestamp = bmx_time;

        assertion(-500890, ((on->dhn->myIID4orig - prev_ogm_iid) <= OGM_IIDOFFST_MASK));

	struct msg_ogm_adv m;
	m.u.o.iidOffset=(on->dhn->myIID4orig - prev_ogm_iid);
	m.u.o.sqn=on->ogmSqn_next;
	m.u.o.mtcExponent = fm.val.f.exp_fm16;
	m.u.o.mtcMantissa = fm.val.f.mantissa_fm16;

	ogm->u.u32 = htonl(m.u.u32);

        return on->dhn->myIID4orig;
}

STATIC_FUNC
void create_ogm_aggregation(void)
{
        TRACE_FUNCTION_CALL;
        uint32_t target_ogms = XMIN(OGMS_PER_AGGREG_MAX,
                ((ogm_aggreg_pending < ((OGMS_PER_AGGREG_PREF / 3)*4)) ? ogm_aggreg_pending : OGMS_PER_AGGREG_PREF));

        struct msg_ogm_adv* msgs =
                debugMalloc((target_ogms + OGM_JUMPS_PER_AGGREGATION) * sizeof (struct msg_ogm_adv), -300177);

        IID_T curr_iid;
        IID_T ogm_iid = 0;
        IID_T ogm_iid_jumps = 0;
        uint16_t ogm_msg = 0;

        dbgf_all(DBGT_INFO, "pending %d target %d", ogm_aggreg_pending, target_ogms);

        for (curr_iid = IID_MIN_USED; curr_iid < my_iid_repos.max_free; curr_iid++) {

                IID_NODE_T *dhn = my_iid_repos.arr.node[curr_iid];
                struct orig_node *on = dhn ? dhn->on : NULL;

                if (on && UXX_GT(OGM_SQN_MASK, on->ogmSqn_next, on->ogmSqn_send)) {

                        if (on != self && (!on->curr_rt_local || on->curr_rt_local->mr.umetric < on->path_metricalgo->umetric_min)) {

                                dbgf_sys(DBGT_WARN,
                                        "id=%s with %s curr_rn and PENDING ogm_sqn=%d but path_metric=%jd < USABLE=%jd",
                                        cryptShaAsString(&on->nodeId), on->curr_rt_local ? " " : "NO", on->ogmSqn_next,
                                        on->curr_rt_local ? on->curr_rt_local->mr.umetric : 0,
                                        on->path_metricalgo->umetric_min);

                                assertion(-500816, (0));

                                continue;
                        }

                        if (((IID_T) (dhn->myIID4orig - ogm_iid) >= OGM_IID_RSVD_JUMP)) {

                                if (ogm_iid_jumps == OGM_JUMPS_PER_AGGREGATION)
                                        break;

                                dbgf((ogm_iid_jumps > 1) ? DBGL_SYS : DBGL_ALL, DBGT_INFO,
                                        "IID jump %d from %d to %d", ogm_iid_jumps, ogm_iid, dhn->myIID4orig);

                                ogm_iid = dhn->myIID4orig;

				struct msg_ogm_adv ogm = {.u.j={.mtcU10=0}};
				ogm.u.j.iid=ogm_iid;
				ogm.u.j.iidOffset=OGM_IID_RSVD_JUMP;

				msgs[ogm_msg + ogm_iid_jumps].u.u32 = htonl(ogm.u.u32);
				
                                ogm_iid_jumps++;
                        }

                        ogm_iid = create_ogm(on, ogm_iid, &msgs[ogm_msg + ogm_iid_jumps]);

                        if ((++ogm_msg) == target_ogms)
                                break;
                }
        }

        assertion(-500817, (IMPLIES(curr_iid == my_iid_repos.max_free, !ogm_aggreg_pending)));

        if (ogm_aggreg_pending) {
                dbgf_sys(DBGT_WARN, "%d ogms left for immediate next aggregation", ogm_aggreg_pending);
        }

        if (!ogm_msg) {
                debugFree( msgs, -300219);
                return;
        }

        struct ogm_aggreg_node *oan = debugMallocReset(sizeof (struct ogm_aggreg_node), -300179);

        oan->aggregated_msgs = ogm_msg + ogm_iid_jumps;
        oan->ogm_advs = msgs;
        oan->tx_attempt = 0;
        oan->sqn = (++ogm_aggreg_sqn_max);
        uint16_t destinations = 0;

        struct avl_node *local_an = NULL;
        struct neigh_node *local;

        while ((local = avl_iterate_item(&local_tree, &local_an))) {

                if (local->myLinkId != LINKADV_ID_IGNORED && local->rp_ogm_request_rcvd) {

                        destinations++;

                        bit_set(local->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, ogm_aggreg_sqn_max, 1);

                } else {
                        bit_set(local->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, ogm_aggreg_sqn_max, 0);
                }
        }

        list_add_tail(&ogm_aggreg_list, &oan->list);

        dbgf_all( DBGT_INFO, "aggregation_sqn=%d ogms=%d jumps=%d destinations=%d",
                oan->sqn, ogm_msg, ogm_iid_jumps, destinations);

        return;
}




static LinkNode **linkArray = NULL;

STATIC_FUNC
void linkArrayPrepare(void)
{
        TRACE_FUNCTION_CALL;

	static uint16_t linkArrayItems = 0;
        struct avl_node *an;
        struct dev_node *dev;

        if (linkArrayItems != dev_ip_tree.items + 1) {

                if (linkArray)
                        debugFree(linkArray, -300180);

                linkArrayItems = dev_ip_tree.items + 1;
                linkArray = debugMalloc((linkArrayItems * sizeof (LinkNode*)), -300182);
        }

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));)
                dev->tmp_flag_for_to_be_send_adv = NO;
}


STATIC_FUNC
LinkNode **get_unacked_ogm_links(struct ogm_aggreg_node *oan)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *local_an = NULL;
        struct neigh_node *local;
        uint16_t d = 0;

        dbgf_all(DBGT_INFO, "aggreg_sqn %d ", oan->sqn);

        linkArrayPrepare();

        memset(oan->ogm_dest_field, 0, sizeof (oan->ogm_dest_field));
        oan->ogm_dest_bytes = 0;

        while ((local = avl_iterate_item(&local_tree, &local_an))) {
               
                assertion(-500971, (IMPLIES(local, local->best_tp_link)));

                if (local->myLinkId == LINKADV_ID_IGNORED || !local->rp_ogm_request_rcvd)
                        bit_set(local->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, oan->sqn, 0);
                
                IDM_T not_acked = bit_get(local->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, oan->sqn);

                if (not_acked || 
			oan->tx_attempt == 0/*first ogm-adv frame shall be send to all neighbors*/) {

			LinkNode *bestLink = local->best_tp_link;
			assertion(-500446, (bestLink->k.myDev));
			assertion(-500447, (bestLink->k.myDev->active));
			assertion(-500444, (d <= dev_ip_tree.items));

                        dbgf_all(DBGT_INFO, "  redundant=%d via dev=%s to local_id=%s dev_idx=0x%X",
                                bestLink->k.myDev->tmp_flag_for_to_be_send_adv, bestLink->k.myDev->label_cfg.str,
                                cryptShaAsString(&bestLink->k.linkDev->key.local_id), bestLink->k.linkDev->key.dev_idx);

                        if (bestLink->k.myDev->tmp_flag_for_to_be_send_adv == NO) {
                                linkArray[d++] = bestLink;
                                bestLink->k.myDev->tmp_flag_for_to_be_send_adv = YES;
                        }

                        if (not_acked) {
                                assertion(-501138, (local->myLinkId < OGM_DEST_ARRAY_BIT_SIZE));
                                oan->ogm_dest_bytes = XMAX(oan->ogm_dest_bytes, ((local->myLinkId / 8) + 1));
                                bit_set(oan->ogm_dest_field, OGM_DEST_ARRAY_BIT_SIZE, local->myLinkId, 1);
                        }


                        if (oan->tx_attempt >= ((ogm_adv_tx_iters * 3) / 4)) {

                                dbg_track(DBGT_WARN, "schedule ogm_aggregation_sqn=%3d msgs=%2d dest_bytes=%d tx_attempt=%2d/%d via dev=%s to NB=%s",
                                        oan->sqn, oan->aggregated_msgs, oan->ogm_dest_bytes, (oan->tx_attempt + 1),
                                        ogm_adv_tx_iters, bestLink->k.myDev->label_cfg.str,
                                        ip6AsStr(&bestLink->k.linkDev->link_ip));
                        }
                }
        }

        linkArray[d] = NULL;

        return linkArray;
}

void schedule_best_tp_links(struct neigh_node *except_local, uint16_t frame_type, int16_t frame_msgs_len, void *data, uint32_t dlen)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *an;
	struct dev_node *dev;
        struct neigh_node *local;
        uint16_t d = 0;

//        linkArrayPrepare();
        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));)
                dev->tmp_flag_for_to_be_send_adv = NO;

        dbgf_all(DBGT_INFO, "NOT local_id=%s ", except_local ? cryptShaAsString(&except_local->local_id) : 0);

        for (an = NULL; (local = avl_iterate_item(&local_tree, &an));) {

                if (except_local != local) {

			LinkNode *bestLink = local->best_tp_link;

                        assertion(-500445, (bestLink));
                        assertion(-500446, (bestLink->k.myDev));
                        assertion(-500447, (bestLink->k.myDev->active));

                        dbgf_all(DBGT_INFO, "  via dev=%s to local_id=%s dev_idx=0x%X (redundant %d)",
                                bestLink->k.myDev->label_cfg.str, cryptShaAsString(&bestLink->k.linkDev->key.local_id),
                                bestLink->k.linkDev->key.dev_idx, bestLink->k.myDev->tmp_flag_for_to_be_send_adv);

                        if (bestLink->k.myDev->tmp_flag_for_to_be_send_adv == NO) {
				schedule_tx_task(bestLink, frame_type, frame_msgs_len, data, dlen);
//				linkArray[d++] = bestLink;
                                bestLink->k.myDev->tmp_flag_for_to_be_send_adv = YES;
                        }

                        assertion(-500444, (d <= dev_ip_tree.items));
                }
        }

//	linkArray[d] = NULL;
//	return linkArray;
}

STATIC_FUNC
void schedule_or_purge_ogm_aggregations(IDM_T purge_all)
{
        TRACE_FUNCTION_CALL;

        static TIME_T timestamp = 0;

        dbgf_all(DBGT_INFO, "max %d   active aggregations %d   pending ogms %d  expiery in %d ms",
                ogm_aggreg_sqn_max, ogm_aggreg_list.items, ogm_aggreg_pending,
                (my_tx_interval - ((TIME_T) (bmx_time - timestamp))));

        if (!purge_all && timestamp != bmx_time) {

                timestamp = bmx_time;

                while (ogm_aggreg_pending) {

                        struct ogm_aggreg_node *oan = list_get_first(&ogm_aggreg_list);

                        if (oan && ((AGGREG_SQN_MASK)& ((ogm_aggreg_sqn_max + 1) - oan->sqn)) >= AGGREG_SQN_CACHE_RANGE) {

                                dbgf_sys(DBGT_WARN,
                                        "ogm_aggreg_list full min %d max %d items %d unaggregated %d",
                                        oan->sqn, ogm_aggreg_sqn_max, ogm_aggreg_list.items, ogm_aggreg_pending);

                                debugFree(oan->ogm_advs, -300185);
                                debugFree(oan, -300186);
                                list_del_next(&ogm_aggreg_list, ((struct list_node*) & ogm_aggreg_list));
                        }

                        create_ogm_aggregation();

#ifdef EXTREME_PARANOIA
                        if (!ogm_aggreg_pending) {

                                IID_T curr_iid;
                                for (curr_iid = IID_MIN_USED; curr_iid < my_iid_repos.max_free; curr_iid++) {

                                        IID_NODE_T *dhn = my_iid_repos.arr.node[curr_iid];
                                        struct orig_node *on = dhn ? dhn->on : NULL;

                                        if (on && on->curr_rt_local &&
                                                UXX_GT(OGM_SQN_MASK, on->ogmSqn_next, on->ogmSqn_send) &&
                                                on->curr_rt_local->mr.umetric >= on->path_metricalgo->umetric_min) {

                                                dbgf_sys(DBGT_ERR,
                                                        "%s with %s curr_rn and PENDING ogm_sqn=%d but path_metric=%jd < USABLE=%jd",
                                                        cryptShaAsString(&on->nodeId),
                                                        on->curr_rt_local ? " " : "NO", on->ogmSqn_next,
                                                        on->curr_rt_local ? on->curr_rt_local->mr.umetric : 0, on->path_metricalgo->umetric_min);

                                                ASSERTION( -500473, (0));

                                        }
                                }
                        }
#endif
                }
        }

        struct list_node *lpos, *tpos, *lprev = (struct list_node*) & ogm_aggreg_list;

        list_for_each_safe(lpos, tpos, &ogm_aggreg_list)
        {
                struct ogm_aggreg_node *oan = list_entry(lpos, struct ogm_aggreg_node, list);

                if (purge_all || oan->tx_attempt >= ogm_adv_tx_iters) {

                        list_del_next(&ogm_aggreg_list, lprev);
                        debugFree(oan->ogm_advs, -300183);
                        debugFree(oan, -300184);

                        continue;

                } else if (oan->tx_attempt < ogm_adv_tx_iters) {

                        LinkNode **array = get_unacked_ogm_links(oan);
                        int d;

                        oan->tx_attempt = (array[0]) ? (oan->tx_attempt + 1) : ogm_adv_tx_iters;

                        for (d = 0; (array[d]); d++) {
				int16_t len = ((oan->aggregated_msgs * sizeof (struct msg_ogm_adv)) + oan->ogm_dest_bytes);
				schedule_tx_task((array[d]), FRAME_TYPE_OGM_ADV, len, &oan->sqn, sizeof(AGGREG_SQN_T));
                        }

                        assertion(-501319, (IMPLIES(d, (oan->aggregated_msgs))));
                }

                lprev = lpos;
        }
}


STATIC_FUNC
int32_t tx_msg_link_version_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct msg_link_version_adv *adv = (struct msg_link_version_adv *) (tx_iterator_cache_msg_ptr(it));

	adv->link_adv_sqn = htons(my_link_adv_sqn);
        adv->dev_idx = it->ttn->task.dev->llip_key.idx;

        return sizeof (struct msg_link_version_adv);
}

STATIC_FUNC
int32_t rx_msg_link_version_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct packet_buff_info *pbi = &it->pb->i;
        struct msg_link_version_adv *msg = (struct msg_link_version_adv*) (it->msg);

	assertion(-502154, (pbi->verifiedLinkDhn)); //

	if (!(pbi->verifiedLink = getLinkNode(pbi->iif, &pbi->llip, ntohs(msg->link_adv_sqn), pbi->verifiedLinkDhn, msg->dev_idx)))
		return TLV_RX_DATA_FAILURE;


	struct neigh_node *local = pbi->verifiedLink->k.linkDev->local;

	assertion(-502155, (local));

	if (msg_dev_req_enabled && UXX_LT(DEVADV_SQN_MAX, local->dev_adv_sqn, local->link_adv_dev_sqn_ref)) {

		dbgf_track(DBGT_INFO,
			"schedule DEV_REQ to NB=%s local_id=%s via dev=%s dev_adv_sqn=%d link_adv_dev_sqn_ref=%d",
			pbi->llip_str, cryptShaAsString(&local->local_id), local->best_tp_link->k.myDev->label_cfg.str,
			local->dev_adv_sqn, local->link_adv_dev_sqn_ref);

		schedule_tx_task(&pbi->iif->dummyLink, FRAME_TYPE_DEV_REQ, SCHEDULE_MIN_MSG_SIZE, &local->local_id, sizeof(LOCAL_ID_T));
	}

	if (UXX_LT(LINKADV_SQN_MAX, local->link_adv_sqn, local->packet_link_sqn_ref)) {

		dbgf_track(DBGT_INFO,
			"schedule LINK_REQ to NB=%s local_id=%s via dev=%s  link_adv_sqn=%d packet_link_sqn_ref=%d",
			pbi->llip_str, cryptShaAsString(&local->local_id), local->best_tp_link->k.myDev->label_cfg.str,
			local->link_adv_sqn, local->packet_link_sqn_ref);

		local->rp_ogm_request_rcvd = 0;

		memset(local->ogm_aggregations_not_acked, 0, sizeof(local->ogm_aggregations_not_acked));

		schedule_tx_task(&pbi->iif->dummyLink, FRAME_TYPE_LINK_REQ, SCHEDULE_MIN_MSG_SIZE, &local->local_id, sizeof(LOCAL_ID_T));
	}
	
        return sizeof (struct msg_link_version_adv);
}

STATIC_FUNC
int32_t tx_msg_hello_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        assertion(-500771, (tx_iterator_cache_data_space_pref(it) >= ((int) sizeof (struct msg_hello_adv))));

        struct tx_task_node *ttn = it->ttn;
        struct msg_hello_adv *adv = (struct msg_hello_adv *) (tx_iterator_cache_msg_ptr(it));

        HELLO_SQN_T sqn_in = ttn->task.dev->link_hello_sqn = ((HELLO_SQN_MASK)&(ttn->task.dev->link_hello_sqn + 1));

        adv->hello_sqn = htons(sqn_in);
        
        dbgf_all(DBGT_INFO, "%s %s SQN %d", ttn->task.dev->label_cfg.str, ttn->task.dev->ip_llocal_str, sqn_in);

        return sizeof (struct msg_hello_adv);
}





STATIC_FUNC
struct ref_node* ref_node_get(SHA1_T *rhash ) {

        struct ref_node *refn = avl_find_item( &ref_tree, rhash);

        if (refn) {

                refn->last_usage = bmx_time;

		return refn;

        } else {

		return NULL;
        }
}


STATIC_FUNC
void ref_node_del (struct ref_node *refn)
{
	assertion(-501667, !refn->dext_tree.items);
	assertion(-501668, ref_tree.items);
	avl_remove(&ref_tree, &refn->rhash, -300560);
	debugFree(refn->f_body, -300624);
	debugFree(refn, -300562);
}

void ref_node_purge (IDM_T all_unused)
{
	struct ref_node *refn, *oldest_unused = NULL;

	SHA1_T rhash;
	memset(&rhash, 0, sizeof(rhash));

	while (( refn = avl_next_item(&ref_tree, &rhash) )) {
		rhash = refn->rhash;

		if (refn->dext_tree.items) {

			refn->last_usage = bmx_time;

		} else if ( all_unused || ((TIME_T)(bmx_time - refn->last_usage)) > (TIME_T) ref_nodes_purge_to ) {

			ref_node_del(refn);

		} else if ( !oldest_unused || U32_LT( refn->last_usage, oldest_unused->last_usage )) {

			oldest_unused = refn;
		}
	}

	if ((int32_t)ref_tree.items - ref_tree_items_used >= ref_nodes_max_unused) {
		assertion(-501669, oldest_unused);
		ref_node_del(oldest_unused);
	}
}

SHA1_T *ref_node_key(uint8_t *f_body, uint32_t f_body_len, uint8_t compression, uint8_t nested, uint8_t reserved)
{
	static SHA1_T rhash;

	assertion(-501616, (f_body && f_body_len));

	struct frame_hdr_rhash_adv rhash_hdr = {.compression=compression, .nested=nested, .reserved=reserved};

	struct tlv_hdr tlv = tlvSetBigEndian(FRAME_TYPE_REF_ADV, (sizeof(tlv) + sizeof(rhash_hdr) + f_body_len));

	cryptShaNew(&tlv, sizeof(tlv));
	cryptShaUpdate(&rhash_hdr, sizeof(rhash_hdr));
	cryptShaUpdate(f_body, f_body_len);
	cryptShaFinal(&rhash);

	dbgf_all(DBGT_INFO, "fhl=%s", memAsHexString(&tlv, sizeof(tlv)));
	dbgf_all(DBGT_INFO, "hdr=%s", memAsHexString(&rhash_hdr, sizeof(rhash_hdr)));
	dbgf_all(DBGT_INFO, "bdy=%s", memAsHexString(f_body, f_body_len));
	dbgf_all(DBGT_INFO, "sha=%s", cryptShaAsString(&rhash));

	return &rhash;
}

STATIC_FUNC
struct ref_node * ref_node_add(uint8_t *f_body, uint32_t f_body_len, uint8_t compression, uint8_t nested, uint8_t reserved)
{

	SHA1_T *rhash = ref_node_key(f_body, f_body_len, compression, nested, reserved);
	struct ref_node *refn = ref_node_get(rhash);

	if (!refn) {

		if ((int32_t)ref_tree.items - ref_tree_items_used >= ref_nodes_max_unused)
			ref_node_purge(NO /*all unused*/);

		refn = debugMallocReset(sizeof(struct ref_node), -300563);
		AVL_INIT_TREE(refn->dext_tree, struct dext_tree_node, dext_key);

		refn->f_body_len = f_body_len;
		refn->f_body = debugMalloc(f_body_len, -300625);
		memcpy(refn->f_body, f_body, f_body_len);
		refn->last_usage = bmx_time;
		refn->rhash = *rhash;
		refn->compression = compression;
		refn->nested = nested;
		refn->reserved = reserved;
		avl_insert(&ref_tree, refn, -300565);

		dbgf_track(DBGT_INFO, "new rhash=%s data_len=%d",
			memAsHexString(rhash, sizeof(SHA1_T)), f_body_len);
	}

	return refn;
}

STATIC_FUNC
void ref_node_use(struct desc_extension *dext, struct ref_node *refn, uint8_t f_type)
{

	assertion(-501617, (f_type <= BMX_DSC_TLV_MAX && f_type != BMX_DSC_TLV_RHASH));

	struct dext_tree_node *dtn = avl_find_item(&refn->dext_tree, &dext);

	assertion(-501618, (!(dtn && !bit_get(dtn->rf_types, (sizeof(dtn->rf_types) * 8), f_type))));

	if (!refn->dext_tree.items)
		ref_tree_items_used++;

	if (!dtn) {
		dtn = debugMallocReset(sizeof(struct dext_tree_node), -300580);
		dtn->dext_key.dext = dext;
		avl_insert(&refn->dext_tree, dtn, -300581);

		struct refnl_node *rn = debugMallocReset(sizeof(struct refnl_node), -300566);
		rn->refn = refn;
		list_add_tail(&dext->refnl_list, &rn->list);

		assertion(-501578, ((int32_t)ref_tree.items >= ref_tree_items_used));

		if (dref_adv_tx_unsolicited && refn->dext_tree.items == 1)
			schedule_best_tp_links(NULL, FRAME_TYPE_REF_ADV, refn->f_body_len, &refn->rhash, sizeof(SHA1_T));

	}

	assertion(-501619, (avl_find(&refn->dext_tree, &dext)));

	bit_set(dtn->rf_types, (sizeof(dtn->rf_types) * 8), f_type, 1);


}

STATIC_FUNC
void ref_node_release( struct desc_extension *dext)
{
	struct refnl_node *rn;

	while ((rn = list_del_head(&dext->refnl_list))) {
		assertion(-501579, (rn->refn->dext_tree.items > 0));
		assertion(-501580, (ref_tree_items_used > 0));

		struct dext_tree_node *dtn = avl_remove(&rn->refn->dext_tree, &dext, -300582);
		assertion(-501620, (dtn && dtn->dext_key.dext == dext));
		debugFree(dtn, -300583);
		assertion(-501621, (!avl_find(&rn->refn->dext_tree, &dext)));

		if(!rn->refn->dext_tree.items)
			ref_tree_items_used--;

		debugFree(rn, -300567);
	}
}



STATIC_FUNC
int32_t tx_msg_ref_request(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	SHA1_T *rhash = (SHA1_T *)it->ttn->task.data;

        if (ref_node_get(rhash)) {
                it->ttn->tx_iterations = 0;
                return TLV_TX_DATA_DONE;
        } else {
		dbgf_sys(DBGT_INFO, DBG_NIL);
		((struct msg_ref_req*) tx_iterator_cache_msg_ptr(it))->rframe_hash = *rhash;
		return sizeof (struct msg_ref_req);
	}
}

STATIC_FUNC
int32_t rx_msg_ref_request(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	SHA1_T *rhash = &(((struct msg_ref_req*)it->msg)->rframe_hash);
	struct ref_node *refn = ref_node_get(rhash);

	dbgf_sys(DBGT_INFO, DBG_NIL);

	if (refn && refn->dext_tree.items)
		schedule_tx_task(&it->pb->i.iif->dummyLink, FRAME_TYPE_REF_ADV, refn->f_body_len, &refn->rhash, sizeof(SHA1_T));

	return sizeof(struct msg_ref_req);
}


STATIC_FUNC
int32_t tx_frame_ref_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	struct ref_node *refn = ref_node_get((SHA1_T *)it->ttn->task.data);

	assertion(-501581, refn);

	if(refn && refn->dext_tree.items) {

		dbgf_sys(DBGT_INFO, "frame_msgs_length=%d f_body_len=%d space_pref=%d space_max=%d",
			it->ttn->frame_msgs_length, refn->f_body_len, tx_iterator_cache_data_space_pref(it), tx_iterator_cache_data_space_max(it));

		assertion(-502049, ((int) it->ttn->frame_msgs_length <= tx_iterator_cache_data_space_max(it)));
		assertion(-502050, ((int) it->ttn->frame_msgs_length == refn->f_body_len));

		struct frame_hdr_rhash_adv *hdr = ((struct frame_hdr_rhash_adv*) tx_iterator_cache_hdr_ptr(it));

		hdr->compression = refn->compression;
		hdr->nested = refn->nested;
		hdr->reserved = refn->reserved;

		memcpy(hdr->msg, refn->f_body, refn->f_body_len);
	
		return refn->f_body_len;
	}
	
	return TLV_TX_DATA_DONE;
}


STATIC_FUNC
int32_t rx_frame_ref_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	dbgf_sys(DBGT_INFO, DBG_NIL);
	
	assertion(-501583, !it->dhnNew && it->frame_type == FRAME_TYPE_REF_ADV);

	if ( 	it->frame_data_length <= (int32_t)(sizeof(struct frame_hdr_rhash_adv)) ||
		it->frame_data_length > (int32_t)(REF_FRAME_BODY_SIZE_MAX + sizeof(struct frame_hdr_rhash_adv))	)
		return TLV_RX_DATA_FAILURE;

	ref_node_add(it->frame_data+sizeof(struct frame_hdr_rhash_adv),
	             it->frame_data_length-sizeof(struct frame_hdr_rhash_adv),
		     ((struct frame_hdr_rhash_adv*)it->frame_data)->compression,
		     ((struct frame_hdr_rhash_adv*)it->frame_data)->nested,
		     ((struct frame_hdr_rhash_adv*)it->frame_data)->reserved
		);


	//TODO: check if demanded, add referencee_tree and required_tree,...

	return it->frame_msgs_length;
}



STATIC_FUNC
int create_dsc_tlv_rhash(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	// description reference extenstions are created on-demand in:
	assertion(-501623, ( TEST_FUNCTION(tx_frame_iterate_finish)));
	// depending on:
	assertion(-501624, (TEST_VARIABLE( ((struct frame_handl*)0)->dextReferencing)));

        return TLV_TX_DATA_IGNORED;
}

STATIC_FUNC
int process_dsc_tlv_rhash(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	// description reference extenstions are processed explicitly in:
	//assertion(-501625, ( TEST_FUNCTION(process_description))); //calling:
	assertion(-501626, ( TEST_FUNCTION(dext_resolve))); //calling:
	assertion(-501627, ( TEST_FUNCTION(resolve_ref_frame)) );
	assertion(-501628, ( TEST_FUNCTION(ref_node_get)) );
	assertion(-501629, ( TEST_FUNCTION(ref_node_use)) );
	// and must be ignored when processed implicitly via:
	assertion(-501630, ( TEST_FUNCTION(rx_frame_iterate)) );
	// either while processing:
	assertion(-501631, ( TEST_STRUCT(struct dsc_msg_version)) );
	// and using:
	assertion(-501632, ( TEST_VALUE( FRAME_TYPE_PROCESS_NONE )) );

	// or while processing:
	assertion(-501633, ( TEST_STRUCT(struct desc_extension)) );
	// where type:
	assertion(-501634, ( TEST_VALUE( BMX_DSC_TLV_RHASH )) );
	// must not exist anymore because it should have been resolved already!

        assertion(-501585, (!it->onOld));
	assertion(-501586, (0));
	
        return TLV_RX_DATA_FAILURE;
}



STATIC_FUNC
struct desc_extension * dext_init(void)
{
	struct desc_extension *dext = debugMallocReset(sizeof(struct desc_extension), -300572);
	LIST_INIT_HEAD(dext->refnl_list, struct refnl_node, list, list);
	return dext;

}

void dext_free(struct desc_extension **dext)
{
	assertion(-501600, dext);
	assertion(-501608, IMPLIES(*dext, *dext!=REJECTED_PTR && *dext!=FAILURE_PTR && *dext!=UNRESOLVED_PTR));

        if(*dext) {

		ref_node_release(*dext);

		if((*dext)->data)
			debugFree((*dext)->data, -300530);

                debugFree((*dext), -300570);
	}

	*dext = NULL;
}

void *dext_dptr( struct desc_extension *dext, uint8_t type)
{
    return (dext && dext->dtd[type].len) ? dext->data + dext->dtd[type].pos : NULL;
}


STATIC_FUNC
struct desc_extension * dext_resolve(struct packet_buff *pb, struct description_cache_node *cache, struct desc_extension *dext)
{
        TRACE_FUNCTION_CALL;
	assertion(-501655, (BMX_DSC_TLV_INVALID > BMX_DSC_TLV_MAX && BMX_DSC_TLV_INVALID <= UINT8_MAX));

	IDM_T unresolved = 0;
	uint8_t dsc_frame_types[BMX_DSC_TLV_ARRSZ] = {0};
	int32_t result;

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .onOld = NULL, .op = TLV_OP_PLUGIN_MIN,
                .db = description_tlv_db, .process_filter = FRAME_TYPE_PROCESS_NONE,
                .frame_type = -1,.frames_in = cache->desc_frame, .frames_length = cache->desc_frame_len };

	uint8_t vf_type = BMX_DSC_TLV_INVALID;
	int32_t vf_data_len = 0;
	uint8_t vf_compression = 0;
	char *goto_error_code = "???";
	int32_t vd_len = 0;


        while ((result=rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

		uint32_t dext_dlen_old = 0;
		vf_type = BMX_DSC_TLV_INVALID;
		vf_data_len = 0;
		vf_compression = 0;

		if (dext) {
			dext_dlen_old = dext->dlen;
			dext->dlen += sizeof(struct tlv_hdr_virtual);
			// hdr setting is done when succeeded
			// data reallocation is done before writing new data
		}

                if (it.frame_type != BMX_DSC_TLV_RHASH) {

			vf_type = it.frame_type;
			vf_data_len = it.frame_data_length;

			if ( vf_data_len <= 0 || vf_data_len > vrt_frame_data_size_in)
				goto_error( resolve_desc_extension_error, "1");

			if (dext) {
				dext->data = debugRealloc(dext->data, dext->dlen + vf_data_len, -300429 );
				memcpy(dext->data + dext->dlen, it.frame_data, vf_data_len);
				dext->dlen += vf_data_len;
			}


                } else if (it.frame_type == BMX_DSC_TLV_RHASH) {

			vf_type = ((struct desc_hdr_rhash*)(it.frame_data))->expanded_type;
			vf_compression = ((struct desc_hdr_rhash*)(it.frame_data))->compression;
			vf_data_len = resolve_ref_frame(pb,
				it.frame_data+sizeof(struct desc_hdr_rhash), it.frame_data_length-sizeof(struct desc_hdr_rhash),
				dext, vf_type, vf_compression, 1);

			if (vf_data_len == 0) {
				unresolved = 1;
			} else if ( vf_data_len < 0) {
				goto_error( resolve_desc_extension_error, "2");
			}


                } else {
			goto_error( resolve_desc_extension_error, "3");
		}

		if (!unresolved) {
			if (vf_type > BMX_DSC_TLV_MAX || dsc_frame_types[vf_type])
				goto_error( resolve_desc_extension_error, "4");
			else
				dsc_frame_types[vf_type] = 1;
		}

		if ((vd_len = vd_len + vf_data_len) > vrt_desc_size_in)
			goto_error( resolve_desc_extension_error, "5");

		dbgf_track(DBGT_INFO, "converted type=%d %s f_data_length=%d compression=%d -> type=%d %s vf_data_len=%d, dext.len=%d",
		           it.frame_type, it.handl->name, it.frame_data_length, vf_compression,
			   vf_type, vf_type <= it.db->handl_max ? it.db->handls[vf_type].name : "???",
			   vf_data_len, dext ? dext->dlen : 0 );

		if (dext) {

			dext->dtd[vf_type].pos = dext_dlen_old + sizeof(struct tlv_hdr_virtual);
			dext->dtd[vf_type].len = vf_data_len;

			struct tlv_hdr_virtual *vf_hdr = (struct tlv_hdr_virtual *)(dext->data + dext_dlen_old);
			memset(vf_hdr, 0, sizeof(struct tlv_hdr_virtual));
			vf_hdr->type = vf_type;
			vf_hdr->mbz = 0;
			vf_hdr->length = htonl(sizeof(struct tlv_hdr_virtual) + vf_data_len);

			assertion(-501659, (vf_data_len <= vrt_frame_data_size_in));
			assertion(-501660, (vf_data_len > 0 && vf_type <= BMX_DSC_TLV_MAX));
			assertion(-501661, (dext->dlen == dext_dlen_old + ntohl(vf_hdr->length)));
			assertion(-501662, (dext->dlen <= (uint32_t)vrt_desc_size_in));
		}
        }


	if (result != TLV_RX_DATA_DONE) {
                dbgf_sys(DBGT_ERR, "problematic description_ltv from %s, near type=%s frame_data_length=%d frames_pos=%d tlv_result=%s",
                        pb ? pb->i.llip_str : DBG_NIL, it.db->handls[it.frame_type].name,
                        it.frame_data_length, it.frames_pos, tlv_tx_result_str(result));

		goto_error( resolve_desc_extension_error, "6");
        }

	if (unresolved)
		return (struct desc_extension *) UNRESOLVED_PTR;

        return dext;


resolve_desc_extension_error:

	assertion(-501663, (!dext)); //otherwise the check should have failed!
	//free_desc_extensions(&dext);
        dbgf_sys(DBGT_ERR, "Failed converting type=%d max_known=%d f_data_len=%d compression=%d -> type=%d vf_data_len=%d vf_error=%s",
                 it.frame_type, BMX_DSC_TLV_MAX_KNOWN, it.frame_data_length, vf_compression, vf_type, vf_data_len, goto_error_code);

	return (struct desc_extension *) FAILURE_PTR;
}





/*
 * tries to resolve data,len and requests unknown ref-hashes, updates dext if available and successfull
 * returns: > 0 if successfully resolved
 *          ==0 if unresolved
 *          < 0 if error (nest_level exceeded, ...)
 */
STATIC_FUNC
int32_t resolve_ref_frame(struct packet_buff *pb, uint8_t *f_body, uint32_t f_body_len, struct desc_extension *dext, uint8_t rf_type, uint8_t compression, uint8_t nest_level )
{
	assertion(-501598, (FAILURE==-1 && SUCCESS==0));

        struct desc_msg_rhash *msg = (struct desc_msg_rhash *)f_body;
	int32_t m = 0, msgs = f_body_len / sizeof(struct desc_msg_rhash);
	int32_t ref_len = 0;
	struct desc_extension *solvable = dext ? dext : dext_init();
	struct desc_extension *solvable_free = dext ? NULL : solvable;
	uint32_t solvable_begin = solvable->dlen;
	char *goto_error_code = " ";

	if ((++nest_level) > MAX_REF_NESTING)
		goto_error( resolve_ref_frame_error, "exceeded nest level");

	solvable->max_nesting = nest_level;

	for (; m < msgs && ref_len < MAX_DESC_LEN; m++) {

                struct ref_node *refn = ref_node_get(&(msg[m].rframe_hash));

		if (!refn) {

			if(pb) {
				LinkNode *bestLink = pb->i.verifiedLink ? pb->i.verifiedLink->k.linkDev->local->best_tp_link : &pb->i.iif->dummyLink;
				schedule_tx_task(bestLink, FRAME_TYPE_REF_REQ, SCHEDULE_MIN_MSG_SIZE, &(msg[m].rframe_hash), sizeof(SHA1_T));
			}

			solvable = NULL;

		} else if (refn->nested) {

			int32_t tmp_len = resolve_ref_frame(pb, refn->f_body, refn->f_body_len, solvable, rf_type, refn->compression, nest_level);

			if (tmp_len < 0)
				goto_error( resolve_ref_frame_error, "failed next recursion");
			if (tmp_len == 0)
				solvable = NULL;
			if (tmp_len > 0)
				ref_len += tmp_len;

		} else if (refn->compression == FRAME_COMPRESSION_NONE  && solvable) {

			solvable->data = debugRealloc(solvable->data, solvable->dlen + refn->f_body_len, -300569);
			memcpy(solvable->data + solvable->dlen, refn->f_body, refn->f_body_len);
			solvable->dlen += refn->f_body_len;

			if (solvable == dext)
				ref_node_use(solvable, refn, rf_type);

			ref_len += refn->f_body_len;

		} else if (refn->compression == FRAME_COMPRESSION_GZIP  && solvable) {

			int32_t tmp_len = z_decompress(refn->f_body, refn->f_body_len, &solvable->data, solvable->dlen);

			if (tmp_len <= 0)
				goto_error( resolve_ref_frame_error, "failed inner decompression");

			solvable->dlen += tmp_len;

			if (solvable == dext)
				ref_node_use(solvable, refn, rf_type);

			ref_len += tmp_len;

		} else {
			goto_error( resolve_ref_frame_error, "invalid case");
		}

		assertion(-501599, IMPLIES(solvable, solvable_begin + ref_len == solvable->dlen));
		assertion(-501653, IMPLIES(solvable, rf_type <= BMX_DSC_TLV_MAX));
        }

	if (m != msgs)
		goto_error( resolve_ref_frame_error, "invalid msgs");

	if (!solvable)
		goto resolve_ref_frame_unresolved;

	if (compression == FRAME_COMPRESSION_NONE) {

	} else if (compression == FRAME_COMPRESSION_GZIP) {

		if ((ref_len = z_decompress(solvable->data + solvable_begin, ref_len, &solvable->data, solvable_begin)) <= 0)
			goto_error( resolve_ref_frame_error, "failed outer decompression");

		solvable->dlen = solvable_begin + ref_len;

	} else {
		goto_error( resolve_ref_frame_error, "invalid outer decompression");
	}

	dext_free(&solvable_free);
	return ref_len;

resolve_ref_frame_unresolved:
	dext_free(&solvable_free);
	return SUCCESS; // 0 == unresolved

resolve_ref_frame_error:
{
	dbgf_sys(DBGT_ERR, "dlen=%d compression=%d dext=%d  msgs=%d nest_level=%d solvable=%d rf_type=%d m=%d ref_len=%d error=%s",
		f_body_len, compression, dext?1:0, msgs, nest_level, solvable?1:0, rf_type, m, ref_len, goto_error_code);


	dext_free(&solvable_free);
	assertion(-501654, !dext); // this function should only be called with dext if a prior call with dext=NULL succeeded
	return FAILURE;
}
}


struct dhash_node * process_description(struct packet_buff *pb, DHASH_T *dhash)
{
        TRACE_FUNCTION_CALL;
        assertion(-500262, (pb));
        ASSERTION(-500381, (!get_dhash_tree_node( dhash )));
	ASSERTION(-502213, (!avl_find_item(&deprecated_dhash_tree, dhash)));

	struct description_cache_node *cache = avl_find_item(&description_cache_tree, dhash);

	if (!cache) {
		LinkNode *link = pb->i.verifiedLink ? pb->i.verifiedLink->k.linkDev->local->best_tp_link : &pb->i.iif->dummyLink;
		schedule_tx_task(link, FRAME_TYPE_DESC_REQ, SCHEDULE_MIN_MSG_SIZE, dhash, sizeof(DHASH_T));
		return NULL;
	}

	// First check if dext is fully resolvable::
        struct desc_extension *dext = dext_resolve(pb, cache, NULL);
	struct dhash_node *dhnNew = NULL;
	struct orig_node *on = NULL;
	int32_t result = TLV_RX_DATA_FAILURE;

	if (dext == FAILURE_PTR) {

		goto process_desc0_error;

        } else if (dext == UNRESOLVED_PTR) {

		dbgf_sys(DBGT_WARN, "UNRESOLVED global_id=%s rcvd via_dev=%s via_ip=%s",
			nodeIdAsStringFromDescAdv(cache->desc_frame), pb->i.iif->label_cfg.str, pb->i.llip_str);

		return (struct dhash_node *) UNRESOLVED_PTR;

	} else if (dext) {
		cleanup_all(-502051);
	}

	// only if dext is fully resolvable then allocate it, so this should always succeed!!!
	dext = dext_init();

	if ( dext != dext_resolve(pb, cache, dext) )
		cleanup_all(-502052);


	dhnNew = create_dext_dhash(cache->desc_frame, cache->desc_frame_len, dext, dhash);
	on = avl_find_item(&orig_tree, nodeIdFromDescAdv(cache->desc_frame));
	assertion(-502053, IMPLIES(on, on->dhn && on->dhn->desc_frame && on->dhn->dext));

	result = process_description_tlvs(pb, on, dhnNew, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL);

	assertion( -502054, (result==TLV_RX_DATA_BLOCKED || result==TLV_RX_DATA_DONE ||
		result == TLV_RX_DATA_REBOOTED || result == TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_FAILURE));

	if (result==TLV_RX_DATA_REBOOTED || result==TLV_RX_DATA_REJECTED || result==TLV_RX_DATA_FAILURE)
		goto process_desc0_error;

        if (!on) // create new orig:
                on = init_orig_node(nodeIdFromDescAdv(dhnNew->desc_frame));
	else
                cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

        assertion(-501361, (!(on->blocked && on->added)));

        if (result == TLV_RX_DATA_DONE) {

		block_orig_node(NO, on);
                result = process_description_tlvs(pb, on, dhnNew, TLV_OP_NEW, FRAME_TYPE_PROCESS_ALL);
                assertion(-501362, (result == TLV_RX_DATA_DONE)); // checked, so MUST SUCCEED!!
                assertion(-501363, (!on->blocked && on->added));

        } else if (result == TLV_RX_DATA_BLOCKED ) {

                if (on->added) {
			assertion(-502055, (on->dhn && on->dhn->desc_frame && on->dhn->dext));
                        result = process_description_tlvs(pb, on, on->dhn, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL);
                        assertion(-501364, (result == TLV_RX_DATA_DONE));
                }

		block_orig_node(YES, on);

		assertion(-502056, (on->blocked && !on->added));
        }

        del_cached_description(&dhnNew->dhash);

        update_orig_dhash(on, dhnNew);

	cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_CREATED, on);

        return dhnNew;


process_desc0_error:

        if (dhnNew) {
		dext_free(&dhnNew->dext);
		debugFree(dhnNew, -300626);
	}

	dbgf_sys(DBGT_ERR, "%s global_id=%s rcvd via_dev=%s via_ip=%s", tlv_rx_result_str(result),
		cache ? nodeIdAsStringFromDescAdv(cache->desc_frame) : "???", pb->i.iif->label_cfg.str, pb->i.llip_str);


	if (result==TLV_RX_DATA_REBOOTED) {

		assertion(-502156, (on));
		assertion(-502157, (on != self));
		free_orig_node(on);
		return (struct dhash_node *) UNRESOLVED_PTR;

	} else if (result == TLV_RX_DATA_REJECTED) {

		return (struct dhash_node *) REJECTED_PTR;

	} else {
		assertion(-502158, (result==TLV_RX_DATA_FAILURE));
		badlist_neighbor_if_verified(pb);
		return (struct dhash_node *) FAILURE_PTR;
	}
}




STATIC_FUNC
int32_t tx_msg_dhash_request(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct tx_task_node *ttn = it->ttn;
        struct hdr_dhash_request *hdr = ((struct hdr_dhash_request*) tx_iterator_cache_hdr_ptr(it));
        struct msg_dhash_request *msg = ((struct msg_dhash_request*) tx_iterator_cache_msg_ptr(it));
	IID_T *neighIID4x = ((IID_T*)ttn->task.data);

        assertion(-500855, (tx_iterator_cache_data_space_pref(it) >= ((int) (sizeof (struct msg_dhash_request)))));
        assertion(-500856, (ttn->task.linkDev));
        assertion(-500870, (ttn->tx_iterations > 0 && ttn->considered_ts != bmx_time));

	struct dhash_node *dhn = iid_get_node_by_neighIID4x(ttn->task.linkDev->local, *neighIID4x, YES/*verbose*/);

        dbgf_track(DBGT_INFO, "%s dev=%s to local_id=%s dev_idx=0x%X iterations=%d time=%d requesting %s",
                it->db->handls[ttn->task.type].name, ttn->task.dev->label_cfg.str, cryptShaAsString(&ttn->task.linkDev->key.local_id),
                ttn->task.linkDev->key.dev_idx, ttn->tx_iterations, ttn->considered_ts,
                dhn ? "ALREADY RESOLVED (req cancelled)" : "ABOUT SOMEBODY");

        assertion(-500858, (IMPLIES((dhn && dhn->on), dhn->desc_frame)));

        if (dhn) {
                // description (and hash) already resolved, skip sending..
                ttn->tx_iterations = 0;
                return TLV_TX_DATA_DONE;
        }

        if (hdr->msg == msg) {
                assertion(-500854, (is_zero(hdr, sizeof (*hdr))));
                hdr->destination_local_id = ttn->task.linkDev->key.local_id;
        } else {
                assertion(-500871, (cryptShasEqual(&hdr->destination_local_id, &ttn->task.linkDev->key.local_id)));
        }

        dbgf_track(DBGT_INFO, "creating msg=%d", ((int) ((((char*) msg) - ((char*) hdr) - sizeof ( *hdr)) / sizeof (*msg))));

        msg->receiverIID4x = htons(*neighIID4x);

        return sizeof (struct msg_dhash_request);
}

STATIC_FUNC
int32_t tx_msg_description_request(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct tx_task_node *ttn = it->ttn;
        struct hdr_description_request *hdr = ((struct hdr_description_request*) tx_iterator_cache_hdr_ptr(it));
        struct msg_description_request *msg = ((struct msg_description_request*) tx_iterator_cache_msg_ptr(it));
	DHASH_T *dhash = (DHASH_T*)ttn->task.data;
        struct dhash_node *dhn = get_dhash_tree_node(dhash);
	struct dhash_node *deprecated = avl_find_item(&deprecated_dhash_tree, dhash);
	LinkDevNode *linkDev = ttn->task.linkDev;

        assertion(-500855, (tx_iterator_cache_data_space_pref(it) >= ((int) (sizeof (struct msg_description_request)))));
        assertion(-500870, (ttn->tx_iterations > 0 && ttn->considered_ts != bmx_time));
        assertion(-500858, (IMPLIES((dhn && dhn->on), dhn->desc_frame)));

        dbgf_track(DBGT_INFO, "%s dev=%s to local_id=%s dev_idx=%d iterations=%d time=%d requesting dhash=%s %s %s %s llneigh=%d",
                it->db->handls[ttn->task.type].name, ttn->task.dev->label_cfg.str, cryptShaAsString(linkDev? &linkDev->key.local_id : 0),
                linkDev ? linkDev->key.dev_idx : -1, ttn->tx_iterations, ttn->considered_ts, cryptShaAsString(dhash),
                (dhn ? "ALREADY RESOLVED" : ""), (deprecated ? "DEPRECATED" : ""), ((dhn || deprecated) ? "CANCELLED" : ""), (!!linkDev ));

        if (dhn || deprecated) {
                // description (and hash) already resolved, skip sending..
                ttn->tx_iterations = 0;
                return TLV_TX_DATA_DONE;
        }

        if (hdr->msg == msg) {
                assertion(-500854, (is_zero(hdr, sizeof (*hdr))));
		if (linkDev)
			hdr->destination_local_id = linkDev->key.local_id;
        } else {
                assertion(-500871, (linkDev ? cryptShasEqual(&hdr->destination_local_id, &linkDev->key.local_id) : is_zero(&hdr->destination_local_id, sizeof(LOCAL_ID_T))));
        }

        dbgf_track(DBGT_INFO, "creating msg=%d", ((int) ((((char*) msg) - ((char*) hdr) - sizeof ( *hdr)) / sizeof (*msg))));

        msg->dhash = *dhash;

        return sizeof (struct msg_description_request);
}

STATIC_FUNC
int32_t create_dsc_tlv_version(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	struct dsc_msg_version *dsc = (struct dsc_msg_version *)tx_iterator_cache_msg_ptr(it);

        // add some randomness to the ogm_sqn_range, that not all nodes invalidate at the same time:
        int32_t random_range = first_packet ? rand_num(ogmSqnRange) :
		ogmSqnRange - (ogmSqnRange / (_DEF_OGM_SQN_DIV*2)) + rand_num(ogmSqnRange / _DEF_OGM_SQN_DIV);

        self->ogmSqn_rangeSize = ((OGM_SQN_MASK)&(XMAX(_MIN_OGM_SQN_RANGE, XMIN(_MAX_OGM_SQN_RANGE, random_range)) ));

        self->ogmSqn_rangeMin = ((OGM_SQN_MASK)&(self->ogmSqn_rangeMin + _MAX_OGM_SQN_RANGE));

        self->ogmSqn_maxRcvd = set_ogmSqn_toBeSend_and_aggregated(self, UMETRIC_MAX,
                (OGM_SQN_MASK)&(self->ogmSqn_rangeMin - (self->ogmSqn_next == self->ogmSqn_send ? 1 : 0)),
                (OGM_SQN_MASK)&(self->ogmSqn_rangeMin - 1));

        dsc->ogmSqnMin = htons(self->ogmSqn_rangeMin);
        dsc->ogmSqnRange = htons(self->ogmSqn_rangeSize);
        dsc->capabilities = htons(my_desc_capabilities);
	dsc->runtimeKey = htonl(my_runtimeKey);

        uint32_t rev_u32;
        sscanf(GIT_REV, "%8X", &rev_u32);
        dsc->codeRevision = htonl(rev_u32);
        dsc->comp_version = my_compatibility;
        dsc->descSqn = getDescriptionSqn( NULL, 1);

	return sizeof(struct dsc_msg_version);
}

STATIC_FUNC
int32_t process_dsc_tlv_version(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if (it->op != TLV_OP_TEST && it->op != TLV_OP_NEW)
		return it->frame_data_length;

	struct dsc_msg_version *new = (struct dsc_msg_version*)it->frame_data;

        if (validate_param(new->comp_version, (my_compatibility-(my_pettiness?0:1)), (my_compatibility+(my_pettiness?0:1)), "compatibility version"))
		return TLV_RX_DATA_REJECTED;

        if (it->op == TLV_OP_TEST && it->onOld && it->onOld->dhn) {

		struct dsc_msg_version *old = dext_dptr(it->onOld->dhn->dext, BMX_DSC_TLV_VERSION);

		assertion(-502059, (old));
		
		if (ntohl(new->descSqn) <= ntohl(old->descSqn)) {

			if (new->descSqn == old->descSqn) {
				dbgf_sys(DBGT_ERR, "IGNORED rcvd descSqn=%d (current descSqn=%d) from nodeId=%s via dev=%s ip=%s",
					ntohl(new->descSqn), ntohl(old->descSqn), nodeIdAsStringFromDescAdv(it->dhnNew->desc_frame),
					it->pb->i.iif->label_cfg.str, it->pb->i.llip_str);
			}
			return TLV_RX_DATA_REJECTED;
		}

		if (new->runtimeKey != old->runtimeKey) {

			if (it->onOld == self) {
				dbgf_sys(DBGT_ERR, "WTF: rcvd my nodeId=%s (%s) with different runtimeKey=%X (%X) and greater descSqn=%d (%d)",
					nodeIdAsStringFromDescAdv(it->dhnNew->desc_frame), cryptShaAsString(&self->nodeId),
					ntohl(new->runtimeKey), ntohl(old->runtimeKey), ntohl(new->descSqn), ntohl(old->descSqn));
				EXITERROR(-502159, (0));
				return TLV_RX_DATA_REJECTED;
			}

			return TLV_RX_DATA_REBOOTED;
		}
	}

	if (validate_param(ntohs(new->ogmSqnRange), _MIN_OGM_SQN_RANGE, _MAX_OGM_SQN_RANGE, ARG_OGM_SQN_RANGE))
		return TLV_RX_DATA_FAILURE;

	if (it->op == TLV_OP_NEW) {

		struct orig_node *on = it->onOld;
		on->updated_timestamp = bmx_time;
		on->ogmSqn_rangeMin = ntohs(new->ogmSqnMin);
		on->ogmSqn_rangeSize = ntohs(new->ogmSqnRange);
		on->ogmSqn_maxRcvd = (OGM_SQN_MASK & (on->ogmSqn_rangeMin - 1));
		set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_maxRcvd, on->ogmSqn_maxRcvd);
	}
	
	return sizeof(struct dsc_msg_version);
}

STATIC_FUNC
int32_t create_dsc_tlv_names(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	dbgf_all(DBGT_INFO, "%s", my_Hostname);

	int32_t nameLen = strlen(my_Hostname);

	if (nameLen > tx_iterator_cache_data_space_pref(it))
		return TLV_TX_DATA_FULL;

	if (nameLen<=0)
		return TLV_TX_DATA_IGNORED;

	memcpy(tx_iterator_cache_msg_ptr(it), my_Hostname, nameLen);

	self->hostname = my_Hostname;
	return nameLen;
}

STATIC_FUNC
int32_t process_dsc_tlv_names(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	char name[MAX_HOSTNAME_LEN];

	dbgf_all(DBGT_INFO, "op=%s", tlv_op_str(it->op) );

	if (it->frame_data_length>=MAX_HOSTNAME_LEN)
		return TLV_RX_DATA_FAILURE;

	memcpy(name, it->frame_data, it->frame_data_length);
	name[it->frame_data_length]=0;

	if (validate_name_string(name, it->frame_data_length+1, NULL) == FAILURE)
		return TLV_RX_DATA_FAILURE;

	if ((it->op==TLV_OP_NEW || it->op == TLV_OP_DEL) && it->onOld->hostname) {
		debugFree(it->onOld->hostname, -300634);
		it->onOld->hostname = NULL;
	}

	if (it->op == TLV_OP_NEW) {
		it->onOld->hostname = debugMalloc(it->frame_data_length+1, -300635);
		strcpy(it->onOld->hostname, name);
	}

	return TLV_RX_DATA_PROCESSED;
}

STATIC_FUNC
int32_t tx_frame_description_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	DHASH_T *dhash = (DHASH_T*)it->ttn->task.data;
        struct dhash_node *dhn = get_dhash_tree_node(dhash);

	if (!dhn) {
		dbgf_sys(DBGT_WARN, "UNKNOWN dhash=%s!", cryptShaAsString(dhash));
		// a meanwhile invalidated dhn migh have been scheduled when it was still valid

		IDM_T TODO_this_one_crashes_but_why;
		ASSERTION(-502160, (avl_find(&deprecated_dhash_tree, dhash)));

                return TLV_TX_DATA_DONE;
        }

	assertion(-502060, (it->ttn->frame_msgs_length == dhn->desc_frame_len));
	assertion(-502061, (dhn->desc_frame_len <= tx_iterator_cache_data_space_max(it)));

        memcpy(tx_iterator_cache_msg_ptr(it), dhn->desc_frame, dhn->desc_frame_len);

	dbgf_track(DBGT_INFO, "dhash=%s id=%s descr_size=%d",
		cryptShaAsString(dhash), cryptShaAsString(&dhn->on->nodeId), dhn->desc_frame_len);

        return dhn->desc_frame_len;
}




STATIC_FUNC
int32_t tx_msg_dhash_adv(struct tx_frame_iterator *it)
{

        TRACE_FUNCTION_CALL;
        assertion(-500774, (tx_iterator_cache_data_space_pref(it) >= ((int) sizeof (struct msg_dhash_adv))));

	IID_T *myIID4x = (IID_T*)it->ttn->task.data;
        assertion(-500556, (*myIID4x >= IID_MIN_USED));
        struct msg_dhash_adv *adv = (struct msg_dhash_adv *) tx_iterator_cache_msg_ptr(it);
        struct dhash_node *dhn;


        if (*myIID4x == myIID4me) {

                adv->transmitterIID4x = htons(myIID4me);
                dhn = self->dhn;

        } else if ((dhn = iid_get_node_by_myIID4x(*myIID4x)) && dhn->on) {

                assertion(-500259, (dhn->desc_frame));
                adv->transmitterIID4x = htons(*myIID4x);

        } else {

                dbgf_sys(DBGT_WARN, "%s myIID4x %d !", dhn ? "INVALID" : "UNKNOWN", *myIID4x);

                // an meanwhile invalidated dhn migh have been scheduled when it was still valid, but not an unknown:
//                assertion(-500978, (dhn && !dhn->on));

                return TLV_TX_DATA_DONE;
        }

        memcpy((char*) & adv->dhash, (char*) & dhn->dhash, sizeof(DHASH_T));

        dbgf_track(DBGT_INFO, "id=%s", cryptShaAsString(&dhn->on->nodeId));

        return sizeof (struct msg_dhash_adv);
}



void update_my_dev_adv(void)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct dev_node *dev;
        uint16_t msg = 0;
        static PKT_SQN_T last_dev_packet_sqn = 0;

        // no need to increment dev_adv_sqn if no packet has been emitted since last dev_adv change:
        if (last_dev_packet_sqn != my_packet_sqn) {
                last_dev_packet_sqn = my_packet_sqn;

                if ((++my_dev_adv_sqn) == DEVADV_SQN_DISABLED)
                        my_dev_adv_sqn++;
        }

        if (my_dev_adv_buff) {
                debugFree(my_dev_adv_buff, -300318);
                my_dev_adv_buff = NULL;
                my_dev_adv_msgs_size = 0;
        }

        if(terminating)
                return;

        if (dev_ip_tree.items) {
                my_dev_adv_buff = debugMallocReset(dev_ip_tree.items * sizeof (struct msg_dev_adv), -300319);
        }

        for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));)
                dev->dev_adv_msg = DEVADV_MSG_IGNORED;

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                if (dev->linklayer == TYP_DEV_LL_LO)
                        continue;

                my_dev_adv_buff[msg].dev_idx = dev->llip_key.idx;
                my_dev_adv_buff[msg].channel = dev->channel;
                my_dev_adv_buff[msg].tx_bitrate_min = umetric_to_fmu8(&dev->umetric_min);
                my_dev_adv_buff[msg].tx_bitrate_max = umetric_to_fmu8(&dev->umetric_max);
                my_dev_adv_buff[msg].llip = dev->llip_key.ip;
                my_dev_adv_buff[msg].mac = dev->mac;

                dev->dev_adv_msg = msg++;
        }

        my_dev_adv_msgs_size = msg * sizeof (struct msg_dev_adv);

        if (dev_adv_tx_unsolicited) {

                struct dev_node *dev;

                for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));)
                        schedule_tx_task(&dev->dummyLink, FRAME_TYPE_DEV_ADV, SCHEDULE_UNKNOWN_MSGS_SIZE, 0, 0);

        }


        update_my_link_adv(LINKADV_CHANGES_CRITICAL);
}


STATIC_FUNC
int32_t tx_frame_dev_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct hdr_dev_adv* hdr = ((struct hdr_dev_adv*) tx_iterator_cache_hdr_ptr(it));

        assertion(-500933, (hdr->msg == ((struct msg_dev_adv*) tx_iterator_cache_msg_ptr(it))));
        assertion(-500934, ((int) it->ttn->frame_msgs_length <= tx_iterator_cache_data_space_pref(it)));

        if (my_dev_adv_msgs_size > tx_iterator_cache_data_space_pref(it))
                return TLV_TX_DATA_FULL;

        hdr->dev_sqn = htons(my_dev_adv_sqn);

        memcpy(hdr->msg, my_dev_adv_buff, my_dev_adv_msgs_size);

        return my_dev_adv_msgs_size;
}


STATIC_FUNC
int32_t rx_msg_dev_req( struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct msg_dev_req* req = ((struct msg_dev_req*) it->msg);

        if (cryptShasEqual(&req->destination_local_id, &self->nodeId))
                schedule_tx_task(&it->pb->i.iif->dummyLink, FRAME_TYPE_DEV_ADV, SCHEDULE_UNKNOWN_MSGS_SIZE, 0, 0);

        return sizeof (struct msg_dev_req);
}


STATIC_FUNC
int32_t tx_msg_dev_req(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node *ttn = it->ttn;
        struct msg_dev_req *msg = ((struct msg_dev_req*) tx_iterator_cache_msg_ptr(it));
	LOCAL_ID_T *local_id = ((LOCAL_ID_T*)ttn->task.data);
        struct neigh_node *local = avl_find_item(&local_tree, local_id);

        assertion(-500986, (ttn->tx_iterations > 0 && ttn->considered_ts != bmx_time));

        dbgf_track(DBGT_INFO, "%s dev=%s to local_id=%s iterations=%d %s",
                it->db->handls[ttn->task.type].name, ttn->task.dev->label_cfg.str, cryptShaAsString(local_id), ttn->tx_iterations,
                !local ? "UNKNOWN" : (local->link_adv_sqn == local->packet_link_sqn_ref ? "SOLVED" : "UNSOLVED"));


        if (!local || local->dev_adv_sqn == local->link_adv_dev_sqn_ref) {
                ttn->tx_iterations = 0;
                return TLV_TX_DATA_DONE;
        }

        msg->destination_local_id = local->local_id;

        dbgf_track(DBGT_INFO, "creating msg=%d",
                ((int) ((((char*) msg) - ((char*) tx_iterator_cache_hdr_ptr(it))) / sizeof (*msg))));

        return sizeof (struct msg_dev_req);
 }


STATIC_FUNC
int32_t rx_frame_dev_adv( struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct hdr_dev_adv* hdr = (struct hdr_dev_adv*) it->frame_data;;
        struct msg_dev_adv* adv = (struct msg_dev_adv*) it->msg;

        assertion(-500979, (adv == hdr->msg));
	assertion(-502161, (it->pb->i.verifiedLink));

        uint16_t msgs = it->frame_msgs_length / sizeof (struct msg_dev_adv);

        struct neigh_node *local = it->pb->i.verifiedLink->k.linkDev->local;

        DEVADV_SQN_T dev_sqn = ntohs(hdr->dev_sqn);

        dbgf_all(DBGT_INFO, " ");

        if (!msg_dev_req_enabled) {

                return it->frame_msgs_length;

        } else if (dev_sqn == local->dev_adv_sqn) {

                if (local->dev_adv_msgs != msgs || memcmp(local->dev_adv, adv, it->frame_msgs_length )) {
                        dbgf_sys(DBGT_ERR, "DAD-Alert: dev_adv_msgs=%d != msgs=%d || memcmp(local->dev_adv, adv)=%d",
                                local->dev_adv_msgs, msgs, memcmp(local->dev_adv, adv, it->frame_msgs_length));

                        purge_local_node(local);

                        return TLV_RX_DATA_FAILURE;
                }

        } else if (((DEVADV_SQN_T) (dev_sqn - local->dev_adv_sqn)) > DEVADV_SQN_DAD_RANGE) {

                dbgf_sys(DBGT_ERR, "DAD-Alert: NB=%s dev=%s dev_sqn=%d dev_sqn_max=%d dad_range=%d",
                        it->pb->i.llip_str, it->pb->i.iif->label_cfg.str, dev_sqn, local->dev_adv_sqn, DEVADV_SQN_DAD_RANGE);

                purge_local_node(local);
                
                return TLV_RX_DATA_FAILURE;


        } else if (local->dev_adv_sqn != dev_sqn) {

                dbgf_track(DBGT_INFO, "new DEV_ADV from NB=%s local_id=%s dev=%s dev_sqn=%d->%d",
                        it->pb->i.llip_str,  cryptShaAsString(&local->local_id) , it->pb->i.iif->label_cfg.str,
                        local->dev_adv_sqn, dev_sqn);

                if (local->dev_adv)
                        debugFree(local->dev_adv, -300340);

                local->dev_adv = debugMalloc(it->frame_msgs_length, -300341);

                memcpy(local->dev_adv, adv, it->frame_msgs_length);

                local->dev_adv_sqn = dev_sqn;
//              local->dev_adv_time_max = bmx_time;
                local->dev_adv_msgs = msgs;
        }

        return it->frame_msgs_length;
}


STATIC_FUNC
void set_link_adv_msg(uint16_t myLinkId, LinkNode *link)
{
        my_link_adv_buff[myLinkId].transmitter_dev_idx = link->k.myDev->llip_key.idx;
        my_link_adv_buff[myLinkId].peer_dev_idx = link->k.linkDev->key.dev_idx;
        my_link_adv_buff[myLinkId].peer_local_id = link->k.linkDev->key.local_id;

        link->myLinkId = myLinkId;
        
        if (link->k.linkDev->local->myLinkId == LINKADV_ID_IGNORED)
                link->k.linkDev->local->myLinkId = myLinkId;
}

void update_my_link_adv(uint32_t changes)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *an;
        LinkNode *link;
        struct neigh_node *local;
        uint16_t myLinkId = 0;
        static PKT_SQN_T last_link_packet_sqn = 0;
        static TIME_T last_link_adv_time = 0;
        static uint32_t my_link_adv_changes = LINKADV_CHANGES_NONE;

        my_link_adv_changes += changes;

        // no need to increment link_adv_sqn if no packet has been emitted since last link_adv change:
        if (last_link_packet_sqn != my_packet_sqn && !terminating) {

                if (my_link_adv_changes >= LINKADV_CHANGES_CRITICAL ||
                        (my_link_adv_changes >= LINKADV_CHANGES_NEW && ((TIME_T) (bmx_time - last_link_adv_time)) >= LINKADV_INTERVAL_NEW) ||
                        (my_link_adv_changes >= LINKADV_CHANGES_REMOVED && ((TIME_T) (bmx_time - last_link_adv_time)) >= LINKADV_INTERVAL_REMOVED) ) {

			last_link_packet_sqn = my_packet_sqn;
			my_link_adv_sqn++;

		} else {
			return;
		}
        }

        last_link_adv_time = bmx_time;
        my_link_adv_changes = LINKADV_CHANGES_NONE;

        if (my_link_adv_buff) {
                debugFree(my_link_adv_buff, -300342);
                my_link_adv_buff = NULL;
                my_link_adv_msgs = 0;
        }

        if (terminating)
                return;

        if (link_tree.items)
                my_link_adv_buff = debugMallocReset(link_tree.items * sizeof (struct msg_link_adv), -300343);

        for (an = NULL; (link = avl_iterate_item(&link_tree, &an));){
                link->myLinkId = LINKADV_ID_IGNORED;
                link->k.linkDev->local->myLinkId = LINKADV_ID_IGNORED;
        }

        for (an = NULL; (local = avl_iterate_item(&local_tree, &an));)
                set_link_adv_msg(myLinkId++, local->best_rp_link);

        assertion(-501140, (myLinkId <= LOCALS_MAX));


        for (an = NULL; (link = avl_iterate_item(&link_tree, &an));) {

                if (link->myLinkId > LINKADV_ID_IGNORED)
                        continue;

                //TODO: sort out lndevs with reasonable worse rq than best_rqlndev: if (lndev->key.link->local->best_lndev)
                if (link->timeaware_rx_probe * LINKADV_ADD_RP_4DIF >=
                        link->k.linkDev->local->best_rp_link->timeaware_rx_probe * LINKADV_ADD_RP_4MIN)
                        set_link_adv_msg(myLinkId++, link);

        }

        my_link_adv_msgs = myLinkId;

        if (link_adv_tx_unsolicited) {

                struct dev_node *dev;

                for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));)
                        schedule_tx_task(&dev->dummyLink, FRAME_TYPE_LINK_ADV, (myLinkId * sizeof (struct msg_link_adv)), 0, 0);

        }

        dbgf_track(DBGT_INFO, "new link_adv_sqn=%d with link_adv_msgs=%d", my_link_adv_sqn, my_link_adv_msgs);
}


STATIC_FUNC
int32_t tx_frame_link_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct hdr_link_adv* hdr = ((struct hdr_link_adv*) tx_iterator_cache_hdr_ptr(it));

        assertion(-500933, (hdr->msg == ((struct msg_link_adv*) tx_iterator_cache_msg_ptr(it))));
        assertion(-500934, ((int) it->ttn->frame_msgs_length <= tx_iterator_cache_data_space_pref(it)));

        if ((my_link_adv_msgs * (int32_t)sizeof (struct msg_link_adv)) > tx_iterator_cache_data_space_pref(it))
                return TLV_TX_DATA_FULL;

        hdr->dev_sqn_ref = htons(my_dev_adv_sqn);

        memcpy(hdr->msg, my_link_adv_buff, (my_link_adv_msgs * sizeof (struct msg_link_adv)));

        return (my_link_adv_msgs * sizeof (struct msg_link_adv));
}


STATIC_FUNC
int32_t rx_msg_link_req( struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct msg_link_req* req = ((struct msg_link_req*) it->msg);

        if (cryptShasEqual(&req->destination_local_id, &self->nodeId))
		schedule_tx_task(&it->pb->i.iif->dummyLink, FRAME_TYPE_LINK_ADV, (my_link_adv_msgs * sizeof(struct msg_link_adv)), 0, 0);
 

        return sizeof (struct msg_link_req);
}


STATIC_FUNC
int32_t tx_msg_link_req(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node *ttn = it->ttn;
        struct msg_link_req *msg = ((struct msg_link_req*) tx_iterator_cache_msg_ptr(it));
	LOCAL_ID_T *local_id = ((LOCAL_ID_T*)ttn->task.data);
        struct neigh_node *local = avl_find_item(&local_tree, local_id);

        assertion(-500988, (ttn->tx_iterations > 0 && ttn->considered_ts != bmx_time));

        dbgf_track(DBGT_INFO, "%s dev=%s to local_id=%s iterations=%d %s",
                it->db->handls[ttn->task.type].name, ttn->task.dev->label_cfg.str, cryptShaAsShortStr(local_id), ttn->tx_iterations,
                !local ? "UNKNOWN" : (local->link_adv_sqn == local->packet_link_sqn_ref ? "SOLVED" : "UNSOLVED"));


        if (!local || local->link_adv_sqn == local->packet_link_sqn_ref) {
                ttn->tx_iterations = 0;
                return TLV_TX_DATA_DONE;
        }

        msg->destination_local_id = local->local_id;

        dbgf_track(DBGT_INFO, "creating msg=%d",
                ((int) ((((char*) msg) - ((char*) tx_iterator_cache_hdr_ptr(it))) / sizeof (*msg))));

        return sizeof (struct msg_link_req);
 }



STATIC_FUNC
int32_t rx_frame_link_adv( struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502162, (it->pb->i.verifiedLink));

        struct hdr_link_adv* hdr = (struct hdr_link_adv*) it->frame_data;;
        struct msg_link_adv* adv = (struct msg_link_adv*) it->msg;

        uint16_t msgs = it->frame_msgs_length  / sizeof (struct msg_link_adv);

        struct neigh_node *local = it->pb->i.verifiedLink->k.linkDev->local;

	LINKADV_SQN_T link_sqn = local->packet_link_sqn_ref;
        DEVADV_SQN_T dev_sqn_ref = ntohs(hdr->dev_sqn_ref);


        dbgf_all(DBGT_INFO, " ");

       // DAD:link_adv_sqn mismatch has been checked in get_link_node()!

        if (link_sqn == local->link_adv_sqn) {

                if (local->link_adv_dev_sqn_ref != dev_sqn_ref || local->link_adv_msgs != msgs || memcmp(local->link_adv, adv, it->frame_msgs_length )) {

                        dbgf_sys(DBGT_ERR,
                                "DAD-Alert: link_adv_dev_sqn_ref=%d != dev_sqn_ref=%d || link_adv_msgs=%d != msgs=%d || memcmp(link_adv, adv)=%d",
                                local->link_adv_dev_sqn_ref, dev_sqn_ref, local->link_adv_msgs, msgs, memcmp(local->link_adv, adv, it->frame_msgs_length));

                        purge_local_node(local);

                        return TLV_RX_DATA_FAILURE;
                }

        } else {

                dbgf_track(DBGT_INFO, "new LINK_ADV from NB=%s dev=%s link_sqn=%d->%d dev_sqn=%d->%d dev_adv_sqn=%d",
                        it->pb->i.llip_str, it->pb->i.iif->label_cfg.str, local->link_adv_sqn, link_sqn,
                        local->link_adv_dev_sqn_ref, dev_sqn_ref, local->dev_adv_sqn);


                if (local->link_adv)
                        debugFree(local->link_adv, -300344);

                local->link_adv = debugMalloc(it->frame_msgs_length, -300345);

                memcpy(local->link_adv, adv, it->frame_msgs_length);

                local->link_adv_sqn = link_sqn;
                local->link_adv_time = bmx_time;
                local->link_adv_dev_sqn_ref = dev_sqn_ref;
                local->link_adv_msgs = msgs;
                local->neighLinkId = LINKADV_ID_IGNORED;

                uint16_t m;
                for (m = 0; m < msgs; m++) {

			if (cryptShasEqual(&local->link_adv[m].peer_local_id, &self->nodeId)) {
                                local->neighLinkId = m;
                                break;
                        }
                }

        }


        return it->frame_msgs_length;
}




STATIC_FUNC
int32_t tx_frame_rp_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct msg_rp_adv* msg = ((struct msg_rp_adv*) tx_iterator_cache_msg_ptr(it));
        struct avl_node *an;
        LinkNode *link;
        uint16_t msgs = 0;
        uint16_t msg_max = 0;

        if ((my_link_adv_msgs * (int32_t)sizeof (struct msg_rp_adv)) > tx_iterator_cache_data_space_pref(it))
                return TLV_TX_DATA_FULL;

        for (an = NULL; (link = avl_iterate_item(&link_tree, &an));) {

                if (link->myLinkId == LINKADV_ID_IGNORED)
                        continue;

                assertion(-501040, (link->myLinkId < my_link_adv_msgs ));
                assertion(-501041, (link->rx_probe_record.hello_umetric <= UMETRIC_MAX));

                if (link->timeaware_rx_probe * LINKADV_ADD_RP_4DIF <
                        link->k.linkDev->local->best_rp_link->timeaware_rx_probe * LINKADV_ADD_RP_4MAX)
                        continue;

                msg[link->myLinkId].rp_127range = (link->timeaware_rx_probe * 127) / UMETRIC_MAX;

                msg[link->myLinkId].ogm_request = link->k.linkDev->local->orig_routes ? YES : NO;

                msg_max = XMAX(msg_max, link->myLinkId);

                msgs++;
        }

        assertion(-501042, (msgs <= my_link_adv_msgs));

        if (msgs)
                return ((msg_max + 1) * sizeof (struct msg_rp_adv));
        else
                return TLV_TX_DATA_DONE;

}


STATIC_FUNC
int32_t rx_frame_rp_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502163, (it->pb->i.verifiedLink));

        struct msg_rp_adv* adv = (struct msg_rp_adv*) it->msg;
	struct neigh_node *local = it->pb->i.verifiedLink->k.linkDev->local;
	LINKADV_SQN_T link_sqn = local->packet_link_sqn_ref;
        struct avl_node *link_an = NULL;
	LinkDevNode *linkDev;
        LinkNode *link = NULL;
        uint16_t msgs = it->frame_msgs_length / sizeof (struct msg_rp_adv);
        uint16_t m;

        if (link_sqn != local->link_adv_sqn)
                return it->frame_msgs_length;

        if (msgs > local->link_adv_msgs)
                return TLV_RX_DATA_FAILURE;


        local->rp_adv_time = bmx_time;

        while ((linkDev = avl_iterate_item(&local->linkDev_tree, &link_an))) {

                for (link = NULL; (link = list_iterate(&linkDev->link_list, link));)
                        link->tx_probe_umetric = 0;

        }


        for (m = 0; m < msgs; m++) {

		if (!cryptShasEqual(&local->link_adv[m].peer_local_id, &self->nodeId))
                        continue;


                if (local->rp_ogm_request_rcvd != adv[m].ogm_request) {

                        dbgf_track(DBGT_INFO, "changed ogm_request=%d from NB=%s", adv[m].ogm_request, it->pb->i.llip_str);

                        if (local->rp_ogm_request_rcvd)
                                memset(local->ogm_aggregations_not_acked, 0, sizeof (local->ogm_aggregations_not_acked));

                        local->rp_ogm_request_rcvd = adv[m].ogm_request;
                }

                if (!(linkDev = avl_find_item(&local->linkDev_tree, &local->link_adv[m].transmitter_dev_idx)))
                        continue;


                for (link = NULL; (link = list_iterate(&linkDev->link_list, link));) {

                        if (link->k.myDev->llip_key.idx == local->link_adv[m].peer_dev_idx) {

                                link->tx_probe_umetric = (UMETRIC_MAX * ((UMETRIC_T) (adv[m].rp_127range))) / 127;
                                lndev_assign_best(local, link);
                                break;
                        }
                }
        }


        return it->frame_msgs_length;
}



















STATIC_FUNC
int32_t tx_frame_ogm_advs(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node *ttn = it->ttn;
        AGGREG_SQN_T sqn = *((AGGREG_SQN_T*)ttn->task.data); // because AGGREG_SQN_T is just 8 bit!

        struct ogm_aggreg_node *oan = list_find_next(&ogm_aggreg_list, &sqn, NULL);

        if (oan) {

                dbgf_all(DBGT_INFO, "aggregation_sqn=%d ogms+jumps=%d dest_bytes=%d attempt=%d",
                        oan->sqn, oan->aggregated_msgs, oan->ogm_dest_bytes, oan->tx_attempt);

                uint16_t msgs_length = (oan->aggregated_msgs * sizeof (struct msg_ogm_adv));
                struct hdr_ogm_adv* hdr = ((struct hdr_ogm_adv*) tx_iterator_cache_hdr_ptr(it));

                assertion(-501141, (oan->sqn == sqn));
                assertion(-501143, (oan->ogm_dest_bytes <= (OGM_DEST_ARRAY_BIT_SIZE/8)));
                assertion(-500859, (hdr->msg == ((struct msg_ogm_adv*) tx_iterator_cache_msg_ptr(it))));
                assertion(-500429, (ttn->frame_msgs_length == msgs_length + oan->ogm_dest_bytes));
                assertion(-501144, (((int) ttn->frame_msgs_length) <= tx_iterator_cache_data_space_pref(it)));

                hdr->aggregation_sqn = sqn;
		hdr->transmittersIID = htons(myIID4me);
                hdr->ogm_dst_field_size = oan->ogm_dest_bytes;
                
                if (oan->ogm_dest_bytes)
                        memcpy(tx_iterator_cache_msg_ptr(it), oan->ogm_dest_field, oan->ogm_dest_bytes);

                memcpy(tx_iterator_cache_msg_ptr(it) + oan->ogm_dest_bytes, oan->ogm_advs, msgs_length);

                return ttn->frame_msgs_length;
        }

        // this happens when the to-be-send ogm aggregation has already been purged...
        dbgf_sys(DBGT_WARN, "aggregation_sqn %d does not exist anymore in ogm_aggreg_list", sqn);
        ttn->tx_iterations = 0;
        return TLV_TX_DATA_DONE;
}


STATIC_FUNC
int32_t tx_msg_ogm_ack(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node *ttn = it->ttn;
        assertion(-500587, (ttn->task.linkDev));

        struct msg_ogm_ack *ack = (struct msg_ogm_ack *) (tx_iterator_cache_msg_ptr(it));

        //ack->transmitterIID4x = htons(ttn->task.myIID4x);
        ack->aggregation_sqn = *((AGGREG_SQN_T*)ttn->task.data);
        ack->ogm_destination = ttn->task.linkDev->local->myLinkId;

        dbgf_all(DBGT_INFO, " aggreg_sqn=%d to ogm_destination=%d", ack->aggregation_sqn, ack->ogm_destination);

        return sizeof (struct msg_ogm_ack);
}







STATIC_FUNC
int32_t rx_frame_ogm_advs(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502164, (it->pb->i.verifiedLink));

        struct hdr_ogm_adv *hdr = (struct hdr_ogm_adv *) it->frame_data;
        struct packet_buff *pb = it->pb;
        struct neigh_node *local = pb->i.verifiedLink->k.linkDev->local;
	LINKADV_SQN_T link_sqn = local->packet_link_sqn_ref;
        uint8_t *ogm_destination_field = it->msg;
        AGGREG_SQN_T aggregation_sqn = hdr->aggregation_sqn;
        uint16_t ogm_dst_field_size = hdr->ogm_dst_field_size;
	IID_T transmittersIID = ntohs(hdr->transmittersIID);

        if (ogm_dst_field_size > (OGM_DEST_ARRAY_BIT_SIZE / 8) ||
                it->frame_msgs_length < ((int) sizeof (struct msg_ogm_adv)) ||
                ogm_dst_field_size > (it->frame_msgs_length - sizeof (struct msg_ogm_adv))) {

                dbgf_sys(DBGT_ERR, "invalid ogm_dst_field_size=%d frame_msgs_length=%d ",
                        ogm_dst_field_size, it->frame_msgs_length);
                return TLV_RX_DATA_FAILURE;
        }

        if (link_sqn != local->link_adv_sqn) {

                dbgf_track(DBGT_INFO, "rcvd link_sqn=%d != local->link_adv_sqn=%d", link_sqn, local->link_adv_sqn);
                return it->frame_msgs_length;

        } else if (ogm_dst_field_size > ((local->link_adv_msgs / 8) + ((local->link_adv_msgs % 8) ? 1 : 0))) {

                dbgf_sys(DBGT_ERR, "invalid ogm_dst_field_size=%d link_adv_msgs=%d",
                        ogm_dst_field_size, local->link_adv_msgs);
                return TLV_RX_DATA_FAILURE;
        }

        IDM_T only_process_sender_and_refresh_all = !local->orig_routes;

        IDM_T ack_sender = (local->neighLinkId != LINKADV_ID_IGNORED &&
                local->neighLinkId < (ogm_dst_field_size * 8) &&
                bit_get(ogm_destination_field, (ogm_dst_field_size * 8), local->neighLinkId));

        if (only_process_sender_and_refresh_all || !ack_sender) {
                dbgf_all(DBGT_INFO, "not wanted: link_adv_msg_for_me=%d ogm_destination_bytes=%d orig_routes=%d",
                        local->neighLinkId, ogm_dst_field_size, local->orig_routes);
        }


        // TODO: ogm_aggregations from this guy must be processed only for ogms from him if not being in his ogm_destination_array
        // to find out about the direct metric to him....

        uint16_t msgs = (it->frame_msgs_length - ogm_dst_field_size) / sizeof (struct msg_ogm_adv);

        dbgf_all(DBGT_INFO, " ");


        if (!(local->ogm_new_aggregation_rcvd || local->ogm_aggregation_cleard_max /*ever used*/) ||
                ((AGGREG_SQN_MASK)& (local->ogm_aggregation_cleard_max - aggregation_sqn)) >= AGGREG_SQN_CACHE_RANGE) {

                if ((local->ogm_new_aggregation_rcvd || local->ogm_aggregation_cleard_max /*ever used*/) &&
                        ((AGGREG_SQN_MASK)& (aggregation_sqn - local->ogm_aggregation_cleard_max)) > AGGREG_SQN_CACHE_WARN) {

                        dbgf_track(DBGT_WARN, "neigh=%s with NEW, unknown, and LOST aggregation_sqn=%d  max=%d  ogms=%d",
                                pb->i.llip_str, aggregation_sqn, local->ogm_aggregation_cleard_max, msgs);
                } else {
                        dbgf_all(DBGT_INFO, "neigh=%s with NEW, unknown aggregation_sqn=%d  max=%d  msgs=%d",
                                pb->i.llip_str, aggregation_sqn, local->ogm_aggregation_cleard_max, msgs);
                }

                if ((AGGREG_SQN_MASK & (aggregation_sqn - (local->ogm_aggregation_cleard_max + 1))) >= AGGREG_SQN_CACHE_RANGE) {

                        memset(local->ogm_aggregations_rcvd, 0, AGGREG_SQN_CACHE_RANGE / 8);
                        
                } else {
                        bits_clear(local->ogm_aggregations_rcvd, AGGREG_SQN_CACHE_RANGE,
                                ((AGGREG_SQN_MASK)& (local->ogm_aggregation_cleard_max + 1)), aggregation_sqn, AGGREG_SQN_MASK);
                }

/*
                if ((AGGREG_SQN_MASK& (neigh->ogm_aggregation_cleard_max + 1 - aggregation_sqn)) >= AGGREG_SQN_CACHE_RANGE) {
                        memset(neigh->ogm_aggregations_rcvd, 0, AGGREG_SQN_CACHE_RANGE / 8);
                } else {
                        bits_clear(neigh->ogm_aggregations_rcvd, AGGREG_SQN_CACHE_RANGE,
                                ((AGGREG_SQN_MASK)& (neigh->ogm_aggregation_cleard_max + 1)), aggregation_sqn, AGGREG_SQN_MASK);
                }
*/
                
                local->ogm_aggregation_cleard_max = aggregation_sqn;
                local->ogm_new_aggregation_rcvd = bmx_time;
                
        } else {

                if (bit_get(local->ogm_aggregations_rcvd, AGGREG_SQN_CACHE_RANGE, aggregation_sqn)) {

                        dbgf_all(DBGT_INFO, "neigh: id=%s via dev=%s with OLD, already KNOWN ogm_aggregation_sqn=%d",
                                cryptShaAsString(&local->dhn->on->nodeId), pb->i.iif->label_cfg.str, aggregation_sqn);

                        if (ack_sender)
                                schedule_tx_task(local->best_tp_link, FRAME_TYPE_OGM_ACK, SCHEDULE_MIN_MSG_SIZE, &aggregation_sqn, sizeof(aggregation_sqn));

                        return it->frame_msgs_length;

                } else /*if (((AGGREG_SQN_MASK)& (neigh->ogm_aggregation_cleard_max - aggregation_sqn)) > AGGREG_SQN_CACHE_WARN)*/ {

                        dbgf_track(DBGT_WARN, "neigh=%s  orig=%s with OLD, unknown aggregation_sqn=%d  max=%d  ogms=%d",
                                pb->i.llip_str, cryptShaAsString(&local->dhn->on->nodeId),
                                aggregation_sqn, local->ogm_aggregation_cleard_max, msgs);
                }
        }



        uint16_t m;
        IID_T neighIID4x = 0;

        for (m = 0; m < msgs; m++) {

		struct msg_ogm_adv ogm = { .u.u32 = ntohl( ((struct msg_ogm_adv*)(it->msg + ogm_dst_field_size))[m].u.u32 ) };

                if (ogm.u.j.iidOffset == OGM_IID_RSVD_JUMP) {

                        dbgf_all(DBGT_INFO, " IID jump from %d to %d", neighIID4x, ogm.u.j.iid);
                        neighIID4x = ogm.u.j.iid;

                        if ((m + 1) >= msgs)
                                return TLV_RX_DATA_FAILURE;

                        continue;

                } else {

                        dbgf_all(DBGT_INFO, " IID offset from %d to %d", neighIID4x, neighIID4x + ogm.u.o.iidOffset);
                        neighIID4x += ogm.u.o.iidOffset;
                }

                IID_NODE_T *dhn = iid_get_node_by_neighIID4x(local, neighIID4x, !only_process_sender_and_refresh_all/*verbose*/);

                if (only_process_sender_and_refresh_all && neighIID4x != transmittersIID)
                        continue;


                struct orig_node *on = dhn ? dhn->on : NULL;

                if (on) {

                        if (((OGM_SQN_MASK) & (ogm.u.o.sqn - on->ogmSqn_rangeMin)) >= on->ogmSqn_rangeSize) {

                                dbgf_sys(DBGT_ERR,
                                        "DAD-Alert: EXCEEDED ogm_sqn=%d neighIID4x=%d id=%s via link=%s sqn_min=%d sqn_range=%d",
                                        ogm.u.o.sqn, neighIID4x, cryptShaAsString(&on->nodeId), pb->i.llip_str,
                                        on->ogmSqn_rangeMin, on->ogmSqn_rangeSize);

                                purge_local_node(local);

                                return TLV_RX_DATA_FAILURE;
                        }

                        if (dhn == self->dhn || on->blocked) {

                                dbgf_all(DBGT_WARN, "%s orig_sqn=%d/%d id=%s via link=%s neighIID4x=%d",
                                        dhn == self->dhn ? "MYSELF" : "BLOCKED",
                                        ogm.u.o.sqn, on->ogmSqn_next, cryptShaAsString(&on->nodeId), pb->i.llip_str, neighIID4x);

                                continue;
                        }

			if (verify_neighTrust(on, local) != SUCCESS) {

				dbgf_sys(DBGT_INFO, "DISTRUSTED neigh=%s for orig=%s",
					cryptShaAsShortStr(&local->local_id), cryptShaAsShortStr(&on->nodeId) );

				continue;
			}

                        FMETRIC_U16_T fm = fmetric(ogm.u.o.mtcMantissa, ogm.u.o.mtcExponent);
                        IDM_T valid_metric = is_fmetric_valid(fm);

                        if (!valid_metric) {

                                dbgf_mute(50, DBGL_SYS, DBGT_ERR,
                                        "INVALID metric! orig_sqn=%d/%d orig=%s via link=%s neighIID4x=%d",
                                        ogm.u.o.sqn, on->ogmSqn_next, cryptShaAsString(&on->nodeId), pb->i.llip_str, neighIID4x);

                                return TLV_RX_DATA_FAILURE;
                        }

                        UMETRIC_T um = fmetric_to_umetric(fm);

                        if (um < on->path_metricalgo->umetric_min) {

                                dbgf_mute(50, DBGL_SYS, DBGT_ERR,
                                        "UNUSABLE metric=%ju usable=%ju orig_sqn=%d/%d id=%s via link=%s neighIID4x=%d",
                                        um, on->path_metricalgo->umetric_min,
                                        ogm.u.o.sqn, on->ogmSqn_next, cryptShaAsString(&on->nodeId), pb->i.llip_str, neighIID4x);

                                continue;
                        } 
                        
                        if (update_path_metrics(pb, on, ogm.u.o.sqn, &um) != SUCCESS) {
                                assertion(-501145, (0));
                                return TLV_RX_DATA_FAILURE;
                        }

                } else {

                        dbgf_track(DBGT_WARN, "%s orig_sqn=%d or neighIID4x=%d id=%s via link=%s sqn_min=%d sqn_range=%d",
                                !dhn ? "UNKNOWN DHN" : "INVALIDATED",
                                ogm.u.o.sqn, neighIID4x,
                                on ? cryptShaAsString(&on->nodeId) : DBG_NIL,
                                pb->i.llip_str,
                                on ? on->ogmSqn_rangeMin : 0,
                                on ? on->ogmSqn_rangeSize : 0);

                        if (!dhn) {
                                dbgf_track(DBGT_INFO, "schedule frame_type=%d", FRAME_TYPE_DHASH_REQ);
                                schedule_tx_task(local->best_tp_link, FRAME_TYPE_DHASH_REQ, SCHEDULE_MIN_MSG_SIZE, &neighIID4x, sizeof(IID_T));
                        }

                }
        }

        bit_set(local->ogm_aggregations_rcvd, AGGREG_SQN_CACHE_RANGE, aggregation_sqn, 1);

        if (ack_sender)
                schedule_tx_task(local->best_tp_link, FRAME_TYPE_OGM_ACK, SCHEDULE_MIN_MSG_SIZE, &aggregation_sqn, sizeof(aggregation_sqn));

        return it->frame_msgs_length;
}






STATIC_FUNC
int32_t rx_frame_ogm_acks(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502165, (it->pb->i.verifiedLink));

        struct packet_buff *pb = it->pb;
        struct neigh_node *local = pb->i.verifiedLink->k.linkDev->local;
	LINKADV_SQN_T link_sqn = local->packet_link_sqn_ref;
        uint16_t pos;

        if (!local)
                return it->frame_msgs_length;

        if (link_sqn != local->link_adv_sqn || local->neighLinkId == LINKADV_ID_IGNORED) {

                dbgf_track(DBGT_INFO, "rcvd link_sqn=%d != local->link_adv_sqn=%d or ignored link_adv_msg_for_me=%d",
                        link_sqn, local->link_adv_sqn, local->neighLinkId);

                return it->frame_msgs_length;
        }

        for (pos = 0; pos < it->frame_msgs_length; pos += sizeof (struct msg_ogm_ack)) {

                struct msg_ogm_ack *ack = (struct msg_ogm_ack *) (it->frame_data + pos);

                if (local->neighLinkId != ack->ogm_destination)
                        continue;

                AGGREG_SQN_T aggregation_sqn = ack->aggregation_sqn;

                if (((AGGREG_SQN_MASK)& (ogm_aggreg_sqn_max - aggregation_sqn)) < AGGREG_SQN_CACHE_RANGE) {

                        bit_set(local->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, aggregation_sqn, 0);

                        dbgf_all(DBGT_INFO, "neigh %s  sqn %d <= sqn_max %d",
                                pb->i.llip_str, aggregation_sqn, ogm_aggreg_sqn_max);

                } else {

                        dbgf_sys(DBGT_ERR, "neigh %s  sqn %d <= sqn_max %d",
                                pb->i.llip_str, aggregation_sqn, ogm_aggreg_sqn_max);

                }
        }

        return it->frame_msgs_length;
}




STATIC_FUNC
int32_t rx_msg_dhash_adv( struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct packet_buff *pb = it->pb;
        struct msg_dhash_adv *adv = (struct msg_dhash_adv*) (it->msg);
	DHASH_T *dhash = &adv->dhash;
        IID_T neighIID4x = ntohs(adv->transmitterIID4x);

        dbgf_track(DBGT_INFO, "dhash=%s via NB: %s", cryptShaAsString(dhash), pb->i.llip_str);
	assertion(-502166, (it->pb->i.verifiedLink));
        assertion(-500689, (!cryptShasEqual(&pb->i.verifiedLink->k.linkDev->local->dhn->dhash, &(self->dhn->dhash)))); // cant be transmitter' and myselfs'

	struct neigh_node *viaNeigh = pb->i.verifiedLink->k.linkDev->local;
	IDM_T is_transmitter = cryptShasEqual(dhash, &viaNeigh->dhn->dhash);
	struct dhash_node *dhn = NULL, *dhnOld = NULL;


        if (neighIID4x <= IID_RSVD_MAX)
                return TLV_RX_DATA_FAILURE;

	if (avl_find(&deprecated_dhash_tree, dhash)) {

		dhn = (struct dhash_node*)REJECTED_PTR;

	} else if ((dhn = dhnOld = get_dhash_tree_node(dhash)) || (dhn = process_description(pb, dhash))) {

		if (dhn == REJECTED_PTR) {

			deprecate_dhash_iid(NULL, dhash, NULL);

		} else if (dhn == FAILURE_PTR || dhn == UNRESOLVED_PTR) {

		} else if (iid_set_neighIID4x(&viaNeigh->neighIID4x_repos, neighIID4x, dhn->myIID4orig) == FAILURE) {

			dhn = (struct dhash_node*)FAILURE_PTR;
			
		} else {
			ASSERTION(-502214, (dhn == get_dhash_tree_node(dhash)));
			assertion(-502167, IMPLIES(is_transmitter, dhn == viaNeigh->dhn));
			assertion(-502168, IMPLIES(!is_transmitter, dhn != viaNeigh->dhn));

			if (dhn == self->dhn)
				viaNeigh->neighIID4me = neighIID4x;
			
			if (!dhnOld && desc_adv_tx_unsolicited)
				schedule_best_tp_links(viaNeigh, FRAME_TYPE_DESC_ADVS, dhn->desc_frame_len, &dhn->dhash, sizeof(DHASH_T));

			if (!dhnOld && dhash_adv_tx_unsolicited)
				schedule_best_tp_links(NULL, FRAME_TYPE_DHASH_ADV, SCHEDULE_MIN_MSG_SIZE, &dhn->myIID4orig, sizeof(IID_T));

		}
        }

	dbgf_track(DBGT_INFO, "via dev=%s NB=%s dhash=%8X..  dhn=%s neighIID4x=%d is_transmitter=%d (on)nodeId=%s",
                pb->i.iif->label_cfg.str, pb->i.llip_str, dhash->h.u32[0],
                (dhn ? (dhn==FAILURE_PTR?"FAILURE":
                        (dhn==UNRESOLVED_PTR?"UNRESOLVED":(dhn==REJECTED_PTR?"REJECTED":"RESOLVED"))):"UNKNOWN"),
                neighIID4x, is_transmitter,
		((dhn && dhn!=FAILURE_PTR && dhn!=UNRESOLVED_PTR && dhn!=REJECTED_PTR && dhn->on) ?
			cryptShaAsString(&dhn->on->nodeId) : DBG_NIL));



	if (dhn == FAILURE_PTR)
		return TLV_RX_DATA_FAILURE;
	else
		return sizeof (struct msg_dhash_adv);
}


STATIC_FUNC
int32_t rx_frame_description_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	int32_t goto_error_code;
	GLOBAL_ID_T *nodeId = nodeIdFromDescAdv(it->frame_data);

	if (!nodeId || (it->frame_data_length > (int) MAX_DESC_SIZE))
		goto_error(finish, TLV_RX_DATA_FAILURE);

	struct tlv_hdr pKTlvHdr = { .u.u16 = ntohs(((struct tlv_hdr*)it->frame_data)->u.u16) };
	struct tlv_hdr sigTlvHdr = { .u.u16 = ntohs(((struct tlv_hdr*)(it->frame_data + pKTlvHdr.u.tlv.length))->u.u16) };
	DHASH_T dhash;
	cryptShaAtomic(it->frame_data, it->frame_data_length, &dhash);

	struct dhash_node *deprecated = avl_find_item(&deprecated_dhash_tree, &dhash);
	struct dhash_node *dhn = !deprecated ? get_dhash_tree_node(&dhash) : NULL;
	uint8_t supported = supported_pubkey(nodeId);
	struct ref_node *pubKeyRef = ref_node_get(nodeId);
	int signature = pubKeyRef && pubKeyRef->f_body ?
		process_signature(sigTlvHdr.u.tlv.length - sizeof(struct tlv_hdr), 
		((struct dsc_msg_signature*)(it->frame_data + pKTlvHdr.u.tlv.length + sizeof(struct tlv_hdr))),
		it->frame_data, it->frame_data_length, ((struct dsc_msg_pubkey*)pubKeyRef->f_body)) : TLV_RX_DATA_REJECTED;

	dbgf_sys( DBGT_INFO, "rcvd supportedKey=%d availableKey=%d deprecated=%d signature=%d known=%d dhash=%s nodeId=%s via_dev=%s via_ip=%s",
		supported, !!pubKeyRef, !!deprecated, signature, !!dhn, memAsHexString(&dhash, sizeof(SHA1_T)),
		cryptShaAsString(nodeId), it->pb->i.iif->label_cfg.str, it->pb->i.llip_str);

	assertion(-500000, IMPLIES(dhn, supported));
	assertion(-500000, IMPLIES(dhn, pubKeyRef));

	if (signature < TLV_RX_DATA_REJECTED)
		goto_error(finish, TLV_RX_DATA_FAILURE);

	if (!deprecated && !dhn && !supported)
		deprecate_dhash_iid(NULL, &dhash, nodeId);

	if (!deprecated && !dhn && supported && !pubKeyRef)
		schedule_tx_task(&it->pb->i.iif->dummyLink, FRAME_TYPE_REF_REQ, SCHEDULE_MIN_MSG_SIZE, nodeId, sizeof(SHA1_T));

	if (!deprecated && !dhn && supported && pubKeyRef && signature >= TLV_RX_DATA_PROCESSED && processDescriptionsViaUnverifiedLink) {

		cache_description(it->frame_data, it->frame_data_length, &dhash);

		if ((dhn = process_description(it->pb, &dhash))) {

			if (dhn == FAILURE_PTR) {

				goto_error(finish, TLV_RX_DATA_FAILURE);

			} else if (dhn != REJECTED_PTR && dhn != UNRESOLVED_PTR) {

				ASSERTION(-502215, (dhn == get_dhash_tree_node(&dhash)));

				if (desc_adv_tx_unsolicited)
					schedule_best_tp_links(NULL, FRAME_TYPE_DESC_ADVS, dhn->desc_frame_len, &dhn->dhash, sizeof(DHASH_T));

				if (dhash_adv_tx_unsolicited)
					schedule_best_tp_links(NULL, FRAME_TYPE_DHASH_ADV, SCHEDULE_MIN_MSG_SIZE, &dhn->myIID4orig, sizeof(IID_T));
			}
		}
	}
	
        goto_error(finish, it->frame_data_length);

finish:
	return goto_error_code;
}


STATIC_FUNC
int32_t rx_msg_dhash_request(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502169, (it->pb->i.verifiedLink));

        struct packet_buff *pb = it->pb;
        struct hdr_dhash_request *hdr = (struct hdr_dhash_request*) (it->frame_data);
        struct msg_dhash_request *msg = (struct msg_dhash_request*) (it->msg);
        IID_T myIID4x = ntohs(msg->receiverIID4x);

        if (!cryptShasEqual(&hdr->destination_local_id, &self->nodeId))
		//TODO: consider that the received local_id might be a duplicate:
                return sizeof ( struct msg_dhash_request);

        dbgf_track(DBGT_INFO, "%s NB %s destination_local_id=%s myIID4x %d",
                it->handl->name, pb->i.llip_str, cryptShaAsShortStr(&hdr->destination_local_id), myIID4x);

        if (myIID4x <= IID_RSVD_MAX)
                return TLV_RX_DATA_FAILURE;

        struct dhash_node *dhn = iid_get_node_by_myIID4x(myIID4x);
        struct orig_node *on = dhn ? dhn->on : NULL;

        assertion(-500270, (IMPLIES(dhn, (on && dhn->desc_frame))));

        if (!dhn || ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)) > DEF_DESC0_REFERRED_TO) {

                dbgf_track(DBGT_WARN, "%s from %s requesting %s %s",
                        it->handl->name, pb->i.llip_str,
                        dhn ? "REFERRED TIMEOUT" : "INVALID or UNKNOWN", on ? cryptShaAsString(&on->nodeId) : "?");

                return sizeof ( struct msg_dhash_request);
        }

        assertion(-500251, (dhn && dhn->myIID4orig == myIID4x));

	dhn->referred_by_me_timestamp = bmx_time;

	schedule_tx_task(pb->i.verifiedLink->k.linkDev->local->best_tp_link, FRAME_TYPE_DHASH_ADV, SCHEDULE_MIN_MSG_SIZE, &myIID4x, sizeof(IID_T));

        // most probably the requesting node is also interested in my metric to the requested node:
        if (on->curr_rt_link && on->ogmSqn_next == on->ogmSqn_send &&
                (((OGM_SQN_MASK) & (on->ogmSqn_next - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize) //needed after description updates!
                ) {
                set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_next, ((OGM_SQN_T) (on->ogmSqn_next - 1)));
        }

        return sizeof ( struct msg_dhash_request);
}


STATIC_FUNC
int32_t rx_msg_description_request(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct packet_buff *pb = it->pb;
        struct hdr_description_request *hdr = (struct hdr_description_request*) (it->frame_data);
        struct msg_description_request *msg = (struct msg_description_request*) (it->msg);

	dbgf_track(DBGT_INFO, "%s NB %s destination_local_id=%s dhash=%s",
		it->handl->name, pb->i.llip_str, cryptShaAsString(&hdr->destination_local_id), cryptShaAsString(&msg->dhash));

	assertion(-502170, (!pb->i.verifiedLink));
	assertion(-502171, (pb->i.iif));

        if (is_zero(&hdr->destination_local_id, sizeof(LOCAL_ID_T)) ?
		(cryptShasEqual(&msg->dhash, &self->dhn->dhash)) :
		(cryptShasEqual(&hdr->destination_local_id, &self->nodeId))) {

		dbgf_track(DBGT_INFO, "%s NB %s destination_local_id=%s dhash=%s",
			it->handl->name, pb->i.llip_str, cryptShaAsString(&hdr->destination_local_id), cryptShaAsString(&msg->dhash));

		struct dhash_node *dhn = get_dhash_tree_node(&msg->dhash);
		struct orig_node *on = dhn ? dhn->on : NULL;

		if (!dhn || ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)) > DEF_DESC0_REFERRED_TO) {

			dbgf_track(DBGT_WARN, "%s from %s requesting UNKNOWN dhash=%s dhn=%p",
				it->handl->name, pb->i.llip_str, cryptShaAsString(&msg->dhash), (void*)dhn);

			return sizeof(struct msg_description_request);
		}

		dhn->referred_by_me_timestamp = bmx_time;

		schedule_tx_task(&pb->i.iif->dummyLink, FRAME_TYPE_DESC_ADVS, dhn->desc_frame_len, &msg->dhash, sizeof(DHASH_T));

		if (dhash_adv_tx_unsolicited)
			schedule_tx_task(&pb->i.iif->dummyLink, FRAME_TYPE_DHASH_ADV, SCHEDULE_MIN_MSG_SIZE, &dhn->myIID4orig, sizeof(IID_T));


		// most probably the requesting node is also interested in my metric to the requested node:
		if (on->curr_rt_link && on->ogmSqn_next == on->ogmSqn_send &&
			(((OGM_SQN_MASK) & (on->ogmSqn_next - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize) //needed after description updates!
			) {
			set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_next, ((OGM_SQN_T) (on->ogmSqn_next - 1)));
		}
	}
        return sizeof (struct msg_description_request);
}



STATIC_FUNC
int32_t rx_msg_hello_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	assertion(-502172, (it->pb->i.verifiedLink));

	LinkNode *link = it->pb->i.verifiedLink;
        struct msg_hello_adv *msg = (struct msg_hello_adv*) (it->msg);
        HELLO_SQN_T hello_sqn = ntohs(msg->hello_sqn);


        dbgf_all(DBGT_INFO, "NB=%s via dev=%s SQN=%d",
                it->pb->i.llip_str, it->pb->i.iif->label_cfg.str, hello_sqn);

        if (it->msg != it->frame_data) {
                dbgf_sys(DBGT_WARN, "rcvd %d %s messages in frame_msgs_length=%d",
                        (it->frame_msgs_length / ((uint32_t)sizeof (struct msg_hello_adv))),
                        packet_frame_db->handls[FRAME_TYPE_HELLO_ADV].name, it->frame_msgs_length);
        }

        update_link_probe_record(link, hello_sqn, 1);

	// check if this link is currently ignored in our link_adv frames but
	// is actually a reasonable good link which should be included so that
	// also link_rp msgs could be send:
        if (link->myLinkId == LINKADV_ID_IGNORED && (
                link == link->k.linkDev->local->best_rp_link || // its our best link or
                (link->timeaware_rx_probe * LINKADV_ADD_RP_4DIF >= // its reasonable good compared to our best link
                link->k.linkDev->local->best_rp_link->timeaware_rx_probe * LINKADV_ADD_RP_4MAX)
                )) {
		// then: create new link_adv frame which includes this link.
                update_my_link_adv(LINKADV_CHANGES_NEW);
        }


        return sizeof (struct msg_hello_adv);
}

IDM_T desc_frame_changed(  struct rx_frame_iterator *it, uint8_t type )
{
	assertion(-502063, (it->dhnNew));
	assertion(-502064, (it->dhnNew->dext));
	assertion(-502065, (it->onOld));
	assertion(-502067, IMPLIES(it->onOld->dhn, it->onOld->dhn->dext));
	
	struct desc_extension *dOld = it->onOld->dhn ? it->onOld->dhn->dext : NULL;
	struct desc_extension *dNew = it->dhnNew->dext;

	uint8_t changed = ((dOld ? dOld->dtd[type].len : 0) != dNew->dtd[type].len ||
		(dOld && dOld->dtd[type].len && memcmp(dext_dptr(dOld, type), dext_dptr(dNew, type), dNew->dtd[type].len)));

	dbgf_track(DBGT_INFO, "orig=%s %s type=%d (%s) old_len=%d new_len=%d",
		cryptShaAsString(&it->onOld->nodeId), changed ? "  CHANGED" : "UNCHANGED",
		type, it->db->handls[type].name, (dOld ? dOld->dtd[type].len : 0), dNew->dtd[type].len);

	if (changed)
		return YES;
	else
		return NO;
}


STATIC_FUNC
void process_description_tlvs_del( struct orig_node *on, uint8_t ft_start, uint8_t ft_end ) {

	int8_t t;

	assertion(-502068, (on));
	assertion(-502069, (on->dhn));
	assertion(-502070, (on->dhn->dext));
	
	for (t = ft_start; t <= ft_end; t++) {

		if ( t== BMX_DSC_TLV_RHASH )
			continue;
		
		if (on->dhn->dext->dtd[t].len) {
			int tlv_result = process_description_tlvs(NULL, on, on->dhn, TLV_OP_DEL, t);
			assertion(-501360, (tlv_result == TLV_RX_DATA_DONE));
		}
	}
}

STATIC_FUNC
int8_t missed_mandatory_frames(struct rx_frame_iterator *it, int8_t f_start, int8_t f_end)
{
	assertion(-502173, (f_start >= 0));
	assertion(-502174, (f_end <= it->db->handl_max));

	if (it->process_filter != FRAME_TYPE_PROCESS_ALL || f_start > f_end)
		return NO;

	int8_t f;
	for (f = f_start; f <= f_end; f++) {
		if (it->db->handls[f].alwaysMandatory) {
			dbgf_sys(DBGT_WARN,"frame_type=%s",it->db->handls[f].name);
			return YES;
		}
		if (it->db->handls[f].positionMandatory && f_end < it->db->handl_max) {
			dbgf_sys(DBGT_WARN,"positionMandatory frame_type=%s pos=%d", it->db->handls[f].name, f);
			return YES;
		}
	}


	return NO;
}

int32_t rx_frame_iterate(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	char *goto_error_code = NULL;
        struct frame_handl *f_handl = NULL;
        struct packet_buff *pb = it->pb;
        it->frame_type_expanded = ((it->frame_type == -1) ? -1 : it->frame_type_expanded); //avoids init to -1
	int8_t f_type = -1;
	int32_t f_pos_next = 0;
	int32_t f_len = 0, f_data_len = 0;
	uint8_t *f_data = NULL;
	int32_t result = TLV_RX_DATA_FAILURE;
	uint8_t is_virtual_desc = (it->db == description_tlv_db && it->dhnNew);

        dbgf_all(DBGT_INFO, "%s - db=%s (prev)f_type=%d f_pos=%d f_len=%d",
	        it->caller, it->db->name, it->frame_type, it->frames_pos, it->frames_length);

        if (it->frames_pos == it->frames_length ) {

		if (missed_mandatory_frames(it, it->frame_type+1, it->db->handl_max))
			goto_error(rx_frame_iterate_error, "missing mandatory frame");
		
		if ( it->db == description_tlv_db && it->onOld && it->onOld->added && it->op == TLV_OP_NEW &&
			it->process_filter == FRAME_TYPE_PROCESS_ALL && it->frame_type < it->db->handl_max ) {
			
			process_description_tlvs_del( it->onOld, (it->frame_type + 1), it->db->handl_max );
		}

                dbgf_all(DBGT_INFO, "%s - frames_pos=%d frames_length=%d : DONE", it->caller, it->frames_pos, it->frames_length);
                return TLV_RX_DATA_DONE;
        
        } else if (it->frames_pos + ((int) (is_virtual_desc ? sizeof (struct tlv_hdr_virtual) : sizeof(struct tlv_hdr))) < it->frames_length) {

		if (is_virtual_desc) {
			assertion(-502071, (it->dhnNew->dext));
			struct tlv_hdr_virtual *tlv = (struct tlv_hdr_virtual *) (it->frames_in + it->frames_pos);
			f_type = tlv->type;
			f_len = ntohl(tlv->length);
			f_data_len = f_len - sizeof (struct tlv_hdr_virtual);
			f_data = (uint8_t*)&(tlv[1]);
			f_pos_next = it->frames_pos + f_len;
		} else {
			struct tlv_hdr *tlv = (struct tlv_hdr *) (it->frames_in + it->frames_pos);
			struct tlv_hdr tmp = {.u.u16 = ntohs(tlv->u.u16)};
			f_type = tmp.u.tlv.type;
			f_len = tmp.u.tlv.length;
			f_data_len = f_len - sizeof (struct tlv_hdr);
			f_data = (uint8_t*)&(tlv[1]);
			f_pos_next = it->frames_pos + f_len;
                }

                assertion(-501590, IMPLIES(is_virtual_desc, f_type != BMX_DSC_TLV_RHASH));

		if (f_pos_next > it->frames_length || f_data_len <= 0 ) {
			goto_error(rx_frame_iterate_error, "invalid frames_length");
                }

                it->frames_pos = f_pos_next;


                if ( it->db == description_tlv_db /*&& it->process_filter == FRAME_TYPE_PROCESS_ALL*/ ? (
			( f_type != BMX_DSC_TLV_RHASH && it->frame_type_expanded >= f_type ) ||
			( f_type == BMX_DSC_TLV_RHASH && (f_data_len < (int)sizeof(struct desc_hdr_rhash) ||
			it->frame_type_expanded >= ((struct desc_hdr_rhash*)(f_data))->expanded_type))
			) : (
			it->frame_type > f_type  
			) ) {

			goto_error(rx_frame_iterate_error, "unordered or double frame_type");
                }

		if (missed_mandatory_frames(it, it->frame_type+1, f_type-1))
			goto_error(rx_frame_iterate_error, "missing mandatory frame");

                if (it->db == description_tlv_db && it->onOld && it->onOld->added && it->op == TLV_OP_NEW &&
			it->process_filter == FRAME_TYPE_PROCESS_ALL && it->frame_type + 1 < f_type) {
			
			process_description_tlvs_del( it->onOld, (it->frame_type + 1), (f_type - 1) );
		}


                if (f_type > it->db->handl_max || !(it->db->handls[f_type].rx_frame_handler || it->db->handls[f_type].rx_msg_handler)) {

                        dbgf_mute(50, DBGL_SYS, DBGT_WARN, "%s - unknown type=%d ! check for updates", it->caller, f_type);
                        return my_pettiness ? TLV_RX_DATA_REJECTED : TLV_RX_DATA_PROCESSED;
                }

                f_handl = &it->db->handls[f_type];
                it->frame_data_length = f_data_len;
                it->frame_length = f_len;
                it->frame_data = f_data;
                it->frame_type = f_type;
                it->frame_type_expanded = ((it->db == description_tlv_db && f_type == BMX_DSC_TLV_RHASH) ?
			((struct desc_hdr_rhash*)(f_data))->expanded_type : f_type);

                it->handl = f_handl;
                it->frame_msgs_length = f_data_len - f_handl->data_header_size;
                it->frame_msgs_fixed = (f_handl->fixed_msg_size && f_handl->min_msg_size) ? (it->frame_msgs_length / f_handl->min_msg_size) : 0;
                it->msg = f_data + f_handl->data_header_size;

		dbgf((it->dbgl ? it->dbgl : DBGL_CHANGES), DBGT_INFO,
			"%s - type=%s frame_length=%d frame_data_length=%d frame_msgs_length=%d",
			it->caller, f_handl->name, f_len, f_data_len, it->frame_msgs_length);


                if (f_handl->rx_msg_handler ? // only frame_handler support zero messages per frame!
                        (it->frame_msgs_length < f_handl->min_msg_size) :
                        (it->frame_msgs_length < f_handl->min_msg_size && it->frame_msgs_length != 0)
                        ) {

			goto_error(rx_frame_iterate_error, "too small frame_msgs_length");

                } else if (f_handl->fixed_msg_size && (f_handl->min_msg_size ?
			(it->frame_msgs_length % f_handl->min_msg_size) : (it->frame_msgs_length) ) ) {

			goto_error(rx_frame_iterate_error, "non-matching fixed_msgs_size");
                }

                if (!(it->process_filter == FRAME_TYPE_PROCESS_ALL || it->process_filter == f_type)) {

                        dbgf_all(DBGT_INFO, "%s - type=%d process_filter=%d : IGNORED", it->caller, f_type, it->process_filter);
                        return TLV_RX_DATA_PROCESSED;

		} else if (!(f_handl->rx_processUnVerifiedLink || it->db->rx_processUnVerifiedLink) && !pb->i.verifiedLink) {

			dbgf_sys(DBGT_INFO, "%s - NON-VERIFIED link to neigh=%s, needed for frame type=%s db=%s",
				it->caller, pb->i.llip_str, f_handl->name, it->db->name);

			return TLV_RX_DATA_PROCESSED;

                } else if (pb && f_handl->rx_tp_min &&
                        (!pb->i.verifiedLink || pb->i.verifiedLink->timeaware_tx_probe < *(f_handl->rx_tp_min))) {

                        dbg_mute(60, DBGL_CHANGES, DBGT_WARN, "%s - non-sufficient link %s - %s (tp=%ju), skipping type=%s",
                                it->caller, pb->i.iif->ip_llocal_str, pb->i.llip_str,
                                pb->i.verifiedLink ? pb->i.verifiedLink->timeaware_tx_probe : 0, f_handl->name);

                        return TLV_RX_DATA_PROCESSED;

                } else if (pb && f_handl->rx_rp_min &&
                        (!pb->i.verifiedLink || pb->i.verifiedLink->timeaware_rx_probe < *(f_handl->rx_rp_min))) {

                        dbg_mute(60, DBGL_CHANGES, DBGT_WARN, "%s - non-sufficient link %s - %s (rp=%ju), skipping type=%s",
                                it->caller, pb->i.iif->ip_llocal_str, pb->i.llip_str,
                                pb->i.verifiedLink ? pb->i.verifiedLink->timeaware_rx_probe : 0, f_handl->name);

                        return TLV_RX_DATA_PROCESSED;

                } else if (it->op >= TLV_OP_PLUGIN_MIN && it->op <= TLV_OP_PLUGIN_MAX) {

                        return TLV_RX_DATA_PROCESSED;

                } else if (f_handl->rx_msg_handler && f_handl->fixed_msg_size) {

                        while (it->msg < it->frame_data + it->frame_data_length && (
                                (result = ((*(f_handl->rx_msg_handler)) (it))) == f_handl->min_msg_size || result == TLV_RX_DATA_PROCESSED) ) {

                                it->msg += f_handl->min_msg_size;
                        }

                        if (it->msg == it->frame_data + it->frame_data_length) {
				return TLV_RX_DATA_PROCESSED;
			} else {
				assertion(-502072, (result == TLV_RX_DATA_BLOCKED || result == TLV_RX_DATA_DONE || result == TLV_RX_DATA_FAILURE || result == TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_REBOOTED));
				goto_error(rx_frame_iterate_error, "failed rx_msg_handler");
                        }


                } else if (f_handl->rx_frame_handler) {

                        result = (*(f_handl->rx_frame_handler)) (it);

			if ( result == it->frame_msgs_length || result == TLV_RX_DATA_PROCESSED) {
				return TLV_RX_DATA_PROCESSED;
			} else {
				assertion(-502073, (result == TLV_RX_DATA_BLOCKED || result == TLV_RX_DATA_DONE || result == TLV_RX_DATA_FAILURE || result == TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_REBOOTED));
				goto_error(rx_frame_iterate_error, "failed rx_frame_handler");
                        }
                }

                assertion(-501018, (0));
	}

rx_frame_iterate_error:{

		dbgf(result == TLV_RX_DATA_FAILURE ? DBGL_SYS : (it->dbgl ? it->dbgl : DBGL_CHANGES),
			result == TLV_RX_DATA_FAILURE ? DBGT_ERR : DBGT_WARN,
		"%s - db_name=%s problem=\"%s\" result=%s dhn=%d frame_type=%d=%d=%s prev_expanded=%d "
		"frames_pos=%d frames_length=%d f_pos_next=%d f_data_len=%d f_len=%d frame_msgs_len=%d",
		it->caller, it->db->name, goto_error_code, tlv_rx_result_str(result),
		(it->dhnNew && it->dhnNew->dext),
		it->frame_type, f_type, (f_handl ? f_handl->name : NULL), it->frame_type_expanded,
		it->frames_pos, it->frames_length, f_pos_next, f_data_len, f_len, it->frame_msgs_length);

	EXITERROR(-502074, result != TLV_RX_DATA_FAILURE);
        return result;
}
}




STATIC_FUNC
int8_t send_udp_packet(struct packet_buff *pb, struct sockaddr_storage *dst, int32_t send_sock)
{
        TRACE_FUNCTION_CALL;
	int status;

        dbgf_all(DBGT_INFO, "len=%d via dev=%s", pb->i.length, pb->i.oif->label_cfg.str);

	if ( send_sock == 0 )
		return 0;

	/*
        static struct iovec iov;
        iov.iov_base = udp_data;
        iov.iov_len  = udp_data_len;

        static struct msghdr m = { 0, sizeof( *dst ), &iov, 1, NULL, 0, 0 };
        m.msg_name = dst;

        status = sendmsg( send_sock, &m, 0 );
         */

        status = sendto(send_sock, pb->p.data, pb->i.length, 0, (struct sockaddr *) dst, sizeof (struct sockaddr_storage));

	if ( status < 0 ) {

		if ( errno == 1 ) {

                        dbg_mute(60, DBGL_SYS, DBGT_ERR, "can't send: %s. Does firewall accept %s dev=%s port=%i ?",
                                strerror(errno), family2Str(((struct sockaddr_in*) dst)->sin_family),
                                pb->i.oif->label_cfg.str ,ntohs(((struct sockaddr_in*) dst)->sin_port));

		} else {

                        dbg_mute(60, DBGL_SYS, DBGT_ERR, "can't send via fd=%d dev=%s : %s",
                                send_sock, pb->i.oif->label_cfg.str, strerror(errno));

		}

		return -1;
	}

	return 0;
}



uint8_t use_compression(struct frame_handl *handl)
{
	return (((!handl->dextCompression) ? 0 :
			((*handl->dextCompression==TYP_FZIP_DO) ? 1 :
				((*handl->dextCompression==TYP_FZIP_DONT) ? 0 :
					((dextCompression==TYP_FZIP_DO) ? 1 :
						((dextCompression==TYP_FZIP_DONT) ? 0 : DEF_FZIP==TYP_FZIP_DO ))))));
}

uint8_t use_referencing(struct frame_handl *handl)
{
	return (((!handl->dextReferencing) ? 0 :
			((*handl->dextReferencing==TYP_FREF_DO) ? 1 :
				((*handl->dextReferencing==TYP_FREF_DONT) ? 0 :
					((dextReferencing==TYP_FREF_DO) ? 1 :
						((dextReferencing==TYP_FREF_DONT) ? 0 : DEF_FREF==TYP_FREF_DO ))))));
}



int32_t _tx_iterator_cache_data_space(struct tx_frame_iterator *it, IDM_T max)
{
	IDM_T TODO_must_be_iterative;

	struct frame_handl *handl = &(it->db->handls[it->frame_type]);

	if ( use_referencing( handl ) ) {

		//TODO: this works only for a reference depth = 1
		assertion(-501637, (it->dext));

		int32_t used_cache_space = handl->data_header_size + it->frame_cache_msgs_size;

		int32_t used_ref_msgs = used_cache_space/REF_FRAME_BODY_SIZE_OUT + (used_cache_space%REF_FRAME_BODY_SIZE_OUT?1:0);

		int32_t used_frames_space =
			it->frames_out_pos +
			(int) sizeof(struct tlv_hdr) +
			(int) sizeof(struct desc_hdr_rhash) +
			((int) sizeof(struct desc_msg_rhash) * used_ref_msgs);

		int32_t avail_frames_space = (max ? it->frames_out_max : it->frames_out_pref) - used_frames_space;

		int32_t avail_cache_space_theoretical = (avail_frames_space/sizeof(struct desc_msg_rhash)) * REF_FRAME_BODY_SIZE_OUT;

		int32_t avail_cache_space_practical = XMIN(it->frame_cache_size - used_cache_space, avail_cache_space_theoretical);

		int32_t avail_vrt_desc_space = vrt_desc_size_out - (it->dext->dlen + sizeof(struct tlv_hdr_virtual) + handl->data_header_size);

		return XMIN(avail_cache_space_practical, avail_vrt_desc_space);

	} else {

		int32_t frame_space =
			(max ? it->frames_out_max : it->frames_out_pref) - (
			it->frames_out_pos +
			(int) sizeof(struct tlv_hdr) + handl->data_header_size +
			(handl->next_db ? ((int)sizeof(struct tlv_hdr)) : 0) +
			it->frame_cache_msgs_size );

		int32_t cache_space = it->frame_cache_size - it->frame_cache_msgs_size;

		return XMIN(frame_space, cache_space);
	}
}


STATIC_FUNC
int32_t tx_frame_iterate_finish(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct frame_handl *handl = &(it->db->handls[it->frame_type]);
        int32_t fdata_in = it->frame_cache_msgs_size + handl->data_header_size;
	uint8_t do_fzip = use_compression(handl);
	uint8_t do_fref = use_referencing(handl);

	struct tlv_hdr *tlv = (struct tlv_hdr *) (it->frames_out_ptr + it->frames_out_pos);


        assertion(-500881, (it->frame_cache_msgs_size >= TLV_TX_DATA_PROCESSED));
	assertion(-501638, (it->frame_cache_msgs_size <= vrt_frame_data_size_out));
        assertion(-500786, (tx_iterator_cache_data_space_max(it) >= 0));
        assertion(-500355, (IMPLIES(handl->fixed_msg_size && handl->min_msg_size, !(it->frame_cache_msgs_size % handl->min_msg_size))));
        assertion(-500355, (IMPLIES(handl->fixed_msg_size && !handl->min_msg_size, !it->frame_cache_msgs_size)));
        ASSERTION(-501003, (is_zero((it->frame_cache_array + it->frame_cache_msgs_size + handl->data_header_size), tx_iterator_cache_data_space_max(it))));
        assertion(-501019, (fdata_in)); // there must be some data to send!!

	if (it->db==description_tlv_db && it->dext) {
		// this is the dext creation of my description...
//		assertion(-501639, (it->db==description_tlv_db));

		it->dext->dtd[it->frame_type].len = fdata_in;
		it->dext->dtd[it->frame_type].pos = it->dext->dlen + sizeof(struct tlv_hdr_virtual);

		it->dext->data = debugRealloc( it->dext->data, it->dext->dlen + sizeof(struct tlv_hdr_virtual) + fdata_in, -300568);

		struct tlv_hdr_virtual *vth = (struct tlv_hdr_virtual *)(it->dext->data + it->dext->dlen);

		vth->type = it->frame_type;
		vth->mbz = 0;
		vth->length = htonl(sizeof(struct tlv_hdr_virtual) + fdata_in);
		memcpy(&(vth[1]), it->frame_cache_array, fdata_in);
		it->dext->dlen += (sizeof(struct tlv_hdr_virtual) + fdata_in);

		assertion(-501641, (it->dext->dlen <= (uint32_t)vrt_desc_size_out));
	}

	if (it->db==description_tlv_db && it->dext && do_fref) {
//		assertion(-501642, (it->db==description_tlv_db));

		// calculate description extension frames
		assertion(-501643, TEST_STRUCT(struct tlv_hdr)); // of type:
		assertion(-501645, TEST_VALUE(BMX_DSC_TLV_RHASH));
		// with frame-data hdr and msgs:
		assertion(-501646, TEST_STRUCT(struct desc_hdr_rhash));
		assertion(-501647, TEST_STRUCT(struct desc_msg_rhash));

		uint8_t *rfd_agg_data = it->frame_cache_array;
		int32_t rfd_agg_len = fdata_in;

		if (do_fzip) {
			uint8_t *rfd_zagg_data = NULL;
			int32_t rfd_zagg_len = z_compress(it->frame_cache_array, fdata_in, &rfd_zagg_data, 0, 0, 0);
			assertion(-501606, IMPLIES(do_fzip, rfd_zagg_len >= 0 && rfd_zagg_len < fdata_in));
			if (rfd_zagg_len > 0) {
				assertion(-501594, (rfd_zagg_len > 0 && rfd_zagg_data));
				rfd_agg_len = rfd_zagg_len;
				rfd_agg_data = rfd_zagg_data;
			}
		}

		int32_t rfd_msgs = rfd_agg_len/REF_FRAME_BODY_SIZE_OUT + (rfd_agg_len%REF_FRAME_BODY_SIZE_OUT?1:0);
		int32_t rfd_size = sizeof(struct desc_hdr_rhash) + (rfd_msgs*sizeof(struct desc_msg_rhash));

		dbgf_track(DBGT_INFO, "added %s fDataInLen=%d fDataOutLen=%d -> msgs=%d rfd_size=%d flen=%ld do_fref=%d (%d %d %d) do_fzip=%d (%d %d %d)",
			handl->name, fdata_in, rfd_agg_len, rfd_msgs, rfd_size, sizeof (struct tlv_hdr) + rfd_size,
			do_fref, use_referencing(handl), dextReferencing, DEF_FREF,
			do_fzip, use_compression(handl), dextCompression, DEF_FZIP );

		// set frame header size and values:
		*tlv = tlvSetBigEndian(BMX_DSC_TLV_RHASH, (sizeof (struct tlv_hdr) + rfd_size));
		it->frames_out_pos += sizeof(struct tlv_hdr) + rfd_size; ///TODO
		assertion(-501651, ( it->frames_out_pos <= (int32_t)(desc_size_out - sizeof(struct dsc_msg_version))));

		// set: frame-data hdr:
		struct desc_hdr_rhash *rfd_hdr = (struct desc_hdr_rhash *) ((uint8_t*)&(tlv[1]));
		rfd_hdr->compression = (rfd_agg_len < fdata_in);
		rfd_hdr->expanded_type = it->frame_type;

		// set: frame-data msgs:
		// by splitting potentially huge
		assertion(-501648, TEST_VARIABLE(rfd_agg_data));
		// of size
		assertion(-501649, TEST_VARIABLE(rfd_agg_len));
		// into pieces of max size
		assertion(-501650, TEST_VALUE(REF_FRAME_BODY_SIZE_OUT));
		// and add each's hash as msg
		int32_t pos, m=0;
		for (pos=0; pos < rfd_agg_len; pos += REF_FRAME_BODY_SIZE_OUT) {

			int32_t rsize = XMIN(rfd_agg_len - pos, (int)REF_FRAME_BODY_SIZE_OUT);

			struct ref_node *refn = ref_node_add(rfd_agg_data + pos, rsize, 0, 0, 0);

			rfd_hdr->msg[m++].rframe_hash = refn->rhash;
			ref_node_use(it->dext, refn, it->frame_type);
		}

		if (rfd_agg_data && rfd_agg_data != it->frame_cache_array)
			debugFree(rfd_agg_data, -501595);

		assertion_dbg(-501596, (m == rfd_msgs), "m=%d rfd_msgs=%d", m, rfd_msgs);


	} else {
		
		*tlv = tlvSetBigEndian(it->frame_type, (sizeof ( struct tlv_hdr) + fdata_in));
		it->frames_out_pos += sizeof ( struct tlv_hdr) + fdata_in;
		assertion(-501652, ( it->frames_out_pos <= (int32_t)PKT_FRAMES_SIZE_MAX));

		memcpy(&(tlv[1]), it->frame_cache_array, fdata_in);
	}


        it->frames_out_num++;

        memset(it->frame_cache_array, 0, fdata_in);
        it->frame_cache_msgs_size = 0;

	return TLV_TX_DATA_PROCESSED;
        //return tlv_result;
}

/*
 * iterates over to be created frames and stores them (including frame_header) in it->frames_out  */
STATIC_FUNC
int32_t tx_frame_iterate(IDM_T iterate_msg, struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        uint8_t t = it->frame_type;
        struct frame_handl *handl = (it->handl = &(it->db->handls[t]));

	if (!handl->name)
		return TLV_TX_DATA_DONE;

        int32_t result;// = TLV_DATA_DONE;
        assertion(-500776, (it->frame_cache_array));
	assertion(-502075, IMPLIES(handl->tx_frame_handler, !iterate_msg));
	assertion(-502076, XOR(handl->tx_frame_handler, handl->tx_msg_handler));
        assertion(-501004, (IMPLIES(it->frame_cache_msgs_size, handl->tx_msg_handler)));

        ASSERTION(-500777, (IMPLIES((it->frame_cache_msgs_size && handl->tx_msg_handler),
                is_zero(tx_iterator_cache_msg_ptr(it), tx_iterator_cache_data_space_max(it)))));

        assertion_dbg(-501000, (IMPLIES((!it->frame_cache_msgs_size || handl->tx_frame_handler),
                is_zero(it->frame_cache_array, tx_iterator_cache_data_space_max(it)))),
		"db=%s t=%d cache_msgs_size=%d", it->db->name, t, it->frame_cache_msgs_size);

        assertion(-500779, (it->frames_out_pos <= it->frames_out_max));
        assertion(-500780, (it->frames_out_ptr));
        assertion(-500781, (it->frame_type <= it->db->handl_max));
        assertion(-500784, (IMPLIES(it->frame_cache_msgs_size, it->frame_cache_msgs_size >= TLV_TX_DATA_PROCESSED)));

	if (it->dext) {
		dbgf_track(DBGT_INFO, "from %s iterate_msg=%s frame_type=%d cache_msgs_size=%d cache_data_space=%d frames_out_pos=%d frames_out_pref=%d ",
			it->caller, iterate_msg ? "YES" : "NO ", it->frame_type,
			it->frame_cache_msgs_size, tx_iterator_cache_data_space_pref(it), it->frames_out_pos, it->frames_out_pref);
	}
	
	if ((handl->tx_msg_handler && iterate_msg) || handl->tx_frame_handler) {

                if (handl->min_msg_size > tx_iterator_cache_data_space_pref(it))
                        return TLV_TX_DATA_FULL;

                if (it->ttn && it->ttn->frame_msgs_length > tx_iterator_cache_data_space_sched(it))
                        return TLV_TX_DATA_FULL;
        }

        if (handl->tx_msg_handler && iterate_msg) {

                assertion(-500814, (tx_iterator_cache_data_space_pref(it) >= 0));

                if ((result = (*(handl->tx_msg_handler)) (it)) >= TLV_TX_DATA_PROCESSED) {
                        it->frame_cache_msgs_size += result;
                        ASSERTION(-501002, (is_zero((it->frame_cache_array + it->frame_cache_msgs_size + handl->data_header_size), tx_iterator_cache_data_space_max(it))));

                } else {
                        dbgf_track(DBGT_INFO, "tx_msg_handler()=%s %s remaining iterations=%d",
                                tlv_tx_result_str(result), handl->name, it->ttn ? it->ttn->tx_iterations : -1);
                        assertion(-500810, (result != TLV_TX_DATA_FAILURE));
                        assertion(-500874, (IMPLIES(!it->frame_cache_msgs_size, is_zero(it->frame_cache_array, handl->data_header_size))));
                }

                return result;
        }

        assertion(-500862, (!iterate_msg));

        if (handl->tx_msg_handler && !iterate_msg) {

                result = it->frame_cache_msgs_size;

                assertion(-500863, (result >= handl->min_msg_size));

        } else {
                assertion(-500803, (handl->tx_frame_handler));
                assertion(-500864, (it->frame_cache_msgs_size == 0));

                result = (*(handl->tx_frame_handler)) (it);

                if (!handl->data_header_size && result == 0)
                        result = TLV_TX_DATA_IGNORED;

                if (result >= TLV_TX_DATA_PROCESSED) {

                        it->frame_cache_msgs_size = result;

                } else {
                        dbgf_track(DBGT_INFO, "tx_frame_handler()=%s %s remaining iterations=%d",
                                tlv_tx_result_str(result), handl->name, it->ttn ? it->ttn->tx_iterations : -1);

                        ASSERTION(-501001, (is_zero(it->frame_cache_array, tx_iterator_cache_data_space_max(it))));
                        assertion(-500811, (result != TLV_TX_DATA_FAILURE));
                        return result;
                }
        }


        assertion(-500865, (result == it->frame_cache_msgs_size));

	return tx_frame_iterate_finish(it);
}


STATIC_FUNC
int32_t tx_tlv_msg(struct tx_frame_iterator *in)
{
        TRACE_FUNCTION_CALL;
	assertion(-502079, (in->handl->next_db));

	uint8_t cache_data_array[PKT_FRAMES_SIZE_MAX - sizeof(struct tlv_hdr)] = {0};

	struct tx_frame_iterator out = {
		.caller = in->caller, .ttn = in->ttn, .dext = in->dext, .db = in->handl->next_db,
		.frames_out_ptr = (in->frame_cache_array + in->frame_cache_msgs_size),
		.frames_out_pref = tx_iterator_cache_data_space_pref(in),
		.frames_out_max =  tx_iterator_cache_data_space_max(in),
		.frame_cache_array = cache_data_array, .frame_cache_size = sizeof(cache_data_array),
	};


        for (; out.frame_type <= out.db->handl_max; out.frame_type++) {
		
		assertion(-502080, IMPLIES((out.db->handls[out.frame_type]).name, (out.db->handls[out.frame_type]).tx_frame_handler));
		int32_t result;
		result = tx_frame_iterate(NO/*iterate_msg*/, &out);
		assertion_dbg(-500798, result>=TLV_TX_DATA_DONE, "frame_type=%d result=%s", out.frame_type, tlv_tx_result_str(result));
	}

	assertion(-502081, (out.frames_out_pos>=0));

	if (out.frames_out_pos)
		return out.frames_out_pos;
	else
		return TLV_TX_DATA_IGNORED;
}


STATIC_FUNC
int32_t rx_tlv_frame(struct rx_frame_iterator *in)
{
        TRACE_FUNCTION_CALL;

        int32_t result;
        struct rx_frame_iterator out = {
                .caller = in->caller, .onOld = in->onOld, .dhnNew=in->dhnNew, .op = in->op, .pb = in->pb,
                .db = in->handl->next_db, .process_filter = in->process_filter,
                .frame_type = -1, .frames_in = in->frame_data, .frames_length = in->frame_data_length };

        while ((result = rx_frame_iterate(&out)) > TLV_RX_DATA_DONE);

	if (result == TLV_RX_DATA_DONE)
		return TLV_RX_DATA_PROCESSED;

	dbgf_sys(DBGT_INFO, "t=%s result=%s", out.handl ? out.handl->name : NULL, tlv_rx_result_str(result));

	return result;
}

STATIC_FUNC
void next_tx_task_list(struct dev_node *dev, struct tx_frame_iterator *it, struct avl_node **linkDev_tree_it)
{
        TRACE_FUNCTION_CALL;

	LinkDevNode *linkDev = NULL;

        if (it->tx_task_list && it->tx_task_list->items &&
                ((struct tx_task_node*) (list_get_last(it->tx_task_list)))->considered_ts != bmx_time) {
                return;
        }

        if (it->tx_task_list == &(dev->tx_task_lists[it->frame_type]))
                it->frame_type++;

        while ((linkDev = avl_iterate_item(&link_dev_tree, linkDev_tree_it))) {
                struct list_node *lndev_pos;
                LinkNode *link = NULL;

                list_for_each(lndev_pos, &linkDev->link_list)
                {
                        link = list_entry(lndev_pos, LinkNode, list);

                        if (link->k.myDev == dev && link->tx_task_lists[it->frame_type].items) {

                                assertion(-500866, (link->k.linkDev == linkDev));

                                it->tx_task_list = &(link->tx_task_lists[it->frame_type]);

                                dbgf_track(DBGT_INFO,
                                        "found %s   link nb: nb_local_id=%s nb_dev_idx=%d nbIP=%s   via lndev: my_dev=%s my_dev_idx=%d with lndev->tx_tasks_list[].items=%d",
                                        it->db->handls[it->frame_type].name,
                                        cryptShaAsString(&linkDev->key.local_id), linkDev->key.dev_idx, ip6AsStr(&linkDev->link_ip),
                                        dev->label_cfg.str, dev->llip_key.idx, it->tx_task_list->items);

                                return;
                        }
                }
        }

        *linkDev_tree_it = NULL;
        it->tx_task_list = &(dev->tx_task_lists[it->frame_type]);
        return;
}

void tx_packet(void *devp)
{
        TRACE_FUNCTION_CALL;

        static uint8_t cache_data_array[PKT_FRAMES_SIZE_MAX - sizeof(struct tlv_hdr)] = {0};
        static struct packet_buff pb;
        struct dev_node *dev = devp;
	extern int main(int argc, char *argv[]);
	static struct prof_ctx prof = { .k = {.func=(void(*)(void))tx_packet}, .name=__FUNCTION__, .parent_func=(void (*) (void))main};
	prof_start(&prof);

        assertion(-500204, (dev));

        dev->tx_task = NULL;
        dbgf_all(DBGT_INFO, "dev=%s", dev->label_cfg.str);

        assertion(-500205, (dev->active));

        schedule_tx_task(&dev->dummyLink, FRAME_TYPE_HELLO_ADV, SCHEDULE_MIN_MSG_SIZE, 0, 0);

        if (my_link_adv_msgs)
                schedule_tx_task(&dev->dummyLink, FRAME_TYPE_RP_ADV, (my_link_adv_msgs * sizeof (struct msg_rp_adv)), 0, 0);


        memset(&pb.i, 0, sizeof (pb.i));

        struct tx_frame_iterator it = {
                .caller = __FUNCTION__, .db = packet_frame_db,
                .frames_out_ptr = (pb.p.data + sizeof (struct packet_header)),
                .frames_out_max =  PKT_FRAMES_SIZE_MAX,
                .frames_out_pref = PKT_FRAMES_SIZE_OUT,
                .frame_cache_array = cache_data_array,
		.frame_cache_size = sizeof(cache_data_array),
        };

        struct avl_node *linkDev_tree_it = NULL;
	int8_t unsigned_frames_finished = 0;
	int8_t signed_frames_signed = 0;
	int8_t last_send_frame_type = -1;

        while (it.frame_type < FRAME_TYPE_NOP) {

                next_tx_task_list(dev, &it, &linkDev_tree_it);

                struct list_node *lpos, *ltmp, *lprev = (struct list_node*) it.tx_task_list;
                int32_t result = TLV_TX_DATA_DONE;
                struct frame_handl *handl = &it.db->handls[it.frame_type];
                uint16_t prev_frames_out_pos = it.frames_out_pos;
                uint32_t item =0;

		if (it.frame_type > FRAME_TYPE_LINK_VERSION && it.frames_out_pos > 0 && !unsigned_frames_finished) {

			unsigned_frames_finished = 1;
			result = TLV_TX_DATA_FULL;

		} else if (it.frame_type > FRAME_TYPE_LINK_VERSION && it.frames_out_pos == 0 && !signed_frames_signed) {

			schedule_tx_task(&dev->dummyLink, FRAME_TYPE_SIGNATURE_ADV, sizeof(struct frame_msg_signature) + (my_PktKey ? my_PktKey->rawKeyLen : 0), 0, 0);
//			schedule_tx_task(&dev->dummyLink, FRAME_TYPE_SIGNATURE_DUMMY, SCHEDULE_MIN_MSG_SIZE, 0, 0);
			schedule_tx_task(&dev->dummyLink, FRAME_TYPE_LINK_VERSION, SCHEDULE_MIN_MSG_SIZE, 0, 0);

			signed_frames_signed = 1;
			it.frame_type = FRAME_TYPE_SIGNATURE_ADV;
			linkDev_tree_it = NULL;
			it.tx_task_list = NULL;
			continue;

		} else {


                list_for_each_safe(lpos, ltmp, it.tx_task_list)
                {
                        it.ttn = list_entry(lpos, struct tx_task_node, list);
                        item++;

                        dbgf_all(DBGT_INFO, "%s type=%d =%s", dev->label_cfg.str, it.frame_type, handl->name);

                        assertion(-500440, (it.ttn->task.type == it.frame_type));

			ASSERTION(-500920, (it.ttn->task.dev && it.ttn->task.dev == avl_find_item(&dev_ip_tree, &it.ttn->task.dev->llip_key)));



                        if (it.ttn->tx_iterations <= 0) {

                                result = TLV_TX_DATA_DONE;

                        } else if (it.ttn->considered_ts == bmx_time) {
                                // already considered during this tx iteration
                                result = TLV_TX_DATA_IGNORED;

                        } else if ((result = tx_task_obsolete(it.ttn)) <= TLV_TX_DATA_IGNORED ) {
                                // too recently send! send later;
                                // tlv_result = TLV_TX_DATA_IGNORED;

                        } else if (handl->tx_frame_handler) {

                                result = tx_frame_iterate(NO/*iterate_msg*/, &it);

                        } else if (handl->tx_msg_handler) {

                                result = tx_frame_iterate(YES/*iterate_msg*/, &it);

                        } else {
                                assertion(-500818, (0));
                        }

                        if (handl->tx_msg_handler && it.frame_cache_msgs_size &&
                                (result == TLV_TX_DATA_FULL || lpos == it.tx_task_list->last)) {// last element in list:
                                
                                int32_t fit_result = tx_frame_iterate(NO/*iterate_msg*/, &it);
                                
                                assertion_dbg(-500790, (fit_result >= TLV_TX_DATA_PROCESSED),
                                        "unexpected fit_result=%s (tlv_result=%s) type=%d",
                                        tlv_tx_result_str(fit_result), tlv_tx_result_str(result), it.frame_type);
                        }

                        dbgf_track(DBGT_INFO, "%s type=%d =%s considered=%d iterations=%d tlv_result=%s item=%d/%d",
                                dev->label_cfg.str, it.frame_type, handl->name, it.ttn->considered_ts,
                                it.ttn->tx_iterations, tlv_tx_result_str(result), item, it.tx_task_list->items);

                        if (result == TLV_TX_DATA_DONE) {

                                it.ttn->considered_ts = bmx_time;
                                it.ttn->tx_iterations--;

                                if (freed_tx_task_node(it.ttn, it.tx_task_list, lprev) == NO)
                                        lprev = lpos;

                                continue;

                        } else if (result == TLV_TX_DATA_IGNORED) {

                                it.ttn->considered_ts = bmx_time;

                                lprev = lpos;
                                continue;

                        } else if (result >= TLV_TX_DATA_PROCESSED) {

                                it.ttn->send_ts = bmx_time;
                                it.ttn->considered_ts = bmx_time;
                                it.ttn->tx_iterations--;

                                if (freed_tx_task_node(it.ttn, it.tx_task_list, lprev) == NO)
                                        lprev = lpos;

                                if (handl->tx_frame_handler || lpos == it.tx_task_list->last)
                                        break;

                                continue;

                        } else if (result == TLV_TX_DATA_FULL) {
                                // means not created because would not fit!
                                assertion(-500430, (it.frame_cache_msgs_size || it.frames_out_pos)); // single message larger than MAX_UDPD_SIZE
                                break;

                        } else {

                                dbgf_sys(DBGT_ERR, "frame_type=%d tlv_result=%s", it.frame_type, tlv_tx_result_str(result));
                                assertion(-500791, (0));
                        }
                }
		}

                if (it.frames_out_pos > prev_frames_out_pos) {
			last_send_frame_type = it.frame_type;
                        dbgf_all(DBGT_INFO, "prepared frame_type=%s frame_size=%d frames_out_pos=%d",
                                handl->name, (it.frames_out_pos - prev_frames_out_pos), it.frames_out_pos);
                }

                assertion(-500796, (!it.frame_cache_msgs_size));
                assertion(-500800, (it.frames_out_pos >= prev_frames_out_pos));

                if (result == TLV_TX_DATA_FULL || (it.frame_type == FRAME_TYPE_NOP && it.frames_out_pos)) {

			if (last_send_frame_type < FRAME_TYPE_SIGNATURE_ADV || last_send_frame_type > FRAME_TYPE_LINK_VERSION) {

				if (last_send_frame_type > FRAME_TYPE_LINK_VERSION && my_PktKey && my_PktKey->rawKeyLen) {
					it.db->handls[FRAME_TYPE_SIGNATURE_ADV].tx_frame_handler(&it);
				}

				struct packet_header *phdr = (struct packet_header *) pb.p.data;

				assertion(-501338, (it.frames_out_pos && it.frames_out_num));
				assertion(-501339, IMPLIES(it.frames_out_num > 1, it.frames_out_pos <= it.frames_out_pref));
				assertion(-501340, IMPLIES(it.frames_out_num == 1, it.frames_out_pos <= it.frames_out_max));

				pb.i.oif = dev;
				pb.i.length = (it.frames_out_pos + sizeof( struct packet_header));

				my_packet_sqn++;

				memset(phdr, 0, sizeof(struct packet_header));

				phdr->comp_version = my_compatibility;

				cb_packet_hooks(&pb);

				pb.i.oif->udpOutCurrPackets += 1;
				pb.i.oif->udpOutCurrBytes += pb.i.length;


				send_udp_packet(&pb, &dev->tx_netwbrc_addr, dev->unicast_sock);

				dbgf_all(DBGT_INFO, "send packet size=%d  via dev=%s",
					pb.i.length, dev->label_cfg.str);
			}

                        memset(&pb.i, 0, sizeof (pb.i));

                        it.frames_out_pos = 0;
                        it.frames_out_num = 0;
			signed_frames_signed = 0;

                }
		dbgf_all(DBGT_INFO, "frame_type=%d last_send_frame_type=%d frames_out_pos=%d",
			it.frame_type, last_send_frame_type, it.frames_out_pos);
        }

        assertion(-500797, (!it.frames_out_pos));
	prof_stop(&prof);
}

void tx_packets( void *unused ) {

        TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct dev_node *dev;

        TIME_T dev_next = 0;
        int8_t linklayer;

        dbgf_all(DBGT_INFO, " ");

        // MUST be checked here because:
        // description may have changed (relevantly for ogm_aggregation)
        // during current call of task_next() in bmx() main loop
        if (my_description_changed)
                update_my_description();

	self->dhn->referred_by_me_timestamp = bmx_time;

        schedule_or_purge_ogm_aggregations(NO);
        // this might schedule a new tx_packet because schedule_tx_packet() believes
        // the stuff we are about to send now is still waiting to be send.

        //remove_task(tx_packet, NULL);
        task_register((my_tx_interval + rand_num(my_tx_interval / 10) - (my_tx_interval / 20)), tx_packets, NULL, -300353);


        for (linklayer = TYP_DEV_LL_LAN; linklayer <= TYP_DEV_LL_WIFI; linklayer++) {

                for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                        if (dev->linklayer != linklayer) {

                                continue;

                        } else if (dev->tx_task) {

                                dbgf_sys(DBGT_ERR, "previously scheduled tx_packet( dev=%s ) still pending!", dev->label_cfg.str);
                                continue;

                        } else if (dev->linklayer == TYP_DEV_LL_LAN) {

                                tx_packet(dev);

                        } else {
                                dev->tx_task = tx_packet;
                                task_register(dev_next, tx_packet, dev, -300354);

                                dev_next += (my_tx_interval / 10) / dev_ip_tree.items;
                        }
                }
        }
	first_packet = NO;
}


void schedule_my_originator_message( void* unused )
{
        TRACE_FUNCTION_CALL;

        if (((OGM_SQN_MASK) & (self->ogmSqn_next + 1 - self->ogmSqn_rangeMin)) >= self->ogmSqn_rangeSize)
                my_description_changed = YES;


        self->ogmSqn_maxRcvd = set_ogmSqn_toBeSend_and_aggregated(self, UMETRIC_MAX, (self->ogmSqn_next + 1), self->ogmSqn_send);

        dbgf_all(DBGT_INFO, "ogm_sqn %d", self->ogmSqn_next);

        task_register(my_ogm_interval, schedule_my_originator_message, NULL, -300355);
}



void update_my_description(void)
{
        TRACE_FUNCTION_CALL;
	extern int main(int argc, char *argv[]);
	static struct prof_ctx prof = {.k={.func=(void(*)(void))update_my_description}, .name=__FUNCTION__, .parent_func = (void (*) (void))main};
	prof_start(&prof);

	assertion(-502082, (!terminating));

	dbgf_track(DBGT_INFO, DBG_NIL);

	uint8_t *frame_cache_array = debugMallocReset(vrt_frame_data_size_out, -300586);

        if (!initializing)
                cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, self);

        // add all tlv options:
        struct tx_frame_iterator tx = {
                .caller = __FUNCTION__, .db = description_tlv_db,
		.frames_out_ptr = debugMallocReset(desc_size_out, -300627),
                .frames_out_max = desc_size_out,
                .frames_out_pref = desc_size_out,
		.frame_cache_array = frame_cache_array,
		.frame_cache_size = vrt_frame_data_size_out,
		.dext = dext_init()
        };

        for (; tx.frame_type <= tx.db->handl_max; tx.frame_type++) {
       
		int32_t result;
		assertion(-502083, IMPLIES((tx.db->handls[tx.frame_type]).name, (tx.db->handls[tx.frame_type]).tx_frame_handler));
		result = tx_frame_iterate(NO/*iterate_msg*/, &tx);
		assertion_dbg(-500798, result>=TLV_TX_DATA_DONE, "frame_type=%d result=%s", tx.frame_type, tlv_tx_result_str(result));
	}

        DHASH_T dhashNew;
	cryptShaAtomic(tx.frames_out_ptr, tx.frames_out_pos, &dhashNew);
	struct dhash_node *dhnNew = create_dext_dhash(tx.frames_out_ptr, tx.frames_out_pos, tx.dext, &dhashNew);

	DHASH_T dhashOld = {.h.u32={0}};
	if (!initializing) {
		assertion(-502175, (self->dhn));
		dhashOld = self->dhn->dhash;
		assertion(-502176, IMPLIES(!initializing, !avl_find(&deprecated_dhash_tree, &dhashOld)));
	}

	update_orig_dhash( self, dhnNew );

	assertion(-502177, IMPLIES(!initializing, avl_find(&deprecated_dhash_tree, &dhashOld)));

	dbgf_sys(DBGT_INFO, "dhashOld=%s dhashNew=%s for nodeId=%s",
		cryptShaAsString(&dhashOld), cryptShaAsString(&dhashNew), cryptShaAsString(&self->nodeId));

/*
	dbgf_sys(DBGT_INFO, "adding my desc_frame_size=%d dhash=%s desc_frame_data=%s dext_len=%d dext_data=%s",
		tx.frames_out_pos, cryptShaAsString(&dhash), memAsHexString(tx.frames_out_ptr, tx.frames_out_pos),
		dhn->dext->dlen, memAsHexString(dhn->dext->data, dhn->dext->dlen));

	struct rx_frame_iterator rx1 = {
		.caller = __FUNCTION__, .onOld = NULL, .dhnNew = NULL, .op = TLV_OP_PLUGIN_MIN,
		.db = description_tlv_db, .process_filter = FRAME_TYPE_PROCESS_NONE,
		.frame_type = -1, .frames_in = tx.frames_out_ptr, .frames_length = tx.frames_out_pos };

	while ((rx_frame_iterate(&rx1)) > TLV_RX_DATA_DONE) {
		dbgf_track(DBGT_INFO, "%s: ", rx1.handl->name);
		fields_dbg_lines(NULL, 0, rx1.frame_msgs_length, rx1.msg, rx1.handl->min_msg_size, rx1.handl->msg_format);
	}


	struct rx_frame_iterator rx2 = {
		.caller = __FUNCTION__, .onOld = self, .dhnNew = dhn, .op = TLV_OP_PLUGIN_MIN,
		.db = description_tlv_db, .process_filter = FRAME_TYPE_PROCESS_NONE,
		.frame_type = -1, .frames_in = dhn->dext->data, .frames_length = dhn->dext->dlen };

	while ((rx_frame_iterate(&rx2)) > TLV_RX_DATA_DONE) {
		dbgf_track(DBGT_INFO, "%s: ", rx2.handl->name);
		fields_dbg_lines(NULL, 0, rx2.frame_msgs_length, rx2.msg,	rx2.handl->min_msg_size, rx2.handl->msg_format);
	}
*/


        myIID4me = self->dhn->myIID4orig;
        myIID4me_timestamp = bmx_time;

        if (desc_adv_tx_unsolicited)
		schedule_best_tp_links(NULL, FRAME_TYPE_DESC_ADVS, tx.frames_out_pos, &dhashNew, sizeof(dhashNew));

	if (dhash_adv_tx_unsolicited)
		schedule_best_tp_links(NULL, FRAME_TYPE_DHASH_ADV, SCHEDULE_MIN_MSG_SIZE, &myIID4me, sizeof(IID_T));


        my_description_changed = NO;

	assertion(-502178, (self->dhn && self->dhn == get_dhash_tree_node(&self->dhn->dhash)));
	assertion(-502179, (self == avl_find_item(&orig_tree, &self->nodeId)));

	debugFree(frame_cache_array, -300585);
	prof_stop(&prof);
}


STATIC_FUNC
int32_t opt_show_descriptions(uint8_t cmd, uint8_t _save, struct opt_type *opt,
                              struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY ) {

                struct avl_node *an = NULL;
                struct orig_node *on;
                char *TODOname = NULL;
                int32_t type_filter = DEF_DESCRIPTION_TYPE;
                int32_t relevance = DEF_RELEVANCE;
                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_DESCRIPTION_TYPE)) {
                                type_filter = strtol(c->val, NULL, 10);

                        } else if (!strcmp(c->opt->name, ARG_RELEVANCE)) {
                                relevance = strtol(c->val, NULL, 10);

                        } else if (!strcmp(c->opt->name, ARG_DESCRIPTION_NAME)) {
                                TODOname = c->val;
			}
		}

		dbg_printf( cn, "descriptions:" );

                while ((on = avl_iterate_item(&orig_tree, &an))) {

                        assertion(-500361, (!on || on->dhn));

			struct dhash_node *dhn = on->dhn;

                        if (TODOname && dext_dptr(dhn->dext, BMX_DSC_TLV_NAMES))
                                continue;

                        dbg_printf(cn, "\nnodeId=%s descSha=%s blocked=%d desc_frame_size=%d dext_len=%d:",
                                cryptShaAsString(&on->nodeId), cryptShaAsString(&dhn->dhash), on->blocked,
                                dhn->desc_frame_len, dhn->dext->dlen );

                        struct rx_frame_iterator it = {
                                .caller = __FUNCTION__, .onOld = on, .dhnNew = dhn, .op = TLV_OP_PLUGIN_MIN,
                                .db = description_tlv_db, .process_filter = type_filter,
                                .frame_type = -1, .frames_in = dhn->dext->data, .frames_length = dhn->dext->dlen };

                        int32_t result;
                        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

				dbg_printf(cn, "\n  %s: ", it.handl->name);

				fields_dbg_lines(cn, relevance, it.frame_msgs_length, it.msg,
					it.handl->min_msg_size, it.handl->msg_format);
                        }
                }

		dbg_printf( cn, "\n" );
	}
	return SUCCESS;
}



struct ref_status {
        SHA1_T   f_hash;
	uint8_t  f_compression;
        uint32_t f_body_len; // NOT including frame header!!
        uint32_t last_usage;
        uint32_t usage_counter;
	char ref_types[100];
	char referencees[100];
};

static const struct field_format ref_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_BINARY, ref_status, f_hash,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,          ref_status, f_body_len,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,          ref_status, last_usage,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,          ref_status, usage_counter, 1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,   ref_status, ref_types,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,   ref_status, referencees,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t ref_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *it;
        struct ref_node *rfn;
        uint32_t max_size = ref_tree.items * sizeof (struct ref_status);
        uint32_t i = 0;

        struct ref_status *status = ((struct ref_status*) (handl->data = debugRealloc(handl->data, max_size, -300587)));
        memset(status, 0, max_size);

        for (it = NULL; (rfn = avl_iterate_item(&ref_tree, &it));) {

		memcpy( &(status[i].f_hash), &rfn->rhash, sizeof(SHA1_T));
		status[i].f_body_len = rfn->f_body_len;
		status[i].last_usage = rfn->last_usage;
		status[i].usage_counter = rfn->dext_tree.items;

		status[i].ref_types[0] = 0;
		status[i].referencees[0] = 0;

		struct dext_tree_node *dtn = NULL;
		struct avl_node *an = NULL;
		char* origs_str = status[i].referencees;
		char* ref_str = status[i].ref_types;
		uint8_t rft_bits[sizeof(dtn->rf_types)] = {0};
		uint16_t rft_pos;
		while ((dtn = avl_iterate_item(&rfn->dext_tree, &an))) {

			if (dtn->dext_key.dext->dhn) {
				snprintf(origs_str + strlen(origs_str), sizeof(status[i].referencees) - strlen(origs_str),
					"%s%s", strlen(origs_str) ? " ":"", 
					cryptShaAsShortStr(nodeIdFromDescAdv(dtn->dext_key.dext->dhn->desc_frame)) );
			}

			for (rft_pos=0; rft_pos<sizeof(rft_bits);rft_pos++)
				rft_bits[rft_pos] |= dtn->rf_types[rft_pos];
		}

		for (rft_pos=0; rft_pos<(8*sizeof(rft_bits));rft_pos++) {
			if (bit_get(rft_bits, (8*sizeof(rft_bits)), rft_pos)) {
				snprintf(ref_str + strlen(ref_str), sizeof(status[i].ref_types) - strlen(ref_str),
					"%s%s", strlen(ref_str) ? " ":"", description_tlv_db->handls[rft_pos].name  );
			}
		}

		i++;
		assertion(-501225, (max_size >= i * sizeof (struct ref_status)));
        }

        return i * sizeof (struct ref_status);
}


int32_t opt_update_dext_method(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY )
		my_description_changed = YES;

	return SUCCESS;
}


STATIC_FUNC
IDM_T rx_frames(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        int32_t result;

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .onOld = NULL, .op = 0, .pb = pb,
                .db = packet_frame_db, .process_filter = FRAME_TYPE_PROCESS_ALL,
                .frame_type = -1, .frames_in = (pb->p.data + sizeof (struct packet_header)),
                .frames_length = (pb->i.length - sizeof (struct packet_header)),
		.dhnNew = NULL
	};

        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE);

        if (result <= TLV_RX_DATA_FAILURE) {
                dbgf_sys(DBGT_WARN, "problematic frame_type=%s data_length=%d result=%s pos=%d ",
                        it.db->handls[it.frame_type].name, it.frame_data_length, tlv_rx_result_str(result), it.frames_pos);
                return FAILURE;
        }


        return SUCCESS;
}


void rx_packet( struct packet_buff *pb )
{
        TRACE_FUNCTION_CALL;


	extern int main(int argc, char *argv[]);
	static struct prof_ctx prof = { .k={.func=(void(*)(void))rx_packet}, .name=__FUNCTION__, .parent_func= (void (*) (void))main};
	prof_start(&prof);

	pb->i.verifiedLink = NULL;
	pb->i.verifiedLinkDhn = NULL;
	pb->i.llip = (*((struct sockaddr_in6*) &(pb->i.addr))).sin6_addr;
        ip6ToStr(&pb->i.llip, pb->i.llip_str);

	struct dev_ip_key any_key = { .ip = pb->i.llip, .idx = 0 };
	struct dev_node *anyIf;

        assertion(-500841, ((pb->i.iif->active && pb->i.iif->if_llocal_addr)));

        if (drop_all_packets)
                goto finish;

	if (pb->i.length < (int)sizeof(pb->p.hdr.comp_version) ||
		pb->p.hdr.comp_version < (my_compatibility - 1) || pb->p.hdr.comp_version > (my_compatibility + 1))
                goto process_packet_error;

	if ((pb->i.length != (int) (sizeof(struct packet_header)) &&
		pb->i.length < (int) (sizeof(struct packet_header) + sizeof(struct tlv_hdr))) ||
		pb->i.length > (int) (PKT_FRAMES_SIZE_MAX + sizeof(struct packet_header)))
		goto process_packet_error;

	if ((anyIf = avl_closest_item(&dev_ip_tree, &any_key)) && is_ip_equal(&pb->i.llip, &anyIf->llip_key.ip))
                goto finish;

	cb_packet_hooks(pb);

	if (!is_ip_net_equal(&pb->i.llip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)) {
		dbgf_all(DBGT_ERR, "non-link-local IPv6 source address %s", ip6AsStr(&pb->i.llip));
		goto finish;
	}

	pb->i.iif->udpInCurrPackets += 1;
	pb->i.iif->udpInCurrBytes += pb->i.length;

        if (badlist_neighbor(pb, NULL))
                goto finish;

        if (drop_all_frames)
                goto finish;


        dbgf_all(DBGT_INFO, "via %s %s %s size %d", 
		pb->i.iif->label_cfg.str, pb->i.iif->ip_llocal_str, pb->i.llip_str, pb->i.length);

        dbgf_all(DBGT_INFO, "version=%i, reserved=%X, size=%i rcvd udp_len=%d via NB %s %s %s",
                pb->p.hdr.comp_version, pb->p.hdr.reserved, pb->i.length,
                pb->i.length, pb->i.llip_str, pb->i.iif->label_cfg.str, pb->i.unicast ? "UNICAST" : "BRC");



        if (rx_frames(pb) == SUCCESS)
                goto finish;


process_packet_error:

        dbgf_sys(DBGT_WARN,
                "Drop (remaining) problematic packet: via NB=%s dev=%s len=%d my_version=%d version=%i capabilities=%d",
		pb->i.llip_str, pb->i.iif->label_cfg.str, pb->i.length, my_compatibility, pb->p.hdr.comp_version, pb->p.hdr.reserved);

        badlist_neighbor_if_verified(pb);

finish:
	prof_stop(&prof);
	return;
}

STATIC_FUNC
struct opt_type msg_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

#ifndef LESS_OPTIONS
        {ODI, 0, ARG_UDPD_SIZE,            0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &pref_udpd_size, MIN_UDPD_SIZE,      MAX_UDPD_SIZE,     DEF_UDPD_SIZE,0,      0,
			ARG_VALUE_FORM,	HLP_UDPD_SIZE}
        ,
	{ODI,0,ARG_DROP_ALL_FRAMES,     0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&drop_all_frames,	MIN_DROP_ALL_FRAMES,	MAX_DROP_ALL_FRAMES,	DEF_DROP_ALL_FRAMES,0,	0,
			ARG_VALUE_FORM,	"drop all received frames (but process packet header)"}
        ,
	{ODI,0,ARG_DROP_ALL_PACKETS,     0, 9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&drop_all_packets,	MIN_DROP_ALL_PACKETS,	MAX_DROP_ALL_PACKETS,	DEF_DROP_ALL_PACKETS,0,	0,
			ARG_VALUE_FORM,	"drop all received packets"}
        ,
	{ODI,0,ARG_FREF,                   0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dextReferencing,MIN_FREF,           MAX_FREF,          DEF_FREF,0,           opt_update_dext_method,
			ARG_VALUE_FORM, HLP_FREF},
	{ODI,0,ARG_FZIP,                   0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dextCompression,MIN_FZIP,           MAX_FZIP,          DEF_FZIP,0,           opt_update_dext_method,
			ARG_VALUE_FORM, HLP_FZIP},

	{ODI,0,ARG_DESC_FRAME_SIZE,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &desc_size_out,MIN_DESC_SIZE, MAX_DESC_SIZE,     DEF_DESC_SIZE,0,      opt_update_dext_method,
			ARG_VALUE_FORM, HLP_DESC_FRAME_SIZE},
	{ODI,0,ARG_VRT_FRAME_DATA_SIZE_OUT,0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_frame_data_size_out,MIN_VRT_FRAME_DATA_SIZE,MAX_VRT_FRAME_DATA_SIZE,DEF_VRT_FRAME_DATA_SIZE,0,  opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_FRAME_DATA_SIZE_OUT},
	{ODI,0,ARG_VRT_FRAME_DATA_SIZE_IN, 0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_frame_data_size_in,MIN_VRT_FRAME_DATA_SIZE,MAX_VRT_FRAME_DATA_SIZE,DEF_VRT_FRAME_DATA_SIZE,0,  opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_FRAME_DATA_SIZE_IN},
	{ODI,0,ARG_VRT_DESC_SIZE_OUT,      0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_desc_size_out,MIN_VRT_DESC_SIZE,MAX_VRT_DESC_SIZE,DEF_VRT_DESC_SIZE,0,   opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_DESC_SIZE_OUT},
	{ODI,0,ARG_VRT_DESC_SIZE_IN,       0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_desc_size_in,MIN_VRT_DESC_SIZE,MAX_VRT_DESC_SIZE,DEF_VRT_DESC_SIZE,0,    opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_DESC_SIZE_IN},

        {ODI, 0, ARG_OGM_SQN_RANGE,        0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogmSqnRange,    MIN_OGM_SQN_RANGE,  MAX_OGM_SQN_RANGE, DEF_OGM_SQN_RANGE,0,  0,
			ARG_VALUE_FORM,	"set average OGM sequence number range (affects frequency of bmx6 description updates)"}
        ,
        {ODI, 0, ARG_OGM_TX_ITERS,         0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogm_adv_tx_iters,MIN_OGM_TX_ITERS,MAX_OGM_TX_ITERS,DEF_OGM_TX_ITERS,0,       0,
			ARG_VALUE_FORM,	"set maximum resend attempts for ogm aggregations"}
        ,
        {ODI, 0, ARG_DESC_ADV_UNSOLICITED, 0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_adv_tx_unsolicited,MIN_DESC_ADV_UNSOLICITED,MAX_DESC_ADV_UNSOLICITED,DEF_DESC_ADV_UNSOLICITED,0,0,
			ARG_VALUE_FORM,	"send unsolicited description advertisements after receiving a new one"}
        ,
        {ODI, 0, ARG_DHASH_ADV_UNSOLICITED,0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dhash_adv_tx_unsolicited,MIN_DHASH_ADV_UNSOLICITED,MAX_DHASH_ADV_UNSOLICITED,DEF_DHASH_ADV_UNSOLICITED,0,0,
			ARG_VALUE_FORM,	"send unsolicited dhash advertisements after creating a new IID"}
        ,
        {ODI, 0, ARG_DREF_ADV_UNSOLICITED, 0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dref_adv_tx_unsolicited,MIN_DREF_ADV_UNSOLICITED,MAX_DREF_ADV_UNSOLICITED,DEF_DREF_ADV_UNSOLICITED,0,0,
			ARG_VALUE_FORM,	"send unsolicited description-reference advertisements after receiving a new one"}
        ,
        {ODI, 0, ARG_DSC0_REQS_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_req_tx_iters,MIN_DSC0_REQS_TX_ITERS,MAX_DSC0_REQS_TX_ITERS,DEF_DESC_REQ_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description requests"}
        ,
        {ODI, 0, ARG_DHS0_REQS_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dhash_req_tx_iters,MIN_DHS0_REQS_TX_ITERS,MAX_DHS0_REQS_TX_ITERS,DEF_DHASH_REQ_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description-hash requests"}
        ,
        {ODI, 0, ARG_DSC0_ADVS_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_adv_tx_iters,MIN_DSC0_ADVS_TX_ITERS,MAX_DSC0_ADVS_TX_ITERS,DEF_DESC_ADV_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for descriptions"}
        ,
        {ODI, 0, ARG_DHASH_ADV_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dhash_adv_tx_iters,MIN_DHASH_ADV_TX_ITERS,MAX_DHASH_ADV_TX_ITERS,DEF_DHASH_ADV_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description hashes"}
        ,
        {ODI, 0, ARG_OGM_ACK_TX_ITERS,     0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogm_ack_tx_iters,MIN_OGM_ACK_TX_ITERS,MAX_OGM_ACK_TX_ITERS,DEF_OGM_ACK_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for ogm acknowledgements"}
        ,
#endif
	{ODI, 0, ARG_DESCRIPTIONS,	   0,  9,2, A_PS0N,A_USR, A_DYN, A_ARG, A_ANY, 0,               0,                  0,                 0,0,                  opt_show_descriptions,
			0,		HLP_DESCRIPTIONS}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_DESCRIPTION_TYPE,'t',9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,	        MIN_DESCRIPTION_TYPE,MAX_DESCRIPTION_TYPE,DEF_DESCRIPTION_TYPE,0,opt_show_descriptions,
			"<TYPE>",	HLP_DESCRIPTION_TYPE}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_DESCRIPTION_NAME,'n',9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,		0,	            0,                 0,0,                  opt_show_descriptions,
			"<NAME>",	"only show description of nodes with given name"}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_RELEVANCE,       'r',9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,	        MIN_RELEVANCE,	    MAX_RELEVANCE,     DEF_RELEVANCE,0,      opt_show_descriptions,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
	,
	{ODI, 0, ARG_REFERENCES,	   0,  9,2, A_PS0N,A_USR, A_DYN, A_ARG, A_ANY, 0,               0,                  0,                 0,0,                  opt_status,
			0,		HLP_REFERENCES}


};


void init_msg( void )
{
	assertion(-501567, (FRAME_TYPE_MASK >= FRAME_TYPE_MAX_KNOWN));
	assertion(-501568, (FRAME_TYPE_MASK >= BMX_DSC_TLV_MAX_KNOWN));

        assertion(-500998, (sizeof(struct tlv_hdr) == 2));

        assertion(-500347, (sizeof (DHASH_T) == CRYPT_SHA1_LEN));
        assertion(-501146, (OGM_DEST_ARRAY_BIT_SIZE == ((OGM_DEST_ARRAY_BIT_SIZE / 8)*8)));

	assertion(-502084, (sizeof(struct desc_msg_rhash) == sizeof(struct frame_msg_rhash_adv)));
	assertion(-502085, (sizeof(struct desc_hdr_rhash) == sizeof(struct frame_hdr_rhash_adv)));

	assertion(-502086, ( (tlvSetBigEndian(0x1B, 0x492)).u.u16 == htons(0xDC92) ) );


        ogm_aggreg_sqn_max = ((AGGREG_SQN_MASK) & rand_num(AGGREG_SQN_MAX));

        my_packet_sqn = 1; // dont start with zero because my_link_sqn and my_dev_sqn assume this

	register_options_array( msg_options, sizeof( msg_options ), CODE_CATEGORY_NAME );

        register_status_handl(sizeof (struct ref_status), 1, ref_status_format, ARG_REFERENCES, ref_status_creator);

        task_register(my_ogm_interval, schedule_my_originator_message, NULL, -300356);

	packet_frame_db = init_frame_db(FRAME_TYPE_ARRSZ, 0, "packet_frame_db");
	packet_desc_db = init_frame_db(1, 1, "packet_desc_db");
	description_tlv_db = init_frame_db(BMX_DSC_TLV_ARRSZ, 1, "description_tlv_db");
        description_names_db = init_frame_db(BMX_DSC_NAMES_ARRSZ, 1, "description_names_db");

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));


        static const struct field_format ref_format[] = MSG_RHASH_FORMAT;
        handl.name = "DSC_RHASH";
        handl.data_header_size = sizeof( struct desc_hdr_rhash);
        handl.min_msg_size = sizeof (struct desc_msg_rhash);
        handl.fixed_msg_size = 1;
        handl.tx_frame_handler = create_dsc_tlv_rhash;
        handl.rx_msg_handler = process_dsc_tlv_rhash;
        handl.msg_format = ref_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_RHASH, &handl);


        handl.name = "REFERENCE_REQ";
	handl.rx_processUnVerifiedLink = 1;
        handl.tx_iterations = &desc_req_tx_iters;
        handl.min_msg_size = sizeof (struct msg_ref_req);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = DEF_TX_REF_REQ_TO;
        handl.tx_msg_handler = tx_msg_ref_request;
        handl.rx_msg_handler = rx_msg_ref_request;
        register_frame_handler(packet_frame_db, FRAME_TYPE_REF_REQ, &handl);

        handl.name = "REFERENCE_ADV";
	handl.rx_processUnVerifiedLink = 1;
        handl.tx_iterations = &desc_adv_tx_iters;
	handl.data_header_size = sizeof(struct frame_hdr_rhash_adv);
        handl.min_msg_size = XMIN(1, sizeof(struct frame_msg_rhash_adv));  // this frame does not know what the referenced data is about!
        handl.fixed_msg_size = 0;
        handl.tx_task_interval_min = DEF_TX_DREF_ADV_TO;
        handl.tx_frame_handler = tx_frame_ref_adv;
        handl.rx_frame_handler = rx_frame_ref_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_REF_ADV, &handl);


        handl.name = "DESC_REQ";
	handl.rx_processUnVerifiedLink = 1;
        handl.tx_iterations = &desc_req_tx_iters;
        handl.data_header_size = sizeof( struct hdr_description_request);
        handl.min_msg_size = sizeof (struct msg_description_request);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = DEF_TX_DESC0_REQ_TO;
        handl.tx_msg_handler = tx_msg_description_request;
        handl.rx_msg_handler = rx_msg_description_request;
        register_frame_handler(packet_frame_db, FRAME_TYPE_DESC_REQ, &handl);


	static const struct field_format version_format[] = VERSION_MSG_FORMAT;
        handl.name = "DSC_VERSION";
	handl.alwaysMandatory = 1;
	handl.min_msg_size = sizeof (struct dsc_msg_version);
        handl.fixed_msg_size = 1;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_version;
        handl.rx_frame_handler = process_dsc_tlv_version;
        handl.msg_format = version_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_VERSION, &handl);

	static const struct field_format names_format[] = NAMES_MSG_FORMAT;
        handl.name = "DSC_HOSTNAME";
	handl.min_msg_size = 0;
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_names;
        handl.rx_frame_handler = process_dsc_tlv_names;
        handl.msg_format = names_format;
        register_frame_handler(description_names_db, BMX_DSC_NAMES_HOSTNAME, &handl);

	static const struct field_format tlv_format[] = TLV_FORMAT;
        handl.name = "DSC_NAMES";
	handl.min_msg_size = sizeof (struct tlv_hdr);
	handl.dextReferencing = (int32_t*)&dflt_fref;
	handl.dextCompression = (int32_t*)&dflt_fzip;
        handl.tx_frame_handler = tx_tlv_msg;
        handl.rx_frame_handler = rx_tlv_frame;
        handl.msg_format = tlv_format;
	handl.next_db = description_names_db;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_NAMES, &handl);

	handl.name = "DESC_ADV";
	handl.min_msg_size = (
		sizeof(struct tlv_hdr) + sizeof(struct desc_hdr_rhash) + sizeof(struct desc_msg_rhash) +
		sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) +
		sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_version) );
	handl.tx_frame_handler = tx_frame_description_adv;
	handl.rx_frame_handler = rx_frame_description_adv;
	register_frame_handler(packet_desc_db, 0, &handl);

	handl.name = "DESC_ADVS";
	handl.rx_processUnVerifiedLink = 1;
	handl.tx_iterations = &desc_adv_tx_iters;
	handl.min_msg_size = sizeof (struct tlv_hdr) + packet_desc_db->handls[0].min_msg_size;
	handl.tx_task_interval_min = DEF_TX_DESC0_ADV_TO;
	handl.tx_msg_handler = tx_tlv_msg;
	handl.rx_frame_handler = rx_tlv_frame;
	handl.next_db = packet_desc_db;
	register_frame_handler(packet_frame_db, FRAME_TYPE_DESC_ADVS, &handl);

        handl.name = "DHASH_REQ";
        handl.tx_iterations = &dhash_req_tx_iters;
        handl.tx_tp_min = &UMETRIC_NBDISCOVERY_MIN;
//        handl.rx_rp_min = &UMETRIC_NBDISCOVERY_MIN;
        handl.data_header_size = sizeof( struct hdr_dhash_request);
        handl.min_msg_size = sizeof (struct msg_dhash_request);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = DEF_TX_DHASH0_REQ_TO;
        handl.tx_msg_handler = tx_msg_dhash_request;
        handl.rx_msg_handler = rx_msg_dhash_request;
        register_frame_handler(packet_frame_db, FRAME_TYPE_DHASH_REQ, &handl);

        handl.name = "DHASH_ADV";
        handl.tx_iterations = &dhash_adv_tx_iters;
        handl.min_msg_size = sizeof (struct msg_dhash_adv);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = DEF_TX_DHASH0_ADV_TO;
        handl.tx_msg_handler = tx_msg_dhash_adv;
        handl.rx_msg_handler = rx_msg_dhash_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_DHASH_ADV, &handl);


        handl.name = "LINK_VERSION_ADV";
	handl.positionMandatory = 1;
	handl.rx_processUnVerifiedLink = 1;
        handl.min_msg_size = sizeof (struct msg_link_version_adv);
        handl.fixed_msg_size = 1;
        handl.tx_msg_handler = tx_msg_link_version_adv;
        handl.rx_msg_handler = rx_msg_link_version_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_LINK_VERSION, &handl);

        handl.name = "HELLO_ADV";
        handl.min_msg_size = sizeof (struct msg_hello_adv);
        handl.fixed_msg_size = 1;
        handl.tx_msg_handler = tx_msg_hello_adv;
        handl.rx_msg_handler = rx_msg_hello_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_HELLO_ADV, &handl);



        handl.name = "DEV_REQ";
        handl.tx_iterations = &dev_req_tx_iters;
//        handl.tx_rp_min = &UMETRIC_NBDISCOVERY_MIN;
        handl.min_msg_size = sizeof (struct msg_dev_req);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.tx_msg_handler = tx_msg_dev_req;
        handl.rx_msg_handler = rx_msg_dev_req;
        register_frame_handler(packet_frame_db, FRAME_TYPE_DEV_REQ, &handl);

        handl.name = "DEV_ADV";
        handl.tx_iterations = &dev_adv_tx_iters;
        handl.min_msg_size = sizeof (struct msg_dev_adv);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.data_header_size = sizeof (struct hdr_dev_adv);
        handl.tx_frame_handler = tx_frame_dev_adv;
        handl.rx_frame_handler = rx_frame_dev_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_DEV_ADV, &handl);


        handl.name = "LINK_REQ_ADV";
        handl.tx_iterations = &link_req_tx_iters;
//        handl.tx_rp_min = &UMETRIC_NBDISCOVERY_MIN;
        handl.min_msg_size = sizeof (struct msg_link_req);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.tx_msg_handler = tx_msg_link_req;
        handl.rx_msg_handler = rx_msg_link_req;
        register_frame_handler(packet_frame_db, FRAME_TYPE_LINK_REQ, &handl);

        handl.name = "LINK_ADV";
        handl.tx_iterations = &link_adv_tx_iters;
        handl.min_msg_size = sizeof (struct msg_link_adv);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.data_header_size = sizeof (struct hdr_link_adv);
        handl.tx_frame_handler = tx_frame_link_adv;
        handl.rx_frame_handler = rx_frame_link_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_LINK_ADV, &handl);

        handl.name = "RP_ADV";
        handl.min_msg_size = sizeof (struct msg_rp_adv);
        handl.fixed_msg_size = 1;
        handl.tx_frame_handler = tx_frame_rp_adv;
        handl.rx_frame_handler = rx_frame_rp_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_RP_ADV, &handl);


        handl.name = "OGM_ADV";
        handl.data_header_size = sizeof (struct hdr_ogm_adv);
        handl.min_msg_size = sizeof (struct msg_ogm_adv);
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = tx_frame_ogm_advs;
        handl.rx_frame_handler = rx_frame_ogm_advs;
        register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_ADV, &handl);

        handl.name = "OGM_ACK";
        handl.tx_iterations = &ogm_ack_tx_iters;
        handl.min_msg_size = sizeof (struct msg_ogm_ack);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.tx_msg_handler = tx_msg_ogm_ack;
        handl.rx_frame_handler = rx_frame_ogm_acks;
        register_frame_handler(packet_frame_db, FRAME_TYPE_OGM_ACK, &handl);
}

void cleanup_msg( void )
{
//	update_my_description_adv();

        schedule_or_purge_ogm_aggregations(YES /*purge_all*/);
	
        if (linkArray)
                debugFree(linkArray, -300218);
        
        purge_cached_descriptions(NULL, NULL, NO);

        update_my_dev_adv();

	ref_node_purge(YES /*all_unused*/);

	free_frame_db(&description_names_db);
	free_frame_db(&description_tlv_db);
	free_frame_db(&packet_desc_db);
	free_frame_db(&packet_frame_db);
}

