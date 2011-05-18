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
#include <errno.h>

#include "bmx.h"
#include "msg.h"
#include "ip.h"
#include "metrics.h"
#include "schedule.h"
#include "tools.h"
#include "plugin.h"

#define CODE_CATEGORY_NAME "message"


static int32_t pref_udpd_size = DEF_UDPD_SIZE;

static int32_t ogm_adv_tx_iters = DEF_OGM_TX_ITERS;
static int32_t ogm_ack_tx_iters = DEF_OGM_ACK_TX_ITERS;

static int32_t desc_req_tx_iters = DEF_DESC_REQ_TX_ITERS;
static int32_t desc_adv_tx_iters = DEF_DESC_ADV_TX_ITERS;
static int32_t desc_adv_tx_unsolicited = DEF_DESC_ADV_UNSOLICITED;

static int32_t dhash_req_tx_iters = DEF_DHASH_REQ_TX_ITERS;
static int32_t dhash_adv_tx_iters = DEF_DHASH_ADV_TX_ITERS;


static int32_t dev_req_tx_iters = DEF_DEV_REQS_TX_ITERS;
static int32_t dev_adv_tx_iters = DEF_DEV_ADVS_TX_ITERS;
static int32_t dev_adv_tx_unsolicited = DEF_DEV_ADV_UNSOLICITED;

static int32_t link_req_tx_iters = DEF_LINK_REQS_TX_ITERS;
static int32_t link_adv_tx_iters = DEF_LINK_ADVS_TX_ITERS;
static int32_t link_adv_tx_unsolicited = DEF_LINK_ADV_UNSOLICITED;

union schedule_hello_info {
        uint8_t u8[2];
        uint16_t u16;
};

static Sha bmx_sha;

AVL_TREE( description_cache_tree, struct description_cache_node, dhash );


//int my_desc0_tlv_len = 0;

IID_T myIID4me = IID_RSVD_UNUSED;
TIME_T myIID4me_timestamp = 0;


static PKT_SQN_T my_packet_sqn = 0;

static struct msg_dev_adv *my_dev_adv_buff = NULL;
static DEVADV_SQN_T my_dev_adv_sqn = 0;
static uint16_t my_dev_adv_msgs_size = 0;

static int32_t msg_dev_req_enabled = NO;


static struct msg_link_adv *my_link_adv_buff = NULL;
static LINKADV_SQN_T my_link_adv_sqn = 0;
//static int32_t my_link_adv_msgs_size = 0;
static int32_t my_link_adv_msgs = 0;




LIST_SIMPEL( ogm_aggreg_list, struct ogm_aggreg_node, list, sqn );
uint32_t ogm_aggreg_pending = 0;
static AGGREG_SQN_T ogm_aggreg_sqn_max;

static struct dhash_node* DHASH_NODE_FAILURE = (struct dhash_node*) & DHASH_NODE_FAILURE;


/***********************************************************
  The core frame/message structures and handlers
 ************************************************************/

char *tlv_op_str(uint8_t op)
{
        switch (op) {
        case TLV_OP_DEL:
                return "TLV_OP_DEL";
        case TLV_OP_TEST:
                return "TLV_OP_TEST";
        case TLV_OP_ADD:
                return "TLV_OP_ADD";
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


struct frame_handl packet_frame_handler[FRAME_TYPE_ARRSZ];

struct frame_handl description_tlv_handl[BMX_DSC_TLV_ARRSZ];










void register_frame_handler(struct frame_handl *array, int pos, struct frame_handl *handl)
{
        TRACE_FUNCTION_CALL;
        
        assertion(-500659, (pos < BMX_DSC_TLV_ARRSZ));
        assertion(-500660, (!array[pos].min_msg_size)); // the pos MUST NOT be used yet
        assertion(-500661, (handl && handl->min_msg_size && handl->name));
        assertion(-500806, (XOR(handl->rx_frame_handler, handl->rx_msg_handler) && XOR(handl->tx_frame_handler, handl->tx_msg_handler)));
        assertion(-500879, (!(handl->min_msg_size % TLV_DATA_STEPS) && handl->min_msg_size >= TLV_DATA_STEPS));
        assertion(-500880, (!(handl->data_header_size % TLV_DATA_STEPS)));
        assertion(-500975, (handl->tx_task_interval_min <= CONTENT_MIN_TX_INTERVAL_MAX));

        assertion(-501213, IMPLIES(handl->msg_format, handl->min_msg_size ==
                fields_dbg(NULL, FIELD_RELEVANCE_LOW, 0, NULL, handl->min_msg_size, handl->msg_format)));
                
        array[pos] = *handl;

        memset(handl, 0, sizeof ( struct frame_handl ) );
}


STATIC_FUNC
struct description * remove_cached_description(struct description_hash *dhash)
{
        TRACE_FUNCTION_CALL;
        struct description_cache_node *dcn;

        if (!(dcn = avl_find_item(&description_cache_tree, dhash)))
                return NULL;

        struct description *desc0 = dcn->description;

        avl_remove(&description_cache_tree, &dcn->dhash, -300206);
        debugFree(dcn, -300108);

        return desc0;
}
STATIC_FUNC
struct description_cache_node *purge_cached_descriptions(IDM_T purge_all)
{
        TRACE_FUNCTION_CALL;
        struct description_cache_node *dcn;
        struct description_cache_node *dcn_min = NULL;
        struct description_hash tmp_dhash;
        memset( &tmp_dhash, 0, sizeof(struct description_hash));

        dbgf_all( DBGT_INFO, "%s", purge_all ? "purge_all" : "only_expired");

        while ((dcn = avl_next_item(&description_cache_tree, &tmp_dhash))) {

                memcpy(&tmp_dhash, &dcn->dhash, HASH_SHA1_LEN);

                if (purge_all || ((TIME_T) (bmx_time - dcn->timestamp)) > DEF_DESC0_CACHE_TO) {

                        avl_remove(&description_cache_tree, &dcn->dhash, -300208);
                        debugFree(dcn->description, -300100);
                        debugFree(dcn, -300101);

                } else {

                        if (!dcn_min || U32_LT(dcn->timestamp, dcn_min->timestamp))
                                dcn_min = dcn;
                }
        }

        return dcn_min;
}

STATIC_FUNC
void cache_description(struct description *desc, struct description_hash *dhash)
{
        TRACE_FUNCTION_CALL;
        struct description_cache_node *dcn;

        uint16_t desc_len = sizeof (struct description) + ntohs(desc->dsc_tlvs_len);

        if ((dcn = avl_find_item(&description_cache_tree, dhash))) {
                dcn->timestamp = bmx_time;
                return;
        }

        dbgf_all( DBGT_INFO, "%8X..", dhash->h.u32[0]);


        paranoia(-500261, (description_cache_tree.items > DEF_DESC0_CACHE_SIZE));

        if ( description_cache_tree.items == DEF_DESC0_CACHE_SIZE ) {


                struct description_cache_node *dcn_min = purge_cached_descriptions( NO );

                dbgf_sys(DBGT_WARN, "desc0_cache_tree reached %d items! cleaned up %d items!",
                        DEF_DESC0_CACHE_SIZE, DEF_DESC0_CACHE_SIZE - description_cache_tree.items);

                if (description_cache_tree.items == DEF_DESC0_CACHE_SIZE) {
                        avl_remove(&description_cache_tree, &dcn_min->dhash, -300209);
                        debugFree(dcn_min->description, -300102);
                        debugFree(dcn_min, -300103);
                }
        }

        paranoia(-500273, (desc_len != sizeof ( struct description) + ntohs(desc->dsc_tlvs_len)));

        dcn = debugMalloc(sizeof ( struct description_cache_node), -300104);
        dcn->description = debugMalloc(desc_len, -300105);
        memcpy(dcn->description, desc, desc_len);
        memcpy( &dcn->dhash, dhash, HASH_SHA1_LEN );
        dcn->timestamp = bmx_time;
        avl_insert(&description_cache_tree, dcn, -300145);

}


IDM_T process_description_tlvs(struct packet_buff *pb, struct orig_node *on, struct description *desc, uint8_t op,
                               uint8_t filter, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        assertion(-500370, (op == TLV_OP_DEL || op == TLV_OP_TEST || op == TLV_OP_ADD || op == TLV_OP_DEBUG ||
                (op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX)));
        assertion(-500590, IMPLIES(on == &self, (op == TLV_OP_DEBUG ||
                (op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX))));
        assertion(-500807, (desc));
        assertion(-500829, IMPLIES(op == TLV_OP_DEL, !on->blocked));

        int32_t tlv_result;
        uint16_t dsc_tlvs_len = ntohs(desc->dsc_tlvs_len);

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .on = on, .cn = cn, .op = op, .pb = pb,
                .handls = description_tlv_handl, .handl_max = (BMX_DSC_TLV_MAX), .process_filter = filter,
                .frames_in = (((uint8_t*) desc) + sizeof (struct description)), .frames_pos = 0,
                .frames_length = dsc_tlvs_len
        };

        dbgf_all(DBGT_INFO, "op=%s id=%s dsc_sqn=%d size=%d ",
                tlv_op_str(op), globalIdAsString(&desc->global_id), ntohs(desc->dsc_sqn), dsc_tlvs_len);


        while ((tlv_result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE);

        if ((op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX))
                return TLV_RX_DATA_DONE;

        if (tlv_result == TLV_RX_DATA_BLOCKED) {

                assertion(-500356, (op == TLV_OP_TEST));

                dbgf_sys(DBGT_ERR, "%s frame_data_length=%d  BLOCKED",
                        description_tlv_handl[it.frame_type].name, it.frame_data_length);

                on->blocked = YES;

                if (!avl_find(&blocked_tree, &on->global_id))
                        avl_insert(&blocked_tree, on, -300165);

                return TLV_RX_DATA_BLOCKED;


        } else if (tlv_result == TLV_RX_DATA_FAILURE) {

                dbgf_sys(DBGT_WARN,
                        "rcvd problematic description_ltv from %s near: type=%s  frame_data_length=%d  pos=%d ",
                        pb ? pb->i.llip_str : "---",
                        description_tlv_handl[it.frame_type].name, it.frame_data_length, it.frames_pos);

                return TLV_RX_DATA_FAILURE;
        }

        if ( op == TLV_OP_ADD ) {
                on->blocked = NO;
                avl_remove(&blocked_tree, &on->global_id, -300211);
        }

        return TLV_RX_DATA_DONE;
}



void purge_tx_task_list(struct list_head *tx_task_lists, struct link_node *only_link, struct dev_node *only_dev)
{
        TRACE_FUNCTION_CALL;
        int i;
        assertion(-500845, (tx_task_lists));

        for (i = 0; i < FRAME_TYPE_ARRSZ; i++) {

                struct list_node *lpos, *tpos, *lprev = (struct list_node*) & tx_task_lists[i];

                list_for_each_safe(lpos, tpos, &tx_task_lists[i])
                {
                        struct tx_task_node * tx_task = list_entry(lpos, struct tx_task_node, list);

                        if ((!only_link || only_link == tx_task->task.link) &&
                                (!only_dev || only_dev == tx_task->task.dev)) {


                                if (packet_frame_handler[tx_task->task.type].tx_task_interval_min) {
                                        avl_remove(&tx_task->task.dev->tx_task_interval_tree, &tx_task->task, -300313);
                                }

                                list_del_next(&tx_task_lists[i], lprev);

                                dbgf_all(DBGT_INFO, "removed frame_type=%d ln=%s dev=%s tx_tasks_list.items=%d",
                                        tx_task->task.type,
                                        ipXAsStr(af_cfg, tx_task->task.link ? &tx_task->task.link->link_ip : &ZERO_IP),
                                        tx_task->task.dev->label_cfg.str, tx_task_lists[tx_task->task.type].items);

                                debugFree(tx_task, -300066);

                                continue;
                        }

                        lprev = lpos;
                }
        }
}


STATIC_FUNC
IDM_T freed_tx_task_node(struct tx_task_node *tx_task, struct list_head *tx_task_list, struct list_node *lprev)
{
        TRACE_FUNCTION_CALL;
        assertion(-500372, (tx_task && tx_task->task.dev));
        assertion(-500539, lprev);

        if (tx_task->tx_iterations <= 0) {

                if (packet_frame_handler[tx_task->task.type].tx_task_interval_min) {
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

        if (tx_task->task.myIID4x >= IID_MIN_USED &&
                (!(dhn = iid_get_node_by_myIID4x(tx_task->task.myIID4x)) || !dhn->on)) {

                reason = dhn ? "INVALIDATED" : "UNKNOWN";
                tx_task->tx_iterations = 0;
                problem = TLV_TX_DATA_DONE;

        } else if (packet_frame_handler[tx_task->task.type].tx_task_interval_min &&
                ((TIME_T) (bmx_time - tx_task->send_ts) < packet_frame_handler[tx_task->task.type].tx_task_interval_min)) {

                reason = "RECENTLY SEND";
                problem = TLV_TX_DATA_IGNORED;

        } else {

//                tx_task->send_ts = bmx_time;

                self.dhn->referred_by_me_timestamp = bmx_time;

                if (dhn)
                        dhn->referred_by_me_timestamp = bmx_time;

                return TLV_TX_DATA_PROCESSED;
        }


        dbgf_track(DBGT_INFO,
                "%s type=%s dev=%s myIId4x=%d neighIID4x=%d local_id=%X dev_idx=0x%X name=%s or send just %d ms ago",
                reason,
                packet_frame_handler[tx_task->task.type].name, tx_task->task.dev->name_phy_cfg.str,
                tx_task->task.myIID4x, tx_task->task.neighIID4x,
                tx_task->task.link ? ntohl(tx_task->task.link->key.local_id) : 0,
                tx_task->task.link ? tx_task->task.link->key.dev_idx : 0,
                (dhn && dhn->on) ? globalIdAsString(&dhn->on->global_id) : "???", (bmx_time - tx_task->send_ts));


        return problem;
}



STATIC_FUNC
struct tx_task_node *tx_task_new(struct link_dev_node *dest_lndev, struct tx_task_node *test)
{
        assertion(-500909, (dest_lndev));
        struct frame_handl *handl = &packet_frame_handler[test->task.type];
        struct tx_task_node *ttn = NULL;
        struct dhash_node *dhn;

        if (test->task.myIID4x > IID_RSVD_MAX && (!(dhn = iid_get_node_by_myIID4x(test->task.myIID4x)) || !dhn->on))
                return NULL;
        

        if (handl->tx_task_interval_min) {

                if ((ttn = avl_find_item(&test->task.dev->tx_task_interval_tree, &test->task))) {

                        ASSERTION(-500906, (IMPLIES((!handl->is_advertisement), (ttn->task.link == test->task.link))));

                        ttn->frame_msgs_length = test->frame_msgs_length;
                        ttn->tx_iterations = MAX(ttn->tx_iterations, test->tx_iterations);

                        // then it is already scheduled
                        return ttn;
                }
        }

        ttn = debugMalloc(sizeof ( struct tx_task_node), -300026);
        memcpy(ttn, test, sizeof ( struct tx_task_node));
        ttn->send_ts = ((TIME_T) (bmx_time - handl->tx_task_interval_min));


        if (handl->tx_task_interval_min) {

                avl_insert(&test->task.dev->tx_task_interval_tree, ttn, -300315);

                if (test->task.dev->tx_task_interval_tree.items > DEF_TX_TS_TREE_SIZE) {
                        dbg_mute(20, DBGL_SYS, DBGT_WARN,
                                "%s tx_ts_tree reached %d %s neighIID4x=%d u16=%d u32=%d myIID4x=%d",
                                test->task.dev->name_phy_cfg.str, test->task.dev->tx_task_interval_tree.items,
                                handl->name, test->task.neighIID4x, test->task.u16, test->task.u32,
                                test->task.myIID4x);
                }
        }


        if (handl->is_destination_specific_frame) {

                // ensure, this is NOT a dummy dest_lndev!!!:
                ASSERTION(-500850, (dest_lndev && dest_lndev == avl_find_item(&link_dev_tree, &dest_lndev->key)));

                list_add_tail(&(dest_lndev->tx_task_lists[test->task.type]), &ttn->list);

                dbgf_track(DBGT_INFO, "added %s to lndev local_id=%X link_ip=%s dev=%s tx_tasks_list.items=%d",
                        handl->name, ntohl(dest_lndev->key.link->key.local_id),
                        ipXAsStr(af_cfg, &dest_lndev->key.link->link_ip),
                        dest_lndev->key.dev->label_cfg.str, dest_lndev->tx_task_lists[test->task.type].items);

        } else {

                list_add_tail(&(test->task.dev->tx_task_lists[test->task.type]), &ttn->list);
        }

        return ttn;
}

void schedule_tx_task(struct link_dev_node *dest_lndev, uint16_t frame_type, int16_t frame_msgs_len,
        uint16_t u16, uint32_t u32, IID_T myIID4x, IID_T neighIID4x)
{
        TRACE_FUNCTION_CALL;

        struct frame_handl *handl = &packet_frame_handler[frame_type];

        if (!dest_lndev)
                return;

        assertion(-501047, (!cleaning_up)); // this function MUST NOT be called during cleanup
        assertion(-500756, (dest_lndev && dest_lndev->key.dev));
        ASSERTION(-500713, (iid_get_node_by_myIID4x(myIID4me)));
        ASSERTION(-500714, (!myIID4x || iid_get_node_by_myIID4x(myIID4x)));
        assertion(-501090, (frame_msgs_len >= SCHEDULE_MIN_MSG_SIZE));
        assertion(-501091, (dest_lndev->key.dev->active));
        assertion(-501092, (dest_lndev->key.dev->linklayer != TYP_DEV_LL_LO));

        // ensure, this is NOT a dummy dest_lndev if:!!!
        ASSERTION(-500976, (IMPLIES(handl->is_destination_specific_frame,
                (dest_lndev == avl_find_item(&link_dev_tree, &dest_lndev->key)))));


        if (handl->tx_iterations && !(*handl->tx_iterations))
                return;


        dbgf((( /* debug interesting frame types: */ frame_type == FRAME_TYPE_PROBLEM_ADV ||
                frame_type == FRAME_TYPE_HASH_REQ || frame_type == FRAME_TYPE_HASH_ADV ||
                frame_type == FRAME_TYPE_DESC_REQ ||frame_type == FRAME_TYPE_DESC_ADV ||
                frame_type == FRAME_TYPE_LINK_REQ || frame_type == FRAME_TYPE_LINK_ADV ||
                frame_type == FRAME_TYPE_DEV_REQ || frame_type == FRAME_TYPE_DEV_ADV)
                ? DBGL_CHANGES : DBGL_ALL), DBGT_INFO,
                 "%s to NB=%s local_id=0x%X via dev=%s frame_msgs_len=%d u16=%d u32=%d myIID4x=%d neighIID4x=%d ",
                handl->name,
                dest_lndev->key.link ? ipXAsStr(af_cfg, &dest_lndev->key.link->link_ip) : "---",
                dest_lndev->key.link ? dest_lndev->key.link->local->local_id : 0,
                dest_lndev->key.dev->label_cfg.str, frame_msgs_len, u16, u32, myIID4x, neighIID4x);

        if (handl->tx_tp_min && *(handl->tx_tp_min) > dest_lndev->timeaware_tx_probe) {

                dbgf_track(DBGT_INFO, "NOT sending %s (via %s sqn %d myIID4x %d neighIID4x %d) tp=%ju < %ju",
                        handl->name, dest_lndev->key.dev->label_cfg.str, u16, myIID4x, neighIID4x,
                        dest_lndev->timeaware_tx_probe, *(handl->tx_tp_min));
                return;
        }

        if (handl->tx_rp_min && *(handl->tx_rp_min) > dest_lndev->timeaware_rx_probe) {

                dbgf_track(DBGT_INFO, "NOT sending %s (via %s sqn %d myIID4x %d neighIID4x %d) rp=%ju < %ju",
                        handl->name, dest_lndev->key.dev->label_cfg.str, u16, myIID4x, neighIID4x,
                        dest_lndev->timeaware_rx_probe, *(handl->tx_rp_min));
                return;
        }

        struct tx_task_node test_task;
        memset(&test_task, 0, sizeof (test_task));
        test_task.task.u16 = u16;
        test_task.task.u32 = u32;
        test_task.task.dev = dest_lndev->key.dev;
        test_task.task.myIID4x = myIID4x;
        test_task.task.neighIID4x = neighIID4x;
        test_task.task.type = frame_type;
        test_task.tx_iterations = handl->tx_iterations ? *handl->tx_iterations : 1;
        test_task.considered_ts = bmx_time - 1;

        // advertisements are send to all and are not bound to a specific destinations,
        // therfore tx_task_obsolete should not filter due to the destination_dev_id
        if (!handl->is_advertisement && dest_lndev->key.link) {
                //ASSERTION(-500915, (dest_lndev == avl_find_item(&link_dev_tree, &dest_lndev->key)));
                test_task.task.link = dest_lndev->key.link;
        }

        test_task.frame_msgs_length = frame_msgs_len == SCHEDULE_MIN_MSG_SIZE ? handl->min_msg_size : frame_msgs_len;


        assertion(-500371, IMPLIES(handl->fixed_msg_size, !(test_task.frame_msgs_length % handl->min_msg_size)));
/*
        if (frame_msgs_len) {
                test_task.frame_msgs_length = frame_msgs_len;
        } else {
                assertion(-500769, (handl->fixed_msg_size && handl->min_msg_size));
                test_task.frame_msgs_length = handl->min_msg_size;
        }
*/

        tx_task_new(dest_lndev, &test_task);
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
        assertion(-501063, ((((OGM_SQN_MASK) & (on->ogmSqn_next - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize)));

        FMETRIC_U16_T fm = umetric_to_fmetric(on->ogmMetric_next);

        if (UXX_GT(OGM_SQN_MASK, on->ogmSqn_next, on->ogmSqn_send + OGM_SQN_STEP)) {

                dbgf_track(DBGT_WARN, "id=%s delayed %d < %d", globalIdAsString(&on->global_id), on->ogmSqn_send, on->ogmSqn_next);
        } else {

                dbgf_all(DBGT_INFO, "id=%s in-time %d < %d", globalIdAsString(&on->global_id), on->ogmSqn_send, on->ogmSqn_next);
        }

        set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_next, on->ogmSqn_next);

        on->dhn->referred_by_me_timestamp = bmx_time;

        assertion(-500890, ((on->dhn->myIID4orig - prev_ogm_iid) <= OGM_IIDOFFST_MASK));

        OGM_MIX_T mix =
                ((on->dhn->myIID4orig - prev_ogm_iid) << OGM_IIDOFFST_BIT_POS) +
                ((fm.val.f.exp_fm16) << OGM_EXPONENT_BIT_POS) +
                ((fm.val.f.mantissa_fm16) << OGM_MANTISSA_BIT_POS);

        ogm->mix = htons(mix);
        ogm->u.ogm_sqn = htons(on->ogmSqn_next);

        return on->dhn->myIID4orig;
}

STATIC_FUNC
void create_ogm_aggregation(void)
{
        TRACE_FUNCTION_CALL;
        uint32_t target_ogms = MIN(OGMS_PER_AGGREG_MAX,
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

                        if (on != &self && (!on->curr_rt_local || on->curr_rt_local->mr.umetric < on->path_metricalgo->umetric_min)) {

                                dbgf_sys(DBGT_WARN,
                                        "id=%s with %s curr_rn and PENDING ogm_sqn=%d but path_metric=%jd < USABLE=%jd",
                                        globalIdAsString(&on->global_id), on->curr_rt_local ? " " : "NO", on->ogmSqn_next,
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

                                msgs[ogm_msg + ogm_iid_jumps].mix = htons((OGM_IID_RSVD_JUMP) << OGM_IIDOFFST_BIT_POS);
                                msgs[ogm_msg + ogm_iid_jumps].u.transmitterIIDabsolute = htons(ogm_iid);

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

        struct ogm_aggreg_node *oan = debugMalloc(sizeof (struct ogm_aggreg_node), -300179);
        memset(oan, 0, sizeof (struct ogm_aggreg_node));

        oan->aggregated_msgs = ogm_msg + ogm_iid_jumps;
        oan->ogm_advs = msgs;
        oan->tx_attempt = 0;
        oan->sqn = (++ogm_aggreg_sqn_max);
        uint16_t destinations = 0;

        struct avl_node *neigh_an = NULL;
        struct neigh_node *neigh;
        struct local_node *local;

        while ((neigh = avl_iterate_item(&neigh_tree, &neigh_an)) && (local = neigh->local)) {

                if (local->link_adv_msg_for_him != LINKADV_MSG_IGNORED && local->rp_ogm_request_rcvd) {

                        destinations++;

/*
                        assertion(-501137, (local->link_adv_msg_for_him < OGM_DESTINATION_ARRAY_BIT_SIZE));
                        oan->ogm_dest_bytes = MAX(oan->ogm_dest_bytes, ((local->link_adv_msg_for_him / 8) + 1));
                        bit_set(oan->ogm_dest_field, OGM_DESTINATION_ARRAY_BIT_SIZE, local->link_adv_msg_for_him, 1);
*/

                        bit_set(neigh->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, ogm_aggreg_sqn_max, 1);

                } else {
                        bit_set(neigh->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, ogm_aggreg_sqn_max, 0);
                }
        }

        list_add_tail(&ogm_aggreg_list, &oan->list);

        dbgf_all( DBGT_INFO, "aggregation_sqn=%d ogms=%d jumps=%d destinations=%d",
                oan->sqn, ogm_msg, ogm_iid_jumps, destinations);

        return;
}




static struct link_dev_node **lndev_arr = NULL;
static uint16_t lndev_arr_items = 0;

STATIC_FUNC
void lndevs_prepare(void)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct dev_node *dev;

        if (lndev_arr_items < dev_ip_tree.items + 1) {

                if (lndev_arr)
                        debugFree(lndev_arr, -300180);

                lndev_arr_items = dev_ip_tree.items + 1;
                lndev_arr = debugMalloc((lndev_arr_items * sizeof (struct link_dev_node*)), -300182);
        }

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));)
                dev->lndevs_tmp = NO;
}


STATIC_FUNC
struct link_dev_node **lndevs_get_unacked_ogm_neighbors(struct ogm_aggreg_node *oan)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *neigh_an = NULL;
        struct neigh_node *neigh;
        struct local_node *local;
        uint16_t d = 0;

        dbgf_all(DBGT_INFO, "aggreg_sqn %d ", oan->sqn);

        lndevs_prepare();

        memset(oan->ogm_dest_field, 0, sizeof (oan->ogm_dest_field));
        oan->ogm_dest_bytes = 0;

        while ((neigh = avl_iterate_item(&neigh_tree, &neigh_an)) && (local = neigh->local)) {
               
                assertion(-500971, (IMPLIES(local, local->best_tp_lndev)));

                if (local->link_adv_msg_for_him == LINKADV_MSG_IGNORED || !local->rp_ogm_request_rcvd)
                        bit_set(neigh->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, oan->sqn, 0);
                
                IDM_T not_acked = bit_get(neigh->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, oan->sqn);

                if (not_acked || oan->tx_attempt == 0) {

                        struct dev_node *dev_best = local->best_tp_lndev->key.dev;

                        dbgf_all(DBGT_INFO, "  redundant=%d via dev=%s to local_id=%X dev_idx=0x%X",
                                dev_best->lndevs_tmp, dev_best->label_cfg.str,
                                ntohl(local->best_tp_lndev->key.link->key.local_id),
                                local->best_tp_lndev->key.link->key.dev_idx);

                        if (dev_best->lndevs_tmp == NO) {

                                assertion(-500446, (dev_best));
                                assertion(-500447, (dev_best->active));
                                assertion(-500444, (d <= dev_ip_tree.items));

                                lndev_arr[d++] = local->best_tp_lndev;
                                dev_best->lndevs_tmp = YES;
                        }

                        if (not_acked) {
                                assertion(-501138, (local->link_adv_msg_for_him < OGM_DEST_ARRAY_BIT_SIZE));
                                oan->ogm_dest_bytes = MAX(oan->ogm_dest_bytes, ((local->link_adv_msg_for_him / 8) + 1));
                                bit_set(oan->ogm_dest_field, OGM_DEST_ARRAY_BIT_SIZE, local->link_adv_msg_for_him, 1);
                        }


                        if (oan->tx_attempt >= ((ogm_adv_tx_iters * 3) / 4)) {

                                dbg_track(DBGT_WARN, "schedule ogm_aggregation_sqn=%3d msgs=%2d dest_bytes=%d tx_attempt=%2d/%d via dev=%s to NB=%s",
                                        oan->sqn, oan->aggregated_msgs, oan->ogm_dest_bytes, (oan->tx_attempt + 1),
                                        ogm_adv_tx_iters, local->best_tp_lndev->key.dev->label_cfg.str,
                                        ipXAsStr(af_cfg, &local->best_tp_lndev->key.link->link_ip));
                        }
                }
        }

        lndev_arr[d] = NULL;

        return lndev_arr;
}

STATIC_FUNC
struct link_dev_node **lndevs_get_best_tp(struct local_node *except_local)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct local_node *local;
        uint16_t d = 0;

        lndevs_prepare();

        dbgf_all(DBGT_INFO, "NOT local_id=%d ", except_local ? except_local->local_id : 0);

        for (an = NULL; (local = avl_iterate_item(&local_tree, &an));) {

                if (except_local != local) {

                        assertion(-500445, (local->best_tp_lndev && local->best_tp_lndev->key.dev));

                        struct dev_node *dev_best = local->best_tp_lndev->key.dev;

                        assertion(-500446, (dev_best));
                        assertion(-500447, (dev_best->active));

                        dbgf_all(DBGT_INFO, "  via dev=%s to local_id=%X dev_idx=0x%X (redundant %d)",
                                dev_best->label_cfg.str, ntohl(local->best_tp_lndev->key.link->key.local_id),
                                local->best_tp_lndev->key.link->key.dev_idx, dev_best->lndevs_tmp);

                        if (dev_best->lndevs_tmp == NO) {

                                lndev_arr[d++] = local->best_tp_lndev;

                                dev_best->lndevs_tmp = YES;
                        }

                        assertion(-500444, (d <= dev_ip_tree.items));
                }
        }


        lndev_arr[d] = NULL;

        return lndev_arr;
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
                                                        on->id.name, on->curr_rt_local ? " " : "NO", on->ogmSqn_next,
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

                        struct link_dev_node **lndev_arr = lndevs_get_unacked_ogm_neighbors(oan);
                        int d;

                        oan->tx_attempt = (lndev_arr[0]) ? (oan->tx_attempt + 1) : ogm_adv_tx_iters;

                        for (d = 0; (lndev_arr[d]); d++) {

                                schedule_tx_task((lndev_arr[d]), FRAME_TYPE_OGM_ADV,
                                        ((oan->aggregated_msgs * sizeof (struct msg_ogm_adv)) + oan->ogm_dest_bytes),
                                        oan->sqn, 0, 0, 0);

                        }

                        assertion(-501139, (IMPLIES(d, (oan->aggregated_msgs))));
                }

                lprev = lpos;
        }
}




STATIC_FUNC
int32_t tx_msg_hello_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        assertion(-500771, (tx_iterator_cache_data_space(it) >= ((int) sizeof (struct msg_hello_adv))));

        struct tx_task_node *ttn = it->ttn;
        struct msg_hello_adv *adv = (struct msg_hello_adv *) (tx_iterator_cache_msg_ptr(it));

        HELLO_SQN_T sqn_in = ttn->task.dev->link_hello_sqn = ((HELLO_SQN_MASK)&(ttn->task.dev->link_hello_sqn + 1));

        adv->hello_sqn = htons(sqn_in);
        
        dbgf_all(DBGT_INFO, "%s %s SQN %d", ttn->task.dev->label_cfg.str, ttn->task.dev->ip_llocal_str, sqn_in);

        return sizeof (struct msg_hello_adv);
}



/*


STATIC_FUNC
int32_t tx_frame_test_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        static uint8_t i = 0xFF;
        struct hdr_test_adv* hdr = ((struct hdr_test_adv*) tx_iterator_cache_hdr_ptr(it));

        assertion(-501007, (hdr->msg == (struct msg_test_adv*)tx_iterator_cache_msg_ptr(it)));
        assertion(-501008, ((int) it->ttn->frame_msgs_length <= tx_iterator_cache_data_space(it)));

        hdr->hdr_test = i++;

        return 0;
}

STATIC_FUNC
int32_t rx_frame_test_adv( struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct hdr_test_adv* hdr = (struct hdr_test_adv*) it->frame_data;;
        struct msg_test_adv* adv = (struct msg_test_adv*) it->msg;
        assertion(-501017, (adv == hdr->msg));

        uint16_t msgs = it->frame_msgs_length / sizeof (struct msg_test_adv);

        dbgf_sys(DBGT_WARN, "rcvd TEST_ADV via dev=%s msgs_size=%d frame_data_length=%d from: "
                "NB=%s local_id=%X dev_idx=%d hdr_test=%d",
                it->pb->i.iif->label_cfg.str, it->frame_msgs_length, it->frame_data_length,
                it->pb->i.llip_str, it->pb->i.link->key.local_id, it->pb->i.link->key.dev_idx, hdr->hdr_test);

        assertion(-501010, (it->frame_data_length == ((int)(it->frame_msgs_length + sizeof (struct hdr_test_adv)))));
        assertion(-501009, (!msgs && !it->frame_msgs_length));

        return it->frame_msgs_length;
}


*/



STATIC_FUNC
int32_t tx_msg_dhash_or_description_request(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct tx_task_node *ttn = it->ttn;
        struct hdr_dhash_request *hdr = ((struct hdr_dhash_request*) tx_iterator_cache_hdr_ptr(it));
        struct msg_dhash_request *msg = ((struct msg_dhash_request*) tx_iterator_cache_msg_ptr(it));
        struct dhash_node *dhn = (ttn->task.link && ttn->task.link->local->neigh) ?
                iid_get_node_by_neighIID4x(ttn->task.link->local->neigh, ttn->task.neighIID4x, YES/*verbose*/) : NULL;


        dbgf_track(DBGT_INFO, "%s dev=%s to local_id=%X dev_idx=0x%X iterations=%d time=%d requesting neighIID4x=%d %s",
                it->handls[ttn->task.type].name, ttn->task.dev->label_cfg.str, ntohl(ttn->task.link->key.local_id),
                ttn->task.link->key.dev_idx, ttn->tx_iterations, ttn->considered_ts, ttn->task.neighIID4x,
                dhn ? "ALREADY RESOLVED (req cancelled)" : ttn->task.link->local->neigh ? "ABOUT NB HIMSELF" : "ABOUT SOMEBODY");

        assertion(-500853, (sizeof ( struct msg_description_request) == sizeof ( struct msg_dhash_request)));
        assertion(-500855, (tx_iterator_cache_data_space(it) >= ((int) (sizeof (struct msg_dhash_request)))));
        assertion(-500856, (ttn->task.link));
        assertion(-500870, (ttn->tx_iterations > 0 && ttn->considered_ts != bmx_time));
        assertion(-500858, (IMPLIES((dhn && dhn->on), dhn->on->desc)));

        if (dhn) {
                // description (and hash) already resolved, skip sending..
                ttn->tx_iterations = 0;
                return TLV_TX_DATA_DONE;
        }


        if (hdr->msg == msg) {

                assertion(-500854, (is_zero(hdr, sizeof (*hdr))));
                hdr->destination_local_id = ttn->task.link->key.local_id;

        } else {

                assertion(-500871, (hdr->destination_local_id == ttn->task.link->key.local_id));
        }

        dbgf_track(DBGT_INFO, "creating msg=%d", ((int) ((((char*) msg) - ((char*) hdr) - sizeof ( *hdr)) / sizeof (*msg))));

        msg->receiverIID4x = htons(ttn->task.neighIID4x);

        return sizeof (struct msg_dhash_request);
}



STATIC_FUNC
int32_t tx_msg_description_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node * ttn = it->ttn;
        struct dhash_node *dhn;
        struct description *desc0;

        struct msg_description_adv *adv = (struct msg_description_adv *) tx_iterator_cache_msg_ptr(it);

        dbgf_all(DBGT_INFO, "ttn->myIID4x %d", ttn->task.myIID4x);

        assertion( -500555, (ttn->task.myIID4x >= IID_MIN_USED));

        if (ttn->task.myIID4x == myIID4me) {

                dhn = self.dhn;

        } else if ((dhn = iid_get_node_by_myIID4x(ttn->task.myIID4x)) && dhn->on) {

                assertion(-500437, (dhn->on->desc));

        } else {

                dbgf_sys(DBGT_WARN, "%s myIID4x %d !", dhn ? "INVALID" : "UNKNOWN", ttn->task.myIID4x);

                // an meanwhile invalidated dhn migh have been scheduled when it was still valid, but not an unknown:
                assertion(-500977, (dhn && !dhn->on));

                return TLV_TX_DATA_DONE;
        }

        uint16_t tlvs_len = ntohs(dhn->on->desc->dsc_tlvs_len);

        if (tlvs_len + ((int) sizeof (struct msg_description_adv)) > tx_iterator_cache_data_space(it)) {

                dbgf_sys(DBGT_ERR, "tlvs_len=%d + description_len=%zu > cache_data_space=%d",
                        tlvs_len, sizeof (struct msg_description_adv), tx_iterator_cache_data_space(it));

                return TLV_TX_DATA_FULL;
        }

        adv->transmitterIID4x = htons(ttn->task.myIID4x);
        desc0 = dhn->on->desc;

        memcpy((char*) & adv->desc, (char*) desc0, sizeof (struct description) + tlvs_len);

        dbgf_track(DBGT_INFO, "id=%s descr_size=%zu", globalIdAsString(&dhn->on->global_id), (tlvs_len + sizeof (struct msg_description_adv)));

        return (tlvs_len + sizeof (struct msg_description_adv));
}




STATIC_FUNC
int32_t tx_msg_dhash_adv(struct tx_frame_iterator *it)
{

        TRACE_FUNCTION_CALL;
        assertion(-500774, (tx_iterator_cache_data_space(it) >= ((int) sizeof (struct msg_dhash_adv))));
        assertion(-500556, (it && it->ttn->task.myIID4x >= IID_MIN_USED));

        struct tx_task_node *ttn = it->ttn;
        struct msg_dhash_adv *adv = (struct msg_dhash_adv *) tx_iterator_cache_msg_ptr(it);
        struct dhash_node *dhn;


        if (ttn->task.myIID4x == myIID4me) {

                adv->transmitterIID4x = htons(myIID4me);
                dhn = self.dhn;

        } else if ((dhn = iid_get_node_by_myIID4x(ttn->task.myIID4x)) && dhn->on) {

                assertion(-500259, (dhn->on->desc));
                adv->transmitterIID4x = htons(ttn->task.myIID4x);

        } else {

                dbgf_sys(DBGT_WARN, "%s myIID4x %d !", dhn ? "INVALID" : "UNKNOWN", ttn->task.myIID4x);

                // an meanwhile invalidated dhn migh have been scheduled when it was still valid, but not an unknown:
                assertion(-500978, (dhn && !dhn->on));

                return TLV_TX_DATA_DONE;
        }

        memcpy((char*) & adv->dhash, (char*) & dhn->dhash, sizeof ( struct description_hash));

        dbgf_track(DBGT_INFO, "id=%s", globalIdAsString(&dhn->on->global_id));

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
                my_dev_adv_buff = debugMalloc(dev_ip_tree.items * sizeof (struct msg_dev_adv), -300319);
                memset(my_dev_adv_buff, 0, dev_ip_tree.items * sizeof (struct msg_dev_adv));
        }

        for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));)
                dev->dev_adv_msg = DEVADV_MSG_IGNORED;

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                if (dev->linklayer == TYP_DEV_LL_LO)
                        continue;

                my_dev_adv_buff[msg].dev_idx = dev->dev_adv_idx;
                my_dev_adv_buff[msg].channel = dev->channel;
                my_dev_adv_buff[msg].tx_bitrate_min = umetric_to_fmu8(&dev->umetric_min);
                my_dev_adv_buff[msg].tx_bitrate_max = umetric_to_fmu8(&dev->umetric_max);
                my_dev_adv_buff[msg].llip = dev->llocal_ip_key;
                my_dev_adv_buff[msg].mac = dev->mac;

                dev->dev_adv_msg = msg++;
        }

        my_dev_adv_msgs_size = msg * sizeof (struct msg_dev_adv);

        if (dev_adv_tx_unsolicited) {

                struct dev_node *dev;

                for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));)
                        schedule_tx_task(&dev->dummy_lndev, FRAME_TYPE_DEV_ADV, SCHEDULE_UNKNOWN_MSGS_SIZE, 0, 0, 0, 0);

        }


        update_my_link_adv(LINKADV_CHANGES_CRITICAL);
}


STATIC_FUNC
int32_t tx_frame_dev_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct hdr_dev_adv* hdr = ((struct hdr_dev_adv*) tx_iterator_cache_hdr_ptr(it));

        assertion(-500933, (hdr->msg == ((struct msg_dev_adv*) tx_iterator_cache_msg_ptr(it))));
        assertion(-500934, ((int) it->ttn->frame_msgs_length <= tx_iterator_cache_data_space(it)));

        if (my_dev_adv_msgs_size > tx_iterator_cache_data_space(it))
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

        if (req->destination_local_id == my_local_id)
                schedule_tx_task(&it->pb->i.iif->dummy_lndev, FRAME_TYPE_DEV_ADV, SCHEDULE_UNKNOWN_MSGS_SIZE, 0, 0, 0, 0);

        return sizeof (struct msg_dev_req);
}


STATIC_FUNC
int32_t tx_msg_dev_req(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node *ttn = it->ttn;
        struct msg_dev_req *msg = ((struct msg_dev_req*) tx_iterator_cache_msg_ptr(it));
        struct local_node *local = avl_find_item(&local_tree, &ttn->task.u32);

        assertion(-500986, (ttn->tx_iterations > 0 && ttn->considered_ts != bmx_time));

        dbgf_track(DBGT_INFO, "%s dev=%s to local_id=%X iterations=%d %s",
                it->handls[ttn->task.type].name, ttn->task.dev->label_cfg.str, ntohl(ttn->task.u32), ttn->tx_iterations,
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

        uint16_t msgs = it->frame_msgs_length / sizeof (struct msg_dev_adv);

        struct local_node *local = it->pb->i.link->local;

        DEVADV_SQN_T dev_sqn = ntohs(hdr->dev_sqn);

        dbgf_all(DBGT_INFO, " ");

        if (!msg_dev_req_enabled) {

                return it->frame_msgs_length;

        } else if (dev_sqn == local->dev_adv_sqn) {

                if (local->dev_adv_msgs != msgs || memcmp(local->dev_adv, adv, it->frame_msgs_length )) {
                        dbgf_sys(DBGT_ERR, "DAD-Alert: dev_adv_msgs=%d != msgs=%d || memcmp(local->dev_adv, adv)=%d",
                                local->dev_adv_msgs, msgs, memcmp(local->dev_adv, adv, it->frame_msgs_length));

                        purge_local_node(local);

                        return FAILURE;
                }

        } else if (((DEVADV_SQN_T) (dev_sqn - local->dev_adv_sqn)) > DEVADV_SQN_DAD_RANGE) {

                dbgf_sys(DBGT_ERR, "DAD-Alert: NB=%s dev=%s dev_sqn=%d dev_sqn_max=%d dad_range=%d",
                        it->pb->i.llip_str, it->pb->i.iif->label_cfg.str, dev_sqn, local->dev_adv_sqn, DEVADV_SQN_DAD_RANGE);

                purge_local_node(local);
                
                return FAILURE;


        } else if (local->dev_adv_sqn != dev_sqn) {

                dbgf_track(DBGT_INFO, "new DEV_ADV from NB=%s local_id=0x%X dev=%s dev_sqn=%d->%d",
                        it->pb->i.llip_str,  it->pb->i.link->local->local_id , it->pb->i.iif->label_cfg.str,
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
void set_link_adv_msg(uint16_t msg, struct link_dev_node *lndev)
{
        my_link_adv_buff[msg].transmitter_dev_idx = lndev->key.dev->dev_adv_idx;
        my_link_adv_buff[msg].peer_dev_idx = lndev->key.link->key.dev_idx;
        my_link_adv_buff[msg].peer_local_id = lndev->key.link->key.local_id;
        lndev->link_adv_msg = msg;
        
        if (lndev->key.link->local->link_adv_msg_for_him == LINKADV_MSG_IGNORED)
                lndev->key.link->local->link_adv_msg_for_him = msg;
}

void update_my_link_adv(uint32_t changes)
{
        TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct link_dev_node *lndev;
        struct local_node *local;
        uint16_t msg = 0;
        static PKT_SQN_T last_link_packet_sqn = 0;
        static TIME_T last_link_adv_time = 0;
        static uint32_t my_link_adv_changes = LINKADV_CHANGES_NONE;

        my_link_adv_changes += changes;

        // no need to increment link_adv_sqn if no packet has been emitted since last link_adv change:
        if (!terminating && last_link_packet_sqn != my_packet_sqn) {

                if (!(my_link_adv_changes >= LINKADV_CHANGES_CRITICAL ||
                        (my_link_adv_changes >= LINKADV_CHANGES_NEW && ((TIME_T) (bmx_time - last_link_adv_time)) >= LINKADV_INTERVAL_NEW) ||
                        (my_link_adv_changes >= LINKADV_CHANGES_REMOVED && ((TIME_T) (bmx_time - last_link_adv_time)) >= LINKADV_INTERVAL_REMOVED) ))
                        return;

                last_link_packet_sqn = my_packet_sqn;
                my_link_adv_sqn++;
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

        if (link_dev_tree.items) {
                my_link_adv_buff = debugMalloc(link_dev_tree.items * sizeof (struct msg_link_adv), -300343);
                memset(my_link_adv_buff, 0, link_dev_tree.items * sizeof (struct msg_link_adv));
        }

        for (an = NULL; (lndev = avl_iterate_item(&link_dev_tree, &an));){
                lndev->link_adv_msg = LINKADV_MSG_IGNORED;
                lndev->key.link->local->link_adv_msg_for_him = LINKADV_MSG_IGNORED;
        }

        for (an = NULL; (local = avl_iterate_item(&local_tree, &an));)
                set_link_adv_msg(msg++, local->best_rp_lndev);

        assertion(-501140, (msg <= LOCALS_MAX));


        for (an = NULL; (lndev = avl_iterate_item(&link_dev_tree, &an));) {

                if (lndev->link_adv_msg > LINKADV_MSG_IGNORED)
                        continue;

                //TODO: sort out lndevs with reasonable worse rq than best_rqlndev: if (lndev->key.link->local->best_lndev)
                if (lndev->timeaware_rx_probe * LINKADV_ADD_RP_4DIF >=
                        lndev->key.link->local->best_rp_lndev->timeaware_rx_probe * LINKADV_ADD_RP_4MIN)
                        set_link_adv_msg(msg++, lndev);

        }

        my_link_adv_msgs = msg;

        if (link_adv_tx_unsolicited) {

                struct dev_node *dev;

                for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));)
                        schedule_tx_task(&dev->dummy_lndev, FRAME_TYPE_LINK_ADV, (msg * sizeof (struct msg_link_adv)), 0, 0, 0, 0);

        }

        dbgf_track(DBGT_INFO, "new link_adv_sqn=%d with link_adv_msgs=%d", my_link_adv_sqn, my_link_adv_msgs);
}


STATIC_FUNC
int32_t tx_frame_link_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct hdr_link_adv* hdr = ((struct hdr_link_adv*) tx_iterator_cache_hdr_ptr(it));

        assertion(-500933, (hdr->msg == ((struct msg_link_adv*) tx_iterator_cache_msg_ptr(it))));
        assertion(-500934, ((int) it->ttn->frame_msgs_length <= tx_iterator_cache_data_space(it)));

        if ((my_link_adv_msgs * (int32_t)sizeof (struct msg_link_adv)) > tx_iterator_cache_data_space(it))
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

        if (req->destination_local_id == my_local_id) {
                schedule_tx_task(&it->pb->i.iif->dummy_lndev, FRAME_TYPE_LINK_ADV,
                        (my_link_adv_msgs * sizeof (struct msg_link_adv)), 0, 0, 0, 0);
        }

        return sizeof (struct msg_link_req);
}


STATIC_FUNC
int32_t tx_msg_link_req(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node *ttn = it->ttn;
        struct msg_link_req *msg = ((struct msg_link_req*) tx_iterator_cache_msg_ptr(it));
        struct local_node *local = avl_find_item(&local_tree, &ttn->task.u32);

        assertion(-500988, (ttn->tx_iterations > 0 && ttn->considered_ts != bmx_time));

        dbgf_track(DBGT_INFO, "%s dev=%s to local_id=%X iterations=%d %s",
                it->handls[ttn->task.type].name, ttn->task.dev->label_cfg.str, ntohl(ttn->task.u32), ttn->tx_iterations,
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

        struct hdr_link_adv* hdr = (struct hdr_link_adv*) it->frame_data;;
        struct msg_link_adv* adv = (struct msg_link_adv*) it->msg;
        assertion(-500980, (adv == hdr->msg));

        uint16_t msgs = it->frame_msgs_length  / sizeof (struct msg_link_adv);

        struct local_node *local = it->pb->i.link->local;

        DEVADV_SQN_T dev_sqn_ref = ntohs(hdr->dev_sqn_ref);

        dbgf_all(DBGT_INFO, " ");

       // DAD:link_adv_sqn mismatch has been checked in get_link_node()!

        if (it->pb->i.link_sqn == local->link_adv_sqn) {

                if (local->link_adv_dev_sqn_ref != dev_sqn_ref || local->link_adv_msgs != msgs || memcmp(local->link_adv, adv, it->frame_msgs_length )) {

                        dbgf_sys(DBGT_ERR,
                                "DAD-Alert: link_adv_dev_sqn_ref=%d != dev_sqn_ref=%d || link_adv_msgs=%d != msgs=%d || memcmp(link_adv,adv)=%d",
                                local->link_adv_dev_sqn_ref, dev_sqn_ref, local->link_adv_msgs, msgs, memcmp(local->link_adv, adv,it->frame_msgs_length));

                        purge_local_node(local);

                        return FAILURE;
                }

        } else {

                dbgf_track(DBGT_INFO, "new LINK_ADV from NB=%s dev=%s link_sqn=%d->%d dev_sqn=%d->%d dev_adv_sqn=%d",
                        it->pb->i.llip_str, it->pb->i.iif->label_cfg.str, local->link_adv_sqn, it->pb->i.link_sqn,
                        local->link_adv_dev_sqn_ref, dev_sqn_ref, local->dev_adv_sqn);


                if (local->link_adv)
                        debugFree(local->link_adv, -300344);

                local->link_adv = debugMalloc(it->frame_msgs_length, -300345);

                memcpy(local->link_adv, adv, it->frame_msgs_length);

                local->link_adv_sqn = it->pb->i.link_sqn;
                local->link_adv_time = bmx_time;
                local->link_adv_dev_sqn_ref = dev_sqn_ref;
                local->link_adv_msgs = msgs;
                local->link_adv_msg_for_me = LINKADV_MSG_IGNORED;

                uint16_t m;
                for (m = 0; m < msgs; m++) {

                        if (local->link_adv[m].peer_local_id == my_local_id) {
                                local->link_adv_msg_for_me = m;
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
        struct link_dev_node *lndev;
        uint16_t msgs = 0;
        uint16_t msg_max = 0;

        if ((my_link_adv_msgs * (int32_t)sizeof (struct msg_rp_adv)) > tx_iterator_cache_data_space(it))
                return TLV_TX_DATA_FULL;

        for (an = NULL; (lndev = avl_iterate_item(&link_dev_tree, &an));) {

                if (lndev->link_adv_msg == LINKADV_MSG_IGNORED)
                        continue;

                assertion(-501040, (lndev->link_adv_msg < my_link_adv_msgs ));
                assertion(-501041, (lndev->rx_probe_record.hello_umetric <= UMETRIC_MAX));

                if (lndev->timeaware_rx_probe * LINKADV_ADD_RP_4DIF <
                        lndev->key.link->local->best_rp_lndev->timeaware_rx_probe * LINKADV_ADD_RP_4MAX)
                        continue;

                msg[lndev->link_adv_msg].rp_127range = (lndev->timeaware_rx_probe * 127) / UMETRIC_MAX;

                msg[lndev->link_adv_msg].ogm_request = lndev->key.link->local->orig_routes ? YES : NO;

                msg_max = MAX(msg_max, lndev->link_adv_msg);

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

        struct msg_rp_adv* adv = (struct msg_rp_adv*) it->msg;
        struct local_node *local = it->pb->i.link->local;
        struct avl_node *link_an = NULL;
        struct link_node *link;
        struct link_dev_node *lndev = NULL;
        uint16_t msgs = it->frame_msgs_length / sizeof (struct msg_rp_adv);
        uint16_t m;

        if (it->pb->i.link_sqn != local->link_adv_sqn)
                return it->frame_msgs_length;

        if (msgs > local->link_adv_msgs)
                return TLV_RX_DATA_FAILURE;


        local->rp_adv_time = bmx_time;

        while ((link = avl_iterate_item(&local->link_tree, &link_an))) {

                for (lndev = NULL; (lndev = list_iterate(&link->lndev_list, lndev));)
                        lndev->tx_probe_umetric = 0;

        }


        for (m = 0; m < msgs; m++) {

                if (local->link_adv[m].peer_local_id != my_local_id) 
                        continue;


                if (local->rp_ogm_request_rcvd != adv[m].ogm_request) {

                        dbgf_track(DBGT_INFO, "changed ogm_request=%d from NB=%s", adv[m].ogm_request, it->pb->i.llip_str);

                        if (local->rp_ogm_request_rcvd && local->neigh)
                                memset(local->neigh->ogm_aggregations_not_acked, 0, sizeof (local->neigh->ogm_aggregations_not_acked));

                        local->rp_ogm_request_rcvd = adv[m].ogm_request;
                }

                if (!(link = avl_find_item(&local->link_tree, &local->link_adv[m].transmitter_dev_idx)))
                        continue;


                for (lndev = NULL; (lndev = list_iterate(&link->lndev_list, lndev));) {

                        if (lndev->key.dev->dev_adv_idx == local->link_adv[m].peer_dev_idx) {

                                lndev->tx_probe_umetric = (UMETRIC_MAX * ((UMETRIC_T) (adv[m].rp_127range))) / 127;
                                lndev_assign_best(local, lndev);
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
        AGGREG_SQN_T sqn = ttn->task.u16; // because AGGREG_SQN_T is just 8 bit!

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
                assertion(-501144, (((int) ttn->frame_msgs_length) <= tx_iterator_cache_data_space(it)));

                hdr->aggregation_sqn = sqn;
                hdr->ogm_destination_array = oan->ogm_dest_bytes;
                
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
        assertion(-500587, (ttn->task.link));

        struct msg_ogm_ack *ack = (struct msg_ogm_ack *) (tx_iterator_cache_msg_ptr(it));

        //ack->transmitterIID4x = htons(ttn->task.myIID4x);
        ack->aggregation_sqn = ttn->task.u16;
        ack->ogm_destination = ttn->task.link->local->link_adv_msg_for_him;

        dbgf_all(DBGT_INFO, " aggreg_sqn=%d to ogm_destination=%d", ack->aggregation_sqn, ack->ogm_destination);

        return sizeof (struct msg_ogm_ack);
}






STATIC_FUNC
int32_t tx_frame_problem_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct tx_task_node *ttn = it->ttn;
        struct msg_problem_adv *adv = ((struct msg_problem_adv*) tx_iterator_cache_msg_ptr(it));

        assertion(-500860, (ttn && ttn->task.u32));
        assertion(-500936, (ttn->task.u32 > LOCAL_ID_INVALID));

        dbgf_all(DBGT_INFO, "FRAME_TYPE_PROBLEM_CODE=%d dev_id=0x%X", ttn->task.u16, ttn->task.u32);

        if (ttn->task.u16 == FRAME_TYPE_PROBLEM_CODE_DUP_LINK_ID) {
                
                adv->reserved = 0;
                adv->code = ttn->task.u16;
                adv->local_id = ttn->task.u32;

                return sizeof (struct msg_problem_adv);

        } else {

                assertion(-500846, (0));
        }

        return TLV_TX_DATA_FAILURE;
}




STATIC_FUNC
int32_t rx_frame_problem_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct msg_problem_adv *adv = (struct msg_problem_adv *) it->frame_data;

        if (adv->code == FRAME_TYPE_PROBLEM_CODE_DUP_LINK_ID) {

                if (it->frame_data_length != sizeof (struct msg_problem_adv)) {

                        dbgf_sys(DBGT_ERR,"frame_data_length=%d !!", it->frame_data_length);
                        return TLV_RX_DATA_FAILURE;
                }

                if (adv->local_id == my_local_id) {

                        if (new_local_id(NULL) == LOCAL_ID_INVALID) {
                                return TLV_RX_DATA_FAILURE;
                        }

                        dbgf_sys(DBGT_ERR, "reselect my_local_id=%X (old %X) as signalled by NB=%s via dev=%s",
                                ntohl(my_local_id), ntohl(adv->local_id), it->pb->i.llip_str, it->pb->i.iif->label_cfg.str);

                }

        } else {
                return TLV_RX_DATA_IGNORED;
        }

        return it->frame_msgs_length;
}



STATIC_FUNC
int32_t rx_frame_ogm_advs(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

        struct hdr_ogm_adv *hdr = (struct hdr_ogm_adv *) it->frame_data;
        struct packet_buff *pb = it->pb;
        struct local_node *local = pb->i.link->local;
        struct neigh_node *neigh = pb->i.link->local->neigh;
        uint8_t *ogm_destination_field = it->msg;
        AGGREG_SQN_T aggregation_sqn = hdr->aggregation_sqn;
        uint16_t ogm_destination_bytes = hdr->ogm_destination_array;

        if (ogm_destination_bytes > (OGM_DEST_ARRAY_BIT_SIZE / 8)) {

                dbgf_sys(DBGT_ERR, "invalid ogm_destination_bytes=%d", ogm_destination_bytes);
                return TLV_RX_DATA_FAILURE;

        } else if (it->frame_msgs_length < ((int) sizeof (struct msg_ogm_adv)) ||
                ogm_destination_bytes > (it->frame_msgs_length - sizeof (struct msg_ogm_adv))) {

                dbgf_sys(DBGT_ERR, "invalid ogm_destination_bytes=%d frame_msgs_length=%d ",
                        ogm_destination_bytes, it->frame_msgs_length);
                return TLV_RX_DATA_FAILURE;

        } else if (it->pb->i.link_sqn != local->link_adv_sqn) {

                dbgf_track(DBGT_INFO, "rcvd link_sqn=%d != local->link_adv_sqn=%d",
                        it->pb->i.link_sqn, local->link_adv_sqn);
                return it->frame_msgs_length;

        } else if (ogm_destination_bytes > ((local->link_adv_msgs / 8) + ((local->link_adv_msgs % 8) ? 1 : 0))) {

                dbgf_sys(DBGT_ERR, "invalid ogm_destination_bytes=%d link_adv_msgs=%d",
                        ogm_destination_bytes, local->link_adv_msgs);
                return TLV_RX_DATA_FAILURE;

        }

        IDM_T only_process_sender_and_refresh_all = !local->orig_routes;

        IDM_T ack_sender = (local->link_adv_msg_for_me != LINKADV_MSG_IGNORED &&
                local->link_adv_msg_for_me < (ogm_destination_bytes * 8) &&
                bit_get(ogm_destination_field, (ogm_destination_bytes * 8), local->link_adv_msg_for_me));

        if (only_process_sender_and_refresh_all || !ack_sender) {
                dbgf_all(DBGT_INFO, "not wanted: link_adv_msg_for_me=%d ogm_destination_bytes=%d orig_routes=%d",
                        local->link_adv_msg_for_me, ogm_destination_bytes, local->orig_routes);
        }


        // TODO: ogm_aggregations from this guy must be processed only for ogms from him if not being in his ogm_destination_array
        // to find out about the direct metric to him....

        uint16_t msgs = (it->frame_msgs_length - ogm_destination_bytes) / sizeof (struct msg_ogm_adv);
        struct msg_ogm_adv *ogm = (struct msg_ogm_adv*)(it->msg + ogm_destination_bytes);

        dbgf_all(DBGT_INFO, " ");


        if (((AGGREG_SQN_MASK)& (neigh->ogm_aggregation_cleard_max - aggregation_sqn)) >= AGGREG_SQN_CACHE_RANGE) {

                if (neigh->ogm_aggregation_cleard_max &&
                        ((AGGREG_SQN_MASK)& (aggregation_sqn - neigh->ogm_aggregation_cleard_max)) > AGGREG_SQN_CACHE_WARN) {

                        dbgf_track(DBGT_WARN, "neigh=%s with unknown LOST aggregation_sqn=%d  max=%d  ogms=%d",
                                pb->i.llip_str, aggregation_sqn, neigh->ogm_aggregation_cleard_max, msgs);
                } else {
                        dbgf_all(DBGT_INFO, "neigh=%s with unknown NEW aggregation_sqn=%d  max=%d  msgs=%d",
                                pb->i.llip_str, aggregation_sqn, neigh->ogm_aggregation_cleard_max, msgs);
                }

                if (((AGGREG_SQN_MASK)& (neigh->ogm_aggregation_cleard_max + 1 - aggregation_sqn)) >= AGGREG_SQN_CACHE_RANGE) {
                        memset(neigh->ogm_aggregations_rcvd, 0, AGGREG_SQN_CACHE_RANGE / 8);
                } else {
                        bits_clear(neigh->ogm_aggregations_rcvd, AGGREG_SQN_CACHE_RANGE,
                                ((AGGREG_SQN_MASK)& (neigh->ogm_aggregation_cleard_max + 1)), aggregation_sqn);
                }
                
                neigh->ogm_aggregation_cleard_max = aggregation_sqn;

        } else {

                if (bit_get(neigh->ogm_aggregations_rcvd, AGGREG_SQN_CACHE_RANGE, aggregation_sqn)) {

                        dbgf_all(DBGT_INFO, "neigh: id=%s via dev=%s with already KNOWN ogm_aggregation_sqn=%d",
                                globalIdAsString(&neigh->dhn->on->global_id), pb->i.iif->label_cfg.str, aggregation_sqn);

                        if (ack_sender)
                                schedule_tx_task(local->best_tp_lndev, FRAME_TYPE_OGM_ACK, SCHEDULE_MIN_MSG_SIZE, aggregation_sqn, 0, neigh->dhn->myIID4orig, 0);

                        return it->frame_msgs_length;

                } else if (((AGGREG_SQN_MASK)& (neigh->ogm_aggregation_cleard_max - aggregation_sqn)) > AGGREG_SQN_CACHE_WARN) {

                        dbgf_track(DBGT_WARN, "neigh=%s with unknown OLD aggregation_sqn=%d  max=%d  ogms=%d",
                                pb->i.llip_str, aggregation_sqn, neigh->ogm_aggregation_cleard_max, msgs);
                }
        }



        uint16_t m;
        IID_T neighIID4x = 0;

        for (m = 0; m < msgs; m++) {

                uint16_t offset = ((ntohs(ogm[m].mix) >> OGM_IIDOFFST_BIT_POS) & OGM_IIDOFFST_MASK);

                if (offset == OGM_IID_RSVD_JUMP) {

                        uint16_t absolute = ntohs(ogm[m].u.transmitterIIDabsolute);

                        dbgf_all(DBGT_INFO, " IID jump from %d to %d", neighIID4x, absolute);
                        neighIID4x = absolute;

                        if ((m + 1) >= msgs)
                                return FAILURE;

                        continue;

                } else {

                        dbgf_all(DBGT_INFO, " IID offset from %d to %d", neighIID4x, neighIID4x + offset);
                        neighIID4x += offset;
                }

                IID_NODE_T *dhn = iid_get_node_by_neighIID4x(neigh, neighIID4x, !only_process_sender_and_refresh_all/*verbose*/);

                if (only_process_sender_and_refresh_all && neighIID4x != pb->i.transmittersIID)
                        continue;


                struct orig_node *on = dhn ? dhn->on : NULL;

                OGM_SQN_T ogm_sqn = ntohs(ogm[m].u.ogm_sqn);


                if (on) {

                        if (((OGM_SQN_MASK) & (ogm_sqn - on->ogmSqn_rangeMin)) >= on->ogmSqn_rangeSize) {

                                dbgf_sys(DBGT_ERR,
                                        "DAD-Alert: EXCEEDED ogm_sqn=%d neighIID4x=%d id=%s via link=%s sqn_min=%d sqn_range=%d",
                                        ogm_sqn, neighIID4x, globalIdAsString(&on->global_id), pb->i.llip_str,
                                        on->ogmSqn_rangeMin, on->ogmSqn_rangeSize);

                                purge_local_node(pb->i.link->local);
                                free_orig_node(on);

                                return FAILURE;
                        }

                        if (dhn == self.dhn || on->blocked) {

                                dbgf_all(DBGT_WARN, "%s orig_sqn=%d/%d id=%s via link=%s neighIID4x=%d",
                                        dhn == self.dhn ? "MYSELF" : "BLOCKED",
                                        ogm_sqn, on->ogmSqn_next, globalIdAsString(&on->global_id), pb->i.llip_str, neighIID4x);

                                continue;
                        }


                        OGM_MIX_T mix = ntohs(ogm[m].mix);
                        uint8_t exp = ((mix >> OGM_EXPONENT_BIT_POS) & OGM_EXPONENT_MASK);
                        uint8_t mant = ((mix >> OGM_MANTISSA_BIT_POS) & OGM_MANTISSA_MASK);

                        FMETRIC_U16_T fm = fmetric(mant, exp);
                        IDM_T valid_metric = is_fmetric_valid(fm);

                        if (!valid_metric) {

                                dbgf_mute(50, DBGL_SYS, DBGT_ERR,
                                        "INVALID metric! orig_sqn=%d/%d orig=%s via link=%s neighIID4x=%d",
                                        ogm_sqn, on->ogmSqn_next, globalIdAsString(&on->global_id), pb->i.llip_str, neighIID4x);

                                return FAILURE;
                        }

                        UMETRIC_T um = fmetric_to_umetric(fm);

                        if (um < on->path_metricalgo->umetric_min) {

                                dbgf_mute(50, DBGL_SYS, DBGT_ERR,
                                        "UNUSABLE metric=%ju usable=%ju orig_sqn=%d/%d id=%s via link=%s neighIID4x=%d",
                                        um, on->path_metricalgo->umetric_min,
                                        ogm_sqn, on->ogmSqn_next, globalIdAsString(&on->global_id), pb->i.llip_str, neighIID4x);

                                continue;
                        } 
                        
                        if (update_path_metrics(pb, on, ogm_sqn, &um) != SUCCESS) {
                                assertion(-501145, (0));
                                return FAILURE;
                        }

                } else {

                        dbgf_track(DBGT_WARN, "%s orig_sqn=%d or neighIID4x=%d id=%s via link=%s sqn_min=%d sqn_range=%d",
                                !dhn ? "UNKNOWN DHN" : "INVALIDATED",
                                ogm_sqn, neighIID4x,
                                on ? globalIdAsString(&on->global_id) : "---",
                                pb->i.llip_str,
                                on ? on->ogmSqn_rangeMin : 0,
                                on ? on->ogmSqn_rangeSize : 0);

                        if (!dhn) {
                                dbgf_track(DBGT_INFO, "schedule frame_type=%d", FRAME_TYPE_HASH_REQ);
                                schedule_tx_task(local->best_tp_lndev, FRAME_TYPE_HASH_REQ, SCHEDULE_MIN_MSG_SIZE, 0, 0, 0, neighIID4x);
                        }

                }
        }

        bit_set(neigh->ogm_aggregations_rcvd, AGGREG_SQN_CACHE_RANGE, aggregation_sqn, 1);

        if (ack_sender)
                schedule_tx_task(local->best_tp_lndev, FRAME_TYPE_OGM_ACK, SCHEDULE_MIN_MSG_SIZE, aggregation_sqn, 0, neigh->dhn->myIID4orig, 0);

        return it->frame_msgs_length;
}






STATIC_FUNC
int32_t rx_frame_ogm_acks(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct packet_buff *pb = it->pb;
        struct local_node *local = pb->i.link->local;
        struct neigh_node *neigh = pb->i.link->local->neigh;
        uint16_t pos;

        if (!neigh)
                return it->frame_msgs_length;

        if (it->pb->i.link_sqn != local->link_adv_sqn || local->link_adv_msg_for_me == LINKADV_MSG_IGNORED) {

                dbgf_track(DBGT_INFO, "rcvd link_sqn=%d != local->link_adv_sqn=%d or ignored link_adv_msg_for_me=%d",
                        it->pb->i.link_sqn, local->link_adv_sqn, local->link_adv_msg_for_me);

                return it->frame_msgs_length;
        }

        for (pos = 0; pos < it->frame_msgs_length; pos += sizeof (struct msg_ogm_ack)) {

                struct msg_ogm_ack *ack = (struct msg_ogm_ack *) (it->frame_data + pos);

                if (local->link_adv_msg_for_me != ack->ogm_destination)
                        continue;

                AGGREG_SQN_T aggregation_sqn = ack->aggregation_sqn;

                if (((AGGREG_SQN_MASK)& (ogm_aggreg_sqn_max - aggregation_sqn)) < AGGREG_SQN_CACHE_RANGE) {

                        bit_set(neigh->ogm_aggregations_not_acked, AGGREG_SQN_CACHE_RANGE, aggregation_sqn, 0);

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
struct dhash_node *process_dhash_description_neighIID4x
(struct packet_buff *pb, struct description_hash *dhash, struct description *dsc, IID_T neighIID4x)
{
        TRACE_FUNCTION_CALL;
        struct dhash_node *orig_dhn = NULL;
        struct local_node *local = pb->i.link->local;
        IDM_T invalid = NO;
        struct description *cache = NULL;
        IDM_T is_transmitters_iid = (neighIID4x == pb->i.transmittersIID);

        assertion(-500688, (dhash));
        assertion(-500689, (!(is_transmitters_iid && !memcmp(dhash, &(self.dhn->dhash), sizeof(*dhash))))); // cant be transmitters' and myselfs'

        if (avl_find(&dhash_invalid_tree, dhash)) {

                invalid = YES;

        } else if ((orig_dhn = avl_find_item(&dhash_tree, dhash))) {
                // is about a known dhash:
                
                if (is_transmitters_iid) {
                        // is about the transmitter:

                        if (update_local_neigh(pb, orig_dhn) == FAILURE)
                                return DHASH_NODE_FAILURE;

                        if (iid_set_neighIID4x(&local->neigh->neighIID4x_repos, neighIID4x, orig_dhn->myIID4orig) == FAILURE)
                                return DHASH_NODE_FAILURE;

                        assertion(-500968, (is_described_neigh(pb->i.link, pb->i.transmittersIID)));

                } else if (local->neigh) {
                        // received via a known neighbor, and is NOT about the transmitter:

                        if (orig_dhn == self.dhn) {
                                // is about myself:


                                dbgf_all(DBGT_INFO, "msg refers myself via %s neighIID4me %d", pb->i.llip_str, neighIID4x);

                                local->neigh->neighIID4me = neighIID4x;

                        } else if (orig_dhn == local->neigh->dhn && !is_transmitters_iid) {
                                // is about a neighbors' dhash itself which is NOT the transmitter ???!!!

                                dbgf_sys(DBGT_ERR, "%s via %s neighIID4x=%d IS NOT transmitter=%d",
                                        globalIdAsString(&orig_dhn->on->global_id), pb->i.llip_str, neighIID4x, pb->i.transmittersIID);

                                return DHASH_NODE_FAILURE;

                        } else {
                                // is about.a another dhash known by me and a (neighboring) transmitter..:
                        }

                        if (iid_set_neighIID4x(&local->neigh->neighIID4x_repos, neighIID4x, orig_dhn->myIID4orig) == FAILURE)
                                return DHASH_NODE_FAILURE;

                }

        } else {
                // is about an unconfirmed or unkown dhash:

                // its just the easiest to cache and remove because cache description is doing all the checks for us
                if (dsc)
                        cache_description(dsc, dhash);

                if (is_transmitters_iid && (cache = remove_cached_description(dhash))) {
                        //is about the transmitter  and  a description + dhash is known

                        if ((orig_dhn = process_description(pb, cache, dhash))) {

                                if (update_local_neigh(pb, orig_dhn) == FAILURE)
                                        return DHASH_NODE_FAILURE;

                                if (iid_set_neighIID4x(&local->neigh->neighIID4x_repos, neighIID4x, orig_dhn->myIID4orig) == FAILURE)
                                        return DHASH_NODE_FAILURE;

                                assertion(-500969, (is_described_neigh(pb->i.link, pb->i.transmittersIID)));

                        }

                } else if (local->neigh && (cache = remove_cached_description(dhash))) {

                        if ((orig_dhn = process_description(pb, cache, dhash))) {

                                if (iid_set_neighIID4x(&local->neigh->neighIID4x_repos, neighIID4x, orig_dhn->myIID4orig) == FAILURE)
                                        return DHASH_NODE_FAILURE;
                        }
                }
        }


        dbgf_track(DBGT_INFO, "via dev=%s NB=%s dhash=%8X.. %s neighIID4x=%d  is_sender=%d %s",
                pb->i.iif->label_cfg.str, pb->i.llip_str, dhash->h.u32[0],
                (dsc ? "DESCRIPTION" : (cache ? "CACHED_DESCRIPTION" : (orig_dhn?"KNOWN":"UNDESCRIBED"))),
                neighIID4x, is_transmitters_iid,
                invalid ? "INVALIDATED" : (orig_dhn && orig_dhn->on ? globalIdAsString(&orig_dhn->on->global_id) : "---"));


        return orig_dhn;
}


STATIC_FUNC
int32_t rx_msg_dhash_adv( struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct packet_buff *pb = it->pb;
        struct msg_dhash_adv *adv = (struct msg_dhash_adv*) (it->msg);
        IID_T neighIID4x = ntohs(adv->transmitterIID4x);
        IDM_T is_transmitter_adv = (neighIID4x == pb->i.transmittersIID);
        struct dhash_node *dhn;

        dbgf_track(DBGT_INFO, "via NB: %s", pb->i.llip_str);

        if (neighIID4x <= IID_RSVD_MAX)
                return FAILURE;

        if (!(is_transmitter_adv || is_described_neigh(pb->i.link, pb->i.transmittersIID))) {
                dbgf_track(DBGT_INFO, "via undescribed NB: %s", pb->i.llip_str);
                return sizeof (struct msg_dhash_adv);
        }

        if ((dhn = process_dhash_description_neighIID4x(pb, &adv->dhash, NULL, neighIID4x)) == DHASH_NODE_FAILURE)
                return FAILURE;

        assertion(-500690, (!dhn || dhn->on)); // UNDESCRIBED or fully described

        //if rcvd transmitters' description then it must have become a described neighbor:
        assertion(-500488, (IMPLIES((dhn && is_transmitter_adv), (dhn->on && is_described_neigh(pb->i.link, pb->i.transmittersIID)))));


        if (!dhn)
                schedule_tx_task(pb->i.link->local->best_tp_lndev, FRAME_TYPE_DESC_REQ, SCHEDULE_MIN_MSG_SIZE, 0, 0, 0, neighIID4x);

        return sizeof (struct msg_dhash_adv);
}


STATIC_FUNC
int32_t rx_frame_description_advs(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        int32_t pos = 0;
        uint16_t tlvs_len = 0;
        IID_T neighIID4x = 0;
        struct packet_buff *pb = it->pb;

        assertion(-500550, (it->frame_msgs_length >= ((int) sizeof (struct msg_description_adv))));

        while (pos < it->frame_msgs_length && pos + ((int) sizeof (struct msg_description_adv)) <= it->frame_msgs_length) {

                struct msg_description_adv *adv = ((struct msg_description_adv*) (it->frame_data + pos));
                struct description *desc = &adv->desc;
                struct description_hash dhash0;
                struct dhash_node *dhn;

                tlvs_len = ntohs(desc->dsc_tlvs_len);
                neighIID4x = ntohs(adv->transmitterIID4x);
                pos += (sizeof ( struct msg_description_adv) + tlvs_len);

                if (neighIID4x <= IID_RSVD_MAX || tlvs_len > MAX_DESC0_TLV_SIZE || pos > it->frame_msgs_length)
                        break;

                ShaUpdate(&bmx_sha, (byte*) desc, (sizeof (struct description) +tlvs_len));
                ShaFinal(&bmx_sha, (byte*) & dhash0);

                dhn = process_dhash_description_neighIID4x(pb, &dhash0, desc, neighIID4x);

                dbgf_all( DBGT_INFO, "rcvd %s desc: global_id=%s via_dev=%s via_ip=%s",
                        (dhn && dhn != DHASH_NODE_FAILURE) ? "accepted" : "denied",
                        globalIdAsString(&desc->global_id), pb->i.iif->label_cfg.str, pb->i.llip_str);

                if (dhn == DHASH_NODE_FAILURE)
                        return FAILURE;

                assertion(-500691, (IMPLIES(dhn, (dhn->on))));
                assertion(-500692, (IMPLIES(dhn && neighIID4x == pb->i.transmittersIID, is_described_neigh(pb->i.link, pb->i.transmittersIID))));

                if (desc_adv_tx_unsolicited && dhn && dhn->on->updated_timestamp == bmx_time && is_described_neigh(pb->i.link, pb->i.transmittersIID)) {

                        struct link_dev_node **lndev_arr = lndevs_get_best_tp(pb->i.link->local);
                        int d;

                        uint16_t desc_len = sizeof ( struct msg_description_adv) +ntohs(dhn->on->desc->dsc_tlvs_len);

                        for (d = 0; (lndev_arr[d]); d++)
                                schedule_tx_task(lndev_arr[d], FRAME_TYPE_DESC_ADV, desc_len, 0, 0, dhn->myIID4orig, 0);

                }
        }

        
        if (pos != it->frame_msgs_length) {

                dbgf_sys(DBGT_ERR, "(pos=%d) + (desc_size=%zu) + (tlvs_len=%d) frame_data_length=%d neighIID4x=%d",
                        pos, sizeof ( struct msg_description_adv), tlvs_len, it->frame_data_length, neighIID4x);

                return FAILURE;
        }

        return pos;
}

STATIC_FUNC
int32_t rx_msg_dhash_or_description_request(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        assertion( -500365 , (sizeof( struct msg_description_request ) == sizeof( struct msg_dhash_request)));

        struct packet_buff *pb = it->pb;
        struct hdr_dhash_request *hdr = (struct hdr_dhash_request*) (it->frame_data);
        struct msg_dhash_request *req = (struct msg_dhash_request*) (it->msg);
        IID_T myIID4x = ntohs(req->receiverIID4x);

        if (hdr->destination_local_id != my_local_id)
                return sizeof ( struct msg_dhash_request);

        //TODO: consider that the received local_id might be a duplicate:

        dbgf_track(DBGT_INFO, "%s NB %s destination_local_id=0x%X myIID4x %d",
                it->handls[it->frame_type].name, pb->i.llip_str, ntohl(hdr->destination_local_id), myIID4x);


        if (myIID4x <= IID_RSVD_MAX)
                return sizeof ( struct msg_dhash_request);

        struct dhash_node *dhn = iid_get_node_by_myIID4x(myIID4x);
        struct orig_node *on = dhn ? dhn->on : NULL;

        assertion(-500270, (IMPLIES(dhn, (on && on->desc))));

        if (!dhn || ((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)) > DEF_DESC0_REFERRED_TO) {

                dbgf_track(DBGT_WARN, "%s from %s requesting %s %s",
                        it->handls[it->frame_type].name, pb->i.llip_str,
                        dhn ? "REFERRED TIMEOUT" : "INVALID or UNKNOWN", on ? globalIdAsString(&on->global_id) : "?");

                return sizeof ( struct msg_dhash_request);
        }

        assertion(-500251, (dhn && dhn->myIID4orig == myIID4x));

        uint16_t desc_len = ntohs(dhn->on->desc->dsc_tlvs_len) + sizeof ( struct msg_description_adv);

        if (it->frame_type == FRAME_TYPE_DESC_REQ) {

                schedule_tx_task(pb->i.link->local->best_tp_lndev, FRAME_TYPE_DESC_ADV, desc_len, 0, 0, myIID4x, 0);

        } else {

                schedule_tx_task(pb->i.link->local->best_tp_lndev, FRAME_TYPE_HASH_ADV, SCHEDULE_MIN_MSG_SIZE, 0, 0, myIID4x, 0);
        }




        // most probably the requesting node is also interested in my metric to the requested node:
        if (on->curr_rt_lndev && on->ogmSqn_next == on->ogmSqn_send &&
                (((OGM_SQN_MASK) & (on->ogmSqn_next - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize) //needed after description updates!
                ) {
                set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_next, ((OGM_SQN_T) (on->ogmSqn_next - 1)));
        }



        return sizeof ( struct msg_dhash_request);
}



STATIC_FUNC
int32_t rx_msg_hello_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct packet_buff *pb = it->pb;
        struct msg_hello_adv *msg = (struct msg_hello_adv*) (it->msg);
        HELLO_SQN_T hello_sqn = ntohs(msg->hello_sqn);

        dbgf_all(DBGT_INFO, "NB=%s via dev=%s SQN=%d",
                pb->i.llip_str, pb->i.iif->label_cfg.str, hello_sqn);

        if (it->msg != it->frame_data) {
                dbgf_sys(DBGT_WARN, "rcvd %d %s messages in frame_msgs_length=%d",
                        (it->frame_msgs_length / ((uint32_t)sizeof (struct msg_hello_adv))),
                        packet_frame_handler[FRAME_TYPE_HELLO_ADV].name, it->frame_msgs_length);
        }

        update_link_probe_record(pb->i.lndev, hello_sqn, 1);


        if (pb->i.lndev->link_adv_msg == LINKADV_MSG_IGNORED && (
                pb->i.lndev == pb->i.link->local->best_rp_lndev ||
                (pb->i.lndev->timeaware_rx_probe * LINKADV_ADD_RP_4DIF >=
                pb->i.link->local->best_rp_lndev->timeaware_rx_probe * LINKADV_ADD_RP_4MAX)
                )) {

                update_my_link_adv(LINKADV_CHANGES_NEW);
        }


        return sizeof (struct msg_hello_adv);
}


int32_t rx_frame_iterate(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        int32_t f_type, f_len;
        struct frame_handl *f_handl;
        struct packet_buff *pb = it->pb;

        dbgf_all(DBGT_INFO, "%s - frame_pos=%d frame_len=%d", it->caller, it->frames_pos, it->frames_length);

        if (it->frames_pos + ((int)sizeof (struct frame_header_short)) + TLV_DATA_STEPS <= it->frames_length) {

                struct frame_header_short *fhs = (struct frame_header_short *) (it->frames_in + it->frames_pos);
                it->frame_type = f_type = fhs->type;

                assertion(-500775, (fhs->type == ((struct frame_header_long*) fhs)->type));

                it->is_short_header = fhs->is_short;

                if (it->is_short_header) {

                        f_len = fhs->length_TLV_DATA_STEPS * TLV_DATA_STEPS;
                        it->frame_data_length = f_len - sizeof (struct frame_header_short);
                        it->frame_data = it->frames_in + it->frames_pos + sizeof (struct frame_header_short);

                } else {

                        f_len = ntohs(((struct frame_header_long*) fhs)->length);
                        it->frame_data_length = f_len - sizeof (struct frame_header_long);
                        it->frame_data = it->frames_in + it->frames_pos + sizeof (struct frame_header_long);
                }

                it->frames_pos += f_len;

                if (it->frames_pos > it->frames_length ||
                        it->frame_data_length < TLV_DATA_STEPS || it->frame_data_length % TLV_DATA_STEPS) {
                        // not yet processed anything, so return failure:

                        dbgf_sys(DBGT_ERR, "%s - type=%d frame_pos=%d frame_len=%d frame_data_len=%d",
                                it->caller, f_type, it->frames_pos, it->frames_length, it->frame_data_length);

                        return TLV_RX_DATA_FAILURE;

                } else if (f_type > it->handl_max || !(it->handls[f_type].rx_frame_handler || it->handls[f_type].rx_msg_handler)) {

                        dbgf_sys(DBGT_WARN, "%s - unknown type=%d ! check for updates", it->caller, f_type);

                        if (f_type > it->handl_max || fhs->is_relevant)
                                return TLV_RX_DATA_FAILURE;

                        return TLV_RX_DATA_IGNORED;
                }

                f_handl = &it->handls[f_type];
                it->frame_msgs_length = it->frame_data_length - f_handl->data_header_size;

                
                dbgf_all(DBGT_INFO, "%s - type=%s frame_length=%d frame_data_length=%d frame_msgs_length=%d",
                        it->caller, f_handl->name, f_len, it->frame_data_length, it->frame_msgs_length);

                assertion(-500994, (f_handl->min_msg_size));


                if (f_handl->rx_msg_handler ? // only frame_handler support zero messages per frame!
                        (it->frame_msgs_length < f_handl->min_msg_size) :
                        (it->frame_msgs_length < f_handl->min_msg_size && it->frame_msgs_length != 0)
                        ) {

                        dbgf_sys(DBGT_WARN, "%s - too small length=%d for type=%s", it->caller, f_len, f_handl->name);
                        return TLV_RX_DATA_FAILURE;

                } else if (f_handl->fixed_msg_size && it->frame_msgs_length % f_handl->min_msg_size) {

                        dbgf_sys(DBGT_WARN, "%s - nonmaching length=%d for type=%s", it->caller, f_len, f_handl->name);
                        return TLV_RX_DATA_FAILURE;

                } else if (f_handl->is_relevant != fhs->is_relevant) {
                        dbgf_sys(DBGT_ERR, "%s - type=%s frame_length=%d from %s, signals %s but known as %s",
                                it->caller, f_handl->name, f_len, pb ? pb->i.llip_str : "---",
                                fhs->is_relevant ? "RELEVANT" : "IRRELEVANT",
                                f_handl->is_relevant ? "RELEVANT" : "IRRELEVANT");
                        return TLV_RX_DATA_FAILURE;
                }


                if (!(it->process_filter == FRAME_TYPE_PROCESS_ALL || it->process_filter == f_type)) {

                        dbgf_all(DBGT_INFO, "%s - type=%d process_filter=%d : IGNORED", it->caller, f_type, it->process_filter);

                        return TLV_RX_DATA_IGNORED;

                } else if (pb && f_handl->rx_tp_min &&
                        (!pb->i.lndev || pb->i.lndev->timeaware_tx_probe < *(f_handl->rx_tp_min))) {

                        dbg_mute(60, DBGL_CHANGES, DBGT_WARN, "%s - non-sufficient link %s - %s (tp=%ju), skipping type=%s",
                                it->caller, pb->i.iif->ip_llocal_str, pb->i.llip_str,
                                pb->i.lndev ? pb->i.lndev->timeaware_tx_probe : 0, f_handl->name);

                        return TLV_RX_DATA_IGNORED;

                } else if (pb && f_handl->rx_rp_min &&
                        (!pb->i.lndev || pb->i.lndev->timeaware_rx_probe < *(f_handl->rx_rp_min))) {

                        dbg_mute(60, DBGL_CHANGES, DBGT_WARN, "%s - non-sufficient link %s - %s (rp=%ju), skipping type=%s",
                                it->caller, pb->i.iif->ip_llocal_str, pb->i.llip_str,
                                pb->i.lndev ? pb->i.lndev->timeaware_rx_probe : 0, f_handl->name);

                        return TLV_RX_DATA_IGNORED;


                } else if (!IMPLIES(f_handl->rx_requires_described_neigh, (pb && is_described_neigh(pb->i.link, pb->i.transmittersIID)))) {

                        dbgf_track(DBGT_INFO, "%s - UNDESCRIBED IID=%d of neigh=%s - skipping frame type=%s",
                                it->caller, pb->i.transmittersIID, pb->i.llip_str, f_handl->name);

                        return TLV_RX_DATA_IGNORED;

                } else if (it->op >= TLV_OP_PLUGIN_MIN && it->op <= TLV_OP_PLUGIN_MAX) {

                        it->msg = it->frame_data + f_handl->data_header_size;

                        return it->frame_msgs_length;

                } else if (f_handl->rx_msg_handler && f_handl->fixed_msg_size) {

                        it->msg = it->frame_data + f_handl->data_header_size;

                        while (it->msg < it->frame_data + it->frame_data_length &&
                                ((*(f_handl->rx_msg_handler)) (it)) == f_handl->min_msg_size) {

                                it->msg += f_handl->min_msg_size;
                        }

                        if (it->msg != it->frame_data + it->frame_data_length) {
                                dbgf_sys(DBGT_ERR, "%s- rx_msg_handler(%s)  it->msg=%p frame_data=%p frame_data_length=%d : FAILURE",
                                        it->caller, f_handl->name, it->msg, it->frame_data, it->frame_data_length);
                                return TLV_RX_DATA_FAILURE;
                        }

                        return it->frame_data_length;

                } else if (f_handl->rx_frame_handler) {

                        it->msg = it->frame_data + f_handl->data_header_size;

                        int32_t receptor_result = (*(f_handl->rx_frame_handler)) (it);

                        if (receptor_result == TLV_RX_DATA_BLOCKED) {
                                dbgf_sys(DBGT_ERR, "%s - rx_frame_handler(%s)=%d frame_msgs_len=%d : BLOCKED",
                                        it->caller, f_handl->name, receptor_result, it->frame_msgs_length );

                                return TLV_RX_DATA_BLOCKED;
                        }

                        if (it->frame_msgs_length != receptor_result) {
                                dbgf_sys(DBGT_ERR, "%s - rx_frame_handler(%s)=%d frame_msgs_len=%d : FAILURE",
                                        it->caller, f_handl->name, receptor_result, it->frame_msgs_length );
                                return TLV_RX_DATA_FAILURE;
                        }

                        return receptor_result;
                }

                assertion(-501018, (0));
                return TLV_RX_DATA_FAILURE;

        } else if (it->frames_pos == it->frames_length) {

                dbgf_all(DBGT_INFO, "%s - frames_pos=%d frames_length=%d : DONE", it->caller, it->frames_pos, it->frames_length);
                return TLV_RX_DATA_DONE;
        }

        dbgf_sys(DBGT_ERR, "%s - frames_pos=%d frames_length=%d : FAILURE", it->caller, it->frames_pos, it->frames_length);
        return TLV_RX_DATA_FAILURE;
}

IDM_T rx_frames(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        int32_t it_result;

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .on = NULL, .cn = NULL, .op = 0, .pb = pb,
                .handls = packet_frame_handler, .handl_max = FRAME_TYPE_MAX, .process_filter = FRAME_TYPE_PROCESS_ALL,
                .frames_in = (((uint8_t*) & pb->packet.header) + sizeof (struct packet_header)),
                .frames_length = (ntohs(pb->packet.header.pkt_length) - sizeof (struct packet_header)), .frames_pos = 0
        };

        while ((it_result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE || it_result == TLV_RX_DATA_BLOCKED);

        if (it_result <= TLV_RX_DATA_FAILURE) {
                dbgf_sys(DBGT_WARN, "problematic frame_type=%s data_length=%d iterator_result=%d pos=%d ",
                        packet_frame_handler[it.frame_type].name, it.frame_data_length, it_result, it.frames_pos);
                return FAILURE;
        }
        struct local_node *local = pb->i.link->local;

        if (!is_described_neigh(pb->i.link, pb->i.transmittersIID)) {

                dbgf_track(DBGT_INFO, "schedule frame_type=%d", FRAME_TYPE_HASH_REQ);

                schedule_tx_task(local->best_tp_lndev, FRAME_TYPE_HASH_REQ, SCHEDULE_MIN_MSG_SIZE, 0, 0, 0, pb->i.transmittersIID);
        }

        if (msg_dev_req_enabled && UXX_LT(DEVADV_SQN_MAX, local->dev_adv_sqn, local->link_adv_dev_sqn_ref)) {

                dbgf_track(DBGT_INFO,
                        "schedule DEV_REQ to NB=%s local_id=0x%X via dev=%s dev_adv_sqn=%d link_adv_dev_sqn_ref=%d",
                        pb->i.llip_str, local->local_id, local->best_tp_lndev->key.dev->label_cfg.str,
                        local->dev_adv_sqn, local->link_adv_dev_sqn_ref);

                schedule_tx_task(&pb->i.iif->dummy_lndev, FRAME_TYPE_DEV_REQ, SCHEDULE_MIN_MSG_SIZE, 0, local->local_id, 0, 0);
        }

//        if (UXX_LT(LINKADV_SQN_MAX, pb->i.link->local->link_adv_sqn, pb->i.link_sqn)) {
        if (UXX_LT(LINKADV_SQN_MAX, local->link_adv_sqn, local->packet_link_sqn_ref)) {

                dbgf_track(DBGT_INFO,
                        "schedule LINK_REQ to NB=%s local_id=0x%X via dev=%s  link_adv_sqn=%d packet_link_sqn_ref=%d",
                        pb->i.llip_str, local->local_id, local->best_tp_lndev->key.dev->label_cfg.str,
                        local->link_adv_sqn, local->packet_link_sqn_ref);

                local->rp_ogm_request_rcvd = 0;

                if (local->neigh)
                        memset(local->neigh->ogm_aggregations_not_acked, 0, sizeof (local->neigh->ogm_aggregations_not_acked));

                schedule_tx_task(&pb->i.iif->dummy_lndev, FRAME_TYPE_LINK_REQ, SCHEDULE_MIN_MSG_SIZE, 0, local->local_id, 0, 0);
        }


        return SUCCESS;
}






STATIC_FUNC
int8_t send_udp_packet(struct packet_buff *pb, struct sockaddr_storage *dst, int32_t send_sock)
{
        TRACE_FUNCTION_CALL;
	int status;

        dbgf_all(DBGT_INFO, "len=%d via dev=%s", pb->i.total_length, pb->i.oif->label_cfg.str);

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

        status = sendto(send_sock, pb->packet.data, pb->i.total_length, 0, (struct sockaddr *) dst, sizeof (struct sockaddr_storage));

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




/*
 * iterates over to be created frames and stores them (including frame_header) in it->frames_out  */
STATIC_FUNC
int32_t tx_frame_iterate(IDM_T iterate_msg, struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        uint8_t t = it->frame_type;
        struct frame_handl *handl = &(it->handls[t]);
        int32_t tlv_result;// = TLV_DATA_DONE;
        assertion(-500977, (handl->min_msg_size));
        assertion(-500776, (it->cache_data_array));
        assertion(-501004, (IMPLIES(it->cache_msgs_size, handl->tx_msg_handler)));

        ASSERTION(-500777, (IMPLIES((it->cache_msgs_size && handl->tx_msg_handler),
                is_zero(tx_iterator_cache_msg_ptr(it), tx_iterator_cache_data_space(it)))));

        ASSERTION(-501000, (IMPLIES((!it->cache_msgs_size || handl->tx_frame_handler),
                is_zero(it->cache_data_array, tx_iterator_cache_data_space(it)))));

        assertion(-500779, (it->frames_out_pos <= it->frames_out_max));
        assertion(-500780, (it->frames_out));
        assertion(-500781, (it->frame_type <= it->handl_max));
        assertion(-500784, (IMPLIES(it->cache_msgs_size, it->cache_msgs_size >= TLV_TX_DATA_PROCESSED)));

        dbgf_all(DBGT_INFO, "from %s iterate_msg=%s frame_type=%d cache_msgs_size=%d cache_data_space=%d frames_out_pos=%d frames_out_max=%d ",
                it->caller, iterate_msg ? "YES" : "NO ", it->frame_type,
                it->cache_msgs_size, tx_iterator_cache_data_space(it), it->frames_out_pos, it->frames_out_max);

        if (handl->tx_frame_handler || iterate_msg) {

                if (handl->min_msg_size > tx_iterator_cache_data_space(it))
                        return TLV_TX_DATA_FULL;

                if (it->ttn && it->ttn->frame_msgs_length > tx_iterator_cache_data_space(it))
                        return TLV_TX_DATA_FULL;
        }

        if (handl->tx_msg_handler && iterate_msg) {

                assertion(-500814, (tx_iterator_cache_data_space(it) >= 0));

                if ((tlv_result = (*(handl->tx_msg_handler)) (it)) >= TLV_TX_DATA_PROCESSED) {
                        it->cache_msgs_size += tlv_result;
                        ASSERTION(-501002, (is_zero((it->cache_data_array + it->cache_msgs_size + handl->data_header_size), tx_iterator_cache_data_space(it))));

                } else {
                        dbgf_track(DBGT_INFO, "tx_msg_handler()=%d %s remaining iterations=%d",
                                tlv_result, handl->name, it->ttn ? it->ttn->tx_iterations : -1);
                        assertion(-500810, (tlv_result != TLV_TX_DATA_FAILURE));
                        assertion(-500874, (IMPLIES(!it->cache_msgs_size, is_zero(it->cache_data_array, handl->data_header_size))));
                }

                return tlv_result;
        }

        assertion(-500862, (!iterate_msg));

        if (handl->tx_msg_handler && !iterate_msg) {

                tlv_result = it->cache_msgs_size;

                assertion(-500863, (tlv_result >= handl->min_msg_size));

        } else {
                assertion(-500803, (handl->tx_frame_handler));
                assertion(-500864, (it->cache_msgs_size == 0));

                tlv_result = (*(handl->tx_frame_handler)) (it);

                if (tlv_result >= TLV_TX_DATA_PROCESSED) {

                        it->cache_msgs_size = tlv_result;

                } else {
                        dbgf_track(DBGT_INFO, "tx_frame_handler()=%d %s remaining iterations=%d",
                                tlv_result, handl->name, it->ttn ? it->ttn->tx_iterations : -1);
                        ASSERTION(-501001, (is_zero(it->cache_data_array, tx_iterator_cache_data_space(it))));
                        assertion(-500811, (tlv_result != TLV_TX_DATA_FAILURE));
                        return tlv_result;
                }
        }


        assertion(-500865, (tlv_result == it->cache_msgs_size));
        assertion(-500881, (tlv_result >= TLV_TX_DATA_PROCESSED));
        assertion(-500786, (tx_iterator_cache_data_space(it) >= 0));
        assertion(-500787, (!(tlv_result % TLV_DATA_STEPS)));
        assertion(-500355, (IMPLIES(handl->fixed_msg_size, !(tlv_result % handl->min_msg_size))));
        ASSERTION(-501003, (is_zero((it->cache_data_array + tlv_result + handl->data_header_size), tx_iterator_cache_data_space(it))));

        int32_t cache_pos = tlv_result + handl->data_header_size;

        assertion(-501019, (cache_pos)); // there must be some data to send!!

        IDM_T is_short_header = ((cache_pos + sizeof ( struct frame_header_short)) <= SHORT_FRAME_DATA_MAX);
        struct frame_header_short *fhs = (struct frame_header_short *) (it->frames_out + it->frames_out_pos);

        if (is_short_header) {
                fhs->length_TLV_DATA_STEPS = ((cache_pos + sizeof ( struct frame_header_short)) / TLV_DATA_STEPS);
                it->frames_out_pos += sizeof ( struct frame_header_short);
        } else {
                struct frame_header_long *fhl = (struct frame_header_long *) fhs;
                memset(fhl, 0, sizeof (struct frame_header_long));
                fhl->length = htons(cache_pos + sizeof ( struct frame_header_long));
                it->frames_out_pos += sizeof ( struct frame_header_long);
        }

        fhs->is_short = is_short_header;
        fhs->is_relevant = handl->is_relevant;
        fhs->type = t;

        memcpy(it->frames_out + it->frames_out_pos, it->cache_data_array, cache_pos);
        it->frames_out_pos += cache_pos;

        dbgf_all(DBGT_INFO, "added %s frame_header type=%s frame_data_length=%d frame_msgs_length=%d",
                is_short_header ? "SHORT" : "LONG", handl->name, cache_pos, tlv_result);

        memset(it->cache_data_array, 0, tlv_result + handl->data_header_size);
        it->cache_msgs_size = 0;

        return tlv_result;
}


STATIC_FUNC
void next_tx_task_list(struct dev_node *dev, struct tx_frame_iterator *it, struct avl_node **link_tree_iterator)
{
        TRACE_FUNCTION_CALL;

        struct link_node *link = NULL;

        if (it->tx_task_list && it->tx_task_list->items &&
                ((struct tx_task_node*) (list_get_last(it->tx_task_list)))->considered_ts != bmx_time) {
                return;
        }

        if (it->tx_task_list == &(dev->tx_task_lists[it->frame_type]))
                it->frame_type++;

        while ((link = avl_iterate_item(&link_tree, link_tree_iterator))) {
                struct list_node *lndev_pos;
                struct link_dev_node *lndev = NULL;

                list_for_each(lndev_pos, &link->lndev_list)
                {
                        lndev = list_entry(lndev_pos, struct link_dev_node, list);

                        if (lndev->key.dev == dev && lndev->tx_task_lists[it->frame_type].items) {

                                assertion(-500866, (lndev->key.link == link));

                                it->tx_task_list = &(lndev->tx_task_lists[it->frame_type]);

                                dbgf_track(DBGT_INFO,
                                        "found %s   link nb: nb_local_id=%X nb_dev_idx=%d nbIP=%s   via lndev: my_dev=%s my_dev_idx=%d with lndev->tx_tasks_list[].items=%d",
                                        it->handls[it->frame_type].name,
                                        ntohl(link->key.local_id), link->key.dev_idx, ipXAsStr(af_cfg, &link->link_ip),
                                        dev->label_cfg.str, dev->dev_adv_idx, it->tx_task_list->items);

                                return;
                        }
                }
        }

        *link_tree_iterator = NULL;
        it->tx_task_list = &(dev->tx_task_lists[it->frame_type]);
        return;
}

STATIC_FUNC
void tx_packet(void *devp)
{
        TRACE_FUNCTION_CALL;

        static uint8_t cache_data_array[MAX_UDPD_SIZE] = {0};
        static struct packet_buff pb;
        struct dev_node *dev = devp;

        assertion(-500204, (dev));

        dev->tx_task = NULL;
        dbgf_all(DBGT_INFO, "dev=%s", dev->label_cfg.str);

        assertion(-500205, (dev->active));
        ASSERTION(-500788, ((pb.packet.data) == ((uint8_t*) (&pb.packet.header))));
        ASSERTION(-500789, ((pb.packet.data + sizeof (struct packet_header)) == ((uint8_t*) &((&pb.packet.header)[1]))));


        schedule_tx_task(&dev->dummy_lndev, FRAME_TYPE_HELLO_ADV, SCHEDULE_MIN_MSG_SIZE, 0, 0, 0, 0);

        if (my_link_adv_msgs)
                schedule_tx_task(&dev->dummy_lndev, FRAME_TYPE_RP_ADV, (my_link_adv_msgs * sizeof (struct msg_rp_adv)), 0, 0, 0, 0);

        //schedule_tx_task(&dev->dummy_lndev, FRAME_TYPE_TEST_ADV, SCHEDULE_UNKOWN_MSGS_SIZE, 0, 0, 0, 0);





        memset(&pb.i, 0, sizeof (pb.i));

        struct tx_frame_iterator it = {
                .caller = __FUNCTION__, .handls = packet_frame_handler, .handl_max = FRAME_TYPE_MAX,
                .frames_out = (pb.packet.data + sizeof (struct packet_header)), .frames_out_pos = 0,
                .frames_out_max = (pref_udpd_size - sizeof (struct packet_header)),
                .cache_data_array = cache_data_array, .cache_msgs_size = 0,
                .frame_type = 0, .tx_task_list = NULL
        };

        struct avl_node *link_tree_iterator = NULL;

        while (it.frame_type < FRAME_TYPE_NOP) {

                next_tx_task_list(dev, &it, &link_tree_iterator);

                struct list_node *lpos, *ltmp, *lprev = (struct list_node*) it.tx_task_list;
                int32_t tlv_result = TLV_TX_DATA_DONE;
                struct frame_handl *handl = &packet_frame_handler[it.frame_type];
                uint16_t old_frames_out_pos = it.frames_out_pos;
                uint32_t item =0;

                list_for_each_safe(lpos, ltmp, it.tx_task_list)
                {
                        it.ttn = list_entry(lpos, struct tx_task_node, list);
                        item++;

                        assertion(-500440, (it.ttn->task.type == it.frame_type));

                        ASSERTION(-500918, (IMPLIES(!handl->is_advertisement, it.ttn->task.link &&
                                it.ttn->task.link == avl_find_item(&link_tree, &it.ttn->task.link->key))));

                        ASSERTION(-500920, (IMPLIES(!handl->is_advertisement, it.ttn->task.dev &&
                                it.ttn->task.dev == avl_find_item(&dev_ip_tree, &it.ttn->task.dev->llocal_ip_key))));


                        dbgf_all(DBGT_INFO, "%s type=%d =%s", dev->label_cfg.str, it.frame_type, handl->name);

                        if (it.ttn->tx_iterations <= 0) {

                                tlv_result = TLV_TX_DATA_DONE;

                        } else if (it.ttn->considered_ts == bmx_time) {
                                // already considered during this tx iteration
                                tlv_result = TLV_TX_DATA_IGNORED;

                        } else if ((tlv_result = tx_task_obsolete(it.ttn)) <= TLV_TX_DATA_IGNORED ) {
                                // too recently send! send later;
                                // tlv_result = TLV_TX_DATA_IGNORED;

                        } else if (handl->tx_frame_handler) {

                                tlv_result = tx_frame_iterate(NO/*iterate_msg*/, &it);

                        } else if (handl->tx_msg_handler) {

                                tlv_result = tx_frame_iterate(YES/*iterate_msg*/, &it);

                        } else {
                                assertion(-500818, (0));
                        }

                        if (handl->tx_msg_handler && it.cache_msgs_size &&
                                (tlv_result == TLV_TX_DATA_FULL || lpos == it.tx_task_list->last)) {// last element in list:
                                
                                int32_t it_result = tx_frame_iterate(NO/*iterate_msg*/, &it);

                                if (it_result < TLV_TX_DATA_PROCESSED) {
                                        dbgf_sys(DBGT_ERR, "unexpected it_result=%d (tlv_result=%d) type=%d",
                                                it_result, tlv_result, it.frame_type);

                                        cleanup_all(-500790);
                                }
                        }

                        dbgf_all(DBGT_INFO, "%s type=%d =%s considered=%d iterations=%d tlv_result=%d item=%d/%d",
                                dev->label_cfg.str, it.frame_type, handl->name, it.ttn->considered_ts,
                                it.ttn->tx_iterations, tlv_result, item, it.tx_task_list->items);

                        if (tlv_result == TLV_TX_DATA_DONE) {

                                it.ttn->considered_ts = bmx_time;
                                it.ttn->tx_iterations--;

                                if (freed_tx_task_node(it.ttn, it.tx_task_list, lprev) == NO)
                                        lprev = lpos;

                                continue;

                        } else if (tlv_result == TLV_TX_DATA_IGNORED) {

                                it.ttn->considered_ts = bmx_time;

                                lprev = lpos;
                                continue;

                        } else if (tlv_result >= TLV_TX_DATA_PROCESSED) {

                                it.ttn->send_ts = bmx_time;
                                it.ttn->considered_ts = bmx_time;
                                it.ttn->tx_iterations--;

                                if (freed_tx_task_node(it.ttn, it.tx_task_list, lprev) == NO)
                                        lprev = lpos;

                                if (handl->tx_frame_handler || lpos == it.tx_task_list->last)
                                        break;

                                continue;

                        } else if (tlv_result == TLV_TX_DATA_FULL) {
                                // means not created because would not fit!
                                assertion(-500430, (it.cache_msgs_size || it.frames_out_pos)); // single message larger than max_udpd_size
                                break;

                        } else {

                                dbgf_sys(DBGT_ERR, "frame_type=%d tlv_result=%d",
                                        it.frame_type, tlv_result);
                                assertion(-500791, (0));
                        }
                }

                if (it.frames_out_pos > old_frames_out_pos) {
                        dbgf_all(DBGT_INFO, "prepared frame_type=%s frame_size=%d frames_out_pos=%d",
                                handl->name, (it.frames_out_pos - old_frames_out_pos), it.frames_out_pos);
                }

                assertion(-500796, (!it.cache_msgs_size));
                assertion(-500800, (it.frames_out_pos >= old_frames_out_pos));

                if (tlv_result == TLV_TX_DATA_FULL || (it.frame_type == FRAME_TYPE_NOP && it.frames_out_pos)) {

                        struct packet_header *packet_hdr = &pb.packet.header;

                        assertion(-500208, (it.frames_out_pos && it.frames_out_pos <= it.frames_out_max));

                        pb.i.oif = dev;
                        pb.i.total_length = (it.frames_out_pos + sizeof ( struct packet_header));

                        memset(packet_hdr, 0, sizeof (struct packet_header));

                        packet_hdr->bmx_version = COMPATIBILITY_VERSION;
                        packet_hdr->pkt_length = htons(pb.i.total_length);
                        packet_hdr->transmitterIID = htons(myIID4me);
                        packet_hdr->link_adv_sqn = htons(my_link_adv_sqn);
                        packet_hdr->pkt_sqn = htonl(++my_packet_sqn);
                        packet_hdr->local_id = my_local_id;
                        packet_hdr->dev_idx = dev->dev_adv_idx;

                        cb_packet_hooks(&pb);

                        send_udp_packet(&pb, &dev->tx_netwbrc_addr, dev->unicast_sock);

                        dbgf_all(DBGT_INFO, "send packet size=%d  via dev=%s",
                                pb.i.total_length, dev->label_cfg.str);

                        memset(&pb.i, 0, sizeof (pb.i));

                        it.frames_out_pos = 0;
                }

        }

        assertion(-500797, (!it.frames_out_pos));
}

void tx_packets( void *unused ) {

        TRACE_FUNCTION_CALL;

        struct avl_node *an;
        struct dev_node *dev;

        TIME_T dev_interval = (my_tx_interval / 10) / dev_ip_tree.items;
        TIME_T dev_next = 0;

        dbgf_all(DBGT_INFO, " ");


        schedule_or_purge_ogm_aggregations(NO);
        // this might schedule a new tx_packet because schedule_tx_packet() believes
        // the stuff we are about to send now is still waiting to be send.

        //remove_task(tx_packet, NULL);
        task_register((my_tx_interval + rand_num(my_tx_interval / 10) - (my_tx_interval / 20)), tx_packets, NULL, -300353);

        for (an = NULL; (dev = avl_iterate_item(&dev_ip_tree, &an));) {

                if (dev->linklayer == TYP_DEV_LL_LO)
                        continue;

                if (dev->tx_task) {
                        dbgf_sys(DBGT_ERR, "previously scheduled tx_packet( dev=%s ) still pending!", dev->label_cfg.str);
                } else {
                        dev->tx_task = tx_packet;
                        task_register(dev_next, tx_packet, dev, -300354);
                }

                dev_next += dev_interval;

        }
}


void schedule_my_originator_message( void* unused )
{
        TRACE_FUNCTION_CALL;

        if (((OGM_SQN_MASK) & (self.ogmSqn_next + OGM_SQN_STEP - self.ogmSqn_rangeMin)) >= self.ogmSqn_rangeSize)
                my_description_changed = YES;


        self.ogmSqn_maxRcvd = set_ogmSqn_toBeSend_and_aggregated(&self, UMETRIC_MAX, (self.ogmSqn_next + OGM_SQN_STEP), self.ogmSqn_send);

        dbgf_all(DBGT_INFO, "ogm_sqn %d", self.ogmSqn_next);

        task_register(my_ogm_interval, schedule_my_originator_message, NULL, -300355);
}


STATIC_FUNC
IDM_T validate_description(struct description *desc)
{
        TRACE_FUNCTION_CALL;

        if (validate_hostname(desc->global_id.name) == FAILURE) {

                dbg_sys(DBGT_ERR, "global_id=%s has illegal hostname ", globalIdAsString(&desc->global_id));
                return FAILURE;
        }

        if (
                validate_param(desc->ttl_max, MIN_TTL, MAX_TTL, ARG_TTL) ||
                validate_param(ntohs(desc->ogm_sqn_range), MIN_OGM_SQN_RANGE, MAX_OGM_SQN_RANGE, ARG_OGM_SQN_RANGE) ||
                validate_param(ntohs(desc->tx_interval), MIN_TX_INTERVAL, MAX_TX_INTERVAL, ARG_TX_INTERVAL) ||
                0
                ) {

                return FAILURE;
        }

        return SUCCESS;
}


struct dhash_node * process_description(struct packet_buff *pb, struct description *desc, struct description_hash *dhash)
{
        TRACE_FUNCTION_CALL;
        assertion(-500262, (pb && pb->i.link && desc));
        assertion(-500381, (!avl_find( &dhash_tree, dhash )));

        struct orig_node *on = NULL;


        if ( validate_description( desc ) != SUCCESS )
                goto process_desc0_error;


        if ((on = avl_find_item(&orig_tree, &desc->global_id))) {

                dbgf_track(DBGT_INFO, "%s desc SQN=%d (old_sqn=%d) from id=%s via_dev=%s via_ip=%s",
                        pb ? "RECEIVED NEW" : "CHECKING OLD (BLOCKED)", ntohs(desc->dsc_sqn), on->descSqn,
                        globalIdAsString(&desc->global_id),
                        pb ? pb->i.iif->label_cfg.str : "---", pb ? pb->i.llip_str : "---");

                assertion(-500383, (on->dhn));

                if (pb && ((TIME_T) (bmx_time - on->dhn->referred_by_me_timestamp)) < (TIME_T) dad_to) {

                        if (((DESC_SQN_MASK)&(ntohs(desc->dsc_sqn) - (on->descSqn + 1))) > DEF_DESCRIPTION_DAD_RANGE) {

                                dbgf_sys(DBGT_ERR, "DAD-Alert: new dsc_sqn %d not > old %d + 1",
                                        ntohs(desc->dsc_sqn), on->descSqn);

                                goto process_desc0_ignore;
                        }

                        if (ntohs(desc->dsc_sqn) == ((DESC_SQN_T) (on->descSqn + 1)) &&
                                UXX_LT(OGM_SQN_MASK, ntohs(desc->ogm_sqn_min), (on->ogmSqn_rangeMin + MAX_OGM_SQN_RANGE))) {

                                dbgf_sys(DBGT_ERR, "DAD-Alert: new ogm_sqn_min %d not > old %d + %d",
                                        ntohs(desc->ogm_sqn_min), on->ogmSqn_rangeMin, MAX_OGM_SQN_RANGE);

                                goto process_desc0_ignore;
                        }
                }

        } else {
                // create new orig:
                on = debugMalloc( sizeof( struct orig_node ), -300128 );
                init_orig_node(on, &desc->global_id);
        }




        int32_t tlv_result;

        if (pb) {

                if (on->desc && !on->blocked) {
                        tlv_result = process_description_tlvs(pb, on, on->desc, TLV_OP_DEL, FRAME_TYPE_PROCESS_ALL, NULL);
                        assertion(-500808, (tlv_result == TLV_RX_DATA_DONE));
                }

                on->updated_timestamp = bmx_time;
                on->descSqn = ntohs(desc->dsc_sqn);

                on->ogmSqn_rangeMin = ntohs(desc->ogm_sqn_min);
                on->ogmSqn_rangeSize = ntohs(desc->ogm_sqn_range);


                on->ogmSqn_maxRcvd = (OGM_SQN_MASK & (on->ogmSqn_rangeMin - OGM_SQN_STEP));
                set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_maxRcvd, on->ogmSqn_maxRcvd);

        }

        if ((tlv_result = process_description_tlvs(pb, on, desc, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL, NULL)) == TLV_RX_DATA_DONE) {
                tlv_result = process_description_tlvs(pb, on, desc, TLV_OP_ADD, FRAME_TYPE_PROCESS_ALL, NULL);
                assertion(-500831, (tlv_result == TLV_RX_DATA_DONE)); // checked, so MUST SUCCEED!!
        }

        if (tlv_result == TLV_RX_DATA_FAILURE)
                goto process_desc0_error;

/*
        // actually I want to accept descriptions without any primary IP:
        if (!on->blocked && !ip_set(&on->ort.primary_ip))
                goto process_desc0_error;
*/

        cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);

        if (on->desc)
                debugFree(on->desc, -300111);

        on->desc = desc;
        desc = NULL;

        update_neigh_dhash(on, dhash);


        assertion(-500970, (on->dhn->on == on));
        assertion(-500309, (on->dhn == avl_find_item(&dhash_tree, &on->dhn->dhash)));
        assertion(-500310, (on == avl_find_item(&orig_tree, &on->desc->global_id)));

        cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_CREATED, on);

        return on->dhn;

process_desc0_error:

        if (on)
                free_orig_node(on);

        blacklist_neighbor(pb);

process_desc0_ignore:

        dbgf_sys(DBGT_WARN, "ignoring global_id=%s rcvd via_dev=%s via_ip=%s",
                desc ? globalIdAsString(&desc->global_id) : "???", pb->i.iif->label_cfg.str, pb->i.llip_str);

        if (desc)
                debugFree(desc, -300109);

        return NULL;
}


void update_my_description_adv(void)
{
        TRACE_FUNCTION_CALL;
        static uint8_t cache_data_array[MAX_UDPD_SIZE] = {0};
        struct description_hash dhash;
        struct description *dsc = self.desc;

        if (terminating)
                return;

        cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, &self);

        // put obligatory stuff:
        memset(dsc, 0, sizeof (struct description));

        dsc->global_id = self.global_id;


        // add some randomness to the ogm_sqn_range, that not all nodes invalidate at the same time:
        uint16_t random_range = ((DEF_OGM_SQN_RANGE - (DEF_OGM_SQN_RANGE/5)) > MIN_OGM_SQN_RANGE) ?
                DEF_OGM_SQN_RANGE - rand_num(DEF_OGM_SQN_RANGE/5) : DEF_OGM_SQN_RANGE + rand_num(DEF_OGM_SQN_RANGE/5);

        self.ogmSqn_rangeSize = ((OGM_SQN_MASK)&(random_range + OGM_SQN_STEP - 1));

        self.ogmSqn_rangeMin = ((OGM_SQN_MASK)&(self.ogmSqn_rangeMin + MAX_OGM_SQN_RANGE));

        self.ogmSqn_maxRcvd = set_ogmSqn_toBeSend_and_aggregated(&self, UMETRIC_MAX,
                (OGM_SQN_MASK)&(self.ogmSqn_rangeMin - (self.ogmSqn_next == self.ogmSqn_send ? OGM_SQN_STEP : 0)),
                (OGM_SQN_MASK)&(self.ogmSqn_rangeMin - OGM_SQN_STEP));

        dsc->ogm_sqn_min = htons(self.ogmSqn_rangeMin);
        dsc->ogm_sqn_range = htons(self.ogmSqn_rangeSize);
        dsc->tx_interval = htons(my_tx_interval);

        dsc->code_version = htons(CODE_VERSION);
        dsc->dsc_sqn = htons(++(self.descSqn));
        dsc->ttl_max = my_ttl;

        // add all tlv options:
        
        struct tx_frame_iterator it = {
                .caller = __FUNCTION__, .frames_out = (((uint8_t*) dsc) + sizeof (struct description)),
                .handls = description_tlv_handl, .handl_max = FRAME_TYPE_MAX, .frames_out_pos = 0,
                .frames_out_max = MAX_UDPD_SIZE -
                (sizeof (struct packet_header) + sizeof (struct frame_header_long) + sizeof (struct msg_description_adv)),
                .cache_data_array = cache_data_array
        };


        for (it.frame_type = 0; it.frame_type < BMX_DSC_TLV_ARRSZ; it.frame_type++) {

                int32_t iterator_result;
                
                if (!it.handls[it.frame_type].min_msg_size)
                        continue;

                iterator_result = tx_frame_iterate(NO/*iterate_msg*/, &it);

                assertion(-500792, (iterator_result >= TLV_TX_DATA_DONE));
        }

        dsc->dsc_tlvs_len = htons(it.frames_out_pos);


        dbgf_all(DBGT_INFO, "added description_tlv_size=%d ", it.frames_out_pos);

        // calculate hash: like shown in CTaoCrypt Usage Reference:
        ShaUpdate(&bmx_sha, (byte*) dsc, (it.frames_out_pos + sizeof (struct description)));
        ShaFinal(&bmx_sha, (byte*) & dhash);

        update_neigh_dhash( &self, &dhash );

        myIID4me = self.dhn->myIID4orig;
        myIID4me_timestamp = bmx_time;

        if (desc_adv_tx_unsolicited) {
                uint16_t desc_len = it.frames_out_pos + sizeof (struct msg_description_adv);
                struct link_dev_node **lndev_arr = lndevs_get_best_tp(NULL);
                int d;

                for (d = 0; (lndev_arr[d]); d++)
                        schedule_tx_task(lndev_arr[d], FRAME_TYPE_DESC_ADV, desc_len, 0, 0, myIID4me, 0);
        }

        my_description_changed = NO;

        cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_CREATED, &self);
}



STATIC_FUNC
int32_t opt_show_descriptions(uint8_t cmd, uint8_t _save, struct opt_type *opt,
                              struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY ) {

                struct avl_node *an = NULL;
                struct orig_node *on;
                char *name = NULL;
                int32_t type_filter = DEF_DESCRIPTION_TYPE;
                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->c_opt->long_name, ARG_DESCRIPTION_TYPE)) {
                                type_filter = strtol(c->c_val, NULL, 10);

                        } else if (!strcmp(c->c_opt->long_name, ARG_DESCRIPTION_NAME)) {
                                name = c->c_val;
			}
		}


                while ((on = avl_iterate_item(&orig_tree, &an))) {

                        assertion(-500361, (!on || on->desc));

                        if (name && strcmp(name, on->desc->global_id.name))
                                continue;

                        dbg_printf(cn, "dhash=%s blocked=%d :\n",
                                memAsHexString(((char*) &(on->dhn->dhash)), 4), on->blocked ? 1 : 0);

                        uint16_t tlvs_len = ntohs(on->desc->dsc_tlvs_len);
                        struct msg_description_adv * desc_buff = debugMalloc(sizeof (struct msg_description_adv) +tlvs_len, -300361);
                        desc_buff->transmitterIID4x = htons(on->dhn->myIID4orig);
                        memcpy(&desc_buff->desc, on->desc, sizeof (struct description) + tlvs_len);
                        
                        dbg_printf(cn, "%s:\n", packet_frame_handler[FRAME_TYPE_DESC_ADV].name);

                        fields_dbg(cn, FIELD_RELEVANCE_HIGH, sizeof (struct msg_description_adv) +tlvs_len, (uint8_t*) desc_buff,
                                packet_frame_handler[FRAME_TYPE_DESC_ADV].min_msg_size,
                                packet_frame_handler[FRAME_TYPE_DESC_ADV].msg_format);

                        debugFree(desc_buff, -300362);

                        struct rx_frame_iterator it = {
                                .caller = __FUNCTION__, .on = on, .cn = cn, .op = TLV_OP_PLUGIN_MIN,
                                .handls = description_tlv_handl, .handl_max = BMX_DSC_TLV_MAX, .process_filter = type_filter,
                                .frames_in = (((uint8_t*) on->desc) + sizeof (struct description)), .frames_length = tlvs_len
                        };

                        while (rx_frame_iterate(&it) > TLV_RX_DATA_DONE) {

                                dbg_printf(it.cn, "%s:\n", it.handls[it.frame_type].name);

                                fields_dbg(it.cn, FIELD_RELEVANCE_HIGH, it.frame_msgs_length, it.msg,
                                        it.handls[it.frame_type].min_msg_size, it.handls[it.frame_type].msg_format);
                        }
                }

		dbg_printf( cn, "\n" );
	}
	return SUCCESS;
}


STATIC_FUNC
struct opt_type msg_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

#ifndef LESS_OPTIONS
        {ODI, 0, ARG_UDPD_SIZE,            0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &pref_udpd_size,   MIN_UDPD_SIZE,      MAX_UDPD_SIZE,     DEF_UDPD_SIZE,0,       0,
			ARG_VALUE_FORM,	"set preferred udp-data size for send packets"}
        ,
        {ODI, 0, ARG_OGM_TX_ITERS,         0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogm_adv_tx_iters,MIN_OGM_TX_ITERS,MAX_OGM_TX_ITERS,DEF_OGM_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set maximum resend attempts for ogm aggregations"}
        ,
        {ODI, 0, ARG_UNSOLICITED_DESC_ADVS,0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_adv_tx_unsolicited,MIN_UNSOLICITED_DESC_ADVS,MAX_UNSOLICITED_DESC_ADVS,DEF_DESC_ADV_UNSOLICITED,0,0,
			ARG_VALUE_FORM,	"send unsolicited description advertisements after receiving a new one"}
        ,
        {ODI, 0, ARG_DSC0_REQS_TX_ITERS,   0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_req_tx_iters,MIN_DSC0_REQS_TX_ITERS,MAX_DSC0_REQS_TX_ITERS,DEF_DESC_REQ_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description requests"}
        ,
        {ODI, 0, ARG_DHS0_REQS_TX_ITERS,   0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dhash_req_tx_iters,MIN_DHS0_REQS_TX_ITERS,MAX_DHS0_REQS_TX_ITERS,DEF_DHASH_REQ_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description-hash requests"}
        ,
        {ODI, 0, ARG_DSC0_ADVS_TX_ITERS,   0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_adv_tx_iters,MIN_DSC0_ADVS_TX_ITERS,MAX_DSC0_ADVS_TX_ITERS,DEF_DESC_ADV_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for descriptions"}
        ,
        {ODI, 0, ARG_DHS0_ADVS_TX_ITERS,   0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dhash_adv_tx_iters,MIN_DHS0_ADVS_TX_ITERS,MAX_DHS0_ADVS_TX_ITERS,DEF_DHASH_ADV_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description hashes"}
        ,
        {ODI, 0, ARG_OGM_ACK_TX_ITERS,     0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogm_ack_tx_iters,MIN_OGM_ACK_TX_ITERS,MAX_OGM_ACK_TX_ITERS,DEF_OGM_ACK_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for ogm acknowledgements"}
        ,
#endif
	{ODI, 0, ARG_DESCRIPTIONS,	   0,  5, A_PS0N,A_USR, A_DYN, A_ARG, A_ANY, 0,                0,                   0,                   0,0,   opt_show_descriptions,
			0,		HLP_DESCRIPTIONS}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_DESCRIPTION_TYPE,'t',5,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,	0,	MIN_DESCRIPTION_TYPE, MAX_DESCRIPTION_TYPE, DEF_DESCRIPTION_TYPE,0, opt_show_descriptions,
			"<TYPE>",	HLP_DESCRIPTION_TYPE}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_DESCRIPTION_NAME,'n',5,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,	0,		0,	0,0,		0, opt_show_descriptions,
			"<NAME>",	"only show description of nodes with given name"}

};


STATIC_FUNC
int32_t init_msg( void )
{
        assertion(-500347, (sizeof (struct description_hash) == HASH_SHA1_LEN));
        assertion(-501146, (OGM_DEST_ARRAY_BIT_SIZE == ((OGM_DEST_ARRAY_BIT_SIZE / 8)*8)));

        memset(description_tlv_handl, 0, sizeof(description_tlv_handl));

        ogm_aggreg_sqn_max = ((AGGREG_SQN_MASK) & rand_num(AGGREG_SQN_MAX));

        my_packet_sqn = (rand_num(PKT_SQN_MAX - 1) + 1); // dont start with zero because my_link_sqn and my_dev_sqn assume this

	register_options_array( msg_options, sizeof( msg_options ), CODE_CATEGORY_NAME );

        InitSha(&bmx_sha);

        task_register(my_ogm_interval, schedule_my_originator_message, NULL, -300356);

        
        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));

        handl.name = "PROBLEM_ADV";
        handl.is_advertisement = 1;
        handl.is_relevant = 1;
        handl.min_msg_size = sizeof (struct msg_problem_adv);
        handl.fixed_msg_size = 0;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.tx_frame_handler = tx_frame_problem_adv;
        handl.rx_frame_handler = rx_frame_problem_adv;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_PROBLEM_ADV, &handl);


/*
        handl.name = "TEST_ADV";
        handl.is_advertisement = 1;
        handl.data_header_size = sizeof ( struct hdr_test_adv);
        handl.min_msg_size = sizeof (struct msg_test_adv);
        handl.fixed_msg_size = 1;
        handl.tx_frame_handler = tx_frame_test_adv;
        handl.rx_frame_handler = rx_frame_test_adv;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_TEST_ADV, &handl);
*/


        handl.name = "DESC_REQ";
        handl.is_destination_specific_frame = 1;
        handl.tx_iterations = &desc_req_tx_iters;
        handl.tx_tp_min = &UMETRIC_NBDISCOVERY_MIN;
//        handl.rx_rp_min = &UMETRIC_NBDISCOVERY_MIN;
        handl.data_header_size = sizeof( struct hdr_description_request);
        handl.min_msg_size = sizeof (struct msg_description_request);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = DEF_TX_DESC0_REQ_TO;
        handl.tx_msg_handler = tx_msg_dhash_or_description_request;
        handl.rx_msg_handler = rx_msg_dhash_or_description_request;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_DESC_REQ, &handl);


        static const struct field_format description_format[] = DESCRIPTION_MSG_FORMAT;
        handl.name = "DESC_ADV";
        handl.is_advertisement = 1;
        handl.tx_iterations = &desc_adv_tx_iters;
        handl.min_msg_size = sizeof (struct msg_description_adv);
        handl.tx_task_interval_min = DEF_TX_DESC0_ADV_TO;
        handl.tx_msg_handler = tx_msg_description_adv;
        handl.rx_frame_handler = rx_frame_description_advs;
        handl.msg_format = description_format;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_DESC_ADV, &handl);

        

        handl.name = "DHASH_REQ";
        handl.is_destination_specific_frame = 1;
        handl.tx_iterations = &dhash_req_tx_iters;
        handl.tx_tp_min = &UMETRIC_NBDISCOVERY_MIN;
//        handl.rx_rp_min = &UMETRIC_NBDISCOVERY_MIN;
        handl.data_header_size = sizeof( struct hdr_dhash_request);
        handl.min_msg_size = sizeof (struct msg_dhash_request);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = DEF_TX_DHASH0_REQ_TO;
        handl.tx_msg_handler = tx_msg_dhash_or_description_request;
        handl.rx_msg_handler = rx_msg_dhash_or_description_request;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_HASH_REQ, &handl);

        handl.name = "DHASH_ADV";
        handl.is_advertisement = 1;
        handl.tx_iterations = &dhash_adv_tx_iters;
        handl.min_msg_size = sizeof (struct msg_dhash_adv);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = DEF_TX_DHASH0_ADV_TO;
        handl.tx_msg_handler = tx_msg_dhash_adv;
        handl.rx_msg_handler = rx_msg_dhash_adv;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_HASH_ADV, &handl);



        handl.name = "HELLO_ADV";
        handl.is_advertisement = 1;
        handl.min_msg_size = sizeof (struct msg_hello_adv);
        handl.fixed_msg_size = 1;
        handl.tx_msg_handler = tx_msg_hello_adv;
        handl.rx_msg_handler = rx_msg_hello_adv;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_HELLO_ADV, &handl);



        handl.name = "DEV_REQ";
        handl.tx_iterations = &dev_req_tx_iters;
//        handl.tx_rp_min = &UMETRIC_NBDISCOVERY_MIN;
        handl.min_msg_size = sizeof (struct msg_dev_req);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.tx_msg_handler = tx_msg_dev_req;
        handl.rx_msg_handler = rx_msg_dev_req;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_DEV_REQ, &handl);

        handl.name = "DEV_ADV";
        handl.is_advertisement = 1;
        handl.tx_iterations = &dev_adv_tx_iters;
        handl.min_msg_size = sizeof (struct msg_dev_adv);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.data_header_size = sizeof (struct hdr_dev_adv);
        handl.tx_frame_handler = tx_frame_dev_adv;
        handl.rx_frame_handler = rx_frame_dev_adv;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_DEV_ADV, &handl);


        handl.name = "LINK_REQ";
        handl.tx_iterations = &link_req_tx_iters;
//        handl.tx_rp_min = &UMETRIC_NBDISCOVERY_MIN;
        handl.min_msg_size = sizeof (struct msg_link_req);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.tx_msg_handler = tx_msg_link_req;
        handl.rx_msg_handler = rx_msg_link_req;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_LINK_REQ, &handl);

        handl.name = "LINK_ADV";
        handl.is_advertisement = 1;
        handl.tx_iterations = &link_adv_tx_iters;
        handl.min_msg_size = sizeof (struct msg_link_adv);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.data_header_size = sizeof (struct hdr_link_adv);
        handl.tx_frame_handler = tx_frame_link_adv;
        handl.rx_frame_handler = rx_frame_link_adv;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_LINK_ADV, &handl);

        handl.name = "RP_ADV";
        handl.is_advertisement = 1;
        handl.min_msg_size = sizeof (struct msg_rp_adv);
        handl.fixed_msg_size = 1;
        handl.tx_frame_handler = tx_frame_rp_adv;
        handl.rx_frame_handler = rx_frame_rp_adv;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_RP_ADV, &handl);


        handl.name = "OGM_ADV";
        handl.is_advertisement = 1;
        handl.rx_requires_described_neigh = 1;
        handl.data_header_size = sizeof (struct hdr_ogm_adv);
        handl.min_msg_size = sizeof (struct msg_ogm_adv);
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = tx_frame_ogm_advs;
        handl.rx_frame_handler = rx_frame_ogm_advs;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_OGM_ADV, &handl);

        handl.name = "OGM_ACK";
        handl.rx_requires_described_neigh = 0;
        handl.tx_iterations = &ogm_ack_tx_iters;
        handl.min_msg_size = sizeof (struct msg_ogm_ack);
        handl.fixed_msg_size = 1;
        handl.tx_task_interval_min = CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY;
        handl.tx_msg_handler = tx_msg_ogm_ack;
        handl.rx_frame_handler = rx_frame_ogm_acks;
        register_frame_handler(packet_frame_handler, FRAME_TYPE_OGM_ACK, &handl);

        return SUCCESS;
}

STATIC_FUNC
void cleanup_msg( void )
{
        schedule_or_purge_ogm_aggregations(YES /*purge_all*/);

        if (lndev_arr)
                debugFree(lndev_arr, -300218);
        
        purge_cached_descriptions(YES);

        update_my_dev_adv();

}


struct plugin *msg_get_plugin( void ) {

	static struct plugin msg_plugin;
	memset( &msg_plugin, 0, sizeof ( struct plugin ) );

	msg_plugin.plugin_name = CODE_CATEGORY_NAME;
	msg_plugin.plugin_size = sizeof ( struct plugin );
        msg_plugin.plugin_code_version = CODE_VERSION;
        msg_plugin.cb_init = init_msg;
	msg_plugin.cb_cleanup = cleanup_msg;

        return &msg_plugin;
}
