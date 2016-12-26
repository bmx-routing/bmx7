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
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "ogm.h"
#include "msg.h"
#include "content.h"
#include "desc.h"
#include "z.h"
#include "ip.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"
#include "prof.h"

#define CODE_CATEGORY_NAME "desc"

int32_t desc_root_size_out = DEF_DESC_ROOT_SIZE;
int32_t vrt_frame_data_size_out = DEF_VRT_FRAME_DATA_SIZE;
int32_t vrt_frame_data_size_in =  DEF_VRT_FRAME_DATA_SIZE;
int32_t desc_vbodies_size_out =       DEF_DESC_VBODIES_SIZE;
int32_t desc_vbodies_size_in =        DEF_DESC_VBODIES_SIZE;
int32_t desc_contents_in =            DEF_DESC_CONTENTS;

int32_t extended_desc_checking = DEF_DESC_CHECKING;


int32_t vrt_frame_max_nesting = 2;

int32_t unsolicitedDescAdvs = DEF_UNSOLICITED_DESC_ADVS;
int32_t maintainanceInterval = DEF_REF_MAINTAIN_INTERVAL;
int32_t resolveIterations = DEF_DHASH_RSLV_ITERS;
int32_t resolveInterval = DEF_DHASH_RSLV_INTERVAL;
int32_t dhashRetryIterations = DEF_DHASH_RETRY_ITERS;
int32_t dhashRetryInterval = DEF_DHASH_RETRY_INTERVAL;

int32_t describeInfos = DEF_DESCRIBE_INFOS;



IDM_T process_description_tlvs(struct packet_buff *pb, struct orig_node *on, struct desc_content *dcOld, struct desc_content *dcOp, uint8_t op, uint8_t filter)
{
        TRACE_FUNCTION_CALL;
        assertion(-500370, (op == TLV_OP_DEL || op == TLV_OP_TEST || op == TLV_OP_NEW || op == TLV_OP_DEBUG ||
                (op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX)));


        int32_t result;
	int8_t blocked = NO;

	assertion(-500807, (dcOp && dcOp->desc_frame));
	assertion(-502047, IMPLIES(op == TLV_OP_DEL || op == TLV_OP_NEW, on && dcOp));

	if (filter <= description_tlv_db->handl_max && !contents_data(dcOp, filter))
		return TLV_RX_DATA_DONE;

        struct rx_frame_iterator it = {
                .caller = __func__, .op = op, .pb = pb, .db = description_tlv_db, .process_filter = filter,
		.on = on, .dcOld = dcOld, .dcOp = dcOp,
		.f_type = -1, .frames_length = 0, .frames_in = NULL
	};


        dbgf_track(DBGT_INFO, "op=%s nodeId=%s filter=%d",
                tlv_op_str(op), nodeIdAsStringFromDescAdv(dcOp->desc_frame), filter);


        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

		if (result == TLV_RX_DATA_BLOCKED)
			blocked = YES;
	}

	assertion( -502048, (result==TLV_RX_DATA_DONE || result==TLV_RX_DATA_REBOOTED || result==TLV_RX_DATA_REJECTED || result==TLV_RX_DATA_FAILURE));

        if ((op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX))
                return result;

        if (result==TLV_RX_DATA_REBOOTED || result==TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_FAILURE || blocked) {

                assertion(-501355, (op == TLV_OP_TEST));

                dbgf_sys(DBGT_WARN, "problematic description_ltv via %s from id=%s near type=%d=%s frame_data_length=%d  pos=%d %s %s",
                        pb ? pb->i.llip_str : DBG_NIL, nodeIdAsStringFromDescAdv(dcOp->desc_frame),
			it.f_type, (((uint8_t)it.f_type) <= description_tlv_db->handl_max) ? description_tlv_db->handls[it.f_type].name : "",
                        it.f_dlen, it._f_pos_next, blocked ? "BLOCKED" : "", tlv_rx_result_str(result));

		return (result == TLV_RX_DATA_DONE ? TLV_RX_DATA_BLOCKED : result);
        }

        return TLV_RX_DATA_DONE;
}











IDM_T desc_frame_changed(  struct desc_content *dcA, struct desc_content *dcB, uint8_t type )
{
	struct key_node *kn = (dcA ? dcA->kn : (dcB ? dcB->kn : NULL));

	assertion(-502274, (kn));

	IDM_T changed = (contents_dlen(dcA, type) != contents_dlen(dcB, type) ||
		(contents_dlen(dcA, type) && memcmp(contents_data(dcA, type), contents_data(dcB, type), contents_dlen(dcB, type))));

	dbgf_track(DBGT_INFO, "orig=%s %s type=%d (%s) dcA_len=%d dcB_len=%d",
		cryptShaAsString(&kn->kHash), changed ? "  CHANGED" : "UNCHANGED",
		type, description_tlv_db->handls[type].name, contents_dlen(dcA, type), contents_dlen(dcB, type));

	return changed;
}






CRYPTSHA_T *nodeIdFromDescAdv(uint8_t *desc_adv)
{
	return &(((struct dsc_hdr_chash*) (desc_adv + sizeof(struct tlv_hdr)))->expanded_chash);
}

char *nodeIdAsStringFromDescAdv(uint8_t *desc_adv)
{
	return cryptShaAsString(nodeIdFromDescAdv(desc_adv));
}













void update_orig_dhash(struct desc_content *dcNew)
{
	assertion(-502469, (dcNew->kn));

	struct key_node *kn = dcNew->kn;
	struct orig_node *on = kn->on;
	struct desc_content *dcOld = on ? on->dc : NULL;
	IID_T iid;

	assertion(-502470, (dcNew && dcNew->kn && !dcNew->on));
	assertion(-502471, (dcNew && dcNew->unresolvedContentCounter == 0 && dcNew->contentRefs_tree.items));
	assertion(-502225, IMPLIES(on, on->dc != dcNew));
	assertion(-502225, IMPLIES(on, on->dc->on == on));
	assertion(-502472, IMPLIES(on, on->dc->descSqn < dcNew->descSqn));
	assertion(-502643, (kn->descSqnMin <= dcNew->descSqn));
	ASSERTION(-502473, (process_description_tlvs(NULL, on, dcOld, dcNew, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL) == TLV_RX_DATA_DONE));

	if (on) {

		cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);
		on->dc = dcNew;
		dcNew->on = on;
		dcOld->on = NULL;
		iid = iid_get_myIID4x_by_node(on);
		
		if (on->ogmAggregActiveMsgLen)
			remove_ogm(on);

	} else {

		on = debugMallocReset(sizeof( struct orig_node) + (sizeof(void*) * plugin_data_registries[PLUGIN_DATA_ORIG]), -300128);
		on->k.nodeId = dcNew->kn->kHash;
		on->kn = dcNew->kn;

		on->dc = dcNew;
		dcNew->on = on;
		dcNew->kn->on = on;

		init_neighTrust(on);

		avl_insert(&orig_tree, on, -300148);
		
		iid = iid_new_myIID4x(on);

		cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);
	}

//	memset(&on->anchor, 0, sizeof(on->anchor));

	update_ogm_mins(kn, dcNew->descSqn, 0, NULL);
	kn->nextDesc = NULL;

	assertion_dbg(-502536, ((on->neighPath.um & ~UMETRIC_MASK) == 0), "um=%ju mask=%ju max=%ju",on->neighPath.um, UMETRIC_MASK, UMETRIC_MAX);

	assertion(-502537, IMPLIES(myKey == on->kn, iid == IID_MIN_USED_FOR_SELF)); // Not strictly necessary yet but maybe this requirement can be useful later.

	process_description_tlvs(NULL, on, dcOld, dcNew, TLV_OP_NEW, FRAME_TYPE_PROCESS_ALL);

	if (dcOld)
		descContent_destroy(dcOld);

	on->updated_timestamp = bmx_time;

	cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_CREATED, on);

	if (unsolicitedDescAdvs || dcNew->kn == myKey) {
		schedule_tx_task(FRAME_TYPE_DESC_ADVS, NULL, NULL, NULL, NULL, dcNew->desc_frame_len, &dcNew->dHash, sizeof(DHASH_T));
		//schedule_tx_task(FRAME_TYPE_IID_ADV, NULL, NULL, NULL, NULL, SCHEDULE_MIN_MSG_SIZE, &iid, sizeof(iid));
	}

	neighRefs_update(on->kn);
}









void process_description_tlvs_del( struct orig_node *on, struct desc_content *dcOld, uint8_t ft_start, uint8_t ft_end ) {

	int8_t t;

	assertion(-502068, (on && dcOld && dcOld->kn));

	for (t = ft_start; t <= ft_end; t++) {

		if ( t== BMX_DSC_TLV_CONTENT_HASH )
			continue;

		if (contents_data(dcOld, t)) {
			int tlv_result = process_description_tlvs(NULL, on, NULL, dcOld, TLV_OP_DEL, t);
			assertion(-501360, (tlv_result == TLV_RX_DATA_DONE));
		}
	}
}




void update_my_description(void)
{
        // MUST be checked here because:
        // description may have changed (relevantly for ogm_aggregation)
        // during current call of task_next() in bmx() main loop
        if (!my_description_changed)
		return;

        TRACE_FUNCTION_CALL;
	prof_start(update_my_description, main);

	assertion(-502082, (!terminating));
	assertion(-502275, (myKey));

	dbgf_track(DBGT_INFO, DBG_NIL);

        // add all tlv options:
        struct tx_frame_iterator tx = {
                .caller = __func__, .db = description_tlv_db, .prev_out_type = -1,
		.frames_out_ptr = debugMallocReset(desc_root_size_out, -300627),
                .frames_out_max = desc_root_size_out,
                .frames_out_pref = desc_root_size_out,
		.frame_cache_array = debugMallocReset(vrt_frame_data_size_out, -300586),
		.frame_cache_size = vrt_frame_data_size_out,
        };

        for (; tx.frame_type <= tx.db->handl_max; tx.frame_type++) {

		int32_t result;
		assertion(-502083, IMPLIES((tx.db->handls[tx.frame_type]).name, (tx.db->handls[tx.frame_type]).tx_frame_handler));
		result = tx_frame_iterate(NO/*iterate_msg*/, &tx);
		assertion_dbg(-500798, result>=TLV_TX_DATA_DONE, "frame_type=%d result=%s", tx.frame_type, tlv_tx_result_str(result));
	}

	ASSERTION(-502315, (test_description_signature(tx.frames_out_ptr, tx.frames_out_pos)));
	DHASH_T oldDHash = myKey->on ? myKey->on->dc->dHash : ZERO_CYRYPSHA;
	struct desc_content *dcNew = descContent_create(tx.frames_out_ptr, tx.frames_out_pos, myKey);

	assertion(-502316, (dcNew));

	dbgf_sys(DBGT_INFO, "nodeId=%s dhashOld=%s dhashNew=%s descSqn=%d",
		cryptShaAsString(&myKey->kHash), cryptShaAsString(&oldDHash), cryptShaAsString(&dcNew->dHash), dcNew->descSqn);

	assertion(-502317, (dcNew->kn == myKey && !myKey->nextDesc));
	assertion(-502318, (dcNew->contentRefs_tree.items && !dcNew->unresolvedContentCounter));
	assertion(-502512, (myKey->on));
	assertion(-502320, (myKey->on->dc == dcNew));

        my_description_changed = NO;

	if (myBurstSqn > ((BURST_SQN_T)(-1000)))
		myBurstSqn = 0;

	debugFree(tx.frames_out_ptr, -300585);
	debugFree(tx.frame_cache_array, -300585);
	prof_stop();
}


STATIC_FUNC
int32_t opt_show_descriptions(uint8_t cmd, uint8_t _save, struct opt_type *opt,
                              struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY ) {

                struct avl_node *an = NULL;
		struct desc_content *dc;
		char *name = NULL;
                int32_t type_filter = DEF_DESCRIPTION_TYPE;
                int32_t relevance = DEF_RELEVANCE;
                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_DESCRIPTION_TYPE)) {
                                type_filter = strtol(c->val, NULL, 10);

                        } else if (!strcmp(c->opt->name, ARG_RELEVANCE)) {
                                relevance = strtol(c->val, NULL, 10);

                        } else if (!strcmp(c->opt->name, ARG_DESCRIPTION_NAME)) {
                                name = c->val;
			}
		}

		dbg_printf( cn, "DESCRIPTIONS:" );

                while ((dc = avl_iterate_item(&descContent_tree, &an))) {

			if (name && (!dc || !dc->on || strcmp(name, dc->on->k.hostname)))
				continue;

                        dbg_printf(cn, "\ndescSha=%s nodeId=%s name=%s state=%s contents=%d/%d neighRefs=%d:",
                                cryptShaAsString(&dc->dHash), cryptShaAsString(dc ? &dc->kn->kHash: NULL),
				dc && dc->on ? dc->on->k.hostname : NULL, dc ? dc->kn->bookedState->secName : NULL,
				dc ? dc->contentRefs_tree.items : 0, dc ? (int)(dc->unresolvedContentCounter + dc->contentRefs_tree.items) : -1,
				dc->kn->neighRefs_tree.items);

			if (!dc || !dc->contentRefs_tree.items || dc->unresolvedContentCounter)
				continue;

			struct rx_frame_iterator it = {.caller = __func__, .on = NULL, .dcOp = dc,
				.op = TLV_OP_PLUGIN_MIN, .db = description_tlv_db, .process_filter = type_filter, .f_type = -1,};

                        int32_t result;
                        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

				dbg_printf(cn, "\n  %s=%d (%s%s length=%d%s):",
					it.f_handl ? it.f_handl->name : "DSC_UNKNOWN", it.f_type_expanded,
					dc->final[it.f_type].desc_tlv_body_len ? "inline" : "ref=",
					dc->final[it.f_type].desc_tlv_body_len ? "" : cryptShaAsString(&dc->final[it.f_type].u.cun->k.content->chash),
					dc->final[it.f_type].desc_tlv_body_len ? dc->final[it.f_type].desc_tlv_body_len : dc->final[it.f_type].u.cun->k.content->f_body_len,
					it.f_handl && it.f_handl->msg_format ? "" : " UNKNOWN_FORMAT"
					);

				if (it.f_msg) {
					if (it.f_handl && it.f_handl->msg_format)
						fields_dbg_lines(cn, relevance, it.f_msgs_len, it.f_msg, it.f_handl->min_msg_size, it.f_handl->msg_format);
					else
						dbg_printf(cn, "\n    hex=%s", memAsHexStringSep(it.f_msg, it.f_msgs_len, it.f_handl->min_msg_size, " "));
				}
                        }

		}

		dbg_printf( cn, "\n" );
	}
	return SUCCESS;
}





int32_t opt_update_dext_method(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY )
		my_description_changed = YES;

	return SUCCESS;
}







STATIC_FUNC
int32_t create_dsc_tlv_info(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if (!describeInfos)
		return TLV_TX_DATA_IGNORED;

	struct description_msg_info *msg = (struct description_msg_info*)tx_iterator_cache_msg_ptr(it);

	msg->type = 0;
	msg->infoOffset = sizeof(struct description_msg_info);
        msg->codeRevision = htonl(bmx_git_rev_u32);

	uint32_t infoLen = 0;

	int32_t nameLen = strlen(my_Hostname);

	if (nameLen>0 && nameLen<255 && nameLen < MAX_HOSTNAME_LEN && nameLen <= tx_iterator_cache_data_space_pref(it, 0, 0)) {
		msg->nameLen = nameLen;
		memcpy(&msg->info[infoLen], my_Hostname, nameLen);
		infoLen += nameLen;
	}

	return (sizeof(struct description_msg_info) + infoLen);
}


STATIC_FUNC
int32_t process_dsc_tlv_info(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	dbgf_all(DBGT_INFO, "op=%s", tlv_op_str(it->op) );

	struct description_msg_info *msg = (struct description_msg_info *) it->f_msg;

	if (!msg || msg->type != 0 || msg->infoOffset < sizeof(struct description_msg_info))
		return TLV_RX_DATA_PROCESSED;

	if (it->f_dlen < (msg->infoOffset + msg->nameLen + msg->mailLen) || msg->nameLen >= MAX_HOSTNAME_LEN || msg->mailLen >= MAX_MAILNAME_LEN)
		return TLV_RX_DATA_FAILURE;

	uint32_t msgInfoPos = 0;

	if (msg->nameLen) {
		char name[MAX_HOSTNAME_LEN];
		memcpy(name, &msg->info[msgInfoPos], msg->nameLen);
		name[msg->nameLen] = 0;

		if (validate_name_string(name, msg->nameLen + 1, NULL) == FAILURE)
			return TLV_RX_DATA_FAILURE;

		if ((it->op==TLV_OP_NEW || it->op == TLV_OP_DEL))
			memset(it->on->k.hostname, 0, sizeof(it->on->k.hostname));

		if (it->op == TLV_OP_NEW)
			strcpy(it->on->k.hostname, name);

		msgInfoPos += msg->nameLen;
	}

	if (msg->mailLen) {
		char mail[MAX_MAILNAME_LEN];
		memcpy(mail, &msg->info[msgInfoPos], msg->mailLen);
		mail[msg->mailLen] = 0;

		if (validate_name_string(mail, msg->mailLen + 1, "@") == FAILURE)
			return TLV_RX_DATA_FAILURE;

		msgInfoPos += msg->mailLen;
	}


	return TLV_RX_DATA_PROCESSED;
}







STATIC_FUNC
int32_t tx_msg_description_request(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct tx_task_node *ttn = it->ttn;
	struct hdr_description_request *hdr = ((struct hdr_description_request*) tx_iterator_cache_hdr_ptr(it));
	struct msg_description_request *msg = ((struct msg_description_request*) tx_iterator_cache_msg_ptr(it));
	struct schedule_dsc_req *req = (struct schedule_dsc_req*)ttn->key.data;
	struct NeighRef_node *ref = (req->iid) ? iid_get_node_by_neighIID4x(&ttn->neigh->neighIID4x_repos, req->iid, NO) : NULL;
	struct key_node *kn = (req->iid && ref) ? ref->kn : keyNode_get(&ttn->key.f.groupId);
	int32_t ret = TLV_TX_DATA_DONE;


	if ((!ref || ref->reqCnt <= dhashRetryIterations || !ref->reqTime || (((TIME_T)(bmx_time - ref->reqTime)) > (TIME_T)dhashRetryInterval)) &&
		(req && kn && (req->descSqn >= kn->descSqnMin) && (req->descSqn > (kn->nextDesc ? kn->nextDesc->descSqn : 0)) && (req->descSqn > (kn->on ? kn->on->dc->descSqn : 0))) && (
		((!req->iid) && kn->bookedState->i.c >= KCTracked && kn->content->f_body && (kn->bookedState->i.r <= KRQualifying || kn->bookedState->i.c >= KCNeighbor)) ||
		(req->iid && ref && iid_get_neighIID4x_timeout_by_node(ref) && kn->bookedState->i.c >= KCTracked && kn->content->f_body && ref->inaptChainOgm && ref->inaptChainOgm->claimedChain && ref->descSqn == req->descSqn)
		)) {

		assertion(-500855, (tx_iterator_cache_data_space_pref(it, 0, 0) >= ((int) (sizeof(struct msg_description_request)))));

		if (hdr->msg == msg) {
			assertion(-500854, (is_zero(hdr, sizeof(*hdr))));
			hdr->dest_kHash = ttn->key.f.groupId;
		} else {
			assertion(-500871, (cryptShasEqual(&hdr->dest_kHash, &ttn->key.f.groupId)));
		}

		msg->kHash = kn->kHash;
		if (ref) {
			ref->reqCnt++;
			ref->reqTime = bmx_time;
		}

		ret = sizeof(struct msg_description_request);
	}

	dbgf_track(DBGT_INFO, "%s dev=%s to neigh khash=%s iterations=%d requesting kHash=%s iid=%d descSqn=%d credits=%s ref=%p reqCnt=%d reqTime=%d ret=%d",
		it->db->handls[ttn->key.f.type].name, ttn->key.f.p.dev->ifname_label.str, cryptShaAsString(&ttn->key.f.groupId),
		ttn->tx_iterations, cryptShaAsString(kn ? &kn->kHash : NULL), req->iid, req->descSqn, kn ? kn->bookedState->secName : NULL, 
		ref, ref ? (int)ref->reqCnt : -1, ref ? ref->reqTime : 0,
		ret);

	return ret;
}

STATIC_FUNC
int32_t rx_msg_description_request(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct packet_buff *pb = it->pb;
	struct hdr_description_request *hdr = (struct hdr_description_request*) (it->f_data);
	struct msg_description_request *msg = (struct msg_description_request*) (it->f_msg);

	assertion(-502171, (pb->i.iif));

	if (cryptShasEqual(&hdr->dest_kHash, &myKey->kHash)) {

		dbgf_track(DBGT_INFO, "%s NB %s destination_dhash=%s requested_kHash=%s",
			it->f_handl->name, pb->i.llip_str, cryptShaAsString(&hdr->dest_kHash), cryptShaAsString(&msg->kHash));

		struct key_node *kn = keyNode_get(&msg->kHash);

		if (kn && kn->on && (pb->i.verifiedLink || kn == myKey)) {

			schedule_tx_task(FRAME_TYPE_DESC_ADVS, NULL, NULL, NULL, pb->i.iif, kn->on->dc->desc_frame_len, &kn->on->dc->dHash, sizeof(kn->on->dc->dHash));

		} else {
			dbgf_sys(DBGT_WARN, "UNVERIFIED neigh=%s llip=%s or non-promoted kHash=%s kn=%d on=%d nextDc=%d",
				pb->i.verifiedLink? cryptShaAsString(&pb->i.verifiedLink->k.linkDev->key.local->local_id) : NULL,
				pb->i.llip_str, cryptShaAsString(&msg->kHash), !!kn, (kn && kn->on), (kn && kn->nextDesc));
		}
	}

	return sizeof(struct msg_description_request);
}

STATIC_FUNC
int32_t tx_frame_description_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	DHASH_T *dhash = (DHASH_T*)it->ttn->key.data;
        struct desc_content *dc = avl_find_item(&descContent_tree, dhash);

	if (!dc || !dc->on) {
		dbgf_sys(DBGT_WARN, "%s dhash=%s!", dc ? "UnKnown" : "UnPromoted", cryptShaAsString(dhash));
                return TLV_TX_DATA_DONE;
        }

	assertion(-502060, (dc->desc_frame_len == it->ttn->frame_msgs_length));
	assertion(-502061, (dc->desc_frame_len <= tx_iterator_cache_data_space_max(it, 0, 0)));

        memcpy(tx_iterator_cache_msg_ptr(it), dc->desc_frame, dc->desc_frame_len);
	iid_get_myIID4x_by_node(dc->on);

	dbgf_track(DBGT_INFO, "dhash=%s id=%s descr_size=%d",
		cryptShaAsString(dhash), cryptShaAsString(&dc->kn->kHash), dc->desc_frame_len);

        return dc->desc_frame_len;
}

STATIC_FUNC
int32_t rx_frame_description_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	char *goto_error_code = NULL;
	int32_t goto_error_ret = TLV_RX_DATA_FAILURE;
	GLOBAL_ID_T *nodeId = NULL;
	struct dsc_msg_version *thisVers, *currVers, *nextVers;
	struct desc_content *dc = NULL;
	CRYPTSHA_T dHash;

	cryptShaAtomic(it->f_data, it->f_dlen, &dHash);


	if (!(nodeId = get_desc_id(it->f_data, it->f_dlen, NULL, &thisVers)))
		goto_error_return(finish, "Invalid nodeId", TLV_RX_DATA_FAILURE);

	struct key_node *kn = keyNode_get(nodeId);
	DESC_SQN_T descSqn = ntohl(thisVers->descSqn);
	union content_sizes virtDescSizes = {.u32 = ntohl(thisVers->virtDescSizes.u32)};

	if (!kn || (kn->bookedState->i.c < KCTracked) || !kn->content || !kn->content->f_body)
		goto_error_return(finish, "Insufficient Credits", it->f_dlen);

	if (!(descSqn) ||
		(kn->descSqnMin > descSqn) ||
		(kn->nextDesc && kn->nextDesc->descSqn >= descSqn) ||
		(kn->on && kn->on->dc->descSqn >= descSqn))
		goto_error_return(finish, "Outdated DescSqn", it->f_dlen);

	if ((dc = avl_find_item(&descContent_tree, &dHash)))
		goto_error_return(finish, "Already known dc", it->f_dlen);

	if (!test_description_signature(it->f_data, it->f_dlen))
		goto_error_return(finish, "Invalid signature", TLV_RX_DATA_FAILURE);

	if (
		(kn->on && (
			!get_desc_id(kn->on->dc->desc_frame, kn->on->dc->desc_frame_len, NULL, &currVers) ||
			currVers->bootSqn != thisVers->bootSqn)) ||
		(kn->nextDesc && (
			!get_desc_id(kn->nextDesc->desc_frame, kn->nextDesc->desc_frame_len, NULL, &nextVers) ||
			nextVers->bootSqn != thisVers->bootSqn))) {

		keyNode_schedLowerWeight(kn, KCListed);

		goto_error_return(finish, "Rebooted", it->f_dlen);
	}

	if ((virtDescSizes.f.length > desc_vbodies_size_in || virtDescSizes.f.contents > desc_contents_in) && (extended_desc_checking >= TYP_DESC_CHECKING_SIZES)) {
		update_ogm_mins(kn, descSqn + 1, 0, NULL);
		goto_error_return(finish, "Intolerable desc sizes", it->f_dlen);
	}

	if (!(dc = descContent_create(it->f_data, it->f_dlen, kn)))
		goto_error_return(finish, "Failed desc content creation", it->f_dlen);

        goto_error_return(finish, "Success", it->f_dlen);

finish:
	if (dc)
		dc->referred_by_others_timestamp = bmx_time;

	dbgf_track(DBGT_INFO, "Finished=%s rcvd dhash=%s nodeId=%s via_dev=%s via_ip=%s dc=%d",
		goto_error_code, memAsHexString(&dHash, sizeof(dHash)), cryptShaAsString(nodeId),
		it->pb->i.iif->ifname_label.str, it->pb->i.llip_str, !!dc);

	return goto_error_ret;
}

STATIC_FUNC
int32_t tx_msg_iid_request(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct hdr_iid_request *hdr = ((struct hdr_iid_request*) tx_iterator_cache_hdr_ptr(it));
	struct msg_iid_request *msg = ((struct msg_iid_request*) tx_iterator_cache_msg_ptr(it));

	int32_t ret = TLV_TX_DATA_DONE;

	IID_T *iid = ((IID_T*) it->ttn->key.data);
	struct NeighRef_node *ref = iid_get_node_by_neighIID4x(&it->ttn->neigh->neighIID4x_repos, *iid, NO);

	if (ref && (ref->reqCnt <= dhashRetryIterations || !ref->reqTime || (((TIME_T)(bmx_time - ref->reqTime)) > (TIME_T)dhashRetryInterval)) &&
		iid_get_neighIID4x_timeout_by_node(ref) && (!ref->kn || (ref->inaptChainOgm && !ref->inaptChainOgm->claimedChain))) {

		if (hdr->msg == msg) {
			assertion(-502287, (is_zero(hdr, sizeof(*hdr))));
			hdr->dest_nodeId = it->ttn->key.f.groupId;
		} else {
			assertion(-502288, (cryptShasEqual(&hdr->dest_nodeId, &it->ttn->key.f.groupId)));
		}

		msg->receiverIID4x = htons(*iid);
		ref->reqCnt++;
		ref->reqTime = bmx_time;

		ret = sizeof(struct msg_iid_request);
	}

	dbgf_track(DBGT_INFO, "iid=%d ref=%d nodeId=%s to neighId=%s dev=%s reqCnt=%d ref=%p reqTime=%d ret=%d",
		*iid, !!ref, cryptShaAsShortStr(ref && ref->kn ? &ref->kn->kHash : NULL), cryptShaAsShortStr(&it->ttn->key.f.groupId), it->ttn->key.f.p.dev->ifname_label.str,
		ref, ref ? (int)ref->reqCnt : -1, ref ? ref->reqTime : 0, ret);

	return ret;
}

STATIC_FUNC
int32_t rx_frame_iid_request(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
	struct hdr_iid_request *hdr = (struct hdr_iid_request*) (it->f_data);
	struct msg_iid_request *msg = (struct msg_iid_request*) (it->f_msg);

	if (msg && cryptShasEqual(&hdr->dest_nodeId, &myKey->kHash)) {

		for (; msg < &(hdr->msg[it->f_msgs_fixed]); msg++) {

			MIID_T *in;
			IID_T iid = ntohs(msg->receiverIID4x);
			if ((in = iid_get_node_by_myIID4x(iid))) {
			
				schedule_tx_task(FRAME_TYPE_IID_ADV, NULL, NULL, NULL, nn->best_tq_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &iid, sizeof(iid));

				dbgf_track(DBGT_INFO, "neigh=%s iid=%d", nn->on->k.hostname, iid);
			}

		}
	}
	return TLV_RX_DATA_PROCESSED;
}


STATIC_FUNC
int32_t tx_msg_iid_adv(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct msg_iid_adv *msg = ((struct msg_iid_adv*) tx_iterator_cache_msg_ptr(it));
	IID_T *iid = (IID_T*) it->ttn->key.data;
	MIID_T *in;

	if ((in = iid_get_node_by_myIID4x(*iid))) {
		msg->nodeId = in->kn->kHash;
		msg->transmitterIID4x = htons(*iid);
		msg->descSqn = htonl(in->dc->descSqn);
		msg->chainOgm = chainOgmCalc(in->dc, in->dc->ogmSqnMaxSend);

		dbgf_track(DBGT_INFO, "iid=%d nodeId=%s descSqn=%d ogmSqn=%d chainOgm=%s",
			*iid, cryptShaAsShortStr(&msg->nodeId), in->dc->descSqn, in->dc->ogmSqnMaxSend, memAsHexString(&msg->chainOgm, sizeof(msg->chainOgm)));

		return sizeof(struct msg_iid_adv);
	}

	return TLV_TX_DATA_DONE;
}

STATIC_FUNC
int32_t rx_msg_iid_adv(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct msg_iid_adv *msg = (struct msg_iid_adv*) (it->f_msg);
	struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
	AGGREG_SQN_T aggSqnInvalidMax = (nn->ogm_aggreg_max - AGGREG_SQN_CACHE_RANGE);
	struct InaptChainOgm chainOgm = {.chainOgm = msg->chainOgm, .claimedMetric = {.val = {.u16 = 0}}, .claimedHops = 0, .claimedChain = 1};
	IID_T iid = ntohs(msg->transmitterIID4x);
	DESC_SQN_T descSqn = ntohl(msg->descSqn);

	dbgf_track(DBGT_INFO, "neigh=%s iid=%d nodeId=%s descSqn=%d chainOgm=%s",
		nn->on->k.hostname, iid, cryptShaAsShortStr(&msg->nodeId), descSqn, memAsHexString(&msg->chainOgm, sizeof(msg->chainOgm)));

//	if (iid == IID_MIN_USED_FOR_SELF && !cryptShasEqual(&msg->nodeId, &nn->local_id))
//		return TLV_RX_DATA_FAILURE;

	neighRef_update(nn, aggSqnInvalidMax, iid, &msg->nodeId, descSqn, &chainOgm);

	return TLV_RX_DATA_PROCESSED;
}


STATIC_FUNC
int32_t opt_dsqn_path(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	static uint8_t checked = NO;

	if ( (cmd == OPT_CHECK || cmd == OPT_SET_POST) && initializing && !checked ) {

		if (!newDescriptionSqn((cmd==OPT_CHECK ? patch->val : DEF_DSQN_PATH), 0))
			return FAILURE;

		checked = YES;
        }

	return SUCCESS;
}

int32_t opt_update_description(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_APPLY )
		my_description_changed = YES;

	return SUCCESS;
}


STATIC_FUNC
struct opt_type desc_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

#ifndef LESS_OPTIONS
	{ODI,0,ARG_DESC_ROOT_SIZE,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &desc_root_size_out,MIN_DESC_ROOT_SIZE, MAX_DESC_ROOT_SIZE,     DEF_DESC_ROOT_SIZE,0,      opt_update_dext_method,
			ARG_VALUE_FORM, HLP_DESC_ROOT_SIZE},
	{ODI,0,ARG_VRT_FRAME_DATA_SIZE_OUT,0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_frame_data_size_out,MIN_VRT_FRAME_DATA_SIZE,MAX_VRT_FRAME_DATA_SIZE,DEF_VRT_FRAME_DATA_SIZE,0,  opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_FRAME_DATA_SIZE_OUT},
	{ODI,0,ARG_VRT_FRAME_DATA_SIZE_IN, 0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_frame_data_size_in,MIN_VRT_FRAME_DATA_SIZE,MAX_VRT_FRAME_DATA_SIZE,DEF_VRT_FRAME_DATA_SIZE,0,  opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_FRAME_DATA_SIZE_IN},
	{ODI,0,ARG_DESC_VBODIES_SIZE_OUT,  0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &desc_vbodies_size_out,MIN_DESC_VBODIES_SIZE,MAX_DESC_VBODIES_SIZE,DEF_DESC_VBODIES_SIZE,0,   opt_update_dext_method,
			ARG_VALUE_FORM, HLP_DESC_VBODIES_SIZE_OUT},
	{ODI,0,ARG_DESC_VBODIES_SIZE_IN,   0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &desc_vbodies_size_in,MIN_DESC_VBODIES_SIZE,MAX_DESC_VBODIES_SIZE,DEF_DESC_VBODIES_SIZE,0,    opt_update_dext_method,
			ARG_VALUE_FORM, HLP_DESC_VBODIES_SIZE_IN},
	{ODI,0,ARG_DESC_CHECKING,          0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &extended_desc_checking,MIN_DESC_CHECKING,MAX_DESC_CHECKING,DEF_DESC_CHECKING,          0,    NULL,
			ARG_VALUE_FORM, HLP_DESC_CHECKING},
	{ODI,0,ARG_UNSOLICITED_DESC_ADVS,  0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &unsolicitedDescAdvs,MIN_UNSOLICITED_DESC_ADVS,MAX_UNSOLICITED_DESC_ADVS,DEF_UNSOLICITED_DESC_ADVS,0,NULL,
			ARG_VALUE_FORM, "enable unrequested propagation (flooding) of new description advertisements"},
        {ODI,0,ARG_REF_MAINTAIN_INTERVAL,    0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &maintainanceInterval,MIN_REF_MAINTAIN_INTERVAL, MAX_REF_MAINTAIN_INTERVAL,DEF_REF_MAINTAIN_INTERVAL,0,    NULL,
			ARG_VALUE_FORM,	"set interval for resolving unresolved neighRefs in ms"},
        {ODI,0,ARG_DHASH_RSLV_ITERS,    0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &resolveIterations,MIN_DHASH_RSLV_ITERS, MAX_DHASH_RSLV_ITERS,DEF_DHASH_RSLV_ITERS,0,    NULL,
			ARG_VALUE_FORM,	"set max tx iterations for resolving unknown descriptions"},
        {ODI,0,ARG_DHASH_RSLV_INTERVAL, 0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &resolveInterval,MIN_DHASH_RSLV_INTERVAL, MAX_DHASH_RSLV_INTERVAL,DEF_DHASH_RSLV_INTERVAL,0,    NULL,
			ARG_VALUE_FORM,	"set tx interval for resolving unknown descriptions"},
        {ODI,0,ARG_DHASH_RETRY_ITERS,    0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dhashRetryIterations,MIN_DHASH_RETRY_ITERS, MAX_DHASH_RETRY_ITERS,DEF_DHASH_RETRY_ITERS,0,    NULL,
			ARG_VALUE_FORM,	"set max tx iterations for retrying unresolved descriptions"},
        {ODI,0,ARG_DHASH_RETRY_INTERVAL, 0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dhashRetryInterval,MIN_DHASH_RETRY_INTERVAL, MAX_DHASH_RETRY_INTERVAL,DEF_DHASH_RETRY_INTERVAL,0,    NULL,
			ARG_VALUE_FORM,	"set tx interval for re-retrying unresolved descriptions"},
        {ODI,0,ARG_DESCRIBE_INFOS,         0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &describeInfos,MIN_DESCRIBE_INFOS, MAX_DESCRIBE_INFOS,DEF_DESCRIBE_INFOS,0,    opt_update_description,
			ARG_VALUE_FORM,	"publish optional node metadata via node description"},
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
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE},

	{ODI,0,ARG_DSQN_PATH,		0,  9,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_DSQN_PATH,opt_dsqn_path,
			ARG_DIR_FORM,	"set path to file containing latest used description SQN of this node"},

	{ODI,0,"descUpdate",		0,  9,1,A_PS0,A_ADM,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_update_description,
			0,		"update own description"}
        ,

};

void init_desc( void )
{
	register_options_array( desc_options, sizeof( desc_options ), CODE_CATEGORY_NAME );


	struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));


	static const struct field_format info_format[] = DESCRIPTION_MSG_INFO_FORMAT;
        handl.name = "DSC_INFO";
	handl.min_msg_size = sizeof(struct description_msg_info);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&fref_dflt;
	handl.dextCompression = (int32_t*)&dflt_fzip;
        handl.tx_frame_handler = create_dsc_tlv_info;
        handl.rx_frame_handler = process_dsc_tlv_info;
	handl.msg_format = info_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_INFO, &handl);





	handl.name = "DESC_REQ";
	handl.rx_processUnVerifiedLink = 1;
	handl.data_header_size = sizeof( struct hdr_description_request);
	handl.min_msg_size = sizeof(struct msg_description_request);
	handl.fixed_msg_size = 1;
	handl.tx_iterations = &resolveIterations;
	handl.tx_task_interval_min = &resolveInterval;
	handl.tx_msg_handler = tx_msg_description_request;
	handl.rx_msg_handler = rx_msg_description_request;
	register_frame_handler(packet_frame_db, FRAME_TYPE_DESC_REQ, &handl);

	handl.name = "DESC_ADV";
	handl.rx_processUnVerifiedLink = 1;
	handl.min_msg_size = (
		sizeof(struct tlv_hdr) + sizeof(struct dsc_hdr_chash) +
		sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) +
		sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_version) );
	handl.tx_packet_prepare_always = update_my_description;
	handl.tx_frame_handler = tx_frame_description_adv;
	handl.rx_frame_handler = rx_frame_description_adv;
	register_frame_handler(packet_frame_db, FRAME_TYPE_DESC_ADVS, &handl);


        handl.name = "IID_REQ";
        handl.data_header_size = sizeof( struct hdr_iid_request);
        handl.min_msg_size = sizeof (struct msg_iid_request);
        handl.fixed_msg_size = 1;
	handl.tx_iterations = &resolveIterations;
	handl.tx_packet_prepare_casuals = neighRefs_resolve_or_destroy;
	handl.tx_task_interval_min = &resolveInterval;
        handl.tx_msg_handler = tx_msg_iid_request;
        handl.rx_frame_handler = rx_frame_iid_request;
	handl.rx_minNeighCol = KCNeighbor;
	handl.rx_minNeighCond = kPref_neighbor_metric;
        register_frame_handler(packet_frame_db, FRAME_TYPE_IID_REQ, &handl);

        handl.name = "IID_ADV";
        handl.min_msg_size = sizeof (struct msg_iid_adv);
        handl.fixed_msg_size = 1;
        handl.tx_msg_handler = tx_msg_iid_adv;
        handl.rx_msg_handler = rx_msg_iid_adv;
	handl.rx_minNeighCol = KCNeighbor;
	handl.rx_minNeighCond = kPref_neighbor_metric;
        register_frame_handler(packet_frame_db, FRAME_TYPE_IID_ADV, &handl);


}


