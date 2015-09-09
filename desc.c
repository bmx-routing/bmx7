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
#include "desc.h"
#include "content.h"
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

int32_t vrt_frame_max_nesting = 2;

int32_t unsolicitedDescAdvs = DEF_UNSOLICITED_DESC_ADVS;





IDM_T process_description_tlvs(struct packet_buff *pb, struct orig_node *on, struct desc_content *dcOld, struct desc_content *dcNew, uint8_t op, uint8_t filter)
{
        TRACE_FUNCTION_CALL;
        assertion(-500370, (op == TLV_OP_DEL || op == TLV_OP_TEST || op == TLV_OP_NEW || op == TLV_OP_DEBUG ||
                (op >= TLV_OP_CUSTOM_MIN && op <= TLV_OP_CUSTOM_MAX) || (op >= TLV_OP_PLUGIN_MIN && op <= TLV_OP_PLUGIN_MAX)));


        int32_t result;
	int8_t blocked = NO;

	assertion(-500807, (dcNew && dcNew->desc_frame && dcNew->dhn));
	assertion(-502047, IMPLIES(op == TLV_OP_DEL || op == TLV_OP_NEW, on && dcNew));

	if (filter <= description_tlv_db->handl_max && !contents_data(dcNew, filter))
		return TLV_RX_DATA_DONE;

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .op = op, .pb = pb, .db = description_tlv_db, .process_filter = filter,
		.on = on, .dcOld = dcOld, .dcNew = dcNew,
		.f_type = -1, .frames_length = 0, .frames_in = NULL
	};


        dbgf_track(DBGT_INFO, "op=%s nodeId=%s filter=%d",
                tlv_op_str(op), nodeIdAsStringFromDescAdv(dcNew->desc_frame), filter);


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
			it.f_type, (((uint8_t)it.f_type) <= description_tlv_db->handl_max) ? description_tlv_db->handls[it.f_type].name : "",
                        it.f_dlen, it._f_pos_next, blocked ? "BLOCKED" : "", tlv_rx_result_str(result));

		return (result == TLV_RX_DATA_DONE ? TLV_RX_DATA_BLOCKED : result);
        }

        return TLV_RX_DATA_DONE;
}











IDM_T desc_frame_changed(  struct rx_frame_iterator *it, uint8_t type )
{
	struct desc_content *rOld = it->dcOld;
	struct desc_content *rNew = it->dcNew;
	struct key_node *kn = (rOld ? rOld->key : (rNew ? rNew->key : NULL));

	assertion(-502274, (kn));

	IDM_T changed = (contents_dlen(rOld, type) != contents_dlen(rNew, type) ||
		(contents_dlen(rOld, type) && memcmp(contents_data(rOld, type), contents_data(rNew, type), contents_dlen(rNew, type))));

	dbgf_track(DBGT_INFO, "orig=%s %s type=%d (%s) old_len=%d new_len=%d",
		cryptShaAsString(&kn->kHash), changed ? "  CHANGED" : "UNCHANGED",
		type, it->db->handls[type].name, contents_dlen(rOld, type), contents_dlen(rNew, type));

	return changed;
}






SHA1_T *nodeIdFromDescAdv(uint8_t *desc_adv)
{
	return &(((struct dsc_hdr_chash*) (desc_adv + sizeof(struct tlv_hdr)))->expanded_chash);
}

char *nodeIdAsStringFromDescAdv(uint8_t *desc_adv)
{
	return cryptShaAsString(nodeIdFromDescAdv(desc_adv));
}













void update_orig_dhash(struct desc_content *dcNew)
{
	assertion(-502469, (dcNew->key));

	struct key_node *kn = dcNew->key;
	struct orig_node *on = kn->currOrig;
	struct desc_content *dcOld = on ? on->descContent : NULL;

	assertion(-502470, (dcNew && dcNew->key && !dcNew->orig));
	assertion(-502471, (dcNew && dcNew->unresolvedContentCounter == 0 && dcNew->contentRefs_tree.items));
	assertion(-502225, IMPLIES(on, on->descContent != dcNew));
	assertion(-502225, IMPLIES(on, on->descContent->orig == on));
	assertion(-502472, IMPLIES(on, on->descContent->descSqn < dcNew->descSqn));
	ASSERTION(-502473, (process_description_tlvs(NULL, on, dcOld, dcNew, TLV_OP_TEST, FRAME_TYPE_PROCESS_ALL) == TLV_RX_DATA_DONE));

	if (on) {
		cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_DESTROY, on);
		on->descContent = dcNew;
		dcNew->orig = on;
		dcOld->orig = NULL;
	} else {
		on = debugMallocReset(sizeof( struct orig_node) + (sizeof(void*) * plugin_data_registries[PLUGIN_DATA_ORIG]), -300128);
		on->k.nodeId = dcNew->key->kHash;
		on->key = dcNew->key;

		on->descContent = dcNew;
		dcNew->orig = on;
		dcNew->key->currOrig = on;

		init_neighTrust(on);

		avl_insert(&orig_tree, on, -300148);

		cb_plugin_hooks(PLUGIN_CB_STATUS, NULL);
	}

	kn->nextDesc = NULL;

	process_description_tlvs(NULL, on, dcOld, dcNew, TLV_OP_NEW, FRAME_TYPE_PROCESS_ALL);

	if (dcOld)
		dhash_node_reject(dcOld->dhn);

	on->updated_timestamp = bmx_time;

	cb_plugin_hooks(PLUGIN_CB_DESCRIPTION_CREATED, on);

	if (unsolicitedDescAdvs) {
		schedule_tx_task(FRAME_TYPE_DESC_ADVS, NULL, NULL, NULL, dcNew->desc_frame_len, &dcNew->dhn->dhash, sizeof(DHASH_T));
		schedule_tx_task(FRAME_TYPE_DHASH_ADV, NULL, NULL, NULL, SCHEDULE_MIN_MSG_SIZE, &dcNew->dhn->dhash, sizeof(DHASH_T));
	}
}









void process_description_tlvs_del( struct orig_node *on, struct desc_content *dcOld, uint8_t ft_start, uint8_t ft_end ) {

	int8_t t;

	assertion(-502068, (on && dcOld && dcOld->dhn && dcOld->key));

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
                .caller = __FUNCTION__, .db = description_tlv_db, .prev_out_type = -1,
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

	struct desc_content *dcNew = descContent_create(tx.frames_out_ptr, tx.frames_out_pos, myKey);

	assertion(-502316, (dcNew && dcNew->dhn));
	assertion(-502317, (dcNew->key == myKey && myKey->nextDesc == dcNew));
	assertion(-502318, (dcNew->contentRefs_tree.items && !dcNew->unresolvedContentCounter));
	assertion(-502319, IMPLIES(myKey->currOrig, myKey->currOrig->descContent->dhn));

	dbgf_sys(DBGT_INFO, "nodeId=%s dhashOld=%s dhashNew=%s descSqn=%d",
		cryptShaAsString(&myKey->kHash),
		cryptShaAsString(myKey->currOrig ? &myKey->currOrig->descContent->dhn->dhash : NULL),
		cryptShaAsString(&dcNew->dhn->dhash),
		dcNew->descSqn);

	keyNode_updCredits(NULL, myKey, NULL);

	assertion(-502512, (myKey->currOrig));
	assertion(-502320, (myKey->currOrig->descContent == dcNew));

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
		struct dhash_node *dhn;
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

                while ((dhn = avl_iterate_item(&dhash_tree, &an))) {

			struct desc_content *dc = dhn->descContent;
			if (name && (!dc->orig || strcmp(name, dc->orig->k.hostname)))
				continue;

                        dbg_printf(cn, "\ndescSha=%s nodeId=%s name=%s state=%s contents=%d/%d rejected=%d neighRefs=%d:",
                                cryptShaAsString(&dhn->dhash), cryptShaAsString(dc ? &dc->key->kHash: NULL),
				dc && dc->orig ? dc->orig->k.hostname : NULL, dc ? dc->key->bookedState->secName : NULL,
				dc ? dc->contentRefs_tree.items : 0, dc ? (int)(dc->unresolvedContentCounter + dc->contentRefs_tree.items) : -1,
				dhn->rejected, dhn->neighRefs_tree.items);

			if (!dc || !dc->contentRefs_tree.items || dc->unresolvedContentCounter)
				continue;

			struct rx_frame_iterator it = {.caller = __FUNCTION__, .on = NULL, .dcNew = dc,
				.op = TLV_OP_PLUGIN_MIN, .db = description_tlv_db, .process_filter = type_filter, .f_type = -1,};

                        int32_t result;
                        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

				if (it.f_handl) {
					dbg_printf(cn, "\n  %s (%s):", it.f_handl->name, dc->final[it.f_type].desc_tlv_body_len ? "inline" : "referenced");
					fields_dbg_lines(cn, relevance, it.f_msgs_len, it.f_msg, it.f_handl->min_msg_size, it.f_handl->msg_format);
				} else {
					dbg_printf(cn, "\n  DSC_UNKNOWN=%d (%s)", it.f_type_expanded, dc->final[it.f_type_expanded].desc_tlv_body_len ? "inline" : "referenced");
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
int32_t create_dsc_tlv_version(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	struct dsc_msg_version *dsc = (struct dsc_msg_version *)tx_iterator_cache_msg_ptr(it);

        dsc->capabilities = htons(my_desc_capabilities);

        uint32_t rev_u32;
        sscanf(GIT_REV, "%8X", &rev_u32);
        dsc->codeRevision = htonl(rev_u32);
        dsc->comp_version = my_compatibility;
        dsc->descSqn = newDescriptionSqn( NULL, 1);

	return sizeof(struct dsc_msg_version);
}

STATIC_FUNC
int32_t process_dsc_tlv_version(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	assertion(-502321, IMPLIES(it->op == TLV_OP_NEW || it->op == TLV_OP_DEL, it->on));

	if (it->op != TLV_OP_TEST && it->op != TLV_OP_NEW)
		return it->f_dlen;

	DESC_SQN_T newSqn = ntohl(((struct dsc_msg_version*)it->f_data)->descSqn);

	if (it->dcOld && newSqn <= it->dcOld->descSqn)
		return TLV_RX_DATA_FAILURE;

	if (it->op == TLV_OP_NEW && it->on->neigh) {

		it->on->neigh->burstSqn = 0;

		if (it->dcOld && newSqn >= (it->dcOld->descSqn + DESC_SQN_REBOOT_ADDS))
			keyNode_schedLowerWeight(it->on->key, KCPromoted);
	}

	return sizeof(struct dsc_msg_version);
}





STATIC_FUNC
int32_t create_dsc_tlv_names(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	dbgf_all(DBGT_INFO, "%s", my_Hostname);

	int32_t nameLen = strlen(my_Hostname);

	if (nameLen<=0 || nameLen>=255 || nameLen >= MAX_HOSTNAME_LEN)
		return TLV_TX_DATA_IGNORED;

	if (nameLen > tx_iterator_cache_data_space_pref(it, 0, 0))
		return TLV_TX_DATA_FULL;

	struct description_msg_name *msg = (struct description_msg_name *) tx_iterator_cache_msg_ptr(it);

	msg->type = 0;
	msg->len = nameLen;
	memcpy(msg->name, my_Hostname, nameLen);

	return sizeof(struct description_msg_name) + nameLen;
}

STATIC_FUNC
int32_t process_dsc_tlv_names(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	char name[MAX_HOSTNAME_LEN];

	dbgf_all(DBGT_INFO, "op=%s", tlv_op_str(it->op) );

	struct description_msg_name *msg = (struct description_msg_name *) it->f_msg;

	if (msg->type != 0 || msg->len >= MAX_HOSTNAME_LEN)
		return TLV_RX_DATA_FAILURE;

	memcpy(name, msg->name, msg->len);
	name[msg->len]=0;

	if (validate_name_string(name, msg->len+1, NULL) == FAILURE)
		return TLV_RX_DATA_FAILURE;

	if (my_conformance_tolerance == 0 && it->f_dlen != (int) (sizeof(struct description_msg_name) +msg->len))
		return TLV_RX_DATA_FAILURE;

	if ((it->op==TLV_OP_NEW || it->op == TLV_OP_DEL)) {
		memset(it->on->k.hostname, 0, sizeof(it->on->k.hostname));
	}

	if (it->op == TLV_OP_NEW) {
		strcpy(it->on->k.hostname, name);
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
	DHASH_T *dhash = NULL;
	IDM_T wanted = NO;;

	if (memcmp((((uint8_t*) ttn->key.data) + sizeof(DESC_SQN_T)), ((uint8_t *) & ZERO_CYRYPSHA1), (sizeof(CRYPTSHA1_T) - sizeof(DESC_SQN_T)))) {

		struct dhash_node *dhn = avl_find_item(&dhash_tree, (dhash = (DHASH_T*) ttn->key.data));
		wanted = (dhn && !dhn->descContent && !dhn->rejected && dhn->neighRefs_tree.items);
	} else {
		DESC_SQN_T *descSqn = (DESC_SQN_T*) ttn->key.data;
		struct key_node *neighKn = keyNode_get(&ttn->key.f.groupId);
		assertion(-502322, IMPLIES(neighKn && neighKn->bookedState->i.c >= KCTracked, neighKn->content));
		wanted = (neighKn && neighKn->bookedState->i.c >= KCTracked && neighKn->content->f_body &&
			(neighKn->nextDesc ? neighKn->nextDesc->descSqn < *descSqn : (neighKn->currOrig ? neighKn->currOrig->descContent->descSqn < *descSqn : YES)));
	}

	assertion(-500855, (tx_iterator_cache_data_space_pref(it, 0, 0) >= ((int) (sizeof(struct msg_description_request)))));

	dbgf_track(DBGT_INFO, "%s dev=%s to khash=%s iterations=%d requesting dhash=%s send=%d",
		it->db->handls[ttn->key.f.type].name, ttn->key.f.p.dev->label_cfg.str, cryptShaAsString(&ttn->key.f.groupId),
		ttn->tx_iterations, cryptShaAsString(dhash), wanted);

	if (!wanted)
		return TLV_TX_DATA_DONE;

	msg->dhash = dhash ? *dhash : ZERO_CYRYPSHA1;

	if (hdr->msg == msg) {
		assertion(-500854, (is_zero(hdr, sizeof(*hdr))));
		hdr->dest_kHash = ttn->key.f.groupId;
	} else {
		assertion(-500871, (cryptShasEqual(&hdr->dest_kHash, &ttn->key.f.groupId)));
	}

	dbgf_track(DBGT_INFO, "created msg=%d", ((int) ((((char*) msg) - ((char*) hdr) - sizeof( *hdr)) / sizeof(*msg))));


	return sizeof(struct msg_description_request);
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

		dbgf_track(DBGT_INFO, "%s NB %s destination_dhash=%s requested_dhash=%s",
			it->f_handl->name, pb->i.llip_str, cryptShaAsString(&hdr->dest_kHash), cryptShaAsString(&msg->dhash));

		struct dhash_node *dhn = cryptShasEqual(&msg->dhash, (void*) &ZERO_CYRYPSHA1) ? myKey->currOrig->descContent->dhn : avl_find_item(&dhash_tree, &msg->dhash);

		if (dhn && dhn->descContent && dhn->descContent->orig && (((TIME_T) (bmx_time - dhn->referred_by_me_timestamp)) <= DEF_DESC0_REFERRED_TO) &&
			(pb->i.verifiedLink|| dhn == myKey->currOrig->descContent->dhn)) {

			dhn->referred_by_me_timestamp = bmx_time;

			schedule_tx_task(FRAME_TYPE_DESC_ADVS, NULL, NULL, pb->i.iif, dhn->descContent->desc_frame_len, &dhn->dhash, sizeof(DHASH_T));


		} else {
			dbgf_sys(DBGT_WARN, "UNVERIFIED neigh=%s llip=%s or UNKNOWN dhash=%s or OUTDATED dhn=%d dc=%d on=%d",
				pb->i.verifiedLink? cryptShaAsString(&pb->i.verifiedLink->k.linkDev->key.local->local_id) : NULL,
				pb->i.llip_str, cryptShaAsString(&msg->dhash), !!dhn, (dhn && dhn->descContent), (dhn && dhn->descContent && dhn->descContent->orig));
		}
	}

	return sizeof(struct msg_description_request);
}

STATIC_FUNC
int32_t tx_frame_description_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	DHASH_T *dhash = (DHASH_T*)it->ttn->key.data;
        struct dhash_node *dhn = avl_find_item(&dhash_tree, dhash);
	struct desc_content *dc = dhn ? dhn->descContent : NULL;

	if (!dc || !dc->orig) {
		dbgf_sys(DBGT_WARN, "%s dhash=%s!", dc ? "UnKnown" : "UnPromoted", cryptShaAsString(dhash));
                return TLV_TX_DATA_DONE;
        }

	assertion(-502060, (dc->desc_frame_len == it->ttn->frame_msgs_length));
	assertion(-502061, (dc->desc_frame_len <= tx_iterator_cache_data_space_max(it, 0, 0)));

        memcpy(tx_iterator_cache_msg_ptr(it), dc->desc_frame, dc->desc_frame_len);
	dc->dhn->referred_by_me_timestamp = bmx_time;
	dbgf_track(DBGT_INFO, "dhash=%s id=%s descr_size=%d",
		cryptShaAsString(dhash), cryptShaAsString(&dc->key->kHash), dc->desc_frame_len);

        return dc->desc_frame_len;
}

STATIC_FUNC
int32_t rx_frame_description_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	int32_t goto_error_code;
	struct key_node *kn;
	GLOBAL_ID_T *nodeId = NULL;
	struct dsc_msg_version *versMsg;
	DHASH_T dhash;
	struct dhash_node *dhn = NULL;
	struct desc_content *dc = NULL;

	cryptShaAtomic(it->f_data, it->f_dlen, &dhash);

	if (!(nodeId = get_desc_id(it->f_data, it->f_dlen, NULL, &versMsg)))
		goto_error(finish, TLV_RX_DATA_FAILURE);

	if (!(kn = keyNode_get(nodeId)) || (kn->bookedState->i.c < KCTracked) || !kn->content || !kn->content->f_body)
		goto_error(finish, it->f_dlen);

	if ((kn->nextDesc && kn->nextDesc->descSqn >= ntohl(versMsg->descSqn)) ||
		(kn->currOrig && kn->currOrig->descContent->descSqn >= ntohl(versMsg->descSqn)))
		goto_error(finish, it->f_dlen);

	if ((dhn = avl_find_item(&dhash_tree, &dhash)) && (dhn->descContent || dhn->rejected))
		goto_error(finish, it->f_dlen);

	if (!test_description_signature(it->f_data, it->f_dlen))
		goto_error(finish, TLV_RX_DATA_FAILURE);

	if ((dc = descContent_create(it->f_data, it->f_dlen, kn)) && !dc->unresolvedContentCounter)
		keyNode_updCredits(NULL, kn, NULL);

        goto_error(finish, it->f_dlen);

finish:
	if (dhn)
		dhn->referred_by_others_timestamp = bmx_time;

	dbgf_track(DBGT_INFO, "rcvd dhash=%s nodeId=%s via_dev=%s via_ip=%s dc=%d",
		memAsHexString(&dhash, sizeof(SHA1_T)), cryptShaAsString(nodeId),
		it->pb->i.iif->label_cfg.str, it->pb->i.llip_str, !!dc);

	return goto_error_code;
}

STATIC_FUNC
int32_t tx_msg_dhash_request(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct hdr_dhash_request *hdr = ((struct hdr_dhash_request*) tx_iterator_cache_hdr_ptr(it));
	struct msg_dhash_request *msg = ((struct msg_dhash_request*) tx_iterator_cache_msg_ptr(it));
	DHASH_T *dhash = ((DHASH_T*) it->ttn->key.data);
	struct dhash_node *dhn = avl_find_item(&dhash_tree, dhash);
	struct reference_node *ref;

	if (!dhn || dhn->rejected || !dhn->neighRefs_tree.items || ((ref = avl_find_item(&it->ttn->neigh->refsByDhash_tree, &dhn)) && ref->claimedKey))
		return TLV_TX_DATA_DONE;

	if (hdr->msg == msg) {
		assertion(-502287, (is_zero(hdr, sizeof(*hdr))));
		hdr->dest_nodeId = it->ttn->key.f.groupId;
	} else {
		assertion(-502288, (cryptShasEqual(&hdr->dest_nodeId, &it->ttn->key.f.groupId)));
	}

	msg->dhash = *dhash;

	return sizeof(struct msg_dhash_request);
}

STATIC_FUNC
int32_t rx_frame_dhash_request(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
	struct hdr_dhash_request *hdr = (struct hdr_dhash_request*) (it->f_data);
	struct msg_dhash_request *msg = (struct msg_dhash_request*) (it->f_msg);

	if (cryptShasEqual(&hdr->dest_nodeId, &myKey->kHash)) {

		for (; msg < &(hdr->msg[it->f_msgs_fixed]); msg++) {

			if ((avl_find(&dhash_tree, &msg->dhash)))
				schedule_tx_task(FRAME_TYPE_DHASH_ADV, NULL, NULL, nn->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &msg->dhash, sizeof(DHASH_T));
		}
	}
	return TLV_RX_DATA_PROCESSED;
}

STATIC_FUNC
void dhash_tree_maintain(void)
{
	struct dhash_node *dhn = NULL;
	DHASH_T dhash = ZERO_CYRYPSHA1;

	while ((dhn = avl_next_item(&dhash_tree, &dhash))) {

		dhash = dhn->dhash;

		if (dhn->descContent || dhn->rejected)
			continue;

		struct neigh_node *nn = NULL;
		struct reference_node *ref;

		while (dhn && (ref = avl_next_item(&dhn->neighRefs_tree, &nn))) {

			struct key_node *claimedKey = ref->claimedKey;
			nn = ref->neigh;

			assertion(-502500, IMPLIES(claimedKey, avl_find(&claimedKey->neighRefs_tree, &nn)));

			if (((AGGREG_SQN_T) ((nn->ogm_aggreg_max - ref->aggSqn)) >= nn->ogm_aggreg_size) && !claimedKey) {

				if (dhn->neighRefs_tree.items == 1)
					dhn = NULL;

				refNode_destroy(ref, NO);

			} else if (!claimedKey) {

				schedule_tx_task(FRAME_TYPE_DHASH_REQ, &nn->local_id, nn, nn->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &dhn->dhash, sizeof(dhn->dhash));

			} else if (claimedKey->content && !claimedKey->content->f_body) {

				assertion(-502323, (claimedKey->bookedState->i.c >= KCTracked));

				//schedule_tx_task(FRAME_TYPE_CONTENT_REQ, &nn->local_id, nn, nn->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &ck->kHash, sizeof(ck->kHash));

			} else if (claimedKey->content) {

				assertion(-502324, (claimedKey->bookedState->i.c >= KCTracked && claimedKey->content->f_body));

				schedule_tx_task(FRAME_TYPE_DESC_REQ, &nn->local_id, nn, nn->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &dhn->dhash, sizeof(dhn->dhash));
			}
		}
	}
}


STATIC_FUNC
int32_t tx_msg_dhash_adv(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct msg_dhash_adv *msg = ((struct msg_dhash_adv*) tx_iterator_cache_msg_ptr(it));
	struct dhash_node *dhn;

	if ((dhn = avl_find_item(&dhash_tree, ((DHASH_T*)it->ttn->key.data)))) {

		msg->dhash = dhn->dhash;

		if (dhn->descContent) {
			msg->descSqn = htonl(dhn->descContent->descSqn);
			msg->kHash = dhn->descContent->key->kHash;
		} //else: notify requesting node of stale dhash.

		return sizeof(struct msg_dhash_adv);
	}

	return TLV_TX_DATA_DONE;
}

STATIC_FUNC
int32_t rx_msg_dhash_adv(struct rx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	struct msg_dhash_adv *msg = (struct msg_dhash_adv*) (it->f_msg);
	struct neigh_node *nn = it->pb->i.verifiedLink->k.linkDev->key.local;
	AGGREG_SQN_T aggSqnInvalidMax = (nn->ogm_aggreg_max - AGGREG_SQN_CACHE_RANGE);
	struct reference_node *ref;

	if (!msg->descSqn) {

		if ((ref = avl_find_item(&nn->refsByDhash_tree, &msg->dhash)))
			ref->aggSqn = aggSqnInvalidMax; // do not try to resolve this anymore

	} else {
		refNode_update(nn, aggSqnInvalidMax, &msg->dhash, &msg->kHash, ntohl(msg->descSqn));
	}

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
	{ODI,0,ARG_UNSOLICITED_DESC_ADVS,  0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &unsolicitedDescAdvs,MIN_UNSOLICITED_DESC_ADVS,MAX_UNSOLICITED_DESC_ADVS,DEF_UNSOLICITED_DESC_ADVS,0,0,
			ARG_VALUE_FORM, NULL},
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

	static const struct field_format version_format[] = VERSION_MSG_FORMAT;
        handl.name = "DSC_VERSION";
	handl.alwaysMandatory = 1;
	handl.min_msg_size = sizeof (struct dsc_msg_version);
        handl.fixed_msg_size = 1;
	handl.dextReferencing = (int32_t*)&fref_never;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_version;
        handl.rx_frame_handler = process_dsc_tlv_version;
        handl.msg_format = version_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_VERSION, &handl);


	static const struct field_format names_format[] = DESCRIPTION_MSG_NAME_FORMAT;
        handl.name = "DSC_NAMES";
	handl.min_msg_size = sizeof(struct description_msg_name);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&fref_dflt;
	handl.dextCompression = (int32_t*)&dflt_fzip;
        handl.tx_frame_handler = create_dsc_tlv_names;
        handl.rx_frame_handler = process_dsc_tlv_names;
        handl.msg_format = names_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_NAMES, &handl);






	handl.name = "DESC_REQ";
	handl.rx_processUnVerifiedLink = 1;
	handl.data_header_size = sizeof( struct hdr_description_request);
	handl.min_msg_size = sizeof(struct msg_description_request);
	handl.fixed_msg_size = 1;
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


        handl.name = "DHASH_REQ";
        handl.data_header_size = sizeof( struct hdr_dhash_request);
        handl.min_msg_size = sizeof (struct msg_dhash_request);
        handl.fixed_msg_size = 1;
	handl.tx_packet_prepare_always = dhash_tree_maintain;
        handl.tx_msg_handler = tx_msg_dhash_request;
        handl.rx_frame_handler = rx_frame_dhash_request;
        register_frame_handler(packet_frame_db, FRAME_TYPE_DHASH_REQ, &handl);

        handl.name = "DHASH_ADV";
        handl.min_msg_size = sizeof (struct msg_dhash_adv);
        handl.fixed_msg_size = 1;
        handl.tx_msg_handler = tx_msg_dhash_adv;
        handl.rx_msg_handler = rx_msg_dhash_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_DHASH_ADV, &handl);


}


