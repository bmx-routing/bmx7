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
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/inotify.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "sec.h"
#include "metrics.h"
#include "msg.h"
//#include "schedule.h"
#include "tools.h"
#include "plugin.h"
#include "prof.h"
#include "ip.h"
#include "schedule.h"
#include "allocate.h"

//#include "ip.h"

#define CODE_CATEGORY_NAME "sec"


static int32_t descVerification = DEF_DESC_VERIFY;

static int32_t packetVerification = DEF_PACKET_VERIFY;


int32_t packetSignLifetime = DEF_PACKET_SIGN_LT;
int32_t packetSigning = DEF_PACKET_SIGN;

CRYPTKEY_T *my_PubKey = NULL;
CRYPTKEY_T *my_PktKey = NULL;

static char *trustedNodesDir = NULL;
static int trusted_ifd = -1;
static int trusted_iwd = -1;

static char *supportedNodesDir = NULL;
static int support_ifd = -1;
static int support_iwd = -1;

struct trust_node {
	GLOBAL_ID_T global_id;
	uint8_t depth;
	uint8_t max;
	uint8_t updated;
};

struct support_node {
	GLOBAL_ID_T global_id;
	uint8_t updated;
};

static AVL_TREE(trusted_nodes_tree, struct trust_node, global_id);
static AVL_TREE(supported_nodes_tree, struct support_node, global_id);



STATIC_FUNC
int create_packet_signature(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct frame_msg_signature *msg = NULL;
	static int32_t dataOffset = 0;

	dbgf_all(DBGT_INFO, "f_type=%s msg=%p frames_out_pos=%d dataOffset=%d", it->handl->name, (void*)msg, it->frames_out_pos, dataOffset  );

	if (it->frame_type==FRAME_TYPE_SIGNATURE_ADV) {

		msg = (struct frame_msg_signature*)tx_iterator_cache_msg_ptr(it);
		msg->dhash = self->dhn->dhash;
		msg->type = my_PktKey ? my_PktKey->rawKeyType : 0;

		if (msg->type) {
			msg = (struct frame_msg_signature*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));
			dataOffset = it->frames_out_pos + sizeof(struct tlv_hdr) + sizeof(struct frame_msg_signature) + my_PktKey->rawKeyLen;
			return sizeof(struct frame_msg_signature) + my_PktKey->rawKeyLen;
		} else {
			msg = NULL;
			dataOffset = 0;
			return sizeof(struct frame_msg_signature);
		}

	} else {
		assertion(-502099, (it->frame_type > FRAME_TYPE_LINK_VERSION));
		assertion(-502100, (msg && dataOffset));
		assertion(-502197, (my_PktKey && my_PktKey->rawKeyLen && my_PktKey->rawKeyType));
		assertion(-502101, (it->frames_out_pos > dataOffset));

		extern void tx_packet(void *devp);
		static struct prof_ctx prof = { .k ={ .func=(void(*)(void))create_packet_signature}, .name=__FUNCTION__, .parent_func=(void (*) (void))tx_packet};
		prof_start(&prof);

		int32_t dataLen = it->frames_out_pos - dataOffset;
		uint8_t *data = it->frames_out_ptr + dataOffset;

		CRYPTSHA1_T packetSha;
		cryptShaNew(&it->ttn->task.dev->if_llocal_addr->ip_addr, sizeof(IP6_T));
		cryptShaUpdate(data, dataLen);
		cryptShaFinal(&packetSha);

		cryptSign(&packetSha, msg->signature, my_PktKey->rawKeyLen, my_PktKey);

		dbgf_all(DBGT_INFO, "fixed RSA%d type=%d signature=%s of dataSha=%s over dataLen=%d data=%s (dataOffset=%d)",
			(my_PktKey->rawKeyLen * 8), msg->type, memAsHexString(msg->signature, my_PktKey->rawKeyLen),
			cryptShaAsString(&packetSha), dataLen, memAsHexString(data, dataLen), dataOffset);

		msg = NULL;
		dataOffset = 0;

		prof_stop(&prof);
		return TLV_TX_DATA_DONE;
	}
}

STATIC_FUNC
int process_packet_signature(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	struct frame_msg_signature *msg = (struct frame_msg_signature*)(it->frame_data);

	if (cryptShasEqual(&msg->dhash, &self->dhn->dhash))
		return TLV_RX_DATA_DONE;

	if (avl_find_item(&deprecated_dhash_tree, &msg->dhash))
		return TLV_RX_DATA_REJECTED;


	char *goto_error_code = NULL;
	static struct prof_ctx prof = { .k ={ .func=(void(*)(void))process_packet_signature}, .name=__FUNCTION__, .parent_func=(void (*) (void))rx_packet};
	struct dhash_node *dhn, *dhnOld;

	prof_start(&prof);

	if (((dhnOld = dhn = get_dhash_tree_node(&msg->dhash)) || (dhn = process_description(it->pb, &msg->dhash)) || !dhn) &&
		(dhn == NULL || dhn == UNRESOLVED_PTR || dhn == REJECTED_PTR || dhn == FAILURE_PTR)) {

		prof_stop(&prof);

		if (dhn==FAILURE_PTR)
			return TLV_RX_DATA_FAILURE;
		else
			return TLV_RX_DATA_DONE;
	}




	assertion(-502198, (dhn && dhn == get_dhash_tree_node(&msg->dhash)));

	int32_t sign_len = it->frame_data_length - sizeof(struct frame_msg_signature);
	uint8_t *data = it->frame_data + it->frame_data_length;
	int32_t dataLen = it->frames_length - it->frames_pos;
	CRYPTSHA1_T packetSha = {.h.u32={0}};
	CRYPTKEY_T *pkey = NULL;
	struct dsc_msg_pubkey *pkey_msg = NULL;

	if (msg->type ? (!cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != sign_len) : (sign_len != 0))
		goto_error( finish, "1");
	
	if ( dataLen <= (int)sizeof(struct tlv_hdr))
		goto_error( finish, "2");

	if ( sign_len > (packetVerification/8) )
		goto_error( finish, "3");


	if (dhn->local) {
		
		pkey = dhn->local->pktKey;
		
	} else if ((pkey_msg = dext_dptr(dhn->dext, BMX_DSC_TLV_PKT_PUBKEY))) {

		if (!(pkey = cryptPubKeyFromRaw(pkey_msg->key, cryptKeyLenByType(pkey_msg->type))))
			goto_error( finish, "4");
	}

	assertion(-502200, (!!pkey == !!dext_dptr(dhn->dext, BMX_DSC_TLV_PKT_PUBKEY)));
	assertion(-502201, IMPLIES(pkey, cryptPubKeyCheck(pkey) == SUCCESS));

	if ( !!pkey != !!msg->type )
		goto_error( finish, "5");

	if (pkey) {

		if ( pkey->rawKeyType != msg->type )
			goto_error( finish, "6");


		cryptShaNew(&it->pb->i.llip, sizeof(IPX_T));
		cryptShaUpdate(data, dataLen);
		cryptShaFinal(&packetSha);

		if (cryptVerify(msg->signature, sign_len, &packetSha, pkey) != SUCCESS)
			goto_error(finish, "8");
	}

	it->pb->i.verifiedLinkDhn = dhn;

finish:{
	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s verifying  data_len=%d data_sha=%s \n"
		"sign_len=%d signature=%s\n"
		"pkey_msg_type=%s pkey_msg_len=%d pkey_type=%s pkey=%s \n"
		"problem?=%s",
		goto_error_code?"Failed":"Succeeded", dataLen, cryptShaAsString(&packetSha),
		sign_len, memAsHexString(msg->signature, sign_len),
		pkey_msg ? cryptKeyTypeAsString(pkey_msg->type) : "---", pkey_msg ? cryptKeyLenByType(pkey_msg->type) : 0,
		pkey ? cryptKeyTypeAsString(pkey->rawKeyType) : "---", pkey ? memAsHexString(pkey->rawKey, pkey->rawKeyLen) : "---",
		goto_error_code);

	if (pkey && !(dhn->local && dhn->local->pktKey))
			cryptKeyFree(&pkey);

	if (!goto_error_code && !dhnOld && dhn) {
		if (desc_adv_tx_unsolicited)
			schedule_best_tp_links(NULL, FRAME_TYPE_DESC_ADVS, dhn->desc_frame_len, &dhn->dhash, sizeof(DHASH_T));

		if (dhash_adv_tx_unsolicited)
			schedule_best_tp_links(NULL, FRAME_TYPE_DHASH_ADV, SCHEDULE_MIN_MSG_SIZE, &dhn->myIID4orig, sizeof(IID_T));
	}

	if (goto_error_code && !dhnOld && dhn && !processDescriptionsViaUnverifiedLink) {
		IDM_T TODO_unknown_descriptions_packet_signature_must_be_checked_with_only_tested_process_description_to_not_leave_blocked_myIID4x;
		free_orig_node(dhn->on);
	}

	prof_stop(&prof);

	if (goto_error_code) {
		EXITERROR(-502202, (0));
		return TLV_RX_DATA_FAILURE;
	}

	return TLV_RX_DATA_PROCESSED;
}
}


STATIC_FUNC
int create_dsc_tlv_pubkey(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502097, (my_PubKey));

	struct dsc_msg_pubkey *msg = ((struct dsc_msg_pubkey*) tx_iterator_cache_msg_ptr(it));

	if ((int) (sizeof(struct dsc_msg_pubkey) +my_PubKey->rawKeyLen) > tx_iterator_cache_data_space_pref(it))
		return TLV_TX_DATA_FULL;

	msg->type = my_PubKey->rawKeyType;

	memcpy(msg->key, my_PubKey->rawKey, my_PubKey->rawKeyLen);
	dbgf_track(DBGT_INFO, "added description rsa description pubkey len=%d", my_PubKey->rawKeyLen);

	return(sizeof(struct dsc_msg_pubkey) +my_PubKey->rawKeyLen);
}

void update_dsc_tlv_pktkey(void*unused) {
	my_description_changed = YES;
}

STATIC_FUNC
int create_dsc_tlv_pktkey(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if (!packetSigning) {

		assertion(-502203, (!my_PktKey));

		return TLV_TX_DATA_DONE;
	}

	if ((int) (sizeof(struct dsc_msg_pubkey) + (packetSigning/8)) > tx_iterator_cache_data_space_pref(it))
		return TLV_TX_DATA_FULL;

	static struct prof_ctx prof = {.k={.func=(void(*)(void))create_dsc_tlv_pktkey}, .name=__FUNCTION__, .parent_func = (void (*) (void))update_my_description};
	prof_start(&prof);

	struct dsc_msg_pubkey *msg = ((struct dsc_msg_pubkey*) tx_iterator_cache_msg_ptr(it));

	uint8_t first = my_PktKey ? NO : YES;

	if (my_PktKey && packetSignLifetime) {

		assertion(-502204, (my_PktKey->endOfLife));

		// renew pktKey if approaching last quarter of pktKey lifetime:
		if (((TIME_SEC_T) ((5*(my_PktKey->endOfLife - (bmx_time_sec+1)))/4)) >= MAX_PACKET_SIGN_LT) {
			task_remove(update_dsc_tlv_pktkey, NULL);
			cryptKeyFree(&my_PktKey);
		}
	}

	if (!my_PktKey) {

		// set end-of-life for first packetKey to smaller random value >= 1:
		int32_t thisSignLifetime = first && packetSignLifetime ? (1+((int32_t)rand_num(packetSignLifetime-1))) : packetSignLifetime;

		my_PktKey = cryptKeyMake(packetSigning);

		my_PktKey->endOfLife = (thisSignLifetime ? bmx_time_sec + thisSignLifetime : 0);

		if (thisSignLifetime)
			task_register(thisSignLifetime*1000, update_dsc_tlv_pktkey, NULL, -300655);
	}
	assertion(-502097, (my_PktKey));


	msg->type = my_PktKey->rawKeyType;

	memcpy(msg->key, my_PktKey->rawKey, my_PktKey->rawKeyLen);

	dbgf_track(DBGT_INFO, "added description rsa packet pubkey len=%d", my_PktKey->rawKeyLen);
	
	prof_stop(&prof);
	
	return(sizeof(struct dsc_msg_pubkey) +my_PktKey->rawKeyLen);
}



STATIC_FUNC
int process_dsc_tlv_pubKey(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	char *goto_error_code = NULL;
	CRYPTKEY_T *pkey = NULL;
	int32_t key_len = -1;
	struct dsc_msg_pubkey *msg = NULL;

	if (it->op == TLV_OP_TEST ) {

		key_len = it->frame_data_length - sizeof(struct dsc_msg_pubkey);
		msg = (struct dsc_msg_pubkey*) (it->frame_data);

		if (!cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != key_len)
			goto_error(finish, "1");

		if (!(pkey = cryptPubKeyFromRaw(msg->key, key_len)))
			goto_error(finish, "2");

		if (cryptPubKeyCheck(pkey) != SUCCESS)
			goto_error(finish, "3");

	} else if (it->op == TLV_OP_DEL && it->frame_type == BMX_DSC_TLV_PKT_PUBKEY &&
		it->onOld && it->onOld->dhn && it->onOld->dhn->local) {

		if (it->onOld->dhn->local->pktKey)
			cryptKeyFree(&it->onOld->dhn->local->pktKey);

	} else if (it->op == TLV_OP_NEW && it->frame_type == BMX_DSC_TLV_PKT_PUBKEY &&
		it->onOld && it->onOld->dhn && it->onOld->dhn->local) {

		if (it->onOld->dhn->local->pktKey)
			cryptKeyFree(&it->onOld->dhn->local->pktKey);

		msg = dext_dptr(it->dhnNew->dext, BMX_DSC_TLV_PKT_PUBKEY);
		assertion(-502205, (msg));

		it->onOld->dhn->local->pktKey = cryptPubKeyFromRaw(msg->key, cryptKeyLenByType(msg->type));
		assertion(-502206, (it->onOld->dhn->local->pktKey && cryptPubKeyCheck(it->onOld->dhn->local->pktKey) == SUCCESS));
	}

finish: {
	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s %s verifying %s type=%s msg_key_len=%d == key_len=%d problem?=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", it->handl->name,
		cryptKeyTypeAsString(msg->type), cryptKeyLenByType(msg->type), key_len, goto_error_code);

	if (pkey)
		cryptKeyFree(&pkey);

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return it->frame_data_length;
}
}


STATIC_FUNC
int create_dsc_tlv_signature(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct dsc_msg_signature *desc_msg = NULL;
	static int32_t dataOffset = 0;

	if (it->frame_type==BMX_DSC_TLV_DSC_SIGNATURE) {

		assertion(-502098, (!desc_msg && !dataOffset));

		desc_msg = (struct dsc_msg_signature*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));

		dataOffset = it->frames_out_pos + sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) + my_PubKey->rawKeyLen;

		return sizeof(struct dsc_msg_signature) + my_PubKey->rawKeyLen;

	} else {
		assertion(-502099, (it->frame_type == BMX_DSC_TLV_SIGNATURE_DUMMY));
		assertion(-502100, (desc_msg && dataOffset));
		assertion(-502101, (it->frames_out_pos > dataOffset));
		assertion(-502102, (dext_dptr(it->dext, BMX_DSC_TLV_DSC_SIGNATURE)));

		int32_t dataLen = it->frames_out_pos - dataOffset;
		uint8_t *data = it->frames_out_ptr + dataOffset;

		CRYPTSHA1_T dataSha;
		cryptShaAtomic(data, dataLen, &dataSha);
		size_t keySpace = my_PubKey->rawKeyLen;

		struct dsc_msg_signature *dext_msg = dext_dptr(it->dext, BMX_DSC_TLV_DSC_SIGNATURE);

		dext_msg->type = my_PubKey->rawKeyType;
		cryptSign(&dataSha, dext_msg->signature, keySpace, NULL);

		desc_msg->type = dext_msg->type;
		memcpy( desc_msg->signature, dext_msg->signature, keySpace);

		dbgf_sys(DBGT_INFO, "fixed RSA%zd type=%d signature=%s of dataSha=%s over dataLen=%d data=%s (dataOffset=%d desc_frames_len=%d)",
			(keySpace*8), desc_msg->type, memAsHexString(desc_msg->signature, keySpace),
			cryptShaAsString(&dataSha), dataLen, memAsHexString(data, dataLen), dataOffset, it->frames_out_pos);

		desc_msg = NULL;
		dataOffset = 0;
		return TLV_TX_DATA_IGNORED;
	}
}

STATIC_FUNC
int process_dsc_tlv_signature(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if (it->frame_type == BMX_DSC_TLV_SIGNATURE_DUMMY)
		return TLV_RX_DATA_PROCESSED;

	assertion(-502104, (it->frame_data_length == it->frame_msgs_length && it->frame_data == it->msg));
	assertion(-502105, (it->dhnNew && it->dhnNew->dext));

	if (it->op != TLV_OP_TEST)
		return TLV_RX_DATA_PROCESSED;

	assertion(-500000, (process_signature(it->frame_data_length, (struct dsc_msg_signature *)it->frame_data, it->dhnNew->desc_frame,
		it->dhnNew->desc_frame_len, dext_dptr(it->dhnNew->dext, BMX_DSC_TLV_DSC_PUBKEY)) >= TLV_RX_DATA_PROCESSED));

	return TLV_RX_DATA_PROCESSED;
}

int process_signature(int32_t sigMsg_length, struct dsc_msg_signature *sigMsg, uint8_t *desc_frames, int32_t desc_frames_len, struct dsc_msg_pubkey *pkeyMsg)
{

	static struct prof_ctx prof = { .k ={ .func=(void(*)(void))process_dsc_tlv_signature}, .name=__FUNCTION__, .parent_func=(void (*) (void))rx_packet};
	prof_start(&prof);

	int32_t sign_len = sigMsg_length - sizeof(struct dsc_msg_signature);
	uint32_t dataOffset = (2*sizeof(struct tlv_hdr)) + sizeof(struct desc_hdr_rhash) + sizeof(struct desc_msg_rhash) + sigMsg_length;
	uint8_t *data = desc_frames + dataOffset;
	int32_t dataLen = desc_frames_len - dataOffset;
	CRYPTKEY_T *pkey = NULL;
	char *goto_error_code = NULL;
	CRYPTSHA1_T dataSha;

	if ( !cryptKeyTypeAsString(sigMsg->type) || cryptKeyLenByType(sigMsg->type) != sign_len )
		goto_error( finish, "1");

	if ( !pkeyMsg || !cryptKeyTypeAsString(pkeyMsg->type) || pkeyMsg->type != sigMsg->type)
		goto_error( finish, "2");

	if ( dataLen < (int)sizeof(struct dsc_msg_version))
		goto_error( finish, "3");

	if ( sign_len > (descVerification/8) )
		goto_error( finish, "4");

	cryptShaAtomic(data, dataLen, &dataSha);

	if (!(pkey = cryptPubKeyFromRaw(pkeyMsg->key, sign_len)))
		goto_error(finish, "5");

	assertion(-502207, (pkey && cryptPubKeyCheck(pkey) == SUCCESS));

	if (cryptVerify(sigMsg->signature, sign_len, &dataSha, pkey) != SUCCESS )
		goto_error( finish, "7");
	
	
finish: {

	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s verifying  desc_frame_len=%d dataOffset=%d data_len=%d data=%s data_sha=%s \n"
		"sign_len=%d signature=%s\n"
		"msg_pkey_type=%s msg_pkey_len=%d pkey_type=%s pkey=%s \n"
		"problem?=%s",
		goto_error_code?"Failed":"Succeeded", desc_frames_len, dataOffset, dataLen, memAsHexString(data, dataLen), cryptShaAsString(&dataSha),
		sign_len, memAsHexString(sigMsg->signature, sign_len),
		pkeyMsg ? cryptKeyTypeAsString(pkeyMsg->type) : "---", pkeyMsg ? cryptKeyLenByType(pkeyMsg->type) : 0,
		pkey ? cryptKeyTypeAsString(pkey->rawKeyType) : "---", pkey ? memAsHexString(pkey->rawKey, pkey->rawKeyLen) : "---",
		goto_error_code);

	if (pkey)
		cryptKeyFree(&pkey);

	prof_stop(&prof);

	ASSERTION(-500000, (!goto_error_code));
	
	if (goto_error_code && sign_len > (descVerification/8))
		return TLV_RX_DATA_REJECTED;
	else if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return TLV_RX_DATA_PROCESSED;
}
}

STATIC_FUNC
int create_dsc_tlv_sha(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct dsc_msg_sha *desc_msg = NULL;
	static uint32_t dataOffset = 0;

	if (it->frame_type==BMX_DSC_TLV_SHA) {
		assertion(-502106, (!desc_msg && !dataOffset));

		desc_msg = (struct dsc_msg_sha*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));
		dataOffset = it->dext->dlen + sizeof(struct tlv_hdr_virtual) + sizeof(struct dsc_msg_sha);

		return sizeof(struct dsc_msg_sha);

	} else {
		assertion(-502107, (it->frame_type == BMX_DSC_TLV_SHA_DUMMY));
		assertion(-502108, (desc_msg && dataOffset));
		assertion(-502109, (it->dext->dlen > dataOffset));
		assertion(-502110, (dext_dptr(it->dext, BMX_DSC_TLV_SHA)));

		// fix my dext:
		struct dsc_msg_sha *dext_msg = dext_dptr(it->dext, BMX_DSC_TLV_SHA);
		dext_msg->dataLen = htonl(it->dext->dlen - dataOffset);
		cryptShaAtomic(it->dext->data + dataOffset, it->dext->dlen - dataOffset, &dext_msg->dataSha);

		// fix my desc_frame:
		desc_msg->dataLen = dext_msg->dataLen;
		desc_msg->dataSha = dext_msg->dataSha;

		dbgf_sys(DBGT_INFO, "fixed description SHA dataLen=%d dataSha=%s data=%s",
			ntohl(desc_msg->dataLen), cryptShaAsString(&desc_msg->dataSha),
			memAsHexString(it->dext->data + dataOffset, it->dext->dlen - dataOffset));

		desc_msg = NULL;
		dataOffset = 0;
		return TLV_TX_DATA_IGNORED;
	}
}

STATIC_FUNC
int process_dsc_tlv_sha(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if (it->frame_type == BMX_DSC_TLV_SHA_DUMMY)
		return TLV_RX_DATA_PROCESSED;
	
	if (it->op != TLV_OP_TEST )
		return TLV_RX_DATA_PROCESSED;

	char *goto_error_code = NULL;
	struct dsc_msg_sha *msg = ((struct dsc_msg_sha*) it->frame_data);
	uint8_t *data = it->frames_in +  it->frames_pos;
	int32_t dataLen = it->frames_length - it->frames_pos;

	if (dataLen <= 0)
		goto_error(finish, "1");

	if( (int)ntohl(msg->dataLen) != dataLen )
		goto_error(finish, "1");

	SHA1_T dataSha;
	cryptShaAtomic(data, dataLen, &dataSha);
	
	if (!cryptShasEqual(&msg->dataSha, &dataSha))
		goto_error(finish, "2"); 

finish: {
	dbgf_sys(goto_error_code?DBGT_ERR:DBGT_INFO, 
		"%s %s verifying  expInLen=%d == msg.expInLen=%d expInSha=%s == msg.expInSha=%s  problem?=%s expIn=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", dataLen, ntohl(msg->dataLen),
		cryptShaAsString(&dataSha), cryptShaAsString(&msg->dataSha),
		goto_error_code, memAsHexString(data, dataLen) );

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return TLV_RX_DATA_PROCESSED;
}
}

int32_t rsa_load( char *tmp_path ) {

	// test with: ./bmx6 f=0 d=0 --keyDir=$(pwdd)/rsa-test/key.der


	dbgf_sys(DBGT_INFO, "testing %s=%s", ARG_KEY_PATH, tmp_path);

	if (!(my_PubKey = cryptKeyFromDer( tmp_path ))) {
		return FAILURE;
	}

	uint8_t in[] = "Everyone gets Friday off.";
	size_t inLen = strlen((char*)in);
	CRYPTSHA1_T inSha;
	uint8_t enc[CRYPT_RSA_MAX_LEN];
	size_t encLen = sizeof(enc);
	uint8_t plain[CRYPT_RSA_MAX_LEN];
	size_t plainLen = sizeof(plain);

	memset(plain, 0, sizeof(plain));

	if (cryptEncrypt(in, inLen, enc, &encLen, my_PubKey) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Encrypt inLen=%zd outLen=%zd inData=%s outData=%s",
			inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, encLen));
		return FAILURE;
	}

	if (cryptDecrypt(enc, encLen, plain, &plainLen) != SUCCESS ||
		inLen != plainLen || memcmp(plain, in, inLen)) {
		dbgf_sys(DBGT_ERR, "Failed Decrypt inLen=%zd outLen=%zd inData=%s outData=%s",
			encLen, plainLen, memAsHexString((char*)enc, encLen), memAsHexString((char*)plain, plainLen));
		return FAILURE;
	}


	cryptShaAtomic(in, inLen, &inSha);

	if (cryptSign(&inSha, enc, my_PubKey->rawKeyLen, NULL) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Sign inLen=%zd outLen=%zd inData=%s outData=%s",
			inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, my_PubKey->rawKeyLen));
		return FAILURE;
	}

	if (cryptVerify(enc, my_PubKey->rawKeyLen, &inSha, my_PubKey) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Verify inSha=%s", cryptShaAsString(&inSha));
		return FAILURE;
	}

	
	return SUCCESS;
}

STATIC_FUNC
int32_t opt_key_path(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	static uint8_t done = NO;
	static char key_path[MAX_PATH_SIZE] = DEF_KEY_PATH;
	char tmp_path[MAX_PATH_SIZE] = "";

	if ( (cmd == OPT_CHECK || cmd == OPT_SET_POST) && initializing && !done ) {

		if (cmd == OPT_CHECK) {
			if ( wordlen( patch->val )+1 >= MAX_PATH_SIZE  ||  patch->val[0] != '/' )
				return FAILURE;

			snprintf( tmp_path, wordlen(patch->val)+1, "%s", patch->val );
		} else {
			strcpy( tmp_path, key_path );
		}

		char *slash = strrchr(tmp_path, '/');
		if (slash) {
			*slash = 0;
			if ( check_dir( tmp_path, YES, YES) == FAILURE ) {
				dbgf_sys(DBGT_ERR, "dir=%s does not exist and can not be created!", tmp_path);
				return FAILURE;
			}
			*slash = '/';
		}

#ifndef NO_KEY_GEN
		if ( check_file( tmp_path, YES/*regular*/,YES/*read*/, NO/*writable*/, NO/*executable*/ ) == FAILURE ) {

			dbgf_sys(DBGT_ERR, "key=%s does not exist! Creating...", tmp_path);

			if (cryptKeyMakeDer(DEF_DESC_SIGN, tmp_path) != SUCCESS) {
				dbgf_sys(DBGT_ERR, "Failed creating new %d bit key to %s!", DEF_DESC_SIGN, tmp_path);
				return FAILURE;
			}
		}
#endif
		if (rsa_load( tmp_path ) == SUCCESS ) {
			dbgf_sys(DBGT_INFO, "Successfully initialized %d bit RSA key=%s !", (my_PubKey->rawKeyLen * 8), tmp_path);
		} else {
			dbgf_sys(DBGT_ERR, "key=%s invalid!", tmp_path);
			return FAILURE;
		}

		strcpy(key_path, tmp_path);

		init_self();

		done = YES;
        }

	return SUCCESS;
}

int32_t opt_packetSigning(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_CHECK || cmd == OPT_APPLY) {
		int32_t val = strtol(patch->val, NULL, 10);

		if (!strcmp(opt->name, ARG_PACKET_SIGN)) {

			if (val!=0 && ((val%8) || cryptKeyTypeByLen(val/8) == FAILURE))
				return FAILURE;

			if ( cmd == OPT_APPLY )
				my_description_changed = YES;

			task_remove(update_dsc_tlv_pktkey, NULL);
			cryptKeyFree(&my_PktKey);



		} else if (!strcmp(opt->name, ARG_PACKET_SIGN_LT)) {

			if (val!=0 && (val<MIN_PACKET_SIGN_LT || val > (int32_t)MAX_PACKET_SIGN_LT))
				return FAILURE;

			if ( cmd == OPT_APPLY ){

				if (!val) {
					if (my_PktKey)
						my_PktKey->endOfLife = 0;
				} else {
					task_remove(update_dsc_tlv_pktkey, NULL);
					cryptKeyFree(&my_PktKey);
					my_description_changed = YES;
				}
			}
		} else
			return FAILURE;
	}


	return SUCCESS;
}



static struct neigh_node *internalNeighId_array[LOCALS_MAX];
static int16_t internalNeighId_max = -1;
static uint8_t internalNeighId_u32s = 0;

IDM_T setted_pubkey(struct dhash_node *dhn, uint8_t type, GLOBAL_ID_T *globalId)
{

	struct dsc_msg_trust *setList = dhn ? dext_dptr(dhn->dext, BMX_DSC_TLV_TRUSTS) : NULL;
	uint32_t m =0, msgs = dhn ? (dhn->dext->dtd[BMX_DSC_TLV_TRUSTS].len / sizeof(struct dsc_msg_trust)) : 0;

	if (setList) {
		for (m = 0; m < msgs; m++) {

			if (cryptShasEqual(globalId, &setList[m].globalId))
				return 1;
		}
		return 0;
	} 
	return -1;
}

STATIC_FUNC
void update_neighTrust(struct orig_node *on, struct dhash_node *dhnNew, struct neigh_node *nn)
{

	if (setted_pubkey(dhnNew, BMX_DSC_TLV_TRUSTS, &nn->local_id)) {

		bit_set((uint8_t*) on->trustedNeighsBitArray, internalNeighId_u32s * 32, nn->internalNeighId, 1);

	} else {

		if (bit_get((uint8_t*) on->trustedNeighsBitArray, internalNeighId_u32s * 32, nn->internalNeighId)) {

			bit_set((uint8_t*) on->trustedNeighsBitArray, internalNeighId_u32s * 32, nn->internalNeighId, 0);

			purge_orig_router(on, nn, NULL, NO);
		}
	}
}

uint32_t *init_neighTrust(struct orig_node *on) {

	on->trustedNeighsBitArray = debugMallocReset(internalNeighId_u32s*4, -300654);

	struct avl_node *an = NULL;
	struct neigh_node *nn;

	while ((nn = avl_iterate_item(&local_tree, &an))) {
		update_neighTrust(on, NULL, nn);
	}

	return on->trustedNeighsBitArray;
}

IDM_T verify_neighTrust(struct orig_node *on, struct neigh_node *neigh){

	if (bit_get((uint8_t*)on->trustedNeighsBitArray, (internalNeighId_u32s * 32), neigh->internalNeighId ))
		return SUCCESS;
	else
		return FAILURE;
}

OGM_DEST_T allocate_internalNeighId(struct neigh_node *nn) {

	int16_t ini;
	struct orig_node *on;
	struct avl_node *an = NULL;

	for (ini=0; ini<LOCALS_MAX && internalNeighId_array[ini]; ini++);

	assertion(-502228, (ini < LOCALS_MAX && ini <= (int)local_tree.items));
	internalNeighId_array[ini] = nn;
	nn->internalNeighId = ini;

	if (ini > internalNeighId_max) {

		uint8_t u32s_needed = (((ini+1)/32) + (!!((ini+1)%32)));
		uint8_t u32s_allocated = internalNeighId_u32s;

		internalNeighId_u32s = u32s_needed;
		internalNeighId_max = ini;

		if (u32s_needed > u32s_allocated) {

			assertion(-502229, (u32s_needed == u32s_allocated + 1));
			
			for (an = NULL; (on = avl_iterate_item(&orig_tree, &an));) {
				on->trustedNeighsBitArray = debugRealloc(on->trustedNeighsBitArray, (u32s_needed * 4), -300656);
				on->trustedNeighsBitArray[u32s_allocated] = 0;
			}

		}

	}

	for (an = NULL; (on = avl_iterate_item(&orig_tree, &an));)
		update_neighTrust(on, on->dhn, nn);


	return ini;
}


void free_internalNeighId(OGM_DEST_T ini) {


	struct orig_node *on;
	struct avl_node *an = NULL;

	while ((on = avl_iterate_item(&orig_tree, &an)))
		bit_set((uint8_t*)on->trustedNeighsBitArray, internalNeighId_u32s * 32, ini, 0);

	internalNeighId_array[ini] = NULL;

}



STATIC_FUNC
int process_dsc_tlv_trusts(struct rx_frame_iterator *it)
{
	if ((it->op == TLV_OP_NEW || it->op == TLV_OP_DEL) && 
		(!it->onOld->dhn || !it->onOld->dhn->dext || desc_frame_changed( it, it->frame_type ))) {

		struct avl_node *an = NULL;
		struct neigh_node *nn;

		while ((nn = avl_iterate_item(&local_tree, &an))) {
			update_neighTrust(it->onOld, it->dhnNew, nn);
		}
	}


	return TLV_RX_DATA_PROCESSED;
}


STATIC_FUNC
int create_dsc_tlv_trusts(struct tx_frame_iterator *it)
{
        struct avl_node *an = NULL;
        struct trust_node *tn;
        struct dsc_msg_trust *msg = (struct dsc_msg_trust *)tx_iterator_cache_msg_ptr(it);
        int32_t max_size = tx_iterator_cache_data_space_pref(it);
        int pos = 0;

	if (trustedNodesDir) {

		while ((tn = avl_iterate_item(&trusted_nodes_tree, &an))) {

			if (pos + (int) sizeof(struct dsc_msg_trust) > max_size) {
				dbgf_sys(DBGT_ERR, "Failed adding %s=%s", it->handl->name, cryptShaAsString(&tn->global_id));
				return TLV_TX_DATA_FULL;
			}

			msg->globalId = tn->global_id;
			msg++;
			pos += sizeof(struct dsc_msg_trust);

			dbgf_sys(DBGT_ERR, "adding %s=%s", it->handl->name, cryptShaAsString(&tn->global_id));
		}

		return pos;
	}

        return TLV_TX_DATA_IGNORED;
}

IDM_T supported_pubkey( CRYPTSHA1_T *pkhash ) {
	return supportedNodesDir ? (avl_find_item(&supported_nodes_tree, pkhash) ? YES : NO) : -1;
}

STATIC_FUNC
void check_supported_nodes(void *unused)
{

	DIR *dir;

	if (support_ifd == -1) {
                task_remove(check_supported_nodes, NULL);
                task_register(DEF_TRUST_DIR_POLLING_INTERVAL, check_supported_nodes, NULL, -300000);
        }

	if ((dir = opendir(supportedNodesDir))) {

		struct dirent *dirEntry;
		struct support_node *sn;
		GLOBAL_ID_T globalId;

		while ((dirEntry = readdir(dir)) != NULL) {

			char globalIdString[(2*sizeof(GLOBAL_ID_T))+1] = {0};

			if (
				(strlen(dirEntry->d_name) >= (2*sizeof(GLOBAL_ID_T))) &&
				(strncpy(globalIdString, dirEntry->d_name, 2*sizeof(GLOBAL_ID_T))) &&
				(hexStrToMem(globalIdString, (uint8_t*)&globalId, sizeof(GLOBAL_ID_T)) == SUCCESS)
				) {

				if ((sn = avl_find_item(&supported_nodes_tree, &globalId))) {

					dbgf(sn->updated ? DBGL_SYS : DBGL_ALL, sn->updated ? DBGT_ERR : DBGT_INFO,
						"file=%s prefix found %d times!",dirEntry->d_name, sn->updated);

				} else {
					sn = debugMallocReset(sizeof(struct support_node), -300000);
					sn->global_id = globalId;
					avl_insert(&supported_nodes_tree, sn, -300000);
					dbgf_sys(DBGT_INFO, "file=%s defines new nodeId=%s!",
						dirEntry->d_name, cryptShaAsString(&globalId));

					purge_deprecated_globalId_tree(&globalId);
				}

				sn->updated++;

			} else {
				dbgf_sys(DBGT_ERR, "file=%s... has illegal format!",dirEntry->d_name);
			}
		}
		closedir(dir);

		memset(&globalId, 0, sizeof(globalId));
		while ((sn = avl_next_item(&supported_nodes_tree, &globalId))) {
			struct orig_node *on;
			globalId = sn->global_id;
			if (!sn->updated && !cryptShasEqual(&sn->global_id, &self->nodeId)) {

				avl_remove(&supported_nodes_tree, &globalId, -300000);

				purge_cached_descriptions(NULL, &globalId, NO);

				if ((on = avl_find_item(&orig_tree, &globalId)))
					free_orig_node(on);

				debugFree(sn, -300000);
			} else {
				sn->updated = 0;
			}
		}

	} else {
		cleanup_all(-500000);
	}
}

STATIC_FUNC
void check_trusted_nodes(void *unused)
{

	DIR *dir;

	if (trusted_ifd == -1) {
                task_remove(check_trusted_nodes, NULL);
                task_register(DEF_TRUST_DIR_POLLING_INTERVAL, check_trusted_nodes, NULL, -300657);
        }

	if ((dir = opendir(trustedNodesDir))) {

		struct dirent *dirEntry;
		struct trust_node *tn;
		int8_t changed = NO;
		GLOBAL_ID_T globalId;

		while ((dirEntry = readdir(dir)) != NULL) {
			
			char globalIdString[(2*sizeof(GLOBAL_ID_T))+1] = {0};

			if (
				(strlen(dirEntry->d_name) >= (2*sizeof(GLOBAL_ID_T))) &&
				(strncpy(globalIdString, dirEntry->d_name, 2*sizeof(GLOBAL_ID_T))) &&
				(hexStrToMem(globalIdString, (uint8_t*)&globalId, sizeof(GLOBAL_ID_T)) == SUCCESS)
				) {

				if ((tn = avl_find_item(&trusted_nodes_tree, &globalId))) {

					dbgf(tn->updated ? DBGL_SYS : DBGL_ALL, tn->updated ? DBGT_ERR : DBGT_INFO,
						"file=%s prefix found %d times!",dirEntry->d_name, tn->updated);

				} else {
					tn = debugMallocReset(sizeof(struct trust_node), -300658);
					tn->global_id = globalId;
					changed = YES;
					avl_insert(&trusted_nodes_tree, tn, -300659);
					dbgf_sys(DBGT_INFO, "file=%s defines new nodeId=%s!",
						dirEntry->d_name, cryptShaAsString(&globalId));
				}

				tn->updated++;

			} else {
				dbgf_sys(DBGT_ERR, "file=%s... has illegal format!",dirEntry->d_name);
			}
		}
		closedir(dir);

		memset(&globalId, 0, sizeof(globalId));
		while ((tn = avl_next_item(&trusted_nodes_tree, &globalId))) {
			globalId = tn->global_id;
			if (!tn->updated && !cryptShasEqual(&tn->global_id, &self->nodeId)) {
				changed = YES;
				avl_remove(&trusted_nodes_tree, &globalId, -300660);
				debugFree(tn, -300000);
			} else {
				tn->updated = 0;
			}
		}


		if (changed) {
			my_description_changed = YES;
			changed = NO;
		}


	} else {
		cleanup_all(-502230);
	}
}

STATIC_FUNC
void inotify_event_hook(int fd)
{
        TRACE_FUNCTION_CALL;

	dbgf_sys(DBGT_INFO, "detected changes in directory: %s", (fd == trusted_ifd) ? trustedNodesDir : supportedNodesDir);

        assertion(-501278, (fd > -1 && (fd == trusted_ifd || fd == support_ifd)));

        int ilen = 1024;
        char *ibuff = debugMalloc(ilen, -300375);
        int rcvd;
        int processed = 0;

        while ((rcvd = read(fd, ibuff, ilen)) == 0 || rcvd == EINVAL) {

                ibuff = debugRealloc(ibuff, (ilen = ilen * 2), -300376);
                assertion(-501279, (ilen <= (1024 * 16)));
        }

        if (rcvd > 0) {

                while (processed < rcvd) {

                        struct inotify_event *ievent = (struct inotify_event *) &ibuff[processed];

                        processed += (sizeof (struct inotify_event) +ievent->len);

                        if (ievent->mask & (IN_DELETE_SELF)) {
				dbgf_sys(DBGT_ERR, "directory %s has been removed \n", (fd == trusted_ifd) ? trustedNodesDir : supportedNodesDir);
                                cleanup_all(-500000);
                        }
                }

        } else {
                dbgf_sys(DBGT_ERR, "read()=%d: %s \n", rcvd, strerror(errno));
        }

        debugFree(ibuff, -300377);

	if (fd == trusted_ifd)
		check_trusted_nodes(NULL);
	else
		check_supported_nodes(NULL);
}


STATIC_FUNC
void cleanup_trusted_nodes(void)
{

	if (trusted_ifd > -1) {

		if (trusted_iwd > -1) {
			inotify_rm_watch(trusted_ifd, trusted_iwd);
			trusted_iwd = -1;
		}

		set_fd_hook(trusted_ifd, inotify_event_hook, DEL);

		close(trusted_ifd);
		trusted_ifd = -1;
	} else {
		task_remove(check_trusted_nodes, NULL);
	}

	while (trusted_nodes_tree.items)
		debugFree(avl_remove_first_item(&trusted_nodes_tree, -300661), -300664);

	trustedNodesDir = NULL;
}


STATIC_FUNC
int32_t opt_trusted_node_dir(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

        if (cmd == OPT_CHECK && check_dir(patch->val, NO/*create*/, NO/*writable*/) == FAILURE)
			return FAILURE;
        
        if (cmd == OPT_APPLY) {

		if (patch->diff == DEL || (patch->diff == ADD && trustedNodesDir))
			cleanup_trusted_nodes();


		if (patch->diff == ADD) {

			assertion(-501286, (patch->val));

			trustedNodesDir = patch->val;

			if ((trusted_ifd = inotify_init()) < 0) {

				dbg_sys(DBGT_WARN, "failed init inotify socket: %s! Using %d ms polling instead! You should enable inotify support in your kernel!",
					strerror(errno), DEF_TRUST_DIR_POLLING_INTERVAL);
				trusted_ifd = -1;

			} else if (fcntl(trusted_ifd, F_SETFL, O_NONBLOCK) < 0) {

				dbgf_sys(DBGT_ERR, "failed setting inotify non-blocking: %s", strerror(errno));
				return FAILURE;

			} else if ((trusted_iwd = inotify_add_watch(trusted_ifd, trustedNodesDir,
				IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO)) < 0) {

				dbgf_sys(DBGT_ERR, "failed adding watch for dir=%s: %s \n", trustedNodesDir, strerror(errno));
				return FAILURE;

			} else {

				set_fd_hook(trusted_ifd, inotify_event_hook, ADD);
			}

			struct trust_node *tn = debugMallocReset(sizeof(struct trust_node), -300662);
			tn->global_id = self->nodeId;
			avl_insert(&trusted_nodes_tree, tn, -300663);

			check_trusted_nodes(NULL);
		}

		my_description_changed = YES;
        }


        return SUCCESS;
}


STATIC_FUNC
void cleanup_supported_nodes(void)
{

	if (support_ifd > -1) {

		if (support_iwd > -1) {
			inotify_rm_watch(support_ifd, support_iwd);
			support_iwd = -1;
		}

		set_fd_hook(support_ifd, inotify_event_hook, DEL);

		close(support_ifd);
		support_ifd = -1;
	} else {
		task_remove(check_supported_nodes, NULL);
	}

	while (supported_nodes_tree.items)
		debugFree(avl_remove_first_item(&supported_nodes_tree, -300000), -300000);

	supportedNodesDir = NULL;
}


STATIC_FUNC
int32_t opt_supported_node_dir(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

        if (cmd == OPT_CHECK && check_dir(patch->val, NO/*create*/, NO/*writable*/) == FAILURE)
			return FAILURE;

        if (cmd == OPT_APPLY) {

		if (patch->diff == DEL || (patch->diff == ADD && supportedNodesDir))
			cleanup_supported_nodes();


		if (patch->diff == ADD) {

			assertion(-501286, (patch->val));

			supportedNodesDir = patch->val;

			if ((support_ifd = inotify_init()) < 0) {

				dbg_sys(DBGT_WARN, "failed init inotify socket: %s! Using %d ms polling instead! You should enable inotify support in your kernel!",
					strerror(errno), DEF_TRUST_DIR_POLLING_INTERVAL);
				support_ifd = -1;

			} else if (fcntl(support_ifd, F_SETFL, O_NONBLOCK) < 0) {

				dbgf_sys(DBGT_ERR, "failed setting inotify non-blocking: %s", strerror(errno));
				return FAILURE;

			} else if ((support_iwd = inotify_add_watch(support_ifd, supportedNodesDir,
				IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO)) < 0) {

				dbgf_sys(DBGT_ERR, "failed adding watch for dir=%s: %s \n", supportedNodesDir, strerror(errno));
				return FAILURE;

			} else {

				set_fd_hook(support_ifd, inotify_event_hook, ADD);
			}

			struct support_node *sn = debugMallocReset(sizeof(struct support_node), -300662);
			sn->global_id = self->nodeId;
			avl_insert(&supported_nodes_tree, sn, -300663);

			check_supported_nodes(NULL);
		}
        }


        return SUCCESS;
}



STATIC_FUNC
struct opt_type sec_options[]=
{
//order must be before ARG_HOSTNAME (which initializes self via init_self):
	{ODI,0,ARG_KEY_PATH,		0,  4,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_KEY_PATH,	opt_key_path,
			ARG_DIR_FORM,	"set path to rsa der-encoded private key file (used as permanent public ID"},
	{ODI,0,ARG_DESC_VERIFY,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &descVerification,MIN_DESC_VERIFY,MAX_DESC_VERIFY,DEF_DESC_VERIFY,0, opt_purge_originators,
			ARG_VALUE_FORM, HLP_DESC_VERIFY},
	{ODI,0,ARG_PACKET_SIGN,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &packetSigning,  MIN_PACKET_SIGN,MAX_PACKET_SIGN,DEF_PACKET_SIGN,0, opt_packetSigning,
			ARG_VALUE_FORM, HLP_PACKET_VERIFY},
	{ODI,0,ARG_PACKET_SIGN_LT,      0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &packetSignLifetime,0,MAX_PACKET_SIGN_LT,DEF_PACKET_SIGN_LT,0, opt_packetSigning,
			ARG_VALUE_FORM, HLP_PACKET_VERIFY},
	{ODI,0,ARG_TRUSTED_NODES_DIR,   0,  9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_TRUSTED_NODES_DIR, opt_trusted_node_dir,
			ARG_DIR_FORM,"directory with global-id hashes of this node's trusted other nodes"},
	{ODI,0,ARG_SUPPORTED_NODES_DIR, 0,  9,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_SUPPORTED_NODES_DIR, opt_supported_node_dir,
			ARG_DIR_FORM,"directory with global-id hashes of this node's supported other nodes"},

};


void init_sec( void )
{
	register_options_array( sec_options, sizeof( sec_options ), CODE_CATEGORY_NAME );

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));

	static const struct field_format frame_signature_format[] = FRAME_MSG_SIGNATURE_FORMAT;
        handl.name = "SIGNATURE_ADV";
	handl.positionMandatory = 1;
	handl.rx_processUnVerifiedLink = 1;
	handl.min_msg_size = sizeof(struct frame_msg_signature);
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_packet_signature;
        handl.rx_frame_handler = process_packet_signature;
	handl.msg_format = frame_signature_format;
        register_frame_handler(packet_frame_db, FRAME_TYPE_SIGNATURE_ADV, &handl);


	static const struct field_format pubkey_format[] = DESCRIPTION_MSG_PUBKEY_FORMAT;
        handl.name = "DSC_PUBKEY";
	handl.alwaysMandatory = 1;
        handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&always_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_pubkey;
        handl.rx_frame_handler = process_dsc_tlv_pubKey;
	handl.msg_format = pubkey_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_DSC_PUBKEY, &handl);

	static const struct field_format dsc_signature_format[] = DESCRIPTION_MSG_SIGNATURE_FORMAT;
        handl.name = "DSC_SIGNATURE";
	handl.alwaysMandatory = 1;
	handl.min_msg_size = sizeof(struct dsc_msg_signature);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_signature;
        handl.rx_frame_handler = process_dsc_tlv_signature;
	handl.msg_format = dsc_signature_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_DSC_SIGNATURE, &handl);

        handl.name = "DSC_SIGNATURE_DUMMY";
	handl.rx_processUnVerifiedLink = 1;
        handl.tx_frame_handler = create_dsc_tlv_signature;
        handl.rx_frame_handler = process_dsc_tlv_signature;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SIGNATURE_DUMMY, &handl);

	static const struct field_format sha_format[] = DESCRIPTION_MSG_SHA_FORMAT;
        handl.name = "DSC_SHA";
        handl.min_msg_size = sizeof(struct dsc_msg_sha);
        handl.fixed_msg_size = 1;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_sha;
        handl.rx_frame_handler = process_dsc_tlv_sha;
	handl.msg_format = sha_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SHA, &handl);

        handl.name = "DSC_SHA_DUMMY";
        handl.min_msg_size = 0;
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_dsc_tlv_sha;
        handl.rx_frame_handler = process_dsc_tlv_sha;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SHA_DUMMY, &handl);


        handl.name = "DSC_PKT_PUBKEY";
	handl.alwaysMandatory = 0;
        handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&always_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_pktkey;
        handl.rx_frame_handler = process_dsc_tlv_pubKey;
	handl.msg_format = pubkey_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_PKT_PUBKEY, &handl);

	static const struct field_format trust_format[] = DESCRIPTION_MSG_TRUST_FORMAT;
        handl.name = "DSC_TRUSTS";
	handl.alwaysMandatory = 0;
        handl.min_msg_size = sizeof(struct dsc_msg_trust);
        handl.fixed_msg_size = 1;
	handl.dextReferencing = (int32_t*)&always_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_trusts;
        handl.rx_frame_handler = process_dsc_tlv_trusts;
	handl.msg_format = trust_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_TRUSTS, &handl);


}

void cleanup_sec( void )
{
        cryptKeyFree(&my_PubKey);

	if (my_PktKey) {
		task_remove(update_dsc_tlv_pktkey, NULL);
		cryptKeyFree(&my_PktKey);
	}

	cleanup_trusted_nodes();
	cleanup_supported_nodes();
}
