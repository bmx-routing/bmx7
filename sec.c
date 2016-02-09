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
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "link.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
//#include "schedule.h"
#include "tools.h"
#include "plugin.h"
#include "prof.h"
#include "ip.h"
#include "schedule.h"
#include "allocate.h"
#include "iptools.h"

//#include "ip.h"

#define CODE_CATEGORY_NAME "sec"


static int32_t nodeSignMax = DEF_NODE_SIGN_MAX;

static int32_t linkSignMax = DEF_LINK_SIGN_MAX;
static int32_t linkSignMin = DEF_LINK_SIGN_MIN;

static int32_t linkVerify = DEF_LINK_VERIFY;
static int32_t nodeVerify = DEF_NODE_VERIFY;


int32_t linkSignLifetime = DEF_LINK_SIGN_LT;
int32_t linkSignLen = DEF_LINK_SIGN_LEN;

CRYPTKEY_T *my_NodeKey = NULL;
CRYPTKEY_T *my_LinkKey = NULL;


AVL_TREE(dirWatch_tree, struct DirWatch, ifd);

static struct DirWatch *trustedDirWatch = NULL;
static struct DirWatch *supportDirWatch = NULL;

GLOBAL_ID_T *get_desc_id(uint8_t *desc_adv, uint32_t desc_len, struct dsc_msg_signature **signpp, struct dsc_msg_version **verspp)
{
	if (!desc_adv || desc_len < packet_frame_db->handls[FRAME_TYPE_DESC_ADVS].min_msg_size || desc_len > MAX_DESC_ROOT_SIZE)
		return NULL;

	GLOBAL_ID_T *id = NULL;
	struct dsc_msg_signature *signMsg = NULL;
	struct dsc_msg_version *versMsg = NULL;
	uint32_t p=0, i=0;

	for (; (p + sizeof(struct tlv_hdr)) < desc_len; i++) {

		struct tlv_hdr tlvHdr = {.u.u16 = ntohs(((struct tlv_hdr*) (desc_adv + p))->u.u16)};

		if (p + tlvHdr.u.tlv.length > desc_len)
			return NULL;

		if (i == 0 && tlvHdr.u.tlv.type == BMX_DSC_TLV_CONTENT_HASH &&
			tlvHdr.u.tlv.length == (sizeof(struct tlv_hdr) + sizeof(struct dsc_hdr_chash))) {

			struct dsc_hdr_chash chashHdr = *((struct dsc_hdr_chash*) (desc_adv + sizeof(struct tlv_hdr)));
			chashHdr.u.u32 = ntohl(chashHdr.u.u32);

			if (chashHdr.u.i.gzip || chashHdr.u.i.maxNesting != 1 || chashHdr.u.i.expanded_type != BMX_DSC_TLV_NODE_PUBKEY)
				return NULL;

			id = &(((struct dsc_hdr_chash*) (desc_adv + p + sizeof(struct tlv_hdr)))->expanded_chash);


		} else if (i==1 && tlvHdr.u.tlv.type == BMX_DSC_TLV_DSC_SIGNATURE &&
			tlvHdr.u.tlv.length > (sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature))) {

			signMsg = (struct dsc_msg_signature*) (desc_adv + p + sizeof(struct tlv_hdr));
			if (!(cryptKeyTypeAsString(signMsg->type) &&
				tlvHdr.u.tlv.length == sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) +cryptKeyLenByType(signMsg->type)))
				return NULL;

		} else if (i==2 && tlvHdr.u.tlv.type == BMX_DSC_TLV_VERSION &&
			tlvHdr.u.tlv.length == (sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_version))) {

			versMsg = (struct dsc_msg_version*) (desc_adv + p + sizeof(struct tlv_hdr));

			if (validate_param(versMsg->comp_version, (my_compatibility-(my_conformance_tolerance?0:1)), (my_compatibility+(my_conformance_tolerance?0:1)), "compatibility version"))
				return NULL;



		} else if (i < 3) {
			return NULL;
		}

		p = p + tlvHdr.u.tlv.length;
	}

	if (p!=desc_len || !id  || !signMsg || !versMsg)
		return NULL;



	if (signpp)
		(*signpp) = signMsg;
	if (verspp)
		(*verspp) = versMsg;

	return id;
}



STATIC_FUNC
int create_packet_signature(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	static struct frame_hdr_signature *hdr = NULL;
	static int32_t dataOffset = 0;

	dbgf_all(DBGT_INFO, "f_type=%s hdr=%p frames_out_pos=%d dataOffset=%d", it->handl->name, (void*) hdr, it->frames_out_pos, dataOffset);

	if (it->frame_type == FRAME_TYPE_SIGNATURE_ADV) {

		hdr = (struct frame_hdr_signature*) tx_iterator_cache_hdr_ptr(it);
		hdr->sqn.u32.burstSqn = htonl(myBurstSqn);
		hdr->sqn.u32.descSqn = htonl(myKey->currOrig->descContent->descSqn);
		hdr->devIdx = htons(it->ttn->key.f.p.dev->llipKey.devIdx);
		
		assertion(-502445, (be64toh(hdr->sqn.u64) == (((uint64_t) myKey->currOrig->descContent->descSqn) << 32) + myBurstSqn));


		struct frame_msg_signature *msg = (struct frame_msg_signature *) &(hdr[1]);
		assertion(-502517, ((uint8_t*)msg == tx_iterator_cache_msg_ptr(it)));


		msg->type = (my_LinkKey && it->ttn->key.f.p.dev->strictSignatures >= OPT_DEV_SIGNATURES_TX) ? my_LinkKey->rawKeyType : 0;

		if (msg->type) {
			//during later signature calculation msg is not hold in iterator cache anymore:
			hdr = (struct frame_hdr_signature*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));
			dataOffset = it->frames_out_pos + sizeof(struct tlv_hdr) + sizeof(struct frame_hdr_signature) + sizeof(struct frame_msg_signature) + my_LinkKey->rawKeyLen;
			return sizeof(struct frame_msg_signature) + my_LinkKey->rawKeyLen;
		} else {
			hdr = NULL;
			dataOffset = 0;
			return sizeof(struct frame_msg_signature);
		}

	} else if (hdr) {
		assertion(-502099, (it->frame_type > FRAME_TYPE_SIGNATURE_ADV));
		assertion(-502100, (hdr && dataOffset));
		assertion(-502197, (my_LinkKey && my_LinkKey->rawKeyLen && my_LinkKey->rawKeyType));
		assertion(-502101, (it->frames_out_pos > dataOffset));

		extern void tx_packets(void *devp);
		prof_start(create_packet_signature, tx_packets);

		struct frame_msg_signature *msg = (struct frame_msg_signature *) &(hdr[1]);
		int32_t dataLen = it->frames_out_pos - dataOffset;
		uint8_t *data = it->frames_out_ptr + dataOffset;

		CRYPTSHA1_T packetSha;
		cryptShaNew(&it->ttn->key.f.p.dev->if_llocal_addr->ip_addr, sizeof(IPX_T));
		cryptShaUpdate(hdr, sizeof(struct frame_hdr_signature));
		cryptShaUpdate(data, dataLen);
		cryptShaFinal(&packetSha);

		cryptSign(&packetSha, msg->signature, my_LinkKey->rawKeyLen, my_LinkKey);

		dbgf_all(DBGT_INFO, "fixed RSA%d type=%d signature=%s of dataSha=%s over dataLen=%d data=%s (dataOffset=%d)",
			(my_LinkKey->rawKeyLen * 8), msg->type, memAsHexString(msg->signature, my_LinkKey->rawKeyLen),
			cryptShaAsString(&packetSha), dataLen, memAsHexString(data, dataLen), dataOffset);

		hdr = NULL;
		dataOffset = 0;

		prof_stop();
	}
	return TLV_TX_DATA_DONE;
}

STATIC_FUNC
int process_packet_signature(struct rx_frame_iterator *it)
{
	struct frame_hdr_signature *hdr = (struct frame_hdr_signature*)(it->f_data);
	struct frame_msg_signature *msg = (struct frame_msg_signature*)(it->f_msg);
	struct packet_buff *pb = it->pb;
	DESC_SQN_T descSqn = ntohl(hdr->sqn.u32.descSqn);
	BURST_SQN_T burstSqn = ntohl(hdr->sqn.u32.burstSqn);
	DEVIDX_T devIdx = ntohs(hdr->devIdx);
	struct key_node *claimedKey = pb->i.claimedKey;;
	int32_t sign_len = it->f_msgs_len - sizeof(struct frame_msg_signature);
	uint8_t *data = it->f_data + it->f_dlen;
	int32_t dataLen = it->frames_length - (it->f_data - it->frames_in) - it->f_dlen;
	struct desc_content *dc = NULL;
	CRYPTSHA1_T packetSha = {.h.u32={0}};
	CRYPTKEY_T *pkey = NULL, *pkeyTmp = NULL;
	struct dsc_msg_pubkey *pkey_msg = NULL;
	uint8_t *llip_data = NULL;
	uint32_t llip_dlen = 0;
	struct neigh_node *nn = NULL;
	char *goto_error_code = NULL;
	int goto_error_ret = TLV_RX_DATA_PROCESSED;

	prof_start( process_packet_signature, rx_packet);

	if (msg->type ? (!cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != sign_len) : (sign_len != 0))
		goto_error_return( finish, "Invalid type or signature-key length!", TLV_RX_DATA_FAILURE);

	if ( dataLen <= (int)sizeof(struct tlv_hdr))
		goto_error_return( finish, "Invalid length of signed data!", TLV_RX_DATA_FAILURE);

	if ( sign_len > (linkSignMax/8) || sign_len < (linkSignMin/8) )
		goto_error_return( finish, "Unsupported signature-key length!", TLV_RX_DATA_PROCESSED);

	if (!claimedKey || claimedKey->bookedState->i.c < KCTracked)
		goto_error_return( finish, "< KCTracked", TLV_RX_DATA_PROCESSED);

	assertion(-502480, (claimedKey->content));

	if (descSqn < (claimedKey->nextDesc ? claimedKey->nextDesc->descSqn : (claimedKey->currOrig ? claimedKey->currOrig->descContent->descSqn : 0)))
		goto_error_return( finish, "outdated descSqn", TLV_RX_DATA_PROCESSED);

	if (!claimedKey->content->f_body) {
//		schedule_tx_task(FRAME_TYPE_CONTENT_REQ, &claimedKey->kHash, NULL, pb->i.iif, SCHEDULE_MIN_MSG_SIZE, &claimedKey->kHash, sizeof(SHA1_T));
		goto_error_return( finish, "unresolved key", TLV_RX_DATA_PROCESSED);
	}

	if (!(dc = (claimedKey->nextDesc ?
		(claimedKey->nextDesc->descSqn == descSqn ? claimedKey->nextDesc : NULL) :
		(claimedKey->currOrig && claimedKey->currOrig->descContent->descSqn == descSqn ? claimedKey->currOrig->descContent : NULL)))) {

		schedule_tx_task(FRAME_TYPE_DESC_REQ, &claimedKey->kHash, NULL, pb->i.iif, SCHEDULE_MIN_MSG_SIZE, &descSqn, sizeof(descSqn));
		goto_error_return( finish, "unknown desc", TLV_RX_DATA_PROCESSED);
	}

	if (claimedKey->bookedState->i.c < KCCertified)
		goto_error_return( finish, "< KCCertified", TLV_RX_DATA_PROCESSED);

	if (dc->unresolvedContentCounter)
		goto_error_return( finish, "unresovled desc content", TLV_RX_DATA_PROCESSED);


	if ((llip_data = contents_data(dc, BMX_DSC_TLV_LLIP)) && (llip_dlen = contents_dlen(dc, BMX_DSC_TLV_LLIP)) &&
		!find_array_data(llip_data, llip_dlen, (uint8_t*) & pb->i.llip, sizeof(struct dsc_msg_llip)))
		goto_error_return( finish, "Missing or Invalid src llip", TLV_RX_DATA_FAILURE);

	if (dc->orig && dc->orig->neigh) {
//		assertion(-502481, (dc->orig->neigh->pktKey));
		pkey = dc->orig->neigh->linkKey;

	} else if ((pkey_msg = contents_data(dc, BMX_DSC_TLV_LINK_PUBKEY))) {

		if (!(pkey = pkeyTmp = cryptPubKeyFromRaw(pkey_msg->key, cryptKeyLenByType(pkey_msg->type))))
			goto_error_return( finish, "Failed key retrieval from description!", TLV_RX_DATA_FAILURE);
	}

	if ( pkey && !msg->type && it->pb->i.iif->strictSignatures >= OPT_DEV_SIGNATURES_RXTX)
		goto_error_return( finish, "Key described but not used!", TLV_RX_DATA_FAILURE);
	else if ( !pkey && msg->type )
		goto_error_return( finish, "Key undescribed but used!", TLV_RX_DATA_FAILURE);

	if (pkey && msg->type) {

		if (pkey->rawKeyType != msg->type)
			goto_error_return(finish, "Described key different from used", TLV_RX_DATA_FAILURE);

		cryptShaNew(&it->pb->i.llip, sizeof(IPX_T));
		cryptShaUpdate(hdr, sizeof(struct frame_hdr_signature));
		cryptShaUpdate(data, dataLen);
		cryptShaFinal(&packetSha);

		if (linkVerify && cryptVerify(msg->signature, sign_len, &packetSha, pkey) != SUCCESS)
			goto_error_return(finish, "Failed signature verification", TLV_RX_DATA_FAILURE);
	}

	dc->dhn->referred_by_others_timestamp = bmx_time;

	struct key_credits kc = {.pktId = 1, .pktSign = 1};
	if (!(claimedKey = keyNode_updCredits(NULL, claimedKey, &kc)) || claimedKey->bookedState->i.c < KCNeighbor)
		goto_error_return( finish, "< KCNeighbor", TLV_RX_DATA_PROCESSED);

	if (dc->orig == claimedKey->currOrig && (nn = dc->orig->neigh)) {

		if (nn->burstSqn <= burstSqn)
			nn->burstSqn = burstSqn;
		else
			goto_error_return(finish, "Outdated burstSqn", TLV_RX_DATA_PROCESSED);


//		pb->i.verifiedNeigh = dc->orig->neigh;
		if (!(pb->i.verifiedLink = getLinkNode(pb->i.iif, &pb->i.llip, devIdx, nn)))
			goto_error_return(finish, "Failed Link detection", TLV_RX_DATA_PROCESSED);
	}



finish:{
	dbgf(
		goto_error_ret != TLV_RX_DATA_PROCESSED ? DBGL_SYS : (goto_error_code ? DBGL_CHANGES : DBGL_ALL),
		goto_error_ret != TLV_RX_DATA_PROCESSED ? DBGT_ERR : DBGT_INFO,
		"%s verifying  data_len=%d data_sha=%s "
		"sign_len=%d signature=%s... "
		"pkey_msg_type=%s pkey_msg_len=%d "
		"pkey_type=%s pkey=%s "
		"dev=%s srcIp=%s llIps=%s pcktSqn=%d/%d "
		"problem?=%s",
		goto_error_code?"Failed":"Done", dataLen, cryptShaAsString(&packetSha),
		sign_len, memAsHexString(msg->signature, XMIN(sign_len,8)),
		pkey_msg ? cryptKeyTypeAsString(pkey_msg->type) : "---", pkey_msg ? cryptKeyLenByType(pkey_msg->type) : 0,
		pkey ? cryptKeyTypeAsString(pkey->rawKeyType) : "---", pkey ? memAsHexString(pkey->rawKey, pkey->rawKeyLen) : "---",
		pb->i.iif->label_cfg.str, pb->i.llip_str, (llip_dlen ? memAsHexStringSep(llip_data, llip_dlen, sizeof(struct dsc_msg_llip), " ") : NULL),
		burstSqn, (nn ? (int)nn->burstSqn : -1),
		goto_error_code);

	if (pkeyTmp)
		cryptKeyFree(&pkeyTmp);

	prof_stop();

	return goto_error_ret;

	if (goto_error_code)
		return goto_error_ret;
	else
		return TLV_RX_DATA_PROCESSED;
}
}




STATIC_FUNC
int create_dsc_tlv_nodeKey(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502097, (my_NodeKey));

	struct dsc_msg_pubkey *msg = ((struct dsc_msg_pubkey*) tx_iterator_cache_msg_ptr(it));

	if ((int) (sizeof(struct dsc_msg_pubkey) +my_NodeKey->rawKeyLen) > tx_iterator_cache_data_space_pref(it, 0, 0))
		return TLV_TX_DATA_FULL;

	msg->type = my_NodeKey->rawKeyType;

	memcpy(msg->key, my_NodeKey->rawKey, my_NodeKey->rawKeyLen);
	dbgf_track(DBGT_INFO, "added description rsa description pubkey len=%d", my_NodeKey->rawKeyLen);

	return(sizeof(struct dsc_msg_pubkey) +my_NodeKey->rawKeyLen);
}

void update_dsc_tlv_linkKey(void*unused)
{
	my_description_changed = YES;
}

STATIC_FUNC
int create_dsc_tlv_linkKey(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	if (!linkSignLen) {
		assertion(-502203, (!my_LinkKey));
		return TLV_TX_DATA_DONE;
	}

	if ((int) (sizeof(struct dsc_msg_pubkey) + (linkSignLen / 8)) > tx_iterator_cache_data_space_pref(it, 0, 0))
		return TLV_TX_DATA_FULL;

	prof_start(create_dsc_tlv_linkKey, update_my_description);

	struct dsc_msg_pubkey *msg = ((struct dsc_msg_pubkey*) tx_iterator_cache_msg_ptr(it));

	uint8_t first = my_LinkKey ? NO : YES;

	if (my_LinkKey && linkSignLifetime) {

		assertion(-502204, (my_LinkKey->endOfLife));

		// renew pktKey if approaching last quarter of pktKey lifetime:
		if (((TIME_SEC_T) ((5 * (my_LinkKey->endOfLife - (bmx_time_sec + 1))) / 4)) >= MAX_LINK_SIGN_LT) {
			task_remove(update_dsc_tlv_linkKey, NULL);
			cryptKeyFree(&my_LinkKey);
		}
	}

	if (!my_LinkKey) {

		// set end-of-life for first packetKey to smaller random value >= 1:
		int32_t thisSignLifetime = first && linkSignLifetime ? (1 + ((int32_t) rand_num(linkSignLifetime - 1))) : linkSignLifetime;

		my_LinkKey = cryptKeyMake(linkSignLen);

		my_LinkKey->endOfLife = (thisSignLifetime ? bmx_time_sec + thisSignLifetime : 0);

		if (thisSignLifetime)
			task_register(thisSignLifetime * 1000, update_dsc_tlv_linkKey, NULL, -300655);
	}
	assertion(-502097, (my_LinkKey));


	msg->type = my_LinkKey->rawKeyType;

	memcpy(msg->key, my_LinkKey->rawKey, my_LinkKey->rawKeyLen);

	dbgf_track(DBGT_INFO, "added description rsa packet pubkey len=%d", my_LinkKey->rawKeyLen);

	prof_stop();

	return(sizeof(struct dsc_msg_pubkey) +my_LinkKey->rawKeyLen);
}



STATIC_FUNC
int process_dsc_tlv_pubKey(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	char *goto_error_code = NULL;
	CRYPTKEY_T *pkey = NULL;
	int32_t key_len = it->f_dlen - sizeof(struct dsc_msg_pubkey);
	struct dsc_msg_pubkey *msg = (struct dsc_msg_pubkey*) (it->f_data);

	if (it->op == TLV_OP_TEST ) {

		if (!cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != key_len)
			goto_error(finish, "1");

		if (!(pkey = cryptPubKeyFromRaw(msg->key, key_len)))
			goto_error(finish, "2");

		if (cryptPubKeyCheck(pkey) != SUCCESS)
			goto_error(finish, "3");

	} else if (it->op == TLV_OP_DEL && it->f_type == BMX_DSC_TLV_LINK_PUBKEY && it->on->neigh) {

		if (it->on->neigh->linkKey)
			cryptKeyFree(&it->on->neigh->linkKey);

	} else if (it->op == TLV_OP_NEW && it->f_type == BMX_DSC_TLV_LINK_PUBKEY && it->on->neigh) {

		if (it->on->neigh->linkKey)
			cryptKeyFree(&it->on->neigh->linkKey);

		it->on->neigh->linkKey = cryptPubKeyFromRaw(msg->key, cryptKeyLenByType(msg->type));
		assertion(-502206, (it->on->neigh->linkKey && cryptPubKeyCheck(it->on->neigh->linkKey) == SUCCESS));
	}

finish: {
	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s %s %s type=%s msg_key_len=%d == key_len=%d problem?=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", it->f_handl->name,
		msg ? cryptKeyTypeAsString(msg->type) : NULL,
		msg ? cryptKeyLenByType(msg->type) : -1, key_len, goto_error_code);

	if (pkey)
		cryptKeyFree(&pkey);

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return it->f_dlen;
}
}


STATIC_FUNC
int create_dsc_tlv_signature(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct dsc_msg_signature *desc_msg = NULL;
	static int32_t dataOffset = 0;

	if (it->frame_type == BMX_DSC_TLV_DSC_SIGNATURE) {

		assertion(-502098, (!desc_msg && !dataOffset));

		desc_msg = (struct dsc_msg_signature*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));

		dataOffset = it->frames_out_pos + sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) + my_NodeKey->rawKeyLen;

		return sizeof(struct dsc_msg_signature) + my_NodeKey->rawKeyLen;

	} else {
		assertion(-502230, (it->frame_type == BMX_DSC_TLV_SIGNATURE_DUMMY));
		assertion(-502231, (desc_msg && dataOffset));
		assertion(-502232, (it->frames_out_pos > dataOffset));

		int32_t dataLen = it->frames_out_pos - dataOffset;
		uint8_t *data = it->frames_out_ptr + dataOffset;

		CRYPTSHA1_T dataSha;
		cryptShaAtomic(data, dataLen, &dataSha);
		size_t keySpace = my_NodeKey->rawKeyLen;

		desc_msg->type = my_NodeKey->rawKeyType;
		cryptSign(&dataSha, desc_msg->signature, keySpace, NULL);

		dbgf_track(DBGT_INFO, "fixed RSA%zd type=%d signature=%s of dataSha=%s over dataLen=%d data=%s (dataOffset=%d desc_frames_len=%d)",
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

	ASSERTION(-502482, IMPLIES(it->f_type == BMX_DSC_TLV_DSC_SIGNATURE && it->op == TLV_OP_TEST,
		test_description_signature(it->dcOp->desc_frame, it->dcOp->desc_frame_len)));

	return TLV_RX_DATA_PROCESSED;
}



struct content_node *test_description_signature(uint8_t *desc, uint32_t desc_len)
{
	prof_start(test_description_signature, main);

	char *goto_error_code = NULL;
	struct content_node *goto_return_code = NULL;
	GLOBAL_ID_T *nodeId = NULL;
	struct dsc_msg_signature *signMsg = NULL;
	struct dsc_msg_version *versMsg = NULL;
	int32_t signLen = 0;
	struct content_node *pkeyRef = NULL;
	struct dsc_msg_pubkey *pkeyMsg = NULL;
	uint32_t dataOffset = 0;
	uint8_t *data = NULL;
	int32_t dataLen = 0;
	CRYPTKEY_T *pkey = NULL;
	CRYPTSHA1_T dataSha;

	if (!(nodeId = get_desc_id(desc, desc_len, &signMsg, &versMsg)))
		goto_error(finish, "Invalid desc structure");

	if ((!(dataOffset = (((uint32_t)(((uint8_t*)versMsg) - desc)) - sizeof(struct tlv_hdr))) || dataOffset >= desc_len))
		goto_error(finish, "Non-matching description length");


	if ((signLen = cryptKeyLenByType(signMsg->type)) > (nodeSignMax / 8)) {
		goto_error( finish, "Unsupported signature length");
	}

	if (!(pkeyRef = content_get(nodeId))) {
		goto_error(finish, "Unresolved signature content");
	}

	if (!(pkeyRef->f_body_len == sizeof(struct dsc_msg_pubkey) + signLen &&
		 (pkeyMsg = (struct dsc_msg_pubkey*) pkeyRef->f_body) && pkeyMsg->type == signMsg->type))
		goto_error(finish, "Invalid pkey content");

	cryptShaAtomic((data = desc + dataOffset), (dataLen = desc_len - dataOffset), &dataSha);

	if (!(pkey = cryptPubKeyFromRaw(pkeyMsg->key, signLen)))
		goto_error(finish, "Invalid pkey");

	assertion(-502207, (pkey && cryptPubKeyCheck(pkey) == SUCCESS));


	if (nodeVerify && cryptVerify(signMsg->signature, signLen , &dataSha, pkey) != SUCCESS )
		goto_error( finish, "Invalid signature");

	goto_return_code = pkeyRef;

finish: {

	dbgf(
		(goto_return_code ? DBGL_ALL : DBGL_SYS),
		(goto_return_code ? DBGT_INFO : DBGT_ERR),
		"%s verifying  descLen=%d nodeId=%s dataOffset=%d dataLen=%d data=%s dataSha=%s \n"
		"signLen=%d signature=%s\n"
		"msg_pkey_type=%s msg_pkey_len=%d pkey_type=%s pkey=%s \n"
		"problem?=%s",
		goto_error_code?"Failed":"Succeeded", desc_len, cryptShaAsString(nodeId),
		dataOffset, dataLen, memAsHexString(data, dataLen), cryptShaAsString(&dataSha),
		signLen, signMsg ? memAsHexString(signMsg->signature, signLen) : NULL,
		pkeyMsg ? cryptKeyTypeAsString(pkeyMsg->type) : NULL, pkeyMsg ? cryptKeyLenByType(pkeyMsg->type) : 0,
		pkey ? cryptKeyTypeAsString(pkey->rawKeyType) : NULL, pkey ? memAsHexString(pkey->rawKey, pkey->rawKeyLen) : NULL,
		goto_error_code);

	if (pkey)
		cryptKeyFree(&pkey);

	prof_stop();

	return goto_return_code;
}
}



int32_t rsa_load( char *tmp_path ) {

	// test with: ./bmx7 f=0 d=0 --keyDir=$(pwdd)/rsa-test/key.der


	dbgf_sys(DBGT_INFO, "testing %s=%s", ARG_KEY_PATH, tmp_path);

	if (!(my_NodeKey = cryptKeyFromDer( tmp_path ))) {
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

	if (cryptEncrypt(in, inLen, enc, &encLen, my_NodeKey) != SUCCESS) {
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

	if (cryptSign(&inSha, enc, my_NodeKey->rawKeyLen, NULL) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Sign inLen=%zd outLen=%zd inData=%s outData=%s",
			inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, my_NodeKey->rawKeyLen));
		return FAILURE;
	}

	if (cryptVerify(enc, my_NodeKey->rawKeyLen, &inSha, my_NodeKey) != SUCCESS) {
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

	static int32_t keyLen = DEF_NODE_SIGN_LEN;


	if (cmd == OPT_CHECK) {

		keyLen = (patch->diff == ADD) ? strtol(patch->val, NULL, 10) : DEF_NODE_SIGN_LEN;

		if (!keyLen || (keyLen%8) || cryptKeyTypeByLen(keyLen/8) == FAILURE)
			return FAILURE;
	}

	if ( (cmd == OPT_CHECK || cmd == OPT_SET_POST) && initializing && !done ) {

		struct opt_child *c = patch ? list_iterate(&patch->childs_instance_list, NULL) : NULL;

		if (cmd == OPT_CHECK && c && c->val) {
			if ( wordlen( c->val )+1 >= MAX_PATH_SIZE  ||  c->val[0] != '/' )
				return FAILURE;

			snprintf( tmp_path, wordlen(c->val)+1, "%s", c->val );
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

			dbgf_sys(DBGT_WARN, "key=%s does not exist! Creating RSA%d private key. This can take a while...", tmp_path, keyLen);

			if (cryptKeyMakeDer(keyLen, tmp_path) != SUCCESS) {
				dbgf_sys(DBGT_ERR, "Failed creating new %d bit key to %s!", keyLen, tmp_path);
				return FAILURE;
			}
		}
#endif
		if (rsa_load( tmp_path ) == SUCCESS && my_NodeKey->rawKeyLen * 8 == keyLen) {
			dbgf_sys(DBGT_INFO, "Successfully initialized RSA%d key=%s !", (my_NodeKey->rawKeyLen * 8), tmp_path);
		} else {
			dbgf_sys(DBGT_ERR, "key=%s (length?) invalid!", tmp_path);
			return FAILURE;
		}

		strcpy(key_path, tmp_path);

		init_self();

		done = YES;
        }

	return SUCCESS;
}

int32_t opt_linkSigning(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd == OPT_CHECK || cmd == OPT_APPLY) {


		if (!strcmp(opt->name, ARG_LINK_SIGN_LEN)) {

			int32_t val = (patch->diff == ADD) ? strtol(patch->val, NULL, 10) : DEF_LINK_SIGN_LEN;

			if (val!=0 && ((val%8) || cryptKeyTypeByLen(val/8) == FAILURE))
				return FAILURE;

			if ( cmd == OPT_APPLY )
				my_description_changed = YES;

			task_remove(update_dsc_tlv_linkKey, NULL);
			cryptKeyFree(&my_LinkKey);



		} else if (!strcmp(opt->name, ARG_LINK_SIGN_LT)) {

			int32_t val = (patch->diff == ADD) ? strtol(patch->val, NULL, 10) : DEF_LINK_SIGN_LT;

			if (val!=0 && (val<MIN_LINK_SIGN_LT || val > (int32_t)MAX_LINK_SIGN_LT))
				return FAILURE;

			if ( cmd == OPT_APPLY ){

				if (!val) {
					if (my_LinkKey)
						my_LinkKey->endOfLife = 0;
				} else {
					task_remove(update_dsc_tlv_linkKey, NULL);
					cryptKeyFree(&my_LinkKey);
					my_description_changed = YES;
				}
			}
		} else
			return FAILURE;
	}


	return SUCCESS;
}



static uint8_t internalNeighId_array[(LOCALS_MAX/8) + (!!(LOCALS_MAX%8))];
static int32_t internalNeighId_max = -1;
static uint16_t internalNeighId_u32s = 0;

IDM_T setted_pubkey(struct desc_content *dc, uint8_t type, GLOBAL_ID_T *globalId)
{

	assertion(-502483, (type <= description_tlv_db->handl_max));
	assertion(-502484, (description_tlv_db->handls[type].fixed_msg_size));
	assertion(-502485, (description_tlv_db->handls[type].data_header_size == 0));
	assertion(-502486, (description_tlv_db->handls[type].min_msg_size == sizeof(struct dsc_msg_trust)));

	struct dsc_msg_trust *setList = contents_data(dc, type);
	uint32_t msgs = contents_dlen(dc, type) / sizeof(struct dsc_msg_trust);
	uint32_t m =0;

	if (setList) {
		for (m = 0; m < msgs; m++) {

			if (cryptShasEqual(globalId, &setList[m].nodeId))
				return 1;
		}
		return 0;
	}
	return -1;
}

STATIC_FUNC
void update_neighTrust(struct orig_node *on, struct desc_content *dcNew, struct neigh_node *nn)
{

	if (setted_pubkey(dcNew, BMX_DSC_TLV_TRUSTS, &nn->local_id)) {

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

IDM_T verify_neighTrust(struct orig_node *on, struct neigh_node *neigh)
{
	return bit_get((uint8_t*)on->trustedNeighsBitArray, (internalNeighId_u32s * 32), neigh->internalNeighId );
}

INT_NEIGH_ID_T allocate_internalNeighId(struct neigh_node *nn) {

	int32_t ini;
	struct orig_node *on;
	struct avl_node *an = NULL;

	for (ini=0; ini<LOCALS_MAX && bit_get(internalNeighId_array, (sizeof(internalNeighId_array)*8), ini); ini++);

	assertion(-502228, (ini < LOCALS_MAX && ini <= (int)local_tree.items));
	bit_set(internalNeighId_array, (sizeof(internalNeighId_array)*8), ini, 1);
	nn->internalNeighId = ini;

	if (ini > internalNeighId_max) {

		uint16_t u32s_needed = (((ini+1)/32) + (!!((ini+1)%32)));
		uint16_t u32s_allocated = internalNeighId_u32s;

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
		update_neighTrust(on, on->descContent, nn);


	return ini;
}


void free_internalNeighId(INT_NEIGH_ID_T ini) {

	struct orig_node *on;
	struct avl_node *an = NULL;

	while ((on = avl_iterate_item(&orig_tree, &an)))
		bit_set((uint8_t*)on->trustedNeighsBitArray, internalNeighId_u32s * 32, ini, 0);

	bit_set(internalNeighId_array, (sizeof(internalNeighId_array)*8),ini,0);
}

STATIC_FUNC
int process_dsc_tlv_supports(struct rx_frame_iterator *it)
{
	return TLV_RX_DATA_PROCESSED;
}


STATIC_FUNC
int create_dsc_tlv_trusts(struct tx_frame_iterator *it)
{
        struct avl_node *an = NULL;
        struct trust_node *tn;
        struct dsc_msg_trust *msg = (struct dsc_msg_trust *)tx_iterator_cache_msg_ptr(it);
        int32_t max_size = tx_iterator_cache_data_space_pref(it, 0, 0);
        int pos = 0;
	struct DirWatch *dw = (it->frame_type==BMX_DSC_TLV_SUPPORTS) ? supportDirWatch : trustedDirWatch;

	assertion(-502487, (it->frame_type == BMX_DSC_TLV_SUPPORTS || it->frame_type == BMX_DSC_TLV_TRUSTS));

	if (dw) {
		IDM_T addedMyself = NO;
		while ((tn = avl_iterate_item(&dw->node_tree, &an)) || !addedMyself) {

			if (pos + (int) sizeof(struct dsc_msg_trust) > max_size) {
				dbgf_sys(DBGT_ERR, "Failed adding %s=%s", it->handl->name, cryptShaAsString(&tn->global_id));
				return TLV_TX_DATA_FULL;
			}

			msg->nodeId = tn ? tn->global_id : myKey->kHash;
			msg++;
			pos += sizeof(struct dsc_msg_trust);

			dbgf_track(DBGT_INFO, "adding %s=%s", it->handl->name, cryptShaAsString(&tn->global_id));

			if (tn && cryptShasEqual(&tn->global_id, &myKey->kHash))
				addedMyself = YES;
			else if (!tn)
				break;
		}

		return pos;
	}

        return TLV_TX_DATA_IGNORED;
}



STATIC_FUNC
int process_dsc_tlv_trusts(struct rx_frame_iterator *it)
{
	if ((it->op == TLV_OP_NEW || it->op == TLV_OP_DEL) && desc_frame_changed( it, it->f_type )) {

		struct avl_node *an = NULL;
		struct neigh_node *nn;

		while ((nn = avl_iterate_item(&local_tree, &an))) {
			update_neighTrust(it->on, (it->op == TLV_OP_NEW ? it->dcOp : NULL), nn);
		}
	}


	return TLV_RX_DATA_PROCESSED;
}


IDM_T supportedKnownKey( CRYPTSHA1_T *pkhash ) {

	struct trust_node *tn;

	if (!pkhash || is_zero(pkhash, sizeof(CRYPTSHA1_T)))
		return NO;

	if (!supportDirWatch)
		return -1;
		
	if (!(tn = avl_find_item(&supportDirWatch->node_tree, pkhash)))
		return NO;

	return tn->maxTrust + YES;

}


STATIC_FUNC
void check_nodes_dir(void *dirWatchPtr)
{
	struct DirWatch *dw = (struct DirWatch*) dirWatchPtr;

	DIR *dir;

	task_remove(check_nodes_dir, dirWatchPtr);

	if ((dir = opendir(dw->pathp))) {

		struct dirent *dirEntry;
		struct trust_node *tn;
		GLOBAL_ID_T globalId;

		dw->retryCnt = 5;

		while ((dirEntry = readdir(dir)) != NULL) {

			char globalIdString[(2*sizeof(GLOBAL_ID_T))+1] = {0};

			if (
				(strlen(dirEntry->d_name) >= (2*sizeof(GLOBAL_ID_T))) &&
				(strncpy(globalIdString, dirEntry->d_name, 2*sizeof(GLOBAL_ID_T))) &&
				(hexStrToMem(globalIdString, (uint8_t*)&globalId, sizeof(GLOBAL_ID_T)) == SUCCESS)
				) {

				if ((tn = avl_find_item(&dw->node_tree, &globalId))) {

					dbgf(tn->updated ? DBGL_SYS : DBGL_ALL, tn->updated ? DBGT_ERR : DBGT_INFO,
						"file=%s prefix found %d times!",dirEntry->d_name, tn->updated);

				} else {
					tn = debugMallocReset(sizeof(struct trust_node), -300658);
					tn->global_id = globalId;
					avl_insert(&dw->node_tree, tn, -300659);
					dbgf_sys(DBGT_INFO, "file=%s defines new nodeId=%s!",
						dirEntry->d_name, cryptShaAsString(&globalId));

					if (dw->idChanged)
						(*dw->idChanged) (ADD, &globalId);
				}

				tn->updated++;

			} else if (strcmp(dirEntry->d_name, ".") && strcmp(dirEntry->d_name, "..")) {
				dbgf_sys(DBGT_ERR, "file=%s has illegal format!", dirEntry->d_name);
			}
		}
		closedir(dir);

		memset(&globalId, 0, sizeof(globalId));
		while ((tn = avl_next_item(&dw->node_tree, &globalId))) {
			globalId = tn->global_id;
			if (tn->updated || (myKey && cryptShasEqual(&tn->global_id, &myKey->kHash))) {
				tn->updated = 0;
			} else {

				if (dw->idChanged)
					(*dw->idChanged) (DEL, &globalId);

				avl_remove(&dw->node_tree, &globalId, -300660);
				dbgf_sys(DBGT_INFO, "removed nodeId=%s!", cryptShaAsString(&globalId));

				debugFree(tn, -300740);
			}
		}

		if (dw->ifd == -1)
			task_register(DEF_TRUST_DIR_POLLING_INTERVAL, check_nodes_dir, dw, -300657);

	} else {

		dbgf_sys(DBGT_WARN, "Problem opening dir=%s: %s! Retrying in %d ms...",
			dw->pathp, strerror(errno), dw->retryCnt);

		task_register(dw->retryCnt, check_nodes_dir, dw, -300741);

		dw->retryCnt = 5000;
	}
}

void inotify_event_hook(int fd)
{
        TRACE_FUNCTION_CALL;

	struct DirWatch *dw = avl_find_item(&dirWatch_tree, &fd);
        assertion(-501278, (fd > -1 && dw && dw->ifd == fd));

	dbgf_track(DBGT_INFO, "detected changes in directory: %s", dw->pathp);


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
				dbgf_sys(DBGT_ERR, "directory %s has been removed \n", dw->pathp);
                                cleanup_all(-502490);
                        }
                }

        } else {
                dbgf_sys(DBGT_ERR, "read()=%d: %s \n", rcvd, strerror(errno));
        }

        debugFree(ibuff, -300377);

	check_nodes_dir(dw);
}


void cleanup_dir_watch(struct DirWatch **dw)
{
	assertion(-500000, (dw));

	if (!(*dw))
		return;

	if ((*dw)->ifd > -1) {

		avl_remove(&dirWatch_tree, &(*dw)->ifd, -300000);

		if ((*dw)->iwd > -1) {
			inotify_rm_watch((*dw)->ifd, (*dw)->iwd);
			(*dw)->iwd = -1;
		}

		set_fd_hook((*dw)->ifd, inotify_event_hook, DEL);

		close((*dw)->ifd);
		(*dw)->ifd = -1;
	} else {
		task_remove(check_nodes_dir, *dw);
	}

	while ((*dw)->node_tree.items) {
		struct trust_node *tn = avl_remove_first_item(&(*dw)->node_tree, -300661);

		if ((*dw)->idChanged)
			(*(*dw)->idChanged)(DEL, &tn->global_id);

		debugFree(tn, -300664);
	}

	if ((*dw)->idChanged)
		(*(*dw)->idChanged)(DEL, NULL);

	debugFree(*dw, -300000);
	*dw = NULL;

}

STATIC_FUNC
void idChanged_Trusted(IDM_T del, GLOBAL_ID_T *id)
{
	my_description_changed = YES;
}

STATIC_FUNC
void idChanged_Supported(IDM_T del, GLOBAL_ID_T *id)
{
	struct key_credits friend_kc = {.friend=1};

	if (!id)
		return;

	if (del && !terminating)
		keyNode_delCredits(id, NULL, &friend_kc);

	else
		keyNode_updCredits(id, NULL, &friend_kc);
}

IDM_T init_dir_watch(struct DirWatch **dw, char *path, void (* idChangedTask) (IDM_T del, GLOBAL_ID_T *id))
{

	cleanup_dir_watch(dw);

	(*dw) = debugMallocReset(sizeof(struct DirWatch), -300000);

	(*dw)->pathp = path;
	(*dw)->idChanged = idChangedTask;
	(*dw)->retryCnt = 5;
	AVL_INIT_TREE((*dw)->node_tree, struct trust_node, global_id);

	if (((*dw)->ifd = inotify_init()) < 0) {

		dbg_sys(DBGT_WARN, "failed init inotify socket: %s! Using %d ms polling instead! You should enable inotify support in your kernel!",
			strerror(errno), DEF_TRUST_DIR_POLLING_INTERVAL);
		(*dw)->ifd = -1;

	} else if (fcntl((*dw)->ifd, F_SETFL, O_NONBLOCK) < 0) {

		dbgf_sys(DBGT_ERR, "failed setting inotify non-blocking: %s", strerror(errno));
		return FAILURE;

	} else if (((*dw)->iwd = inotify_add_watch((*dw)->ifd, (*dw)->pathp,
		IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO)) < 0) {

		dbgf_sys(DBGT_ERR, "failed adding watch for dir=%s: %s \n", (*dw)->pathp, strerror(errno));
		return FAILURE;

	} else {

		set_fd_hook((*dw)->ifd, inotify_event_hook, ADD);
		avl_insert(&dirWatch_tree, (*dw), -300000);
	}

	check_nodes_dir((*dw));

	if (idChangedTask)
		(*idChangedTask)(ADD, NULL);

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_dir_watch(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	assertion(-500000, ((strcmp(opt->name, ARG_TRUSTED_NODES_DIR) == 0)|| (strcmp(opt->name, ARG_SUPPORTED_NODES_DIR) == 0)));

        if (cmd == OPT_CHECK && patch->diff == ADD && check_dir(patch->val, NO/*create*/, NO/*writable*/) == FAILURE)
			return FAILURE;

        if (cmd == OPT_APPLY) {

		struct DirWatch **dw = (strcmp(opt->name, ARG_TRUSTED_NODES_DIR) == 0) ? &trustedDirWatch : &supportDirWatch;

		if (patch->diff == DEL || patch->diff == ADD)
			cleanup_dir_watch(dw);

		if (patch->diff == ADD) {
			assertion(-501286, (patch->val));
			return init_dir_watch(dw, patch->val, !strcmp(opt->name, ARG_SUPPORTED_NODES_DIR)?idChanged_Supported:idChanged_Trusted);
		}
        }

        return SUCCESS;
}



STATIC_FUNC
struct opt_type sec_options[]=
{
//order must be before ARG_HOSTNAME (which initializes self via init_self):
	{ODI,0,ARG_NODE_SIGN_LEN,         0,  4,1,A_PS1N,A_ADM,A_INI,A_CFA,A_ANY,       0,MIN_NODE_SIGN_LEN,MAX_NODE_SIGN_LEN,DEF_NODE_SIGN_LEN,0, opt_key_path,
			ARG_VALUE_FORM, HLP_NODE_SIGN_LEN},
	{ODI,ARG_NODE_SIGN_LEN,ARG_KEY_PATH,0,4,1,A_CS1, A_ADM,A_INI,A_CFA,A_ANY,	0,0,    	    0,		      0,     DEF_KEY_PATH, opt_key_path,
			ARG_DIR_FORM,	"set path to rsa der-encoded private key file (used as permanent public ID"},
	{ODI,0,ARG_NODE_SIGN_MAX,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &nodeSignMax,MIN_NODE_SIGN_MAX,MAX_NODE_SIGN_MAX,DEF_NODE_SIGN_MAX,0, opt_flush_all,
			ARG_VALUE_FORM, HLP_NODE_SIGN_MAX},
	{ODI,0,ARG_LINK_SIGN_LEN,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &linkSignLen,  MIN_LINK_SIGN_LEN,MAX_LINK_SIGN_LEN,DEF_LINK_SIGN_LEN,0, opt_linkSigning,
			ARG_VALUE_FORM, HLP_LINK_SIGN_LEN},
	{ODI,0,ARG_LINK_VERIFY,           0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &linkVerify,   MIN_LINK_VERIFY,MAX_LINK_VERIFY, DEF_LINK_VERIFY,0, NULL,
			ARG_VALUE_FORM, HLP_LINK_VERIFY},
	{ODI,0,ARG_NODE_VERIFY,           0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &nodeVerify,   MIN_NODE_VERIFY,MAX_NODE_VERIFY, DEF_NODE_VERIFY,0, NULL,
			ARG_VALUE_FORM, HLP_NODE_VERIFY},
	{ODI,0,ARG_LINK_SIGN_LT,          0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &linkSignLifetime,0,MAX_LINK_SIGN_LT,DEF_LINK_SIGN_LT,0, opt_linkSigning,
			ARG_VALUE_FORM, HLP_LINK_SIGN_LT},
	{ODI,0,ARG_TRUSTED_NODES_DIR,     0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_TRUSTED_NODES_DIR, opt_dir_watch,
			ARG_DIR_FORM,"directory with global-id hashes of this node's trusted other nodes"},
	{ODI,0,ARG_SUPPORTED_NODES_DIR,   0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_SUPPORTED_NODES_DIR, opt_dir_watch,
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
	handl.data_header_size = sizeof(struct frame_hdr_signature);
	handl.min_msg_size = sizeof(struct frame_msg_signature);
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_packet_signature;
        handl.rx_frame_handler = process_packet_signature;
	handl.msg_format = frame_signature_format;
        register_frame_handler(packet_frame_db, FRAME_TYPE_SIGNATURE_ADV, &handl);



	static const struct field_format pubkey_format[] = DESCRIPTION_MSG_PUBKEY_FORMAT;
        handl.name = "DSC_NODE_KEY";
	handl.alwaysMandatory = 1;
        handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&fref_always_l1;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_nodeKey;
        handl.rx_frame_handler = process_dsc_tlv_pubKey;
	handl.msg_format = pubkey_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_NODE_PUBKEY, &handl);

	static const struct field_format dsc_signature_format[] = DESCRIPTION_MSG_SIGNATURE_FORMAT;
        handl.name = "DSC_SIGNATURE";
	handl.alwaysMandatory = 1;
	handl.min_msg_size = sizeof(struct dsc_msg_signature);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&fref_never;
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

	handl.name = "DSC_LINK_KEY";
	handl.alwaysMandatory = 0;
	handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
	handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*) &fref_always_l1;
	handl.dextCompression = (int32_t*) &never_fzip;
	handl.tx_frame_handler = create_dsc_tlv_linkKey;
	handl.rx_frame_handler = process_dsc_tlv_pubKey;
	handl.msg_format = pubkey_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_LINK_PUBKEY, &handl);



	static const struct field_format trust_format[] = DESCRIPTION_MSG_TRUST_FORMAT;
        handl.name = "DSC_TRUSTS";
	handl.alwaysMandatory = 0;
        handl.min_msg_size = sizeof(struct dsc_msg_trust);
        handl.fixed_msg_size = 1;
	handl.dextReferencing = (int32_t*)&fref_always_l2;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_trusts;
        handl.rx_frame_handler = process_dsc_tlv_trusts;
	handl.msg_format = trust_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_TRUSTS, &handl);

        handl.name = "DSC_SUPPORTS";
	handl.alwaysMandatory = 0;
        handl.min_msg_size = sizeof(struct dsc_msg_trust);
        handl.fixed_msg_size = 1;
	handl.dextReferencing = (int32_t*)&fref_always_l2;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_trusts;
        handl.rx_frame_handler = process_dsc_tlv_supports;
	handl.msg_format = trust_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SUPPORTS, &handl);

}

void cleanup_sec( void )
{
        cryptKeyFree(&my_NodeKey);

	if (my_LinkKey) {
		task_remove(update_dsc_tlv_linkKey, NULL);
		cryptKeyFree(&my_LinkKey);
	}

	cleanup_dir_watch(&trustedDirWatch);
	cleanup_dir_watch(&supportDirWatch);
}
