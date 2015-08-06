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

#define CODE_CATEGORY_NAME "message"

static IDM_T test_unsknown_packet_and_desc_frames_are_simply_ignored;

static int32_t drop_all_packets = DEF_DROP_ALL_PACKETS;

int32_t pref_udpd_size = DEF_UDPD_SIZE;

int32_t txCasualInterval = DEF_TX_CASUAL_INTERVAL;
int32_t txMinInterval = DEF_TX_MIN_INTERVAL;

int32_t overlappingBursts = DEF_OVERLAPPING_BURSTS;


uint32_t txBucket = 0;
int32_t txBucketSize = DEF_TX_BUCKET_SIZE;

static int32_t dextReferencing = DEF_FREF;
static int32_t dextCompression = DEF_FZIP;


const int32_t fref_always_l1 = TYP_FREF_DO1;
const int32_t fref_always_l2 = TYP_FREF_DO2;
const int32_t fref_never = TYP_FREF_DONT;
const int32_t fref_dflt = TYP_FREF_DFLT;

const int32_t never_fzip = TYP_FZIP_DONT;
const int32_t dflt_fzip = TYP_FZIP_DFLT;



union schedule_hello_info {
        uint8_t u8[2];
        uint16_t u16;
};


static AVL_TREE( txTask_tree, struct tx_task_node, key);




static int32_t dbg_frame_types = DEF_DBG_FRAME_TYPES;


static IDM_T first_packets = YES;
BURST_SQN_T myBurstSqn = 0;










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
struct frame_db *description_tlv_db = NULL;




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
struct frame_db *init_frame_db(uint8_t handlSz, uint8_t processUnVerifiedLinks, char *name, int8_t double_frame_types) {

	struct frame_db *db = debugMallocReset(sizeof(struct frame_db) + (handlSz * sizeof(struct frame_handl)), -300622);

	db->handl_max = handlSz -1;
	db->double_frame_types = double_frame_types;
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

	static int32_t tx_iterations = 1;
	handl->tx_task_interval_min = handl->tx_task_interval_min ? handl->tx_task_interval_min : 1;
	handl->tx_iterations = handl->tx_iterations ? handl->tx_iterations : &tx_iterations;

        db->handls[pos] = *handl;


        memset(handl, 0, sizeof ( struct frame_handl ) );
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
        it->f_type_expanded = ((it->f_type == -1) ? -1 : it->f_type_expanded); //avoids init to -1
	int8_t f_type_prev = it->f_type_expanded;
	int32_t result = TLV_RX_DATA_FAILURE;
	struct dsc_hdr_chash chHdr = {.u.u32 = 0};

	it->f_handl = NULL;
	it->f_msgs_len = 0;
	it->f_msgs_fixed = 0;
	it->f_msg = 0;

        dbgf_all(DBGT_INFO, "%s - db=%s f_type_prev=%d f_pos=%d f_len=%d",
	        it->caller, it->db->name, f_type_prev, it->_f_pos_next, it->frames_length);

        if (it->frames_in && it->_f_pos_next == it->frames_length ) {

		if (missed_mandatory_frames(it, f_type_prev+1, it->db->handl_max))
			goto_error(rx_frame_iterate_error, "missing mandatory frame");

                dbgf_all(DBGT_INFO, "%s - frames_pos=%d frames_length=%d : DONE", it->caller, it->_f_pos_next, it->frames_length);
                return TLV_RX_DATA_DONE;


        } else if (it->frames_in && it->_f_pos_next + (int32_t)sizeof(struct tlv_hdr) < it->frames_length) {

		struct tlv_hdr *tlv = (struct tlv_hdr *) (it->frames_in + it->_f_pos_next);
		struct tlv_hdr tmp = {.u.u16 = ntohs(tlv->u.u16)};
		it->f_type = it->f_type_expanded = tmp.u.tlv.type;
		it->f_dlen = tmp.u.tlv.length - sizeof (struct tlv_hdr);
		it->f_data = (uint8_t*)&(tlv[1]);

		it->_f_len = tmp.u.tlv.length;
		it->_f_pos_next = it->_f_pos_next + tmp.u.tlv.length;

		if (it->_f_pos_next > it->frames_length || it->f_dlen <= 0 )
			goto_error(rx_frame_iterate_error, "invalid frames_length");

		if (it->db == description_tlv_db && it->f_type == BMX_DSC_TLV_CONTENT_HASH) {

			if ((it->f_dlen >= (int)sizeof(struct dsc_hdr_chash)) &&
				(chHdr.u.u32 = ntohl(((struct dsc_hdr_chash*)it->f_data)->u.u32)) &&
				(chHdr.u.i.expanded_length <= vrt_frame_data_size_in) &&
				(chHdr.u.i.maxNesting <= vrt_frame_max_nesting) &&
				(chHdr.u.i.gzip <= 1) &&
				(IMPLIES(chHdr.u.i.maxNesting >= 1, !((it->f_dlen - sizeof(struct dsc_hdr_chash)) % sizeof(SHA1_T)) )) &&
				(IMPLIES(chHdr.u.i.maxNesting >= 1 && chHdr.u.i.gzip, ((it->f_dlen - sizeof(struct dsc_hdr_chash)) / sizeof(SHA1_T)) >= 1)) &&
				(IMPLIES(chHdr.u.i.maxNesting == 1 && !chHdr.u.i.gzip && it->f_dlen != sizeof(struct dsc_hdr_chash), ((it->f_dlen - sizeof(struct dsc_hdr_chash)) / sizeof(SHA1_T)) >= 2)) &&
				(IMPLIES(chHdr.u.i.maxNesting == 2 && !chHdr.u.i.gzip && it->f_dlen != sizeof(struct dsc_hdr_chash), ((it->f_dlen - sizeof(struct dsc_hdr_chash)) / sizeof(SHA1_T)) >= 1)) &&
				(IMPLIES(chHdr.u.i.maxNesting == 0, chHdr.u.i.gzip && it->f_dlen > (int) sizeof(struct dsc_hdr_chash)))
				) {

				it->f_type_expanded = chHdr.u.i.expanded_type;

			} else {
				goto_error(rx_frame_iterate_error, "invalid chash hdr or exceeded size");
			}
		}

		if (it->f_type_expanded == BMX_DSC_TLV_CONTENT_HASH)
			goto_error(rx_frame_iterate_error, "chash hdr expanded type");


	} else if (!it->frames_in && it->dcNew) {

		int8_t f_type = it->f_type;
		while( ((++f_type) <= it->db->handl_max) && !contents_data(it->dcNew, f_type));

		if (f_type > it->db->handl_max) {
			if (missed_mandatory_frames(it, f_type_prev+1, it->db->handl_max))
				goto_error(rx_frame_iterate_error, "missing mandatory frame");

			if ( it->db == description_tlv_db && it->on && it->dcOld && it->op == TLV_OP_NEW &&
				it->process_filter == FRAME_TYPE_PROCESS_ALL && f_type_prev < it->db->handl_max ) {
				assertion(-502432, (it->dcOld != it->dcNew));
				process_description_tlvs_del( it->on, it->dcOld, (f_type_prev + 1), it->db->handl_max );
			}

			return TLV_RX_DATA_DONE;
		}

		it->f_type = it->f_type_expanded = f_type;
		it->f_dlen = contents_dlen(it->dcNew, f_type);
		it->f_data = contents_data(it->dcNew, f_type);

		it->_f_len = 0;
		it->_f_pos_next = 0;

	} else {
		assertion(-502433, (0));
	}


	if (it->f_type > it->db->handl_max || !(it->db->handls[it->f_type].rx_frame_handler || it->db->handls[it->f_type].rx_msg_handler)) {

		dbgf_mute(50, DBGL_SYS, DBGT_WARN, "%s - unknown type=%d->%d ! check for updates", it->caller, it->f_type, it->f_type_expanded);
		return my_conformance_tolerance ? TLV_RX_DATA_PROCESSED : TLV_RX_DATA_REJECTED;

	} else {
		it->f_handl = &it->db->handls[it->f_type];
		it->f_msgs_len = it->f_dlen - it->f_handl->data_header_size;
		it->f_msgs_fixed = (it->f_handl->fixed_msg_size && it->f_handl->min_msg_size) ? (it->f_msgs_len / it->f_handl->min_msg_size) : 0;
		it->f_msg = it->f_data + it->f_handl->data_header_size;

		if (f_type_prev >= it->f_type_expanded + it->db->double_frame_types)
			goto_error(rx_frame_iterate_error, "unordered or double frame_type");

		if (missed_mandatory_frames(it, f_type_prev+1, it->f_type_expanded-1))
			goto_error(rx_frame_iterate_error, "missing mandatory frame");

                if (it->f_handl->rx_msg_handler ? // only frame_handler support zero messages per frame!
                        (it->f_msgs_len < it->f_handl->min_msg_size) :
                        (it->f_msgs_len < it->f_handl->min_msg_size && it->f_msgs_len != 0)
                        ) {
			goto_error(rx_frame_iterate_error, "too small frame_msgs_length");
                }

		if (it->f_handl->fixed_msg_size && (it->f_handl->min_msg_size ?
			(it->f_msgs_len % it->f_handl->min_msg_size) : (it->f_msgs_len) ) ) {
			goto_error(rx_frame_iterate_error, "non-matching fixed_msgs_size");
		}

		if (it->db == description_tlv_db && it->on && it->dcOld && it->op == TLV_OP_NEW &&
			it->process_filter == FRAME_TYPE_PROCESS_ALL && f_type_prev + 1 < it->f_type) {

			process_description_tlvs_del( it->on, it->dcOld, (f_type_prev + 1), (it->f_type - 1) );
		}

		dbgf((it->dbgl & (1<<it->f_type) ? DBGL_CHANGES : DBGL_ALL), DBGT_INFO,
			 "%s - type=%s->%s f_data_length=%d",
			 it->caller, it->f_handl->name, it->db->handls[it->f_type_expanded].name, it->f_dlen);


                if (!(it->process_filter == FRAME_TYPE_PROCESS_ALL || it->process_filter == it->f_type)) {

                        dbgf_all(DBGT_INFO, "%s - type=%d process_filter=%d : IGNORED", it->caller, it->f_type, it->process_filter);
                        return TLV_RX_DATA_PROCESSED;

		} else if (!(it->f_handl->rx_processUnVerifiedLink || it->db->rx_processUnVerifiedLink) && !it->pb->i.verifiedLink) {

			dbgf_track(DBGT_INFO, "%s - NON-VERIFIED link to neigh=%s, needed for frame type=%s db=%s",
				it->caller, it->pb->i.llip_str, it->f_handl->name, it->db->name);

			return TLV_RX_DATA_PROCESSED;

                } else if (it->op >= TLV_OP_PLUGIN_MIN && it->op <= TLV_OP_PLUGIN_MAX) {

                        return TLV_RX_DATA_PROCESSED;

                } else if (it->f_handl->rx_msg_handler && it->f_handl->fixed_msg_size) {

                        while (it->f_msg < it->f_data + it->f_dlen && (
                                (result = ((*(it->f_handl->rx_msg_handler)) (it))) == it->f_handl->min_msg_size || result == TLV_RX_DATA_PROCESSED) ) {

                                it->f_msg += it->f_handl->min_msg_size;
                        }

                        if (it->f_msg == it->f_data + it->f_dlen) {
				return TLV_RX_DATA_PROCESSED;
			} else {
				assertion(-502072, (result == TLV_RX_DATA_BLOCKED || result == TLV_RX_DATA_DONE || result == TLV_RX_DATA_FAILURE || result == TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_REBOOTED));
				goto_error(rx_frame_iterate_error, "failed rx_msg_handler");
                        }


                } else if (it->f_handl->rx_frame_handler) {

                        result = (*(it->f_handl->rx_frame_handler)) (it);

			if ( result == it->f_msgs_len || result == TLV_RX_DATA_PROCESSED) {
				return TLV_RX_DATA_PROCESSED;
			} else {
				assertion(-502073, (result == TLV_RX_DATA_BLOCKED || result == TLV_RX_DATA_DONE || result == TLV_RX_DATA_FAILURE || result == TLV_RX_DATA_REJECTED || result == TLV_RX_DATA_REBOOTED));
				goto_error(rx_frame_iterate_error, "failed rx_frame_handler");
                        }
                }

                assertion(-501018, (0));
	}

rx_frame_iterate_error:{

		dbgf_mute(50, result == TLV_RX_DATA_FAILURE ? DBGL_SYS : DBGL_CHANGES,
			result == TLV_RX_DATA_FAILURE ? DBGT_ERR : DBGT_INFO,
			"%s - db_name=%s problem=\"%s\" result=%s dhn=%d frame_type=%d=%s prev_expanded=%d %s=%d "
			"frames_length=%d f_pos_next=%d f_dlen=%d f_mlen=%d "
			"exp_type=%d exp_len=%d gzip=%d maxNesting=%d expHash=%s "
			"f_data=%s",
			it->caller, it->db->name, goto_error_code, tlv_rx_result_str(result),
			!!it->dcNew, it->f_type, (it->f_handl ? it->f_handl->name : NULL), it->f_type_expanded,
			ARG_VRT_FRAME_DATA_SIZE_IN, vrt_frame_data_size_in,
			it->frames_length, it->_f_pos_next, it->f_dlen, it->f_msgs_len,
			chHdr.u.i.expanded_type, chHdr.u.i.expanded_length, chHdr.u.i.gzip, chHdr.u.i.maxNesting, cryptShaAsShortStr(&chHdr.expanded_chash),
			(it->f_data && it->f_dlen) ? memAsHexString(it->f_data, it->f_dlen) : NULL);

	EXITERROR(-502074, result != TLV_RX_DATA_FAILURE);
        return result;
}
}




STATIC_FUNC
int8_t send_bmx_packet(struct packet_buff *pb, struct dev_node *dev, int len)
{
	TRACE_FUNCTION_CALL;

	if (!dev->active || dev->linklayer == TYP_DEV_LL_LO)
		return 0;

	int status;
	struct sockaddr_storage *dst = &dev->tx_netwbrc_addr;
	int32_t send_sock = dev->unicast_sock;

	pb->i.length = len;
	pb->i.oif = dev;
	pb->i.oif->udpTxPacketsCurr += 1;
	pb->i.oif->udpTxBytesCurr += pb->i.length;


	dbgf_all(DBGT_INFO, "len=%d via dev=%s", pb->i.length, pb->i.oif->label_cfg.str);

	if ( send_sock == 0 )
		return 0;

	cb_packet_hooks(pb);

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

uint8_t use_refLevel(struct frame_handl *handl)
{
	uint8_t ret =
		(!handl->dextReferencing ? TYP_FREF_DONT :
		(*handl->dextReferencing != TYP_FREF_DFLT ? *handl->dextReferencing :
		(dextReferencing != TYP_FREF_DFLT ? (dextReferencing) : DEF_FREF)));

	assertion(-502433, (ret <= TYP_FREF_DO3));
	return ret;
}


static inline int32_t tx_iterator_cache_data_space_sched(struct tx_frame_iterator *it)
{
	return((!it->frames_out_pos && !it->frame_cache_msgs_size) || (it->db == packet_frame_db && it->prev_out_type == FRAME_TYPE_SIGNATURE_ADV)) ?
		tx_iterator_cache_data_space_max(it, 0, 0) : tx_iterator_cache_data_space_pref(it, 0, 0);
}


int32_t _tx_iterator_cache_data_space(struct tx_frame_iterator *it, IDM_T max, int32_t len, int32_t rsvd)
{
	assertion(-502434, (len >= 0));

	struct frame_handl *handl = &(it->db->handls[it->frame_type]);
	uint8_t level = use_refLevel(handl);

	if (level) {

		//TODO: this works only for a reference depth = 1

		int32_t used_cache_space = handl->data_header_size + it->frame_cache_msgs_size;

		int32_t used_ref_msgs = used_cache_space/REF_CONTENT_BODY_SIZE_OUT + (used_cache_space%REF_CONTENT_BODY_SIZE_OUT?1:0);


		int32_t hdr_frame_space = (int) sizeof(struct tlv_hdr) + (int) sizeof(struct dsc_hdr_chash) + ((int) sizeof(struct dsc_msg_chash) * used_ref_msgs);

		int32_t unused_root_space = (max ? it->frames_out_max : it->frames_out_pref) - (it->frames_out_pos - rsvd);

		int32_t unused_level1_space = ((unused_root_space/((int)sizeof(struct dsc_msg_chash))) * ((int)REF_CONTENT_BODY_SIZE_OUT));
		int32_t unused_level2_space = (level==2 ? ((unused_level1_space/((int)sizeof(struct dsc_msg_chash))) * ((int)REF_CONTENT_BODY_SIZE_OUT)) : unused_level1_space);

		int32_t avail_ref_space = (unused_root_space > hdr_frame_space ) ? (unused_level2_space - hdr_frame_space) : 0;

		int32_t space = XMIN(it->frame_cache_size - used_cache_space, avail_ref_space);

		dbgf((len + 100 >= space ? DBGL_CHANGES : DBGL_ALL), (len + 100 >= space ? DBGT_WARN : DBGT_INFO),
			"type=%s max=%d len=%d  fom=%d fop=%d fcs=%d  ucs=%d urm=%d hfs=%d ul1s=%d ul2s=%d ars=%d space=%d",
			handl->name, max, len, it->frames_out_max, it->frames_out_pref, it->frame_cache_size,
			used_cache_space, used_ref_msgs, hdr_frame_space, 
			unused_level1_space, unused_level2_space, avail_ref_space, space);

		assertion(-502435, (avail_ref_space >= 0));
		assertion(-502436, (it->frame_cache_size >= used_cache_space));

		if (len)
			return (len <= space);
		else
			return space;

	} else {

		int32_t frame_space =
			(max ? it->frames_out_max : it->frames_out_pref) - (
			it->frames_out_pos +
			(int) sizeof(struct tlv_hdr) + handl->data_header_size +
			it->frame_cache_msgs_size );

		int32_t cache_space = it->frame_cache_size - it->frame_cache_msgs_size;

		assertion(-502437, (cache_space >= 0));

		int32_t space = XMIN(frame_space, cache_space);

		if (len)
			return (len <= space);
		else
			return space;
	}
}



STATIC_FUNC
void tx_frame_iterate_finish_(struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;
	struct frame_handl *handl = &(it->db->handls[it->frame_type]);
	int32_t fdata_len = it->frame_cache_msgs_size + handl->data_header_size;
	struct tlv_hdr *tlv = (struct tlv_hdr *) (it->frames_out_ptr + it->frames_out_pos);
	uint8_t gzip = use_compression(handl);
	uint8_t level = use_refLevel(handl);

	dbgf_all(DBGT_INFO, "%s %s fdata_len=%d prev_out_type=%d gzip=%d level=%d", it->db->name, handl->name, fdata_len, it->prev_out_type, gzip, level);
	assertion(-502438, (it->frame_type != BMX_DSC_TLV_CONTENT_HASH));
	assertion(-500881, (it->frame_cache_msgs_size >= TLV_TX_DATA_PROCESSED));
	assertion(-501638, (it->frame_cache_msgs_size <= vrt_frame_data_size_out));
	assertion(-500786, (tx_iterator_cache_data_space_max(it, 0, 0) >= 0));
	assertion(-500355, (IMPLIES(handl->fixed_msg_size && handl->min_msg_size, !(it->frame_cache_msgs_size % handl->min_msg_size))));
	assertion(-500355, (IMPLIES(handl->fixed_msg_size && !handl->min_msg_size, !it->frame_cache_msgs_size)));
	ASSERTION(-501003, (is_zero((it->frame_cache_array + it->frame_cache_msgs_size + handl->data_header_size), tx_iterator_cache_data_space_max(it, 0, 0))));
	assertion(-501019, (fdata_len)); // there must be some data to send!!


	if (it->db == description_tlv_db && (gzip || level)) {

		it->frames_out_pos += create_chash_tlv(tlv, it->frame_cache_array, fdata_len, it->frame_type, gzip, level);

	} else {

		*tlv = tlvSetBigEndian(it->frame_type, (sizeof( struct tlv_hdr) +fdata_len));
		it->frames_out_pos += sizeof( struct tlv_hdr) +fdata_len;
		assertion(-501652, (it->frames_out_pos <= (int32_t) PKT_FRAMES_SIZE_MAX));

		memcpy(&(tlv[1]), it->frame_cache_array, fdata_len);
	}

	it->prev_out_type = it->frame_type;

	memset(it->frame_cache_array, 0, fdata_len);
	it->frame_cache_msgs_size = 0;
}

/*
 * iterates over to be created frames and stores them (including frame_header) in it->frames_out  */
int32_t tx_frame_iterate(IDM_T iterate_msg, struct tx_frame_iterator *it)
{
	TRACE_FUNCTION_CALL;

	if(it->ttn)
		it->frame_type = it->ttn->key.f.type;

	struct frame_handl *handl = (it->handl = &(it->db->handls[it->frame_type]));
	int32_t result = TLV_TX_DATA_FAILURE;

	if (!handl->name)
		return TLV_TX_DATA_DONE;

	assertion(-502075, IMPLIES(handl->tx_frame_handler, !iterate_msg));
	assertion(-502076, XOR(handl->tx_frame_handler, handl->tx_msg_handler));
	assertion(-500776, (it->frame_cache_array));
	assertion(-500779, (it->frames_out_pos <= it->frames_out_max));
        assertion(-500780, (it->frames_out_ptr));
        assertion(-500781, (it->frame_type <= it->db->handl_max));
	assertion(-500784, (IMPLIES(it->frame_cache_msgs_size, it->frame_cache_msgs_size >= TLV_TX_DATA_PROCESSED)));
        assertion(-501004, (IMPLIES(it->frame_cache_msgs_size, handl->tx_msg_handler)));
        ASSERTION(-500777, (IMPLIES((it->frame_cache_msgs_size && handl->tx_msg_handler),
                is_zero(tx_iterator_cache_msg_ptr(it), tx_iterator_cache_data_space_max(it, 0, 0)))));
        ASSERTION(-501000, (IMPLIES((!it->frame_cache_msgs_size || handl->tx_frame_handler),
                is_zero(it->frame_cache_array, tx_iterator_cache_data_space_max(it, 0, 0)))));


	if ((handl->tx_msg_handler && iterate_msg) || handl->tx_frame_handler) {

		int cdsp = 0, cdss = 0;
		if (
			(handl->min_msg_size > (cdsp=tx_iterator_cache_data_space_pref(it, 0, 0))) ||
			(it->ttn && it->ttn->frame_msgs_length > (cdss=tx_iterator_cache_data_space_sched(it))) ) {

			dbgf_track(DBGT_WARN, "ft=%d mms=%d cdsp=%d, fml=%d cdss=%d",
				it->frame_type, handl->min_msg_size, cdsp, it->ttn ? it->ttn->frame_msgs_length : 0, cdss);
			return TLV_TX_DATA_FULL;
		}
	}

	if (handl->tx_msg_handler && iterate_msg) {

		result = (*(handl->tx_msg_handler)) (it);

		if (result >= TLV_TX_DATA_PROCESSED)
			it->frame_cache_msgs_size += result;

	} else if (handl->tx_msg_handler && !iterate_msg) {

		tx_frame_iterate_finish_(it);
		return TLV_TX_DATA_PROCESSED;

	} else if (handl->tx_frame_handler) {

		result = (*(handl->tx_frame_handler)) (it);

		if (result == 0 && !handl->data_header_size) {
			return TLV_TX_DATA_IGNORED;

		} else if (result >= TLV_TX_DATA_PROCESSED) {

			it->frame_cache_msgs_size = result;
			tx_frame_iterate_finish_(it);
			return TLV_TX_DATA_PROCESSED;
		}
	}
	assertion(-502439, (result != TLV_TX_DATA_FAILURE));
	return result;
}



IDM_T purge_tx_task_tree(struct neigh_node *onlyNeigh, struct dev_node *onlyDev, struct tx_task_node *onlyTtn, IDM_T force)
{
	TRACE_FUNCTION_CALL;
	IDM_T removed = 0;
	struct tx_task_node *curr, *next = onlyTtn ? onlyTtn : avl_first_item(&txTask_tree);

	while ((curr = next)) {
		next = onlyTtn ? NULL : avl_next_item(&txTask_tree, &curr->key);

		if ((onlyNeigh && onlyNeigh != curr->neigh) || (onlyDev && onlyDev != curr->key.f.p.dev) || (onlyTtn && onlyTtn != curr))
			continue;

		if (force || (curr->tx_iterations <= 0 && ((TIME_T) (bmx_time - curr->send_ts) > packet_frame_db->handls[curr->key.f.type].tx_task_interval_min))) {

			avl_remove(&txTask_tree, &curr->key, -300715);

			curr->key.f.p.dev->tx_task_items--;

			debugFree(curr, -300169);

			removed++;

			if (onlyTtn)
				return removed;
		}
	}

	return removed;
}






STATIC_FUNC
struct tx_task_node *get_next_ttn( struct tx_task_node *curr) {

	struct tx_task_node *next;
	struct tx_task_node *nextp = avl_next_item(&txTask_tree, curr ? &curr->key: NULL);

	while ((next = nextp)) {

		nextp = avl_next_item(&txTask_tree, &next->key);

		if ((purge_tx_task_tree(NULL, NULL, next, NO) == NO) &&
			 (next->tx_iterations > 0) &&
			 ((TIME_T) (bmx_time - next->send_ts) >= packet_frame_db->handls[next->key.f.type].tx_task_interval_min)) {

			return next;
		}
	}

	return NULL;
}

TIME_T nextBucketSchedule(TIME_T minInterval, TIME_T drainInterval, TIME_T maxInterval, uint32_t *debtBucket, uint32_t debtLimit, TIME_T *last, IDM_T send, uint32_t variation)
{
	assertion(-502440, (minInterval <= drainInterval && drainInterval <= maxInterval));
	TIME_T elapsed = (((TIME_T) (bmx_time - *last)) > maxInterval) ? maxInterval : ((TIME_T) (bmx_time - *last));
	uint32_t bucketCoinDrain = (elapsed * BUCKET_COIN_SCALE) / drainInterval;

	*debtBucket -= (*debtBucket > bucketCoinDrain) ? bucketCoinDrain : *debtBucket;
	*debtBucket += send ? BUCKET_COIN_SCALE : 0;
	*last = bmx_time;
	
	TIME_T nextInterval = (*debtBucket < (debtLimit * BUCKET_COIN_SCALE)) ? minInterval : maxInterval;

	return (nextInterval + rand_num(nextInterval / variation) - (nextInterval / (2 * variation)));
}


void tx_packets( void *unused ) {

        TRACE_FUNCTION_CALL;
	static TIME_T txCasualNext = 0;
	static TIME_T txBucketLast = 0;
	struct tx_task_node *nextTask = NULL;
	uint8_t ft;

        dbgf_all(DBGT_INFO, " ");


	myKey->currOrig->descContent->dhn->referred_by_me_timestamp = bmx_time;

	// These are always scheduled as needed (if my_tx_interval is due)
	for (ft = 0; ft <= FRAME_TYPE_MAX_KNOWN; ft++) {
		if (packet_frame_db->handls[ft].tx_packet_prepare_always)
			(*(packet_frame_db->handls[ft].tx_packet_prepare_always))();
	}

	if (doNowOrLater(&txCasualNext, txCasualInterval, !!get_next_ttn(NULL))) {

		// These are only scheduled if something is send anyway or if txCasualInterval is due
		for (ft = 0; ft <= FRAME_TYPE_MAX_KNOWN; ft++) {
			if (packet_frame_db->handls[ft].tx_packet_prepare_casuals)
				(*(packet_frame_db->handls[ft].tx_packet_prepare_casuals))();
		}

		nextTask = get_next_ttn(NULL);
	}
	TIME_T nextSchedule = nextBucketSchedule(txMinInterval, ((txCasualInterval*DEF_TX_BUCKET_DRAIN)/100), txCasualInterval, &txBucket, txBucketSize, &txBucketLast, !!nextTask, 10);

	task_register(nextSchedule, tx_packets, NULL, -300353);

	if (!nextTask)
		return;

	prof_start( tx_packets, main );

	int32_t result;
	static uint8_t cache_data_array[PKT_FRAMES_SIZE_MAX - sizeof(struct tlv_hdr)] = {0};
	static struct packet_buff pb;
        memset(&pb.i, 0, sizeof (pb.i));
        struct tx_frame_iterator it = {
                .caller = __FUNCTION__, .db = packet_frame_db, .prev_out_type = -1,
                .frames_out_ptr = (pb.p.data + sizeof (struct packet_header)),
		.frames_out_max = PKT_FRAMES_SIZE_MAX, .frames_out_pref = PKT_FRAMES_SIZE_PREF,
		.frame_cache_array = cache_data_array, .frame_cache_size = sizeof(cache_data_array),
        };


	while ((nextTask)) {

		if (nextTask->key.f.type > FRAME_TYPE_OGM_AGG_SQN_ADV && it.frames_out_pos==0) {
			struct tx_task_node ttn = {.key = {.f = {.p = {.dev = nextTask->key.f.p.dev}}}};
			it.ttn = &ttn;
			
			ttn.key.f.type = FRAME_TYPE_SIGNATURE_ADV;
			result = tx_frame_iterate(NO, &it);

			ttn.key.f.type = FRAME_TYPE_OGM_AGG_SQN_ADV;
			result = tx_frame_iterate(NO, &it);
		}

		it.ttn = nextTask;
		it.frame_type = it.ttn->key.f.type;

		result = tx_frame_iterate(it.db->handls[it.frame_type].tx_msg_handler ? YES : NO, &it);

		assertion_dbg(-502441, (result==TLV_TX_DATA_FULL || result==TLV_TX_DATA_DONE || result==TLV_TX_DATA_IGNORED || result>=TLV_TX_DATA_PROCESSED),
			 "frame_type=%d tlv_result=%d", it.frame_type, result);

		if (result != TLV_TX_DATA_FULL)
			nextTask = get_next_ttn(nextTask);

		if ((result == TLV_TX_DATA_FULL || !nextTask || memcmp(&it.ttn->key.f, &nextTask->key.f, sizeof(nextTask->key.f))) &&
			 it.handl->tx_msg_handler && it.frame_cache_msgs_size) {

			tx_frame_iterate(NO/*iterate_msg*/, &it);
		}

		if (result == TLV_TX_DATA_DONE) {

			it.ttn->tx_iterations = 0;

		} else if (result >= TLV_TX_DATA_PROCESSED) {

			it.ttn->send_ts = bmx_time;
			it.ttn->tx_iterations--;

		} else if (result == TLV_TX_DATA_FULL) {

			assertion(-502442, (it.frame_type < FRAME_TYPE_SIGNATURE_ADV || it.frame_type > FRAME_TYPE_OGM_AGG_SQN_ADV));
			assertion(-502443, (!it.frame_cache_msgs_size));
			assertion(-500430, (it.frames_out_pos)); // single message larger than MAX_UDPD_SIZE
			assertion_dbg(-502444, IMPLIES(it.frame_type > FRAME_TYPE_OGM_AGG_SQN_ADV, it.frames_out_pos > (int) (FRM_SIGN_VERS_SIZE_MIN + my_PktKey->rawKeyLen)),
				"%d %d %d %d", it.frame_type, it.frames_out_pos, (FRM_SIGN_VERS_SIZE_MIN + my_PktKey->rawKeyLen));
		}

		if ((result == TLV_TX_DATA_FULL || !nextTask || memcmp(&it.ttn->key.f.p, &nextTask->key.f.p, sizeof(nextTask->key.f.p))) && it.frames_out_pos) {

			if (it.prev_out_type < FRAME_TYPE_SIGNATURE_ADV || it.prev_out_type > FRAME_TYPE_OGM_AGG_SQN_ADV) {

				memset(&pb.p.hdr, 0, sizeof(struct packet_header));
				pb.p.hdr.comp_version = my_compatibility;
				pb.p.hdr.keyHash = myKey->kHash;

				if (it.prev_out_type > FRAME_TYPE_OGM_AGG_SQN_ADV && my_PktKey && my_PktKey->rawKeyLen)
					it.db->handls[FRAME_TYPE_SIGNATURE_ADV].tx_frame_handler(&it);

				assertion(-502446, (it.frames_out_pos <= it.frames_out_max));

				send_bmx_packet(&pb, it.ttn->key.f.p.dev, it.frames_out_pos + sizeof( struct packet_header));
			}

			memset(&pb.i, 0, sizeof(pb.i));

			it.frames_out_pos = 0;
			it.prev_out_type = -1;
		}
	}

	if ((++myBurstSqn) > ((BURST_SQN_T)(-1000)))
		my_description_changed = YES;

	first_packets = NO;
	prof_stop();
}


void schedule_tx_task(uint8_t f_type, CRYPTSHA1_T *groupId, struct neigh_node *neigh, struct dev_node *dev, int16_t f_msgs_len, void *keyData, uint32_t keyLen)
{
	TRACE_FUNCTION_CALL;

	assertion(-502447, (f_type <= FRAME_TYPE_MAX));
	assertion(-502448, IMPLIES(dev, dev->active && dev->linklayer != TYP_DEV_LL_LO));
	assertion(-501047, (!cleaning_up)); // this function MUST NOT be called during cleanup
        assertion(-501090, (f_msgs_len >= SCHEDULE_MIN_MSG_SIZE));
	assertion(-502449, IMPLIES(keyData, keyLen));
	assertion(-501573, (keyLen <= TX_TASK_MAX_KEY_DATA_LEN));
	struct frame_handl *handl = &packet_frame_db->handls[f_type];
	assertion(-502450, (handl && handl->name));
	assertion(-502451, IMPLIES(handl->tx_iterations, *handl->tx_iterations > 0));

	if (!dev) {
		struct avl_node *an = NULL;
		while ((dev = avl_iterate_item(&dev_ip_tree, &an))) {
			if (dev->active && dev->linklayer != TYP_DEV_LL_LO)
				schedule_tx_task(f_type, groupId, neigh, dev, f_msgs_len, keyData, keyLen);
		}
		return;
	}


	dbgf((dbg_frame_types & (1<<f_type) ? DBGL_CHANGES : DBGL_ALL), DBGT_INFO,
		 "type=%s groupId=%s neigh=%s dev=%s msgs_len=%d data=%s len=%d",
		 handl->name, cryptShaAsString(groupId), neigh ? cryptShaAsShortStr(&neigh->local_id) : NULL,
		 dev ? dev->label_cfg.str : NULL, f_msgs_len, memAsHexString(keyData, keyLen), keyLen);

	if (dev->tx_task_items >= MAX_TX_TS_TREE_SIZE) {
		dbg_mute(20, DBGL_SYS, DBGT_WARN, "%s reached MAX_TX_TS_TREE_SIZE", dev ? dev->label_cfg.str : "all");
		return;
	}

	struct tx_task_node test = {
		.key =	{ .f = { .p = { .sign = (f_type >= FRAME_TYPE_SIGNATURE_ADV), .dev = dev}, .type = f_type, .groupId = groupId ? *groupId : ZERO_CYRYPSHA1} },
		.neigh = neigh, .tx_iterations = *(handl->tx_iterations),
		.send_ts = ((TIME_T) (bmx_time - handl->tx_task_interval_min)),
		.frame_msgs_length = (f_msgs_len == SCHEDULE_MIN_MSG_SIZE ? handl->min_msg_size : f_msgs_len)
	};

	if( keyData && keyLen)
		memcpy(test.key.data, keyData, keyLen);

        assertion(-500371, IMPLIES(handl->fixed_msg_size && handl->min_msg_size, !(test.frame_msgs_length % handl->min_msg_size)));
        assertion(-500371, IMPLIES(handl->fixed_msg_size && !handl->min_msg_size, !test.frame_msgs_length));


	 struct tx_task_node *ttn = NULL;

	 if ((ttn = avl_find_item(&txTask_tree, &test.key))) {
		 assertion(-502452, IMPLIES(ttn->neigh && test.neigh, ttn->neigh == test.neigh));
		 ttn->neigh = ttn->neigh ? ttn->neigh : test.neigh;
		 ttn->frame_msgs_length = test.frame_msgs_length;
		 ttn->tx_iterations = XMAX(ttn->tx_iterations, test.tx_iterations);
		 return;
	 }

        *(ttn = debugMalloc(sizeof ( struct tx_task_node), -300026)) = test;

	avl_insert(&txTask_tree, ttn, -300716);

	dev->tx_task_items++;
}





STATIC_FUNC
IDM_T rx_frames(struct packet_buff *pb)
{
        TRACE_FUNCTION_CALL;
        int32_t result;

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .op = 0, .pb = pb, .dbgl = dbg_frame_types,
                .db = packet_frame_db, .process_filter = FRAME_TYPE_PROCESS_ALL,
                .f_type = -1, .frames_in = (pb->p.data + sizeof (struct packet_header)),
                .frames_length = (pb->i.length - sizeof (struct packet_header))
	};

        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE);

        if (result <= TLV_RX_DATA_FAILURE) {

                dbgf_mute(40, DBGL_SYS, DBGT_WARN, "problematic frame_type=%s data_length=%d result=%s pos=%d ",
                        it.db->handls[it.f_type].name, it.f_dlen, tlv_rx_result_str(result), it._f_pos_next);

                return FAILURE;
	}


        return SUCCESS;
}

struct packet_buff *curr_rx_packet = NULL;

void rx_packet( struct packet_buff *pb )
{
        TRACE_FUNCTION_CALL;
	prof_start( rx_packet, main);
	char *goto_error_code = NULL;

	pb->i.claimedKey = NULL;
	pb->i.verifiedLink = NULL;
	pb->i.llip = (*((struct sockaddr_in6*) &(pb->i.addr))).sin6_addr;
        ip6ToStr(&pb->i.llip, pb->i.llip_str);

        assertion(-500841, ((pb->i.iif->active && pb->i.iif->if_llocal_addr)));

        if (drop_all_packets)
                goto finish;

	DevKey devIpKey = {.llip = pb->i.llip, .devIdx = 0};
	struct dev_node *myTxDev = ((myTxDev = avl_closest_item(&dev_ip_tree, &devIpKey)) && is_ip_equal(&myTxDev->llipKey.llip, &pb->i.llip)) ? myTxDev : NULL;
	IDM_T myTxKey = cryptShasEqual(&myKey->kHash, &pb->p.hdr.keyHash);

	if (myTxDev || myTxKey) {
		
		if (!!myTxDev != !!myTxKey)
			goto_error(process_packet_error, "Neighbor uses my key or llip");

		goto finish;
	}

	if (pb->i.length < (int)sizeof(pb->p.hdr.comp_version) ||
		pb->p.hdr.comp_version < (my_compatibility - 1) || pb->p.hdr.comp_version > (my_compatibility + 1))
		goto_error(process_packet_error, "Invalid compatibility!!!");

	if ((pb->i.length != (int) (sizeof(struct packet_header)) &&
		pb->i.length < (int) (sizeof(struct packet_header) + sizeof(struct tlv_hdr))) ||
		pb->i.length > (int) (PKT_FRAMES_SIZE_MAX + sizeof(struct packet_header)))
		goto_error(process_packet_error, "Invalid packet length!!!");

	if (!is_ip_net_equal(&pb->i.llip, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6)) {
		dbgf_all(DBGT_ERR, "non srcLlIp=%s", ip6AsStr(&pb->i.llip));
		goto finish;
	}

	curr_rx_packet = pb;
	pb->i.iif->udpRxPacketsCurr += 1;
	pb->i.iif->udpRxBytesCurr += pb->i.length;

	struct key_credits kc = {.pktId = 1};
	pb->i.claimedKey = keyNode_updCredits(&pb->p.hdr.keyHash, NULL, &kc);

        dbgf_all(DBGT_INFO, "via dev=%s devLlIp=%s srcLlIp=%s size=%d version=%i rsvd=%X nodeId=%s kState=%s",
		pb->i.iif->label_cfg.str, pb->i.iif->ip_llocal_str, pb->i.llip_str, pb->i.length,
		pb->p.hdr.comp_version, pb->p.hdr.reserved, cryptShaAsShortStr(&pb->p.hdr.keyHash),
		pb->i.claimedKey ? pb->i.claimedKey->bookedState->secName : NULL);

	cb_packet_hooks(pb);

        if (rx_frames(pb) == SUCCESS)
                goto finish;

process_packet_error:

        dbgf_mute(60, DBGL_SYS, DBGT_WARN,
                "Drop (remaining) problematic packet: from nodeId=%s via srcLlIp=%s dev=%s my_version=%d version=%i capabilities=%d len=%d myTxDev=%d myTxKey=%d problem=%s",
		cryptShaAsShortStr(&pb->p.hdr.keyHash), pb->i.llip_str, pb->i.iif->label_cfg.str,
		my_compatibility, pb->p.hdr.comp_version, pb->p.hdr.reserved, pb->i.length,
		!!myTxDev, !!myTxKey, goto_error_code);

	EXITERROR(-502453, 0);

finish:
	curr_rx_packet = NULL;
	prof_stop();
	return;
}











STATIC_FUNC
struct opt_type msg_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

#ifndef LESS_OPTIONS
	{ODI,0,ARG_FREF,                   0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dextReferencing,MIN_FREF,           MAX_FREF,          DEF_FREF,0,           opt_update_dext_method,
			ARG_VALUE_FORM, HLP_FREF},
	{ODI,0,ARG_FZIP,                   0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dextCompression,MIN_FZIP,           MAX_FZIP,          DEF_FZIP,0,           opt_update_dext_method,
			ARG_VALUE_FORM, HLP_FZIP},
        {ODI,0,ARG_TX_MIN_INTERVAL,         0,  9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &txMinInterval, MIN_TX_MIN_INTERVAL, MAX_TX_MIN_INTERVAL, DEF_TX_MIN_INTERVAL,0, NULL,
			ARG_VALUE_FORM,	"set aggregation interval (SHOULD be at most 1/5 of your and other's OGM interval)"},
        {ODI,0,ARG_TX_CASUAL_INTERVAL,    0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &txCasualInterval,MIN_TX_CASUAL_INTERVAL, MAX_TX_CASUAL_INTERVAL,DEF_TX_CASUAL_INTERVAL,0,    NULL,
			ARG_VALUE_FORM,	"set interval for scheduling periodic tasks interval in ms"},
        {ODI,0,ARG_TX_BUCKET_SIZE,        0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &txBucketSize,    MIN_TX_BUCKET_SIZE, MAX_TX_BUCKET_SIZE,DEF_TX_BUCKET_SIZE,0,    NULL,
			ARG_VALUE_FORM,	"set number of tx packets allowed to exceed average tx interval"},
        {ODI,0,ARG_OVERLAPPING_BURSTS,    0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &overlappingBursts,MIN_OVERLAPPING_BURSTS,MAX_OVERLAPPING_BURSTS,DEF_OVERLAPPING_BURSTS,0,    NULL,
			ARG_VALUE_FORM,	"set acceptable burst-sqn overlap for detecting duplicate packets"},
        {ODI, 0, ARG_UDPD_SIZE,            0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &pref_udpd_size, MIN_UDPD_SIZE,      MAX_UDPD_SIZE,     DEF_UDPD_SIZE,0,      0,
			ARG_VALUE_FORM,	HLP_UDPD_SIZE}
	,
	{ODI,0,ARG_DROP_ALL_PACKETS,     0, 9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&drop_all_packets,	MIN_DROP_ALL_PACKETS,	MAX_DROP_ALL_PACKETS,	DEF_DROP_ALL_PACKETS,0,	0,
			ARG_VALUE_FORM,	"drop all received packets"}
        ,
#endif
        {ODI, 0, ARG_DBG_FRAME_TYPES,       0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dbg_frame_types, MIN_DBG_FRAME_TYPES, MAX_DBG_FRAME_TYPES, DEF_DBG_FRAME_TYPES,0,  0,
			ARG_VALUE_FORM,	"bit array of debug-level 3 logged rx/tx frames types"}
};


void init_msg( void )
{
	assertion(-501567, (FRAME_TYPE_MASK >= FRAME_TYPE_MAX_KNOWN));
	assertion(-501568, (FRAME_TYPE_MASK >= BMX_DSC_TLV_MAX_KNOWN));

        assertion(-500998, (sizeof(struct tlv_hdr) == 2));

        assertion(-500347, (sizeof (DHASH_T) == CRYPT_SHA1_LEN));

	assertion(-502086, ( (tlvSetBigEndian(0x1B, 0x492)).u.u16 == htons(0xDC92) ) );

	description_tlv_db = init_frame_db(BMX_DSC_TLV_ARRSZ, 1, "description_tlv_db", 0);
	packet_frame_db = init_frame_db(FRAME_TYPE_ARRSZ, 0, "packet_frame_db", 1);

	register_options_array( msg_options, sizeof( msg_options ), CODE_CATEGORY_NAME );

	task_register(rand_num(txMinInterval), tx_packets, NULL, -300350);

}

void cleanup_msg( void )
{
//	update_my_description_adv();



	free_frame_db(&description_tlv_db);
	free_frame_db(&packet_frame_db);
}

