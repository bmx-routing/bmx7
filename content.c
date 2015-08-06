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

#define CODE_CATEGORY_NAME "content"

AVL_TREE(content_tree, struct content_node, chash);
uint32_t content_tree_unresolveds = 0;


int32_t unsolicitedContentAdvs = DEF_UNSOLICITED_CONTENT_ADVS;

STATIC_FUNC int8_t descContent_resolve(struct desc_content *dc, IDM_T init_not_finalize);



struct content_node * content_get(SHA1_T *chash)
{
	return avl_find_item(&content_tree, chash);
}

struct content_status {
	GLOBAL_ID_T *shortId;
	GLOBAL_ID_T *globalId;
	char *state;
	DESC_SQN_T descSqn;
	char contents[12]; //contentRefs
	char* name;
	uint16_t lastDesc;
	CRYPTSHA1_T *shortDHash;
	CRYPTSHA1_T *dHash;
	uint16_t rej;
	uint16_t lastRef;
	char neighs[12]; //neighRefs
	CRYPTSHA1_T *shortCHash;
	CRYPTSHA1_T *cHash;
	char *typeName;
	uint8_t typeId;
	int8_t fzip;
	int8_t fref;
	uint8_t final;
	uint8_t dup;
	uint8_t gzip;
	uint8_t nested;
	uint8_t level;
	uint8_t maxLevel;
	uint32_t len;
	uint32_t usages;
	char data[12];
};

static const struct field_format content_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  content_status, shortId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, content_status, globalId,      1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      content_status, state,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, descSqn,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       content_status, contents,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      content_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, lastDesc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  content_status, shortDHash,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, content_status, dHash,         1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, rej,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, lastRef,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       content_status, neighs,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  content_status, shortCHash,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, content_status, cHash,         1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      content_status, typeName,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, typeId,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, fzip,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, fref,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, final,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, dup,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, gzip,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, nested,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, level,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, maxLevel,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, len,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              content_status, usages,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       content_status, data,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

STATIC_FUNC
uint8_t *content_status_page(uint8_t *sOut, uint32_t i, struct content_usage_node *cun, struct content_node *cn)
{
	struct desc_content *dc = cun->k.descContent;
	struct key_node *kn = dc ? dc->key : cn->key;
	struct orig_node *on = kn ? kn->currOrig : NULL;

	struct content_status *cs = &(((struct content_status*)(sOut = debugRealloc(sOut, ((i+1)* sizeof (struct content_status)), -300366)))[i]);
	memset(cs, 0, sizeof(struct content_status));

	snprintf(cs->contents, sizeof(cs->contents), "---");
	snprintf(cs->neighs, sizeof(cs->neighs), "---");
	snprintf(cs->data, sizeof(cs->data), "---");

	if (kn) {
		cs->shortId = &kn->kHash;
		cs->globalId = &kn->kHash;
		cs->state = kn->bookedState->secName;
	}

	if (dc) {
		cs->dHash = &dc->dhn->dhash;
		cs->shortDHash= &dc->dhn->dhash;
		cs->descSqn = dc->descSqn;
		cs->rej =  dc->dhn->rejected;
		cs->lastRef = ((bmx_time - dc->dhn->referred_by_others_timestamp) / 1000);
		snprintf(cs->contents, sizeof(cs->contents), "%d/%d", (dc->contentRefs_tree.items - dc->unresolvedContentCounter), dc->contentRefs_tree.items);
	}

	if (kn || dc) {
		snprintf(cs->neighs, sizeof(cs->neighs), "%d/%d", (kn ? kn->neighRefs_tree.items : 0), (dc ? dc->dhn->neighRefs_tree.items : 0));
	}

	if (on) {
		cs->name = on->k.hostname;
		cs->lastDesc = (bmx_time - on->updated_timestamp) / 1000;
	}

	if (cn) {
		cs->cHash = &cn->chash;
		cs->shortCHash = &cn->chash;
		cs->len = cn->f_body_len;
		cs->gzip = cn->gzip;
		cs->nested = cn->nested;
		cs->usages = cn->usage_tree.items;
		if (cn->f_body)
			snprintf(cs->data, sizeof(cs->data), "%s%s",memAsHexString(cn->f_body, XMIN(cn->f_body_len, ((sizeof(cs->data)-4)/2))), (cn->f_body_len > ((sizeof(cs->data)-4)/2))?"...":"");
	}

	if (cun) {
		cs->typeId = cun->k.expanded_type;
		cs->typeName = (cun->k.expanded_type < BMX_DSC_TLV_MAX_KNOWN) ? description_tlv_db->handls[cun->k.expanded_type].name : "---";
		cs->fref = (cun->k.expanded_type < BMX_DSC_TLV_MAX_KNOWN) ? use_refLevel(&description_tlv_db->handls[cun->k.expanded_type]) : -1;
		cs->fzip = (cun->k.expanded_type < BMX_DSC_TLV_MAX_KNOWN) ? use_compression(&description_tlv_db->handls[cun->k.expanded_type]) : -1;
		cs->level = cun->maxUsedLevel;
		cs->maxLevel = cun->maxAllowedLevel;
		cs->final = (cun->k.descContent->final[cun->k.expanded_type].u.cun == cun);
		cs->dup = cun->dup;
	} else {
		cs->fref = -1;
		cs->fzip = -1;
	}

	return sOut;
}

static int32_t content_status_creator(struct status_handl *handl, void *data)
{
	uint32_t i = 0;

	struct avl_node *it;
	struct avl_node *an;
	struct key_node *kn;
	struct orig_node *on;
	struct content_node *cn;
	struct content_usage_node *cun;
	AVL_TREE(orig_name_tree, struct orig_node, k);

	for (it = NULL; (on = avl_iterate_item(&orig_tree, &it));)
		avl_insert(&orig_name_tree, on, -300746);

	while ((on = avl_remove_first_item(&orig_name_tree, -300747))) {

		for (an = NULL; (cun = avl_iterate_item(&on->descContent->contentRefs_tree, &an));)
			handl->data = content_status_page(handl->data, i++, cun, cun->k.content);

		for (an = NULL; on->key->nextDesc && (cun = avl_iterate_item(&on->key->nextDesc->contentRefs_tree, &an));)
			handl->data = content_status_page(handl->data, i++, cun, cun->k.content);
	}

	for (it = NULL; (kn = avl_iterate_item(&key_tree, &it));) {
		for (an = NULL; kn->nextDesc && !kn->currOrig && (cun = avl_iterate_item(&kn->nextDesc->contentRefs_tree, &an));)
			handl->data = content_status_page(handl->data, i++, cun, cun->k.content);
	}

	for (it = NULL; (cn = avl_iterate_item(&content_tree, &it));) {
		if (!cn->key && !cn->usage_tree.items)
			handl->data = content_status_page(handl->data, i++, NULL, cn);
	}

        return ((i)* sizeof (struct content_status));
}


STATIC_FUNC
SHA1_T *content_key(uint8_t *content_body, uint32_t content_body_len, uint8_t gzip, uint8_t maxNesting)
{
	static SHA1_T chash;

	assertion(-501616, (content_body && content_body_len));

	struct frame_hdr_content_adv chash_hdr = {.gzip=gzip, .maxNesting=maxNesting, .reserved=0};

	cryptShaNew(&chash_hdr, sizeof(chash_hdr));
	cryptShaUpdate(content_body, content_body_len);
	cryptShaFinal(&chash);

	dbgf_all(DBGT_INFO, "hdr=%s", memAsHexString(&chash_hdr, sizeof(chash_hdr)));
	dbgf_all(DBGT_INFO, "bdy=%s", memAsHexString(content_body, content_body_len));
	dbgf_all(DBGT_INFO, "sha=%s", cryptShaAsString(&chash));

	return &chash;
}

struct content_node * content_add_hash(SHA1_T *chash)
{
	assertion(-502241, (chash));
	struct content_node *cn = NULL;

	if (!(cn = avl_find_item(&content_tree, chash))) {
		cn = debugMallocReset(sizeof(struct content_node), -300731);
		AVL_INIT_TREE(cn->usage_tree, struct content_usage_node, k);
		cn->chash = *chash;
		avl_insert(&content_tree, cn, -300732);
		content_tree_unresolveds++;
	}

	return cn;
}

STATIC_FUNC
IDM_T contentUse_add_nested(struct desc_content *dc, SHA1_T *f_body, uint32_t f_body_len, uint8_t level, uint8_t maxLevel, uint8_t expanded_type);


struct content_node * content_add_body( uint8_t *body, uint32_t body_len, uint8_t gzip, uint8_t nested, uint8_t force)
{
	assertion(-502242, (body && body_len));

	SHA1_T *chash = content_key(body, body_len, gzip, nested);
	struct content_node *cn = force ? content_add_hash(chash) : content_get(chash);
	struct content_usage_node *cun;
	struct content_usage_node cit = {.maxUsedLevel = 0};
	struct desc_content *dc;
	struct avl_node *an = NULL; ;

	dbgf_track(DBGT_INFO, "unresolveds=%d cHash=%s gzip=%d maxNested=%d force=%d",
		content_tree_unresolveds, cryptShaAsShortStr(chash), gzip, nested, force);

	if (cn && !cn->f_body && (force || cn->usage_tree.items || cn->key)) {

		assertion(-502303, IMPLIES(cn->key, cn->key->bookedState->i.c >= KCTracked));


		cn->f_body = debugMalloc(body_len, -300733);
		memcpy(cn->f_body, body, body_len);
		cn->f_body_len = body_len;
		cn->gzip = gzip;
		cn->nested = nested;

		content_tree_unresolveds--;

		while ((cun = avl_next_item(&cn->usage_tree, &cit.k)) && (dc = cun->k.descContent)) {
			cit.k = cun->k;

			dbgf_track(DBGT_INFO, "updating usage of key=%s unresolvedCCnt=%d cLevel=%d cMaxLevel=%d",
				cryptShaAsShortStr(&dc->key->kHash), dc->unresolvedContentCounter, cun->maxUsedLevel, cun->maxAllowedLevel);

			assertion(-502243, (dc->key));

			if (dc->unresolvedContentCounter) {

				if (
					(cun->maxUsedLevel + nested > cun->maxAllowedLevel) ||
					((nested && contentUse_add_nested(dc, (SHA1_T *) cun->k.content->f_body, cun->k.content->f_body_len, cun->maxUsedLevel + 1, cun->maxAllowedLevel, cun->k.expanded_type) != SUCCESS)) ||
					(!(--dc->unresolvedContentCounter) && descContent_resolve(dc, NO) != SUCCESS) ) {
					dbgf_sys(DBGT_ERR, "FAILED!");
					dhash_node_reject(dc->dhn);
				}
			}
		}

		if (cn->key)
			keyNode_updCredits(NULL, cn->key, NULL);

		while ((cun = avl_iterate_item(&cn->usage_tree, &an))&& (dc = cun->k.descContent)) {
			if (!dc->unresolvedContentCounter && dc->key != cn->key)
				keyNode_updCredits(NULL, dc->key, NULL);
		}
	}

	assertion(-502244, IMPLIES(cn, cn->gzip == gzip));
	assertion(-502245, IMPLIES(cn, cn->nested == nested));

	return cn;
}


void content_purge_unused(struct content_node *onlyCn)
{
	struct content_node *cn;
	struct CRYPTSHA1_T chash = ZERO_CYRYPSHA1;

	while((cn = onlyCn ? onlyCn : avl_next_item(&content_tree, &chash))) {
		chash = cn->chash;

		if (!cn->key && !cn->usage_tree.items) {

			if (cn->f_body)
				debugFree(cn->f_body, -300734);
			else
				content_tree_unresolveds--;

			avl_remove(&content_tree, &chash, -300735);

			debugFree(cn, -300736);
		}

		if (onlyCn)
			break;
	}
}



void *contents_data( struct desc_content *c, uint8_t t)
{
	return (c && c->final[t].desc_tlv_body_len) ? c->final[t].u.desc_tlv_body : ((c && c->final[t].u.cun) ? c->final[t].u.cun->k.content->f_body : NULL);
}

uint32_t contents_dlen( struct desc_content *c, uint8_t t)
{
	return (c && c->final[t].desc_tlv_body_len) ?  c->final[t].desc_tlv_body_len : ((c && c->final[t].u.cun) ? c->final[t].u.cun->k.content->f_body_len : 0);
}


int32_t create_chash_tlv(struct tlv_hdr *tlv, uint8_t *f_data, uint32_t f_len, uint8_t f_type, uint8_t fzip, uint8_t level)
{
	assertion(-502304, (tlv && f_data && f_len <= (uint32_t)vrt_frame_data_size_out && f_type && fzip <= 1 && level <= 2));
	assertion(-502305, (level || fzip));

	uint8_t *cfd_agg_data = f_data;
	uint32_t cfd_agg_len = f_len;

	if (fzip) {
		uint8_t *cfd_zagg_data = NULL;
		int32_t cfd_zagg_len = z_compress(f_data, f_len, &cfd_zagg_data, 0, 0, 0);
		assertion(-501606, IMPLIES(fzip, cfd_zagg_len >= 0 && cfd_zagg_len < (int)f_len));

		if (cfd_zagg_len > 0) {
			assertion(-501594, (cfd_zagg_len > 0 && cfd_zagg_data));

			cfd_agg_len = cfd_zagg_len;
			cfd_agg_data = cfd_zagg_data;
		}
	}

	uint32_t cfd_msgs = cfd_agg_len / REF_CONTENT_BODY_SIZE_OUT + (cfd_agg_len % REF_CONTENT_BODY_SIZE_OUT ? 1 : 0);
	uint8_t cfd_gzip = (cfd_agg_len < f_len);

	dbgf_track(DBGT_INFO, "adding t_type=%d fDataInLen=%d fDataOutLen=%d -> msgs=%d  do_fzip=%d, cfd_gzip=%d",
		f_type, f_len, cfd_agg_len, cfd_msgs, fzip, cfd_gzip);

	assertion(-502306, IMPLIES(!level,  cfd_agg_len <= REF_CONTENT_BODY_SIZE_OUT));

	struct dsc_hdr_chash *cHdp = ((struct dsc_hdr_chash *) ((uint8_t*)&(tlv[1])));
	struct dsc_hdr_chash cHdr = {.u = {.i = {
				.gzip = cfd_gzip,
				.maxNesting = (level <= 1 ? level : ((cfd_gzip || cfd_msgs > 1) ? (2) : (1))),
				.expanded_type = f_type,
				.expanded_length = f_len
	}}};

	cHdp->u.u32 = htonl(cHdr.u.u32);
	cHdp->expanded_chash = (content_add_body(f_data, f_len, 0, 0, YES))->chash;//cn->chash;

	uint32_t m0 = 0, tlv_len = sizeof(struct tlv_hdr) + sizeof(struct dsc_hdr_chash);


	if (cHdr.u.i.maxNesting == 0) {

		memcpy(&cHdp->msg[0], cfd_agg_data, cfd_agg_len);
		tlv_len += cfd_agg_len;

	} else if (cHdr.u.i.maxNesting >= 1 && !cfd_gzip && cfd_msgs == 1) {

		//expanded_chash is enough!

	} else {

		assertion(-502307, (cHdr.u.i.maxNesting >= 1 && (cfd_gzip || cfd_msgs > 1)));

		uint32_t pos = 0;
		uint32_t m1Msgs = (REF_CONTENT_BODY_SIZE_OUT/sizeof(SHA1_T));
		SHA1_T m1Array[m1Msgs];
		SHA1_T *chash = (cHdr.u.i.maxNesting >= 2 ? m1Array : &cHdp->msg[0].chash);
		uint32_t m1 = 0;

		while (pos < cfd_agg_len) {
			for (m1 = 0; (m1 < m1Msgs && pos < cfd_agg_len); pos += REF_CONTENT_BODY_SIZE_OUT) {
				uint32_t cfd_bdy_size = XMIN(cfd_agg_len - pos, REF_CONTENT_BODY_SIZE_OUT);
				struct content_node *cfd_msg_cn = content_add_body(cfd_agg_data + pos, cfd_bdy_size, 0, 0, YES);
				chash[m1++] = cfd_msg_cn->chash;
			}

			if (cHdr.u.i.maxNesting == 1) {
				m0 = m1;
				break;
			} else {
				struct content_node *cfd_msg_cn = content_add_body((uint8_t*) chash, m1 * sizeof(struct dsc_msg_chash), 0, (cHdr.u.i.maxNesting - 1), YES);
				cHdp->msg[m0++].chash = cfd_msg_cn->chash;
			}
		}

		tlv_len += (m0 * sizeof(struct dsc_msg_chash));
	}


	if (cfd_agg_data && cfd_agg_data != f_data)
		debugFree(cfd_agg_data, -501595);

	assertion_dbg(-502308, ((cHdr.u.i.maxNesting <= 2 && cfd_msgs >= 1 && cHdr.u.i.gzip <= 1) &&
		IMPLIES(cHdr.u.i.maxNesting == 1 && cfd_msgs == 1 && cHdr.u.i.gzip == 0, m0 == 0) &&
		IMPLIES(cHdr.u.i.maxNesting == 1 && cfd_msgs == 1 && cHdr.u.i.gzip == 1, m0 == 1) &&
		IMPLIES(cHdr.u.i.maxNesting == 1 && cfd_msgs > 1, cfd_msgs == m0) &&
		IMPLIES(cHdr.u.i.maxNesting == 2 && cfd_msgs == 1 && cHdr.u.i.gzip == 0, m0 == 0) &&
		IMPLIES(cHdr.u.i.maxNesting == 2 && (cfd_msgs > 1 || cHdr.u.i.gzip == 1), m0 >= 1)),
		"level=%d->%d gzip=%d->%d cHashes=%d->%d", level, cHdr.u.i.maxNesting, fzip, cHdr.u.i.gzip, cfd_msgs, m0);

	*tlv = tlvSetBigEndian(BMX_DSC_TLV_CONTENT_HASH, tlv_len);
	return tlv_len;
}


STATIC_FUNC
void content_schedule_requests(void)
{
	struct content_node *cn;
	struct avl_node *anc = NULL;

	while (content_tree_unresolveds && (cn = avl_iterate_item(&content_tree, &anc))) {

		if (cn->f_body)
			continue;

		struct content_usage_node *cun;
		struct reference_node *ref;
		struct avl_node *anu = NULL;

		while ((cun = avl_iterate_item(&cn->usage_tree, &anu))) {

			assertion(-502309, (cun->k.descContent->key->bookedState->i.c >= KCTracked));

			if (!cun->k.descContent->dhn->neighRefs_tree.items && cun->k.descContent->key->content != cn && cun->k.descContent->key->pktIdTime) {
				schedule_tx_task(FRAME_TYPE_CONTENT_REQ, &cun->k.descContent->key->kHash, NULL, NULL, SCHEDULE_MIN_MSG_SIZE, &cn->chash, sizeof(SHA1_T));
			}

			struct avl_node *ann = NULL;
			while ((ref = avl_iterate_item(&cun->k.descContent->dhn->neighRefs_tree, &ann)))
				schedule_tx_task(FRAME_TYPE_CONTENT_REQ, &ref->neigh->local_id, ref->neigh, ref->neigh->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &cn->chash, sizeof(SHA1_T));
		}

		if (cn->key) {

			assertion(-502310, (cn->key->bookedState->i.c >= KCTracked));

			if (cn->key->pktIdTime)
				schedule_tx_task(FRAME_TYPE_CONTENT_REQ, &cn->key->kHash, NULL, NULL, SCHEDULE_MIN_MSG_SIZE, &cn->chash, sizeof(SHA1_T));

			struct avl_node *anr = NULL;
			while ((ref = avl_iterate_item(&cn->key->neighRefs_tree, &anr))) {
				
				if (!ref->dhn->descContent)
					schedule_tx_task(FRAME_TYPE_CONTENT_REQ, &ref->neigh->local_id, ref->neigh, ref->neigh->best_tp_link->k.myDev, SCHEDULE_MIN_MSG_SIZE, &cn->chash, sizeof(SHA1_T));

			}
		}
	}
}


STATIC_FUNC
void contentUse_del_(struct content_usage_node *cun)
{
	avl_remove(&cun->k.descContent->contentRefs_tree, &cun->k, -300728);
	avl_remove(&cun->k.content->usage_tree, &cun->k, -300729);
	content_purge_unused(cun->k.content);
	debugFree(cun, 300000);
}



STATIC_FUNC
struct content_usage_node *contentUse_add(struct desc_content *dc, struct content_node *cn, uint8_t f_type, uint8_t maxUsedLevel, uint8_t maxAllowedLevel, uint8_t expanded_type)
{
	assertion(-502248, (dc && cn));
	assertion(-502311, (maxUsedLevel <= maxAllowedLevel && maxUsedLevel <= vrt_frame_max_nesting));

	dbgf_all(DBGT_INFO, "f_type=%d, cHash=%s bodyLen=%d nested=%d compression=%d data=%d usage=%d",
		f_type, cryptShaAsShortStr(&cn->chash), cn->f_body_len, cn->nested, cn->gzip, !!cn->f_body, cn->usage_tree.items);


	struct content_usage_node *cup;
	struct content_usage_node cuv = {.k = { .expanded_type = expanded_type, .content = cn, .descContent = dc} };

	if ((cup = avl_find_item(&dc->contentRefs_tree, &cuv.k))) {
		cup->dup++;
	} else {
		cup = debugMallocReset(sizeof(struct content_usage_node), -300725);
		*cup = cuv;
		avl_insert(&dc->contentRefs_tree, cup, -300726);
		avl_insert(&cn->usage_tree, cup, -300727);

		if (!cn->f_body)
			dc->unresolvedContentCounter++;
	}

	cup->maxAllowedLevel = XMAX(maxAllowedLevel, cup->maxAllowedLevel);
	cup->maxUsedLevel = XMAX(maxUsedLevel, cup->maxUsedLevel);


	if (f_type != BMX_DSC_TLV_CONTENT_HASH) {
		assertion(-502312, (f_type = expanded_type));
		assertion(-502249, (cn->f_body));
		assertion(-502250, (dc->contentRefs_tree.items));
		assertion(-502251, (!dc->unresolvedContentCounter));
		assertion(-502252, (!dc->final[f_type].desc_tlv_body_len));

		dc->final[f_type].u.cun = cup;
	}

	return cup;
}

STATIC_FUNC
IDM_T contentUse_add_nested(struct desc_content *dc, SHA1_T *f_body, uint32_t f_body_len, uint8_t level, uint8_t maxLevel, uint8_t expanded_type)
{
	uint32_t m;
	dbgf_track(DBGT_INFO, "level=%d maxLevel=%d maxNesting=%d", level, maxLevel, vrt_frame_max_nesting);

	if (level > maxLevel || level > vrt_frame_max_nesting)
		return FAILURE;

	for (m = 0; m < (f_body_len / sizeof(SHA1_T)); m++) {

		struct content_node *cn = content_add_hash(&f_body[m]);

		struct content_usage_node *cun = contentUse_add(dc, cn, BMX_DSC_TLV_CONTENT_HASH, level, maxLevel, expanded_type);

		if (!cun)
			return FAILURE;

		if (cn->f_body && cn->nested) {
			if (contentUse_add_nested(dc, (SHA1_T *) cn->f_body, cn->f_body_len, cun->maxUsedLevel + 1, maxLevel, expanded_type) != SUCCESS)
				return FAILURE;
		}
	}

	return SUCCESS;
}


STATIC_FUNC
IDM_T content_attach_data(uint8_t *outData, uint32_t *outLen, uint8_t *inData, uint32_t inLen, uint8_t gzip, uint32_t maxLen, SHA1_T *checksum)
{
	IDM_T err = 0;

	if (gzip) {
		uint8_t zData[maxLen];
		uint32_t zLen = z_decompress(inData, inLen, zData, maxLen);

		err |= zLen <= 0 || (zLen + *outLen > maxLen);
		err |= !IMPLIES(checksum, (zLen == maxLen && cryptShasEqual(content_key(zData, zLen, 0, 0), checksum)));

		if (!err) {
			memcpy(outData + *outLen, zData, zLen);
			*outLen += zLen;
		}

	} else {

		err |= (inLen + *outLen > maxLen);
		err |= !IMPLIES(checksum, (inLen == maxLen && cryptShasEqual(content_key(inData, inLen, 0, 0), checksum)));

		if (!err) {
			memcpy(outData + *outLen, inData, inLen);
			*outLen += inLen;
		}
	}


	dbgf_track(err ? DBGT_WARN : DBGT_INFO, "((d1=%d)+fbl=%d) > (targetLen=%d) compression=%d targetHash=%s",
		*outLen, inLen, maxLen, gzip, cryptShaAsShortStr(checksum));

	if (err)
		return FAILURE;

	return SUCCESS;
}

STATIC_FUNC
IDM_T content_attach_references(uint8_t *outData, uint32_t *outLen, SHA1_T *f_body, uint32_t f_body_len, uint8_t compression, uint32_t max_len, SHA1_T *checksum)
{
	uint8_t tmpData[max_len];
	uint32_t tmpLen = 0;
	uint32_t m;

	for (m = 0; m < (f_body_len/sizeof(SHA1_T)); m++) {
		struct content_node *cn = content_get(&f_body[m]);
		assertion(-502259, (cn && cn->f_body));

		if (cn->nested) {

			if (content_attach_references(tmpData, &tmpLen, (SHA1_T*)cn->f_body, cn->f_body_len, cn->gzip, max_len, NULL) != SUCCESS)
				return FAILURE;

		} else {

			if (content_attach_data(tmpData, &tmpLen, cn->f_body, cn->f_body_len, cn->gzip, max_len, NULL) != SUCCESS)
				return FAILURE;
		}
	}

	if (content_attach_data(outData, outLen, tmpData, tmpLen, compression, max_len, checksum) != SUCCESS)
		return FAILURE;

	return SUCCESS;
}


STATIC_FUNC
int8_t descContent_resolve(struct desc_content *dc, IDM_T init_not_finalize)
{
	assertion(-502253, (dc && dc->key && dc->desc_frame && dc->desc_frame_len));
	assertion(-502254, (!dc->unresolvedContentCounter)); //always zero during finalize or init
	assertion(-502255, IMPLIES(!init_not_finalize, dc->contentRefs_tree.items));
	assertion(-502256, IMPLIES(init_not_finalize, !dc->contentRefs_tree.items));
	assertion(-502257, (++dc->cntr <= 2));

	int32_t result;
        struct rx_frame_iterator it = {
		.caller = __FUNCTION__, .op = TLV_OP_CUSTOM_MIN, .db = description_tlv_db, .process_filter = FRAME_TYPE_PROCESS_NONE,
		.f_type = -1, .frames_length = dc->desc_frame_len, .frames_in = dc->desc_frame
	};

	dbgf_track(DBGT_INFO, "init=%d dc->key=%s desc_frame_len=%d unresolveds=%d descSqn=%d",
		init_not_finalize, cryptShaAsShortStr(&dc->key->kHash), dc->desc_frame_len, dc->unresolvedContentCounter, dc->descSqn);

        while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

		struct dsc_hdr_chash *cHdrPtr = (it.f_type == BMX_DSC_TLV_CONTENT_HASH ? (struct dsc_hdr_chash *)it.f_data : NULL);
		struct dsc_hdr_chash chHdrVar = {.u = {.u32 = (cHdrPtr ? ntohl(cHdrPtr->u.u32) : 0)}};

		dbgf_track(DBGT_INFO, "f_type=%d=%s f_dlen=%d f_msgs_len=%d fixedMsgs=%d (%s gzip=%d maxNesting=%d targetLen=%d) ",
			it.f_type, it.f_handl->name, it.f_dlen, it.f_msgs_len, it.f_msgs_fixed,
			(cHdrPtr ? it.db->handls[chHdrVar.u.i.expanded_type].name : NULL),
			chHdrVar.u.i.gzip, chHdrVar.u.i.maxNesting, chHdrVar.u.i.expanded_length);

		if (init_not_finalize) {

			if (cHdrPtr) {

				if (!IMPLIES(it.f_msgs_len == 0, chHdrVar.u.i.maxNesting == 1))
					return FAILURE;

				if (!IMPLIES(chHdrVar.u.i.maxNesting == 0, it.f_msgs_len > 0))
					return FAILURE;

				if (!(chHdrVar.u.i.maxNesting <= vrt_frame_max_nesting))
					return FAILURE;

				if (chHdrVar.u.i.expanded_length > vrt_frame_data_size_in)
					return FAILURE;

				if ((dc->ref_content_len += chHdrVar.u.i.expanded_length) > desc_vbodies_size_in)
					return FAILURE;

				if (it.f_msgs_len == 0) {

					if (!contentUse_add(dc, content_add_hash(&cHdrPtr->expanded_chash), BMX_DSC_TLV_CONTENT_HASH, 1, chHdrVar.u.i.maxNesting, chHdrVar.u.i.expanded_type))
						return FAILURE;

				} else if (chHdrVar.u.i.maxNesting) {

					if (contentUse_add_nested(dc, (SHA1_T*) & cHdrPtr[1], it.f_msgs_len, 1, chHdrVar.u.i.maxNesting, chHdrVar.u.i.expanded_type)!=SUCCESS)
						return FAILURE;
				}
			}

		} else {

			if (cHdrPtr) {
				uint8_t data[chHdrVar.u.i.expanded_length];
				uint32_t dlen = 0;

				if (it.f_msgs_len == 0) {

					if (chHdrVar.u.i.gzip)
						return FAILURE; //not possible as unique-existing expanded_chash can not match compressed and uncompressed (resolved) data !!

					struct content_node *cn = content_get(&cHdrPtr->expanded_chash);
					assertion(-502258, (cn && cn->f_body));
					if (cn->gzip || cn->nested || cn->f_body_len != chHdrVar.u.i.expanded_length)
						return FAILURE; //not possible as unique-existing expanded_chash can not match nested and resolved data !!

					if (!contentUse_add(dc, cn, chHdrVar.u.i.expanded_type, 0, 0, chHdrVar.u.i.expanded_type))
						return FAILURE;

				} else if (!chHdrVar.u.i.maxNesting) {

					if (content_attach_data(data, &dlen, (uint8_t*) & cHdrPtr[1], it.f_msgs_len, chHdrVar.u.i.gzip, chHdrVar.u.i.expanded_length, &cHdrPtr->expanded_chash) != SUCCESS)
						return FAILURE;

					if (!contentUse_add(dc, content_add_body(data, dlen, 0, 0, YES), chHdrVar.u.i.expanded_type, 0, 0, chHdrVar.u.i.expanded_type))
						return FAILURE;

				} else {

					if (content_attach_references(data, &dlen, (SHA1_T*) & cHdrPtr[1], it.f_msgs_len, chHdrVar.u.i.gzip, chHdrVar.u.i.expanded_length, &cHdrPtr->expanded_chash) != SUCCESS)
						return FAILURE;

					if (!contentUse_add(dc, content_add_body(data, dlen, 0, 0, YES), chHdrVar.u.i.expanded_type, 0, 0, chHdrVar.u.i.expanded_type))
						return FAILURE;
				}

			} else {
				dc->final[it.f_type].desc_tlv_body_len = it.f_dlen;
				dc->final[it.f_type].u.desc_tlv_body = it.f_data;
			}
		}
	}

	if (result != TLV_RX_DATA_DONE)
		return FAILURE;

	assertion(-502313, IMPLIES(!init_not_finalize, !dc->unresolvedContentCounter));
	if (!dc->unresolvedContentCounter) {
		struct avl_node *an=NULL;
		struct content_usage_node *cun;
		while ((cun = avl_iterate_item(&dc->contentRefs_tree, &an))) {
			assertion(-502314, cun->k.content->f_body);
		}
	}

	if (init_not_finalize && !dc->unresolvedContentCounter)
		return descContent_resolve(dc, NO);

	dbgf_all(DBGT_INFO, "done");
	return SUCCESS;
}



void descContent_destroy(struct desc_content *dc)
{
	assertion(-502260, (dc));
	assertion(-502261, (dc->desc_frame));
	assertion(-502262, (dc->key));
	assertion(-502263, (dc->dhn));
	assertion(-502264, (!dc->orig));

	dc->dhn->descContent = NULL;
	dc->dhn = NULL;

	debugFree(dc->desc_frame, -300738);
	dc->desc_frame = NULL;
	dc->desc_frame_len = 0;


	if (dc->key->nextDesc == dc)
		dc->key->nextDesc = NULL;

	struct content_usage_node *cun;
	while ((cun = avl_first_item(&dc->contentRefs_tree)))
		contentUse_del_(cun);

	debugFree(dc, -300730);
}


struct desc_content* descContent_create(uint8_t *dsc, uint32_t dlen, struct key_node *key)
{
	assertion(-502265, (dsc && dlen && key && key->content && key->content->f_body && key->bookedState->i.c >= KCTracked));

        DHASH_T dhash;
	cryptShaAtomic(dsc, dlen, &dhash);

	struct dhash_node *dhn = dhash_node_create( &dhash, NULL);

	struct dsc_msg_version *versMsg;
	GLOBAL_ID_T *id = get_desc_id(dsc, dlen, NULL, &versMsg);

	assertion(-502266, (!dhn->descContent && !dhn->rejected));
	assertion(-502267, (id && cryptShasEqual(&key->kHash, id)));
	assertion(-502268, (!key->currOrig || key->currOrig->descContent->descSqn < ntohl(versMsg->descSqn)));
	assertion(-502269, (!key->nextDesc || key->nextDesc->descSqn < ntohl(versMsg->descSqn)));
	assertion(-502270, (key->content == test_description_signature(dsc, dlen)));

	if (key->nextDesc)
		dhash_node_reject(key->nextDesc->dhn);

	struct desc_content *dc = debugMallocReset(sizeof(struct desc_content), -300572);
	AVL_INIT_TREE(dc->contentRefs_tree, struct content_usage_node, k);

	dhn->descContent = dc;
	dc->dhn = dhn;

	dc->desc_frame  = debugMalloc(dlen, -300105);
	memcpy(dc->desc_frame, dsc, dlen);

	dc->desc_frame_len = dlen;
	dc->descSqn = ntohl(versMsg->descSqn);
	dc->key = key;

	if (descContent_resolve(dc, YES) != SUCCESS) {
		dbgf_track(DBGT_ERR, "Failed resolving descContent");
		EXITERROR(-502271, (NO));
		descContent_destroy(dc);
		dhash_node_reject(dhn);
		return NULL;
	}

	key->nextDesc = dc;

	return dc;
}























STATIC_FUNC
int create_tlv_content_hash(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        return TLV_TX_DATA_IGNORED;
}

STATIC_FUNC
int process_tlv_content_hash(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        return TLV_RX_DATA_FAILURE;
}

STATIC_FUNC
int32_t tx_msg_content_request(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	SHA1_T *cHash = (SHA1_T *)it->ttn->key.data;
        struct hdr_content_req *hdr = (struct hdr_content_req *)tx_iterator_cache_hdr_ptr(it);
        struct msg_content_req *msg = (struct msg_content_req *)tx_iterator_cache_msg_ptr(it);
	struct content_node *cn;

	if (!content_tree_unresolveds || !(cn = content_get(cHash)) || cn->f_body)
                return TLV_TX_DATA_DONE;

	if (hdr->msg == msg) {
		assertion(-502272, (is_zero(hdr, sizeof (*hdr))));
		hdr->dest_kHash = it->ttn->key.f.groupId;
	} else {
		assertion(-502273, (cryptShasEqual(&hdr->dest_kHash, &it->ttn->key.f.groupId)));
	}

	msg->chash = *cHash;

	return sizeof (struct msg_content_req);
}

STATIC_FUNC
int32_t rx_msg_content_request(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	struct packet_buff *pb = it->pb;
        struct hdr_content_req *hdr = (struct hdr_content_req*) (it->f_data);
        struct msg_content_req *msg = (struct msg_content_req*) (it->f_msg);
	struct content_node *cn;

        if (cryptShasEqual(&hdr->dest_kHash, &myKey->kHash) && (cn = content_get(&msg->chash)) && cn->f_body && cn->f_body_len <= REF_CONTENT_BODY_SIZE_MAX && cn->usage_tree.items) {

		 struct content_usage_node cunKey = {.k = {.descContent = myKey->currOrig->descContent}};
		 struct content_usage_node *cun;

		 if ((pb->i.verifiedLink || ((cun = avl_next_item(&cn->usage_tree, &cunKey.k)) && cun->k.descContent == myKey->currOrig->descContent))) {
			 schedule_tx_task(FRAME_TYPE_CONTENT_ADV, NULL, NULL, pb->i.iif, cn->f_body_len, &cn->chash, sizeof(SHA1_T));
		 } else {
			dbgf_sys(DBGT_WARN, "UNVERIFIED neigh=%s llip=%s or UNKNOWN chash=%s refn=%p refn_usage=%d",
				 pb->i.verifiedLink ? cryptShaAsString(&pb->i.verifiedLink->k.linkDev->key.local->local_id) : NULL,
				 pb->i.llip_str, cryptShaAsString(&msg->chash), (void*)cn, cn->usage_tree.items );
		 }
	 }

	return sizeof(struct msg_content_req);
}


STATIC_FUNC
int32_t tx_frame_content_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	struct content_node *cn = content_get((SHA1_T *)it->ttn->key.data);

	if(cn && cn->f_body && cn->usage_tree.items) {

		dbgf_track(DBGT_INFO, "frame_msgs_length=%d f_body_len=%d space_pref=%d space_max=%d",
			it->ttn->frame_msgs_length, cn->f_body_len, tx_iterator_cache_data_space_pref(it, 0, 0), tx_iterator_cache_data_space_max(it, 0, 0));

		assertion(-502049, ((int) it->ttn->frame_msgs_length <= tx_iterator_cache_data_space_max(it, 0, 0)));
		assertion(-502050, ((int) it->ttn->frame_msgs_length == cn->f_body_len));

		struct frame_hdr_content_adv *hdr = ((struct frame_hdr_content_adv*) tx_iterator_cache_hdr_ptr(it));

		hdr->gzip = cn->gzip;
		hdr->maxNesting = cn->nested;
		hdr->reserved = cn->reserved;

		memcpy(hdr->content, cn->f_body, cn->f_body_len);

		return cn->f_body_len;
	}

	return TLV_TX_DATA_DONE;
}


STATIC_FUNC
int32_t rx_frame_content_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	struct frame_hdr_content_adv *adv = (struct frame_hdr_content_adv*)it->f_data;

	dbgf_track(DBGT_INFO, "unresolveds=%d msgs_len=%d gzip=%d maxNesting=%d",
		content_tree_unresolveds, it->f_msgs_len, adv->gzip, adv->maxNesting);

	if (it->f_msgs_len > (int)REF_CONTENT_BODY_SIZE_MAX)
		return TLV_RX_DATA_FAILURE;

	if (adv->maxNesting && (it->f_msgs_len % sizeof(struct frame_msg_content_adv)))
		return TLV_RX_DATA_FAILURE;

	if (content_tree_unresolveds)
		content_add_body(adv->content, it->f_msgs_len, adv->gzip, adv->maxNesting, NO);

	return it->f_msgs_len;
}

static struct opt_type content_options[]=
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	{ODI,0,ARG_CONTENTS,	        0,  9,1,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show contents\n"},
	{ODI,0,ARG_UNSOLICITED_CONTENT_ADVS,0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&unsolicitedContentAdvs,MIN_UNSOLICITED_CONTENT_ADVS,MAX_UNSOLICITED_CONTENT_ADVS,DEF_UNSOLICITED_CONTENT_ADVS,0,0,
			ARG_VALUE_FORM, NULL},
};


void init_content( void )
{
	register_options_array(content_options, sizeof(content_options), CODE_CATEGORY_NAME);

	register_status_handl(sizeof(struct content_status), 1, content_status_format, ARG_CONTENTS, content_status_creator);

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));


        static const struct field_format msg_content_hash_format[] = DSC_MSG_CHASH_FORMAT;
        handl.name = "CONTENT_HASH";
        handl.data_header_size = sizeof( struct dsc_hdr_chash);
        handl.min_msg_size = sizeof (struct dsc_msg_chash);
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_tlv_content_hash;
        handl.rx_frame_handler = process_tlv_content_hash;
        handl.msg_format = msg_content_hash_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_CONTENT_HASH, &handl);




        handl.name = "CONTENT_REQ";
	handl.rx_processUnVerifiedLink = 1;
	handl.data_header_size = sizeof(struct hdr_content_req);
	handl.min_msg_size = sizeof(struct msg_content_req);
        handl.fixed_msg_size = 1;
	handl.tx_packet_prepare_always = content_schedule_requests;
        handl.tx_msg_handler = tx_msg_content_request;
        handl.rx_msg_handler = rx_msg_content_request;
        register_frame_handler(packet_frame_db, FRAME_TYPE_CONTENT_REQ, &handl);

        handl.name = "CONTENT_ADV";
	handl.rx_processUnVerifiedLink = 1;
	handl.data_header_size = sizeof(struct frame_hdr_content_adv);
        handl.min_msg_size = XMIN(1, sizeof(struct dsc_msg_chash));  // this frame does not know what the referenced data is about!
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = tx_frame_content_adv;
        handl.rx_frame_handler = rx_frame_content_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_CONTENT_ADV, &handl);
}

