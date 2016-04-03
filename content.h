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

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>




//TODO: set REQ_TO to 1 (in a non-packet-loss testenvironment this may be set to 1000 for testing)
#define DEF_TX_CONTENT_REQ_TO   ((DEF_TX_MIN_INTERVAL*3)/2)
#define DEF_TX_CONTENT_ADV_TO   200

#define MAX_DESC_TYPE_CONTENT_OCCURANCE 10
#define ARG_CONTENTS "contents"

#define DEF_UNSOLICITED_CONTENT_ADVS 1
#define MIN_UNSOLICITED_CONTENT_ADVS 0
#define MAX_UNSOLICITED_CONTENT_ADVS 1
#define ARG_UNSOLICITED_CONTENT_ADVS "unsolicitedContentAdvs"

extern struct avl_tree content_tree;



#define DSC_MSG_CHASH_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 160, 1, FIELD_RELEVANCE_LOW,  "chash"},  \
	FIELD_FORMAT_END }

struct dsc_msg_chash {
	SHA1_T chash; // hash over frame data (without frame-header, but including hdr_content_adv and all body data) as transmitted via content_adv
} __attribute__((packed));

struct dsc_hdr_chash {
	SHA1_T expanded_chash; // hash over zero-frame_hdr_content_adv and frame body data with all resolved, re-assembled, uncompressed.
	// So for a dsc_hdr/msg_chash frame with a single uncompressed and non-nested chash this would equal the chash of dsc_msg_chash which MUST be omitted.
	// Otherwise it provides a checksum over the final data.

	union {

		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			unsigned int gzip : 1; // only contents are compressed, all resolved and re-assembled contents are compressed (NOT the hashes)
			unsigned int maxNesting : 2;
			unsigned int expanded_type : 5;
			unsigned int expanded_length : 24;
#elif __BYTE_ORDER == __BIG_ENDIAN
			unsigned int expanded_length : 24;
			unsigned int expanded_type : 5;
			unsigned int maxNesting : 2;
			unsigned int gzip : 1;
#else
#error "Please fix <bits/endian.h>"
#endif
		} __attribute((packed)) i;
		uint32_t u32;
	} u;

	struct dsc_msg_chash msg[];

} __attribute__((packed));

struct frame_msg_content_adv {
	SHA1_T chash; // hash over frame data (without frame-header, but including hdr_content_adv and all body data) as transmitted via content_adv
} __attribute__((packed));

struct frame_hdr_content_adv {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int gzip : 1; // only contents are compressed, all resolved and re-assembled contents are compressed (NOT the hashes)
	unsigned int maxNesting : 2;
	unsigned int reserved : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int reserved : 5;
	unsigned int maxNesting : 2;
	unsigned int gzip : 1;
#else
#error "Please fix <bits/endian.h>"
#endif
	uint8_t content[]; //hashes if nested, otherwise raw content data
} __attribute__((packed));



// for FRAME_TYPE_REF_REQ:

struct msg_content_req {
	SHA1_T chash;
} __attribute__((packed));

//TODO: Use this destination header!!!

struct hdr_content_req { // 20 bytes
	GLOBAL_ID_T dest_kHash;
	struct msg_content_req msg[];
} __attribute__((packed));


int8_t descContent_assemble(struct desc_content *dc, IDM_T init_not_finalize);
struct desc_content* descContent_create(uint8_t *dsc, uint32_t dlen, struct key_node *kn);
void descContent_destroy(struct desc_content *dc);
void content_maintain(struct content_node *cn);
struct content_node * content_get(SHA1_T *chash);
void *contents_data(struct desc_content *contents, uint8_t type);
uint32_t contents_dlen(struct desc_content *contents, uint8_t type);
struct content_node * content_add_hash(SHA1_T *chash);
struct content_node * content_add_body(uint8_t *body, uint32_t body_len, uint8_t compressed, uint8_t nested, uint8_t force);
int32_t create_chash_tlv(struct tlv_hdr *tlv, uint8_t *f_data, uint32_t f_len, uint8_t f_type, uint8_t fzip, uint8_t level);
void content_purge_unused(struct content_node *onlyCn);


void init_content(void);