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

/*
 * Alternative cryptographic libraries are:
 * libtomcrypt and gcrypt
 */

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>

//#define DEF_PERSISTENT_PATH "/etc/bmx6"
#define DEF_TRUST_DIR_POLLING_INTERVAL 5000

#define DEF_TRUSTED_NODES_DIR "/etc/bmx6/trustedNodes"
#define ARG_TRUSTED_NODES_DIR "trustedNodesDir"

#define DEF_SUPPORTED_NODES_DIR "/etc/bmx6/supportedNodes"
#define ARG_SUPPORTED_NODES_DIR "supportedNodesDir"

#define ARG_KEY_PATH "keyPath"
#define DEF_KEY_PATH "/etc/bmx6/rsa.der"

#define ARG_DESC_SIGN "descSignLen"
#define MIN_DESC_SIGN 512
#define MAX_DESC_SIGN 4096
#define DEF_DESC_SIGN 2048
#define HLP_DESC_SIGN "sign own descriptions with given RSA key length"


#define ARG_NODE_SIGN_MAX "descVerificationLenMax"
#define MIN_NODE_SIGN_MAX 512
#define MAX_NODE_SIGN_MAX 4096
#define DEF_NODE_SIGN_MAX 4096
#define HLP_NODE_SIGN_MAX "verify description signatures up-to given RSA key length"

#define ARG_LINK_SIGN_LEN "packetSignLen"
#define MIN_LINK_SIGN_LEN 0
#define MAX_LINK_SIGN_LEN 2048
#define DEF_LINK_SIGN_LEN 896
#define HLP_LINK_SIGN_LEN "sign outgoing packets with given RSA key length"
extern int32_t linkSignLen;


// http://my.opera.com/securitygroup/blog/2009/09/29/512-bit-rsa-key-breaking-developments
// assuming 70 days to crack RSA512 keys (2009!) with a single dual-core machine,
// means can be cracked in
// ~6000 secs with ~1000 machines, or
// ~600 secs with ~10000 machines, or
// ~60 secs with ~100000 machines
// However, this would be for RSA512 but RSA896 is used by default!!:
#define MIN_LINK_SIGN_LT (60)    // one minute, needs ~100000 machines to crack RSA512 before end of life
#define DEF_LINK_SIGN_LT (6000)   // 100 minutes, needs ~1000 machines (in 2013) to crack RSA512 before end of life
#define MAX_LINK_SIGN_LT (REGISTER_TASK_TIMEOUT_MAX/1000)
#define ARG_LINK_SIGN_LT "linkSignLifetime"
#define HLP_LINK_SIGN_LT "Lifetime of outgoing link keys and signatures in seconds"

#define ARG_LINK_SIGN_MAX "linkSignLenMax"
#define MIN_LINK_SIGN_MAX 0
#define MAX_LINK_SIGN_MAX 4096
#define DEF_LINK_SIGN_MAX 2048
#define HLP_LINK_SIGN_MAX "verify incoming link (packet) signature up-to given RSA key length"

#define ARG_LINK_SIGN_MIN "linkSignLenMin"
#define MIN_LINK_SIGN_MIN 0
#define MAX_LINK_SIGN_MIN 4096
#define DEF_LINK_SIGN_MIN 0
#define HLP_LINK_SIGN_MIN "require incoming link (packet) signatures of at least given RSA key length"

extern CRYPTKEY_T *my_NodeKey;
extern CRYPTKEY_T *my_LinkKey;


#define DESCRIPTION_MSG_PUBKEY_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(struct dsc_msg_pubkey),     1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "key" }, \
FIELD_FORMAT_END }

struct dsc_msg_pubkey {
	uint8_t type;
	uint8_t key[];
} __attribute__((packed));


#define DESCRIPTION_MSG_SIGNATURE_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint8_t),                   1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "signature" }, \
FIELD_FORMAT_END }

struct dsc_msg_signature {
	uint8_t type;
	uint8_t signature[];
} __attribute__((packed));



#define DESCRIPTION_MSG_TRUST_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(CRYPTSHA1_T),               1, FIELD_RELEVANCE_HIGH,  "globalId"},  \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint16_t),                   1, FIELD_RELEVANCE_HIGH,  "reserved"}, \
FIELD_FORMAT_END }

struct dsc_msg_trust {
	CRYPTSHA1_T globalId;
	uint16_t reserved;
} __attribute__((packed));

struct dsc_msg_version {
	uint8_t comp_version;
	uint8_t capabilities;

	DESC_SQN_T descSqn;
	uint32_t codeRevision;

} __attribute__((packed));

GLOBAL_ID_T *get_desc_id(uint8_t *desc_adv, uint32_t desc_len, struct dsc_msg_signature **signpp, struct dsc_msg_version **verspp);

struct content_node *test_description_signature(uint8_t *desc, uint32_t desc_len);

IDM_T setted_pubkey(struct desc_content *dc, uint8_t type, GLOBAL_ID_T *globalId);
IDM_T supportedKnownKey(CRYPTSHA1_T *pkhash);
INT_NEIGH_ID_T allocate_internalNeighId(struct neigh_node *nn);
void free_internalNeighId(INT_NEIGH_ID_T ini);
uint32_t *init_neighTrust(struct orig_node *on);
IDM_T verify_neighTrust(struct orig_node *on, struct neigh_node *neigh);

void init_sec(void);
void cleanup_sec(void);
