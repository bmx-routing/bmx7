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

//#define DEF_PERSISTENT_PATH "/etc/bmx7"
#define DEF_TRUST_DIR_POLLING_INTERVAL 5000

#define ARG_TRUST_STATUS "trusted"

#define DEF_TRUSTED_NODES_DIR "/etc/bmx7/trustedNodes"
#define ARG_TRUSTED_NODES_DIR "trustedNodesDir"
#define HLP_TRUSTED_NODES_DIR "directory with global-id hashes of this node's trusted other nodes"

#define ARG_KEY_PATH "keyPath"
#define DEF_KEY_PATH "/etc/bmx7/rsa.der"

#define ARG_SET_TRUSTED "setTrustedNode"
#define ARG_SET_SUPPORT_LEVEL "support"
#define ARG_SET_TRUSTED_LEVEL "trust"
#define MIN_TRUST_LEVEL 0
#define TYP_TRUST_LEVEL_ALL -1
#define TYP_TRUST_LEVEL_NONE 0
#define TYP_TRUST_LEVEL_RECOMMENDED 1
#define TYP_TRUST_LEVEL_DIRECT 2
#define TYP_TRUST_LEVEL_IMPORT 3
#define MAX_TRUST_LEVEL 3
#define DEF_TRUST_LEVEL 2


#define ARG_SUPPORT_PUBLISHING "publishSupportedNodes"
#define MIN_SUPPORT_PUBLISHING 0
#define MAX_SUPPORT_PUBLISHING 1
#define DEF_SUPPORT_PUBLISHING 1
#define HLP_SUPPORT_PUBLISHING "publish (describe) id of nodes supported with priority"

#define ARG_NODE_SIGN_LEN "nodeSignatureLen"
#define MIN_NODE_SIGN_LEN 512
#define MAX_NODE_SIGN_LEN 4096
#define DEF_NODE_SIGN_LEN 2048
#define HLP_NODE_SIGN_LEN "sign own descriptions with given RSA key length (512,768,896,1024,1536,2048,3072,4096)"


#define ARG_NODE_SIGN_MAX "nodeSignatureLenMax"
#define MIN_NODE_SIGN_MAX 512
#define MAX_NODE_SIGN_MAX 4096
#define DEF_NODE_SIGN_MAX 4096
#define HLP_NODE_SIGN_MAX "verify description signatures up-to given RSA key length"

#define ARG_LINK_SIGN_LEN "linkSignatureLen"
#define MIN_LINK_SIGN_LEN 0
#define MAX_LINK_SIGN_LEN 2048
#define DEF_LINK_SIGN_LEN 896
#define HLP_LINK_SIGN_LEN "sign outgoing packets with given RSA key length (512,768,896,1024,1536,2048)"
extern int32_t linkSignLen;

#define ARG_DEV_SIGNATURES "strictSignatures"
#define MIN_DEV_SIGNATURES 0
#define OPT_DEV_SIGNATURES_NONE 0
#define OPT_DEV_SIGNATURES_TX 1
#define OPT_DEV_SIGNATURES_RXTX 2
#define MAX_DEV_SIGNATURES 2
#define DEF_DEV_SIGNATURES 2
#define HLP_DEV_SIGNATURES "force link signatures for device. 0: no, 1: tx, 2: rx&tx"

#define ARG_LINK_VERIFY "linkVerification"
#define MIN_LINK_VERIFY 0
#define MAX_LINK_VERIFY 1
#define DEF_LINK_VERIFY 1
#define HLP_LINK_VERIFY "disable (skip) link-signature verification"

#define ARG_NODE_VERIFY "nodeVerification"
#define MIN_NODE_VERIFY 0
#define MAX_NODE_VERIFY 1
#define DEF_NODE_VERIFY 1
#define HLP_NODE_VERIFY "disable (skip) node description-signature verification"

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
#define ARG_LINK_SIGN_LT "linkSignatureLifetime"
#define HLP_LINK_SIGN_LT "Lifetime of outgoing link keys and signatures in seconds"

#define ARG_LINK_SIGN_MAX "linkSignatureLenMax"
#define MIN_LINK_SIGN_MAX 0
#define MAX_LINK_SIGN_MAX 4096
#define DEF_LINK_SIGN_MAX 2048
#define HLP_LINK_SIGN_MAX "verify incoming link (packet) signature up-to given RSA key length"

#define ARG_LINK_SIGN_MIN "linkSignatureLenMin"
#define MIN_LINK_SIGN_MIN 0
#define MAX_LINK_SIGN_MIN 4096
#define DEF_LINK_SIGN_MIN 0
#define HLP_LINK_SIGN_MIN "require incoming link (packet) signatures of at least given RSA key length"

#define MAX_KEY_FILE_SIZE 100

#define MIN_OGM_SQN_RANGE 10
#define MAX_OGM_SQN_RANGE 8192 // changing this will cause compatibility trouble
#define DEF_OGM_SQN_RANGE 6000
#define ARG_OGM_SQN_RANGE "ogmSqnRange"

#define MIN_OGM_SQN_DEVIATION 1
#define MAX_OGM_SQN_DEVIATION MAX_OGM_SQN_RANGE
#define DEF_OGM_SQN_DEVIATION 10
#define ARG_OGM_SQN_DEVIATION "ogmSqnDeviation"
extern int32_t ogmSqnDeviationMax;

#define MIN_OGM_SQN_RANDOM 0
#define MAX_OGM_SQN_RANDOM (MAX_OGM_SQN_RANGE - 1)
#define DEF_OGM_SQN_RANDOM 0
#define ARG_OGM_SQN_RANDOM "ogmSqnRandom"
extern int32_t ogmSqnRandom;


extern CRYPTKEY_T *my_NodeKey;
extern CRYPTKEY_T *my_LinkKey;


#define OGM_HASH_CHAIN_LINK_BITSIZE 112
// 2^112=5.2e33!
// As of april 2016 total cummulative number of bitcoin double-sha256 hashes is < 1e26 < 2^89 (source http://bitcoin.sipa.be/ ).
// Work for 2^89 double-sha256 == work for 2^90 single-sha256 (and single-sha224)
// Assuming a doubling of hash power per year I assume that 112 bits remains unfeasible for 112-90=22 more years!
// Note that HashChainAnchors are invalidated every OGM_SQN_RANGE ogm intervals (every hour)


typedef struct {
	uint8_t u8[OGM_HASH_CHAIN_LINK_BITSIZE / 8];
} __attribute__((packed)) ChainLink_T;

typedef struct {
	uint8_t u8[sizeof(CRYPTSHA1_T) - (OGM_HASH_CHAIN_LINK_BITSIZE / 8)];
} __attribute__((packed)) ChainSeed_T;

typedef struct {

	union {

		struct {
			ChainLink_T link;
			ChainSeed_T seed;
		} e;
		CRYPTSHA1_T sha;
	} u;
} __attribute__((packed)) ChainElem_T;

typedef struct {
	ChainElem_T elem;
	CRYPTSHA1_T nodeId;
	DESC_SQN_T descSqnNetOrder;
} __attribute__((packed)) ChainInputs_T;

typedef struct {
	DHASH_T dHash;
	ChainInputs_T anchor;
} __attribute__((packed)) ChainOgmConstInput_T;

typedef struct {
	ChainOgmConstInput_T c;
	ChainLink_T l;
} __attribute__((packed)) ChainOgmInput_T;

struct ChainAnchorKey {
	DHASH_T dHash;
	ChainElem_T anchor;
	struct key_node *kn;
	DESC_SQN_T descSqnNetOrder;
} __attribute__((packed));


struct InaptChainOgm {
	ChainLink_T chainOgm;
	FMETRIC_U16_T claimedMetric;
	uint8_t claimedHops;
	uint8_t claimedChain;
	uint16_t pathMetricsByteSize;
	uint8_t pathMetrics[];
};

struct KeyWatchNode {
	// persistent id:
	GLOBAL_ID_T global_id;
	// new file name:
	char fileName[MAX_KEY_FILE_SIZE];
	// old parameters:
	uint8_t updated;
	uint8_t trust;
	uint8_t support;
	uint8_t misc;

	/*
		uint8_t maxDescDepth;
		uint8_t maxDescSize;
		uint8_t maxDescUpdFreq;
		uint32_t minDescSqn;
	 */
};

struct DirWatch {
	char *pathp;
	int ifd;
	int iwd;
	uint32_t retryCnt;
	void (* idChanged) (IDM_T del, struct KeyWatchNode *kwn, struct DirWatch *dw);
	struct avl_tree node_tree;
};





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
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(CRYPTSHA1_T),               1, FIELD_RELEVANCE_HIGH,  "nodeId"},  \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint16_t),                   1, FIELD_RELEVANCE_HIGH,  "reserved"}, \
FIELD_FORMAT_END }

struct desc_msg_trust_fields {

	union {

		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN         // 2 bytes
			unsigned int reserved : 14;
			unsigned int trustLevel : 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
			unsigned int trustLevel : 2;
			unsigned int reserved : 14;
#else
#error "Please fix <bits/endian.h>"
#endif
		} __attribute__((packed)) f;
		uint16_t u16;
	} u;
};

struct dsc_msg_trust {
	CRYPTSHA1_T nodeId;
	struct desc_msg_trust_fields f;

} __attribute__((packed));





#define VERSION_MSG_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8,                              1, FIELD_RELEVANCE_HIGH, "comp_version" }, \
{FIELD_TYPE_HEX,           -1, 8,                              1, FIELD_RELEVANCE_MEDI, "capabilities" }, \
{FIELD_TYPE_UINT,          -1, (8*sizeof(DESC_SQN_T)),         0, FIELD_RELEVANCE_HIGH, "bootSqn" }, \
{FIELD_TYPE_UINT,          -1, (8*sizeof(DESC_SQN_T)),         0, FIELD_RELEVANCE_HIGH, "descSqn" }, \
{FIELD_TYPE_UINT,          -1, (8*sizeof(uint16_t)),           0, FIELD_RELEVANCE_HIGH, "ogmSqnRange" }, \
{FIELD_TYPE_STRING_BINARY, -1, (8*sizeof(ChainElem_T)),        0, FIELD_RELEVANCE_HIGH, "ogmHChainAnchor" }, \
{FIELD_TYPE_HEX,           -1, 32,                             0, FIELD_RELEVANCE_HIGH, "codeRevision" }, \
FIELD_FORMAT_END}

struct dsc_msg_version {
	uint8_t comp_version;
	uint8_t capabilities;
	DESC_SQN_T bootSqn;
	DESC_SQN_T descSqn;
	uint16_t ogmSqnRange;

	ChainElem_T ogmHChainAnchor;

	uint32_t codeRevision;

} __attribute__((packed));

void chainLinkCalc(ChainInputs_T *ci_tmp, OGM_SQN_T diff);
OGM_SQN_T chainOgmFind(ChainLink_T *chainOgm, struct desc_content *dc, OGM_SQN_T maxDeviation);
ChainLink_T chainOgmCalc(struct desc_content *dc, OGM_SQN_T ogmSqn);
ChainElem_T myChainLinkCache(OGM_SQN_T sqn, DESC_SQN_T descSqn);

IPX_T create_crypto_IPv6(struct net_key *prefix, GLOBAL_ID_T *id);
IDM_T verify_crypto_ip6_suffix(IPX_T *ip, uint8_t mask, CRYPTSHA1_T *id);

GLOBAL_ID_T *get_desc_id(uint8_t *desc_adv, uint32_t desc_len, struct dsc_msg_signature **signpp, struct dsc_msg_version **verspp);

struct content_node *test_description_signature(uint8_t *desc, uint32_t desc_len);
void apply_trust_changes(int8_t f_type, struct orig_node *on, struct desc_content* dcOld, struct desc_content *dcNew);
IDM_T setted_pubkey(struct desc_content *dc, uint8_t type, GLOBAL_ID_T *globalId, uint8_t searchDepth);
IDM_T supportedKnownKey(CRYPTSHA1_T *pkhash);
INT_NEIGH_ID_T allocate_internalNeighId(struct neigh_node *nn);
void free_internalNeighId(INT_NEIGH_ID_T ini);
uint32_t *init_neighTrust(struct orig_node *on);
IDM_T verify_neighTrust(struct orig_node *on, struct neigh_node *neigh);
void cleanup_dir_watch(struct DirWatch **dw);
IDM_T init_dir_watch(struct DirWatch **dw, char *path, void (* idChangedTask) (IDM_T del, struct KeyWatchNode *kwn, struct DirWatch *dw));
void inotify_event_hook(int fd);

void init_sec(void);
void cleanup_sec(void);
