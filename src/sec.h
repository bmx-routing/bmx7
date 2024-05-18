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
#define DEF_TRUST_DIR_POLLING_INTERVAL 1000

#define ARG_TRUST_STATUS "trusted"

#define DEF_TRUSTED_NODES_DIR "/etc/bmx7/trustedNodes"
#define ARG_TRUSTED_NODES_DIR "trustedNodesDir"
#define HLP_TRUSTED_NODES_DIR "directory with global-id hashes of this node's trusted other nodes"

#define ARG_KEY_PATH "keyPath"
#define DEF_KEY_PATH "/etc/bmx7/rsa.der"

#define FILE_SUPPORT_LEVEL_PATTERN ".support="
#define FILE_TRUST_LEVEL_PATTERN   ".trust="

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


#define ARG_RESET_NODE "resetNode"
#define HLP_RESET_NODE "reset node id"
#define ARG_RESET_NODE_STATE "state"
#define MIN_RESET_NODE_STATE 0
#define MAX_RESET_NODE_STATE 3
#define DEF_RESET_NODE_STATE 0
#define HLP_RESET_NODE_STATE "specify max-node state: 0) listed, 1) tracked, 2) certified, 3) promoted"

#define ARG_SUPPORT_PUBLISHING "publishSupportedNodes"
#define MIN_SUPPORT_PUBLISHING 0
#define MAX_SUPPORT_PUBLISHING 1
#define DEF_SUPPORT_PUBLISHING 1
#define HLP_SUPPORT_PUBLISHING "publish (describe) id of nodes supported with priority"




#define ARG_NODE_RSA_TX_TYPE "nodeRsaKey"
#define MIN_NODE_RSA_TX_TYPE CRYPT_RSA_MIN_TYPE
#define MAX_NODE_RSA_TX_TYPE CRYPT_RSA4096_TYPE
#define DEF_NODE_RSA_TX_TYPE CRYPT_RSA2048_TYPE
#define HLP_NODE_RSA_TX_TYPE "sign own descriptions with given RSA key type (4:1024, 5:1536, 6:2048, 7:3072, 8:4096)"

#define ARG_NODE_RSA_RX_TYPES "nodeRsaKeys"
#define MIN_NODE_RSA_RX_TYPES (1<<CRYPT_RSA_MIN_TYPE)
#define MAX_NODE_RSA_RX_TYPES ((1<<CRYPT_RSA_MAX_TYPE)-1)
#define DEF_NODE_RSA_RX_TYPES ((1<<CRYPT_RSA1024_TYPE) | (1<<CRYPT_RSA1536_TYPE) | (1<<CRYPT_RSA2048_TYPE) | (1<<CRYPT_RSA3072_TYPE) | (1<<CRYPT_RSA4096_TYPE))
#define HLP_NODE_RSA_RX_TYPES "verify description signatures of flag-given RSA key types"

#define ARG_LINK_RSA_TX_TYPE "linkRsaKey"
#define MIN_LINK_RSA_TX_TYPE 0
#define MAX_LINK_RSA_TX_TYPE CRYPT_RSA2048_TYPE
#define DEF_LINK_RSA_TX_TYPE CRYPT_RSA1024_TYPE
#define HLP_LINK_RSA_TX_TYPE "sign outgoing packets with given RSA key type (0:None and rely on DHM, 4:1024, 5:1536, 6:2048)"
extern int32_t linkRsaSignType;

#define ARG_LINK_RSA_RX_TYPES "linkRsaKeys"
#define MIN_LINK_RSA_RX_TYPES 0
#define MAX_LINK_RSA_RX_TYPES ((1<<CRYPT_RSA_MAX_TYPE)-1)
#define DEF_LINK_RSA_RX_TYPES ((1<<CRYPT_RSA1024_TYPE) | (1<<CRYPT_RSA1536_TYPE) | (1<<CRYPT_RSA2048_TYPE))
#define HLP_LINK_RSA_RX_TYPES "verify incoming link (packet) signaturs of flag-given RSA key types"

#define ARG_LINK_DHM_TX_TYPE "linkDhmKey"
#define MIN_LINK_DHM_TX_TYPE 0
#define MAX_LINK_DHM_TX_TYPE CRYPT_DHM_MAX_TYPE
#define DEF_LINK_DHM_TX_TYPE CRYPT_DHM2048_TYPE
#define HLP_LINK_DHM_TX_TYPE "sign outgoing packets with DH-authenticated HMAC type (0:None and rely on RSA, 16:DH1024M112, 17:DH2048M112, 18:3072M112). Type must match that of neighbors"
extern int32_t linkDhmSignType;


#define ARG_MAX_DHM_NEIGHS "maxDhmNeighs"
#define MIN_MAX_DHM_NEIGHS 0
#define MAX_MAX_DHM_NEIGHS 40
#define DEF_MAX_DHM_NEIGHS (CRYPT_RSA2048_LEN / sizeof(struct frame_msg_dhMac112)) //17 corresponds equivalent maximum signature size of rsa2048 signatures
extern int32_t maxDhmNeighs;





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
#define MIN_LINK_SIGN_LT (1)      // one minute, needs ~100000 machines to crack RSA512 before end of life
#define DEF_LINK_SIGN_LT (6000)   // 100 minutes, needs ~1000 machines (in 2013) to crack RSA512 before end of life
#define MAX_LINK_SIGN_LT (REGISTER_TASK_TIMEOUT_MAX/1000)
#define ARG_LINK_SIGN_LT "linkKeyLifetime"
#define HLP_LINK_SIGN_LT "Lifetime of outgoing link keys and signatures in seconds"


#define MAX_KEY_FILE_SIZE (CRYPT_SHA_LEN + sizeof(FILE_TRUST_LEVEL_PATTERN) + 1 + sizeof(FILE_SUPPORT_LEVEL_PATTERN) + 1 + 1 + sizeof(CRYPT_RSA4096_NAME) + 1 + MAX_HOSTNAME_LEN + 1 ) //100

#define MIN_OGM_SQN_RANGE 10
#define MAX_OGM_SQN_RANGE 8192 // changing this will cause compatibility trouble
#define DEF_OGM_SQN_RANGE 6000
#define ARG_OGM_SQN_RANGE "ogmSqnRange"

#define MIN_OGM_SQN_DEVIATION 1
#define MAX_OGM_SQN_DEVIATION MAX_OGM_SQN_RANGE
#define DEF_OGM_SQN_DEVIATION 10
#define ARG_OGM_SQN_DEVIATION "ogmSqnDeviation"

#define MIN_OGM_SQN_RANDOM 0
#define MAX_OGM_SQN_RANDOM (MAX_OGM_SQN_RANGE - 1)
#define DEF_OGM_SQN_RANDOM 0
#define ARG_OGM_SQN_RANDOM "ogmSqnRandom"


extern CRYPTRSA_T *my_NodeKey;
//extern CRYPTRSA_T *my_RsaLinkKey;
//extern CRYPTDHM_T *my_DhmLinkKey;

typedef struct {
	uint8_t u8[sizeof(CRYPTSHA112_T)];
} __attribute__((packed)) ChainLink_T;

typedef struct {
	uint8_t u8[sizeof(CRYPTSHA_T) - sizeof(CRYPTSHA112_T)];
} __attribute__((packed)) ChainSeed_T;

typedef struct {

	union {

		struct {
			ChainLink_T link;
			ChainSeed_T seed;
		} e;
		CRYPTSHA_T sha;
	} u;
} __attribute__((packed)) ChainElem_T;

typedef struct {
	ChainElem_T elem;
	CRYPTSHA_T nodeId;
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


#define DESCRIPTION_MSG_DHM_LINK_KEY_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8,     0, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,     0, FIELD_RELEVANCE_HIGH,  "gx"}, \
FIELD_FORMAT_END }

struct dsc_msg_dhm_link_key {
	uint8_t type;
	uint8_t gx[];
} __attribute__((packed));



#define DESCRIPTION_MSG_PUBKEY_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(struct dsc_msg_pubkey),     0, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   0, FIELD_RELEVANCE_HIGH,  "key" }, \
FIELD_FORMAT_END }

struct dsc_msg_pubkey {
	uint8_t type;
	uint8_t key[];
} __attribute__((packed));


#define DESCRIPTION_MSG_SIGNATURE_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint8_t),                   0, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   0, FIELD_RELEVANCE_HIGH,  "signature" }, \
FIELD_FORMAT_END }

struct dsc_msg_signature {
	uint8_t type;
	uint8_t signature[];
} __attribute__((packed));



#define DESCRIPTION_MSG_TRUST_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(CRYPTSHA_T),               0, FIELD_RELEVANCE_HIGH,  "nodeId"},  \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint16_t),                  0, FIELD_RELEVANCE_HIGH,  "reserved"}, \
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
	CRYPTSHA_T nodeId;
	struct desc_msg_trust_fields f;

} __attribute__((packed));





#define VERSION_MSG_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8,                              0, FIELD_RELEVANCE_HIGH, "comp_version" }, \
{FIELD_TYPE_HEX,           -1, 8,                              0, FIELD_RELEVANCE_MEDI, "capabilities" }, \
{FIELD_TYPE_UINT,          -1, (8*sizeof(DESC_SQN_T)),         0, FIELD_RELEVANCE_HIGH, "bootSqn" }, \
{FIELD_TYPE_UINT,          -1, (8*sizeof(DESC_SQN_T)),         0, FIELD_RELEVANCE_HIGH, "descSqn" }, \
{FIELD_TYPE_UINT,          -1, (8*sizeof(uint16_t)),           0, FIELD_RELEVANCE_HIGH, "ogmSqnRange" }, \
{FIELD_TYPE_STRING_BINARY, -1, (8*sizeof(ChainElem_T)),        0, FIELD_RELEVANCE_HIGH, "ogmHChainAnchor" }, \
{FIELD_TYPE_UINT,          -1, 21,                             0, FIELD_RELEVANCE_HIGH, "descSize" }, \
{FIELD_TYPE_UINT,          -1, 11,                             0, FIELD_RELEVANCE_HIGH, "descContents" }, \
FIELD_FORMAT_END}

struct dsc_msg_version {
	uint8_t comp_version;
	uint8_t capabilities;
	DESC_SQN_T bootSqn;
	DESC_SQN_T descSqn;
	uint16_t ogmSqnRange;

	ChainElem_T ogmHChainAnchor;

	union content_sizes virtDescSizes;

} __attribute__((packed));

void chainLinkCalc(ChainInputs_T *ci_tmp, OGM_SQN_T diff);
OGM_SQN_T chainOgmFind(ChainLink_T *chainOgm, struct desc_content *dc, IDM_T searchFullRange);
ChainLink_T chainOgmCalc(struct desc_content *dc, OGM_SQN_T ogmSqn);
ChainElem_T myChainLinkCache(OGM_SQN_T sqn, DESC_SQN_T descSqn);

IPX_T create_crypto_IPv6(struct net_key *prefix, GLOBAL_ID_T *id);
IDM_T verify_crypto_ip6_suffix(IPX_T *ip, uint8_t mask, CRYPTSHA_T *id);

GLOBAL_ID_T *get_desc_id(uint8_t *desc_adv, uint32_t desc_len, struct dsc_msg_signature **signpp, struct dsc_msg_version **verspp);
void setQualifyingPromotedOrNeigh(IDM_T in, struct key_node *kn);

struct content_node *test_description_signature(uint8_t *desc, uint32_t desc_len);
void apply_trust_changes(int8_t f_type, struct orig_node *on, struct desc_content* dcOld, struct desc_content *dcNew);
IDM_T setted_pubkey(struct desc_content *dc, uint8_t type, GLOBAL_ID_T *globalId, uint8_t searchDepth);
IDM_T supportedKnownKey(CRYPTSHA_T *pkhash);
INT_NEIGH_ID_T allocate_internalNeighId(struct neigh_node *nn);
void free_internalNeighId(INT_NEIGH_ID_T ini);
uint32_t *init_neighTrust(struct orig_node *on);
IDM_T verify_neighTrust(struct orig_node *on, struct neigh_node *neigh);
void cleanup_dir_watch(struct DirWatch **dw);
IDM_T init_dir_watch(struct DirWatch **dw, char *path, void (* idChangedTask) (IDM_T del, struct KeyWatchNode *kwn, struct DirWatch *dw));
void inotify_event_hook(int fd);

void init_sec(void);
void cleanup_sec(void);
