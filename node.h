/*
 * Copyright (c) 2010  BMX protocol contributor(s):
 * Axel Neumann  <neumann at cgws dot de>
 *
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
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "iid.h"





/*
 * from metrics.h:
 */

// to be used:
typedef uint64_t UMETRIC_T;


#define OGM_MANTISSA_BIT_SIZE  6
#define OGM_EXPONENT_BIT_SIZE  5
#define OGM_EXPONENT_OFFSET    OGM_MANTISSA_BIT_SIZE

#define OGM_EXPONENT_MAX       ((1<<OGM_EXPONENT_BIT_SIZE)-1)
#define OGM_MANTISSA_MASK      ((1<<OGM_MANTISSA_BIT_SIZE)-1)
#define OGM_EXPONENT_MASK      ((1<<OGM_EXPONENT_BIT_SIZE)-1)


#define OGM_MANTISSA_INVALID            0
#define OGM_MANTISSA_MIN__NOT_ROUTABLE  1
#define OGM_MANTISSA_ROUTABLE           2

#define FM8_EXPONENT_BIT_SIZE  OGM_EXPONENT_BIT_SIZE
#define FM8_MANTISSA_BIT_SIZE  (8-FM8_EXPONENT_BIT_SIZE)
#define FM8_MANTISSA_MASK      ((1<<FM8_MANTISSA_BIT_SIZE)-1)
#define FM8_MANTISSA_MIN       (1)

#define OGM_MANTISSA_MAX       (FM8_MANTISSA_MASK << (OGM_MANTISSA_BIT_SIZE - FM8_MANTISSA_BIT_SIZE))

#define UMETRIC_SHIFT_MAX          ((sizeof(UMETRIC_T)*8) - (OGM_EXPONENT_OFFSET+OGM_EXPONENT_MAX+1))
#define UMETRIC_MULTIPLY_MAX       (((UMETRIC_T)-1)>>(OGM_EXPONENT_OFFSET+OGM_EXPONENT_MAX+1))
#define UMETRIC_MASK               ((((UMETRIC_T) 1) << (OGM_EXPONENT_OFFSET+OGM_EXPONENT_MAX+1)) -1)

#define UMETRIC_INVALID            ((((UMETRIC_T) 1) << OGM_EXPONENT_OFFSET) + OGM_MANTISSA_INVALID)
#define UMETRIC_MIN__NOT_ROUTABLE  ((((UMETRIC_T) 1) << OGM_EXPONENT_OFFSET) + OGM_MANTISSA_MIN__NOT_ROUTABLE)
#define UMETRIC_ROUTABLE           ((((UMETRIC_T) 1) << OGM_EXPONENT_OFFSET) + OGM_MANTISSA_ROUTABLE)
#define UMETRIC_FM8_MAX            ((((UMETRIC_T) 1) << (OGM_EXPONENT_OFFSET+OGM_EXPONENT_MAX)) + (((UMETRIC_T) FM8_MANTISSA_MASK) << ((OGM_EXPONENT_OFFSET+OGM_EXPONENT_MAX)-FM8_MANTISSA_BIT_SIZE)))
#define UMETRIC_FM8_MIN            ((((UMETRIC_T) 1) << OGM_EXPONENT_OFFSET) + (((UMETRIC_T) FM8_MANTISSA_MIN) << (OGM_EXPONENT_OFFSET-FM8_MANTISSA_BIT_SIZE)))
#define UMETRIC_MAX                UMETRIC_FM8_MAX
//#define UMETRIC_MAX       ((((UMETRIC_T) 1) << (OGM_EXPONENT_OFFSET+OGM_EXPONENT_MAX)) + (((UMETRIC_T) OGM_MANTISSA_MAX) << ((OGM_EXPONENT_OFFSET+OGM_EXPONENT_MAX)-OGM_MANTISSA_BIT_SIZE)))

// these fixes are used to improove (average) rounding errors in umetric_to_fmetric()
#define UMETRIC_TO_FMETRIC_INPUT_FIX (79)

//#define UMETRIC_MAX_SQRT           ((UMETRIC_T)358956)      // sqrt(UMETRIC_MAX)
//#define UMETRIC_MAX_HALF_SQRT      ((UMETRIC_T)253821)      // sqrt(UMETRIC_MAX/2)
//#define U64_MAX_QUARTER_SQRT       ((UMETRIC_T)2147493120)  // sqrt(U64_MAX/4)

struct float_u16 {

	union {

		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t mantissa_fm16;
			uint8_t exp_fm16;
#elif __BYTE_ORDER == __BIG_ENDIAN
			uint8_t exp_fm16;
			uint8_t mantissa_fm16;
#else
#error "Please fix <bits/endian.h>"
#endif
		} __attribute__((packed)) f;

		uint8_t u8[2];

		uint16_t u16;
	} val;
};


typedef struct float_u16 FMETRIC_U16_T;

struct float_u8 {

	union {

		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			unsigned int mantissa_fmu8 : FM8_MANTISSA_BIT_SIZE;
			unsigned int exp_fmu8 : FM8_EXPONENT_BIT_SIZE;
#elif __BYTE_ORDER == __BIG_ENDIAN
			unsigned int exp_fmu8 : FM8_EXPONENT_BIT_SIZE;
			unsigned int mantissa_fmu8 : FM8_MANTISSA_BIT_SIZE;
#else
#error "Please fix <bits/endian.h>"
#endif
		} __attribute__((packed)) f;
		uint8_t u8;
	} val;
};

typedef struct float_u8 FMETRIC_U8_T;

typedef uint16_t ALGO_T;

struct host_metricalgo {
	FMETRIC_U16_T fmetric_u16_min;

	UMETRIC_T umetric_min;
	ALGO_T algo_type;
	uint16_t flags;
	uint8_t algo_rp_exp_numerator;
	uint8_t algo_rp_exp_divisor;
	uint8_t algo_tp_exp_numerator;
	uint8_t algo_tp_exp_divisor;

	uint8_t lq_tx_point_r255;
	uint8_t lq_ty_point_r255;
	uint8_t lq_t1_point_r255;

	uint8_t ogm_hop_penalty;
	uint8_t ogm_sqn_best_hystere;
	uint16_t ogm_sqn_late_hystere;
	uint16_t ogm_metric_hystere;
};

struct lndev_probe_record {
	HELLO_SQN_T hello_sqn_max; // SQN which has been applied (if equals wa_pos) then wa_unscaled MUST NOT be set again!

	uint8_t hello_array[MAX_HELLO_SQN_WINDOW / 8];
	uint32_t hello_sum;
	UMETRIC_T hello_umetric;
	TIME_T hello_time_max;
};

struct metric_record {
	SQN_T sqn_bit_mask;

	SQN_T clr; // SQN upto which waightedAverageVal has been purged
	SQN_T set; // SQN which has been applied (if equals wa_pos) then wa_unscaled MUST NOT be set again!

	//	UMETRIC_T umetric;
	//	UMETRIC_T umetric_fast;
	UMETRIC_T umetric;
	//	UMETRIC_T umetric_prev;
};

#define ZERO_METRIC_RECORD {0, 0, 0, 0,0,0}





/*
 * from node.h:
 */

typedef CRYPTSHA1_T SHA1_T;
typedef CRYPTSHA1_T DHASH_T;
typedef CRYPTSHA1_T RHASH_T;



typedef CRYPTSHA1_T GLOBAL_ID_T;

typedef uint16_t DEVIDX_T;
#define DEVIDX_INVALID 0
#define DEVIDX_MIN 1
#define DEVIDX_BITS 10
#define DEVIDX_MASK ((1<<DEVIDX_BITS)-1)
#define DEVIDX_MAX DEVIDX_MASK

typedef struct {
	LOCAL_IP_T llip;
	DEVIDX_T devIdx;
} __attribute__((packed)) DevKey;

typedef struct {
	LOCAL_IP_T llocal_ip;
	DEVIDX_T devIdx;
	struct neigh_node *local; // set immediately
} __attribute__((packed)) LinkDevKey;


typedef struct {
	LinkDevKey key;
	uint8_t purge;

	TIME_T pkt_time_max;
	TIME_T hello_time_max;

	HELLO_SQN_T hello_sqn_max;

	struct avl_tree link_tree;
} LinkDevNode;

typedef struct {
	LinkDevNode *linkDev;
	struct dev_node *myDev;
} __attribute__((packed)) LinkKey;

typedef struct {
	struct list_node list;
	LinkKey k;

	UMETRIC_T tx_probe_umetric;
	UMETRIC_T timeaware_tx_probe;
	struct lndev_probe_record rx_probe_record;
	UMETRIC_T timeaware_rx_probe;
	int32_t orig_routes;


	TIME_T rp_time_max;
} LinkNode;

struct neigh_node {
	GLOBAL_ID_T local_id;
	struct avl_tree linkDev_tree;
	LinkNode *best_rp_link;
	LinkNode *best_tp_link;

	BURST_SQN_T burstSqn;

	INT_NEIGH_ID_T internalNeighId;

	int32_t orig_routes;

	struct orig_node *on;
	CRYPTKEY_T *linkKey;


	struct iid_repos neighIID4x_repos;

	TIME_T ogm_aggreg_time;
	AGGREG_SQN_T ogm_aggreg_max;
	AGGREG_SQN_T ogm_aggreg_size;
	uint8_t ogm_aggreg_sqns[(AGGREG_SQN_CACHE_RANGE / 8)];
};

struct content_usage_node {

	struct {
		uint32_t expanded_type;
		struct content_node *content;
		struct desc_content *descContent;
	} __attribute__((packed)) k;

	uint8_t maxUsedLevel;
	uint8_t maxAllowedLevel;
	uint16_t dup;
};

#define MAX_DESC_LEN (INT32_MAX-1)
#define MAX_REF_NESTING 2

struct content_node {
	SHA1_T chash;
	struct key_node *kn;
	uint8_t *f_body;
	uint32_t f_body_len;
	uint8_t nested;
	uint8_t gzip;
	uint8_t reserved;

	struct avl_tree usage_tree;
};

struct desc_tlv_body {

	union {
		struct content_usage_node *cun;
		uint8_t *desc_tlv_body;
	} u;
	uint16_t desc_tlv_body_len;
};


#define OGM_HASH_CHAIN_LINK_BITSIZE 112

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

struct desc_content {
	DHASH_T dHash;

	IDM_T cntr;
	struct key_node *kn;
	struct orig_node *on;
	uint8_t *desc_frame;
	uint16_t desc_frame_len;
	int32_t ref_content_len;
	DESC_SQN_T descSqn;
	TIME_T referred_by_others_timestamp;

	struct avl_tree contentRefs_tree;
	uint32_t unresolvedContentCounter;
	uint8_t max_nesting;

	uint16_t ogmSqnRange;
	OGM_SQN_T ogmSqnMaxSend;
	OGM_SQN_T ogmSqnMaxRcvd;
	ChainLink_T chainLinkMaxRcvd;
	ChainInputs_T chainInputs_tmp;
	CRYPTSHA1_T chainOgmConstInputHash;
	ChainLink_T chainAnchor;

	struct desc_tlv_body final[BMX_DSC_TLV_ARRSZ];
};

struct InaptChainOgm {
	ChainLink_T *chainOgm;
	FMETRIC_U16_T ogmMtc;
};

struct NeighRef_node {
	AGGREG_SQN_T aggSqn;
	uint8_t scheduled_ogm_processing;
	uint8_t shown;

	struct InaptChainOgm *inaptChainOgm;

	// set by ref_node_update():
	IID_T __neighIID4x;
	struct neigh_node *nn;
	struct key_node *kn;
	DESC_SQN_T descSqn;
	OGM_SQN_T ogmSqnMaxRcvd;
	FMETRIC_U16_T ogmMtcMaxRcvd;
	TIME_T ogmTimeMaxRcvd;

	// set by rx_frame_ogm_aggreg_adv():
	TIME_T ogmBestSinceSqn;

};

struct orig_node {
	// filled in by validate_new_link_desc0():

	struct {
		char hostname[MAX_HOSTNAME_LEN];

		GLOBAL_ID_T nodeId;
	} __attribute__((packed)) k;

	//	struct dhash_node *dhn; //TODO: remove
	//	int32_t currKeySupportsPerOrig;
	struct desc_content *dc;
	struct key_node *kn;
	struct neigh_node *neigh;
	IID_T __myIID4x;

	TIME_T updated_timestamp; // last time this on's desc was succesfully updated

	// filled in by process_desc0_tlvs()->
	IPX_T primary_ip;
	//	uint8_t blocked; // blocked description
	//	uint8_t added; // added description

	struct host_metricalgo *mtcAlgo;

	uint32_t *trustedNeighsBitArray;

	IDM_T ogmAggregActive;
	AGGREG_SQN_T ogmAggregSqn;

	UMETRIC_T ogmMetric;
	LinkNode *curr_rt_link; // the configured route in the kernel!

	//size of plugin data is defined during intialization and depends on registered PLUGIN_DATA_ORIG hooks
	void *plugin_data[];

};


struct key_credits {
	uint8_t nQualifying;
	uint8_t dFriend;
	uint8_t pktId;
	uint8_t pktSign;
	struct orig_node *recom;
	struct orig_node *trusteeRef;
	struct NeighRef_node *neighRef;
};

struct key_node {
	GLOBAL_ID_T kHash;
	struct KeyState *bookedState;
	struct KeyState *decreasedEffectiveState;
	struct content_node *content;
	uint8_t dFriend; //[0,1,2=supportHisDirSupKeys]
	TIME_T pktIdTime;
	TIME_T pktSignTime;
	TIME_T nQTime;
	TIME_T TAPTime;
	struct avl_tree neighRefs_tree;
	struct avl_tree trustees_tree;
	struct orig_node *on;
	struct desc_content *nextDesc;
	DESC_SQN_T nextDescSqnMin;
	struct avl_tree recommendations_tree; //ofMyDirect2SupportedKeys
};

struct schedDecreasedEffectiveState_node {
	struct key_node *kn;
};

struct KeyState {

	struct {
		int16_t numSet;
		int16_t numSec;
		uint16_t flags;
		uint8_t c;
		uint8_t r;
		struct KeyState *up;
		struct KeyState *down;
		struct KeyState *left;
		struct KeyState *right;
	} i;
	char *setName;
	char *rowName;
	char *secName;
	int16_t prefBase;
	int16_t(* prefGet) (struct key_node *kn);
	int16_t maxSet;
	void (*setInAction) (GLOBAL_ID_T *kHash, struct key_node **kn, struct KeyState *next);
	void (*setOutAction) (struct key_node **kn, struct KeyState *next);
	int8_t(* colMaintain) (struct key_node *kn);
	int8_t(* colCond) (uint8_t asRow, struct key_node *kn);
	int8_t(* rowCond) (struct key_node *kn, struct key_credits *kc);
};

struct packet_header {
	uint8_t comp_version;
	uint8_t reserved;
	CRYPTSHA1_T keyHash;
} __attribute__((packed, __may_alias__));

struct packet_buff {

	struct packet_buff_info {
		//filled by wait4Event()
		struct sockaddr_storage addr;
		struct timeval tv_stamp;
		struct dev_node *iif;
		int length;
		uint8_t unicast;

		//filled in by tx_packet()
		struct dev_node *oif;

		//filled in by rx_packet():
		IPX_T llip;
		char llip_str[INET6_ADDRSTRLEN];

		struct key_node *claimedKey;
		LinkNode *verifiedLink;
	} i;

	union {
		struct packet_header hdr;
		unsigned char data[MAX_UDPD_SIZE + 1];
	} p;

};


extern struct packet_buff *curr_rx_packet;

extern struct key_node *myKey;




extern struct avl_tree local_tree;
extern struct avl_tree link_dev_tree;
extern struct avl_tree link_tree;
extern struct avl_tree orig_tree;
extern struct avl_tree key_tree;
extern struct avl_tree dhash_tree;
extern struct avl_tree descContent_tree;
extern struct avl_tree ogmHChainLXD_tree;


extern uint32_t content_tree_unresolveds;


/***********************************************************
 Data Infrastructure
 ************************************************************/

void neighRef_destroy(struct NeighRef_node *ref, IDM_T reAssessState);
struct NeighRef_node *neighRef_update(struct neigh_node *nn, AGGREG_SQN_T aggSqn, IID_T neighIID4x, CRYPTSHA1_T *kHash, DESC_SQN_T descSqn, struct InaptChainOgm *chainOgm);
void neighRefs_update(struct key_node *kn);
int purge_orig_router(struct orig_node *onlyOrig, struct neigh_node *onlyNeigh, LinkNode *onlyLink, IDM_T onlyUseless);
void neigh_destroy(struct neigh_node *local);
struct neigh_node *neigh_create(struct orig_node *on);

void destroy_orig_node(struct orig_node *on);
void init_self(void);



