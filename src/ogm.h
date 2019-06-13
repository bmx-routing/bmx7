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






extern uint32_t ogms_pending;

#define ARG_OGM_IFACTOR "ogmIntervalFactor"
#define DEF_OGM_IFACTOR 110
#define MIN_OGM_IFACTOR 100
#define MAX_OGM_IFACTOR 1000


#define ARG_OGM_INTERVAL "ogmInterval"
#define DEF_OGM_INTERVAL 6000
#define MIN_OGM_INTERVAL 200
#define MAX_OGM_INTERVAL 60000 // 60000 = 1 minutes
extern int32_t my_ogmInterval;

#define MIN_OGM_AGGREG_HISTORY 2
#define MAX_OGM_AGGREG_HISTORY AGGREG_SQN_CACHE_RANGE
#define DEF_OGM_AGGREG_HISTORY 20
#define ARG_OGM_AGGREG_HISTORY "ogmAggregHistory"

extern AGGREG_SQN_T ogm_aggreg_sqn_max;
extern AGGREG_SQN_T ogm_aggreg_sqn_max_window_size;
extern AGGREG_SQN_T ogm_aggreg_sqn_send;


#define FRM_SIGN_VERS_SIZE_MAX_XXX (FRM_SIGN_VERS_SIZE_MIN + XMAX(cryptRsaKeyLenByType(MAX_LINK_RSA_TX_TYPE), (MAX_MAX_DHM_NEIGHS*sizeof(struct frame_msg_dhMac112))))

//note that precalculated ogm-aggregations MUST fit into remaining space of DHM signed frames with many neighbors:
#define SIGNED_FRAMES_SIZE_PREF_XXX (PKT_FRAMES_SIZE_PREF - FRM_SIGN_VERS_SIZE_MAX_XXX)

#define OGMS_DHASH_MSGS_LEN_PER_AGGREG_PREF (SIGNED_FRAMES_SIZE_PREF_XXX - (sizeof(struct tlv_hdr) + sizeof (struct hdr_ogm_adv)))

//#define OGMS_DHASH_PER_AGGREG_PREF_REMOVE (OGMS_DHASH_MSGS_LEN_PER_AGGREG_PREF / sizeof(struct msg_ogm_adv))



#define OGM_IID_RSVD_JUMP  (OGM_IIDOFFST_MASK) // 63 //255 // resulting from ((2^transmitterIIDoffset_bit_range)-1)

struct msg_ogm_aggreg_sqn_adv {
	AGGREG_SQN_T max;
	uint16_t size;
} __attribute__((packed));

struct msg_ogm_aggreg_req {
	AGGREG_SQN_T sqn;
} __attribute__((packed));

struct hdr_ogm_aggreg_req {
	GLOBAL_ID_T dest_nodeId;
	struct msg_ogm_aggreg_req msg[];
} __attribute__((packed));

/*
 *            short long
 * sqnHashLink  112  112
 * shortDhash    15   16
 * sqn           13   13
 * flags          1    8
 * metric        11   11
 * ---------------------
 *              152  160
 * */

union msg_ogm_adv_metric {

	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		unsigned int metric_mantissa : OGM_MANTISSA_BIT_SIZE; // 6
		unsigned int metric_exp : OGM_EXPONENT_BIT_SIZE; // 5
		unsigned int hopCount : OGM_HOP_COUNT_BITSIZE; //6
		unsigned int transmitterIID4x : IID_BIT_SIZE; // 14
		unsigned int more : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
		unsigned int more : 1;
		unsigned int transmitterIID4x : IID_BIT_SIZE;
		unsigned int hopCount : OGM_HOP_COUNT_BITSIZE;
		unsigned int metric_exp : OGM_EXPONENT_BIT_SIZE; // 5
		unsigned int metric_mantissa : OGM_MANTISSA_BIT_SIZE; // 6
#else
#error "Please fix <bits/endian.h>"
#endif
	} __attribute__((packed)) f;
	uint32_t u32;
};

struct msg_ogm_adv {
	ChainLink_T chainOgm;

	union msg_ogm_adv_metric u;
	struct msg_ogm_adv_metric_t0 mt0[];

} __attribute__((packed));

struct hdr_ogm_adv {
	AGGREG_SQN_T aggregation_sqn;
	//	struct msg_ogm_adv msg[];
} __attribute__((packed));

struct OgmAggreg_node {
	struct avl_tree tree;
	int16_t msgsLen;
};


struct OgmAggreg_node *getOgmAggregNode(AGGREG_SQN_T aggSqn);


void remove_ogm(struct orig_node *on);
void process_ogm_metric(void *voidRef);

int32_t init_ogm(void);
