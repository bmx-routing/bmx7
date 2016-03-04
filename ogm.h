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






extern int32_t ogmIid;
extern uint32_t ogms_pending;
extern int32_t ogmSqnRange;

#define ARG_OGM_IFACTOR "ogmIntervalFactor"
#define DEF_OGM_IFACTOR 120
#define MIN_OGM_IFACTOR 100
#define MAX_OGM_IFACTOR 10000


#define ARG_OGM_INTERVAL "ogmInterval"
#define DEF_OGM_INTERVAL 6000
#define MIN_OGM_INTERVAL 200
#define MAX_OGM_INTERVAL 60000 // 60000 = 1 minutes

#define _DEF_OGM_SQN_DIV   5
#define _MIN_OGM_SQN_RANGE 32
#define _MAX_OGM_SQN_RANGE 8192 // changing this will cause compatibility trouble

#define MIN_OGM_SQN_RANGE _MIN_OGM_SQN_RANGE + (_MIN_OGM_SQN_RANGE/(2*_DEF_OGM_SQN_DIV))
#define MAX_OGM_SQN_RANGE _MAX_OGM_SQN_RANGE - (_MAX_OGM_SQN_RANGE/(2*_DEF_OGM_SQN_DIV))
#define DEF_OGM_SQN_RANGE MAX_OGM_SQN_RANGE
#define ARG_OGM_SQN_RANGE "ogmSqnRange"

#define MIN_OGM_AGGREG_HISTORY 2
#define MAX_OGM_AGGREG_HISTORY AGGREG_SQN_CACHE_RANGE
#define DEF_OGM_AGGREG_HISTORY 20
#define ARG_OGM_AGGREG_HISTORY "ogmAggregHistory"


#define MIN_SEND_REVISED_OGMS 0
#define DEF_SEND_LINK_REVISED_OGMS 0
#define ARG_SEND_LINK_REVISED_OGMS "sendRevisedOgms"
extern int32_t sendLinkRevisedOgms;

#define OGM_JUMPS_PER_AGGREGATION 10


#define OGMS_DHASH_PER_AGGREG_PREF (SIGNED_FRAMES_SIZE_PREF - (\
                              sizeof(struct tlv_hdr) + \
                              sizeof (struct hdr_ogm_adv))) \
                              / sizeof(struct msg_ogm_dhash_adv)



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

struct msg_ogm_dhash_adv {
	OgmHashChainLink_T sqnHashChainLink;
	DHASH_T dhash;
	ROUGH_DHASH_T roughDHash;

	union {

		struct {
			unsigned int sqn : OGM_SQN_BIT_SIZE; // 14
			unsigned int trustedFlag : 1;
			unsigned int hopCount : 6;
			unsigned int metric_exp : OGM_EXPONENT_BIT_SIZE; // 5
			unsigned int metric_mantissa : OGM_MANTISSA_BIT_SIZE; // 6
		} __attribute__((packed)) f;
		uint16_t u16;
	} u;

} __attribute__((packed));

struct hdr_ogm_adv {
	AGGREG_SQN_T aggregation_sqn;
	struct msg_ogm_dhash_adv msg[];
} __attribute__((packed));

struct avl_tree **ogm_aggreg_origs(AGGREG_SQN_T aggSqn);

void remove_ogm(struct orig_node *on);
void process_ogm_metric(void *voidRef);

int32_t init_ogm(void);
