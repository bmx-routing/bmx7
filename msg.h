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





#define MIN_UDPD_SIZE 128 //(6+4+(22+8)+32)+184=72+56=128
#define DEF_UDPD_SIZE 512 //512
#define MAX_UDPD_SIZE (MIN( 1400, MAX_PACKET_SIZE))
#define ARG_UDPD_SIZE "udpDataSize"



#define DEF_TX_TS_TREE_SIZE 150
#define DEF_TX_TS_TREE_PURGE_FK 3

#define DEF_DESC0_CACHE_SIZE 100
#define DEF_DESC0_CACHE_TO   100000




#define MIN_DEV_ADVS_TX_ITERS 1
#define MAX_DEV_ADVS_TX_ITERS 100
#define DEF_DEV_ADVS_TX_ITERS 1
#define ARG_DEV_ADVS_TX_ITERS "devAdvSends"

#define MIN_DEV_ADVS_UNSOLICITED 0
#define MAX_DEV_ADVS_UNSOLICITED 1
#define DEF_DEV_ADV_UNSOLICITED 3
#define ARG_DEV_ADVS_UNSOLICITED "devUnsolicitedSends"

#define MIN_DEV_REQS_TX_ITERS 1
#define MAX_DEV_REQS_TX_ITERS 100
#define DEF_DEV_REQS_TX_ITERS 4
#define ARG_DEV_REQS_TX_ITERS "devReqSends"




#define MIN_LINK_ADVS_TX_ITERS 1
#define MAX_LINK_ADVS_TX_ITERS 100
#define DEF_LINK_ADVS_TX_ITERS 1
#define ARG_LINK_ADVS_TX_ITERS "linkAdvSends"

#define MIN_LINK_ADVS_UNSOLICITED 0
#define MAX_LINK_ADVS_UNSOLICITED 1
#define DEF_LINK_ADV_UNSOLICITED  1
#define ARG_LINK_ADVS_UNSOLICITED "linkUnsolicitedSends"

#define MIN_LINK_REQS_TX_ITERS 1
#define MAX_LINK_REQS_TX_ITERS 100
#define DEF_LINK_REQS_TX_ITERS 4
#define ARG_LINK_REQS_TX_ITERS "linkReqSends"



#define MIN_DSC0_ADVS_TX_ITERS 1
#define MAX_DSC0_ADVS_TX_ITERS 20
#define DEF_DESC_ADV_TX_ITERS 1
#define ARG_DSC0_ADVS_TX_ITERS "descAdvSends"

#define MIN_UNSOLICITED_DESC_ADVS 0
#define MAX_UNSOLICITED_DESC_ADVS 1
#define DEF_DESC_ADV_UNSOLICITED 1
#define ARG_UNSOLICITED_DESC_ADVS "descUnsolicitedSends"

#define MIN_DSC0_REQS_TX_ITERS 1
#define MAX_DSC0_REQS_TX_ITERS 100
#define DEF_DESC_REQ_TX_ITERS 10 //TODO: will blow lndev->tx_task_list[] if new local_ids appeare just for a moment
#define ARG_DSC0_REQS_TX_ITERS "descReqSends"


#define MIN_DHS0_ADVS_TX_ITERS 1
#define MAX_DHS0_ADVS_TX_ITERS 100
#define DEF_DHASH_ADV_TX_ITERS 1
#define ARG_DHS0_ADVS_TX_ITERS "descShaAdvSends"

#define MIN_DHS0_REQS_TX_ITERS 1
#define MAX_DHS0_REQS_TX_ITERS 100
#define DEF_DHASH_REQ_TX_ITERS 10 //TODO: will blow lndev->tx_task_list[] if new local_ids appeare just for a moment
#define ARG_DHS0_REQS_TX_ITERS "descShaReqSends"


#define MIN_OGM_TX_ITERS 0
#define MAX_OGM_TX_ITERS 30
#define DEF_OGM_TX_ITERS 10
#define ARG_OGM_TX_ITERS "ogmAdvSends"

#define DEF_OGM_ACK_TX_ITERS 1
#define MIN_OGM_ACK_TX_ITERS 0
#define MAX_OGM_ACK_TX_ITERS 4
#define ARG_OGM_ACK_TX_ITERS "ogmAckSends"

#define CONTENT_MIN_TX_INTERVAL_MIN 0
#define CONTENT_MIN_TX_INTERVAL__CHECK_FOR_REDUNDANCY 1
#define CONTENT_MIN_TX_INTERVAL_MAX 50000

//TODO: set REQ_TO to 1 (in a non-packet-loss testenvironment this may be set to 1000 for testing)
#define DEF_TX_DESC0_REQ_TO  ((DEF_TX_INTERVAL*3)/2)
#define DEF_TX_DESC0_ADV_TO  200
#define DEF_TX_DHASH0_REQ_TO ((DEF_TX_INTERVAL*3)/2)
#define DEF_TX_DHASH0_ADV_TO 200

#define MIN_DESC0_REFERRED_TO 10000
#define MAX_DESC0_REFERRED_TO 100000
#define DEF_DESC0_REFERRED_TO 10000

#define DEF_DESC0_REQ_STONE_OLD_TO 40000

#define MAX_PKT_MSG_SIZE (MAX_UDPD_SIZE - sizeof(struct packet_header) - sizeof(struct frame_header_long))

#define MAX_DESC0_TLV_SIZE (MAX_PKT_MSG_SIZE - sizeof(struct msg_description_adv) )



#define FRAME_TYPE_RSVD0        0

#define FRAME_TYPE_PROBLEM_ADV  2  // yet only used to indicate dev_id collisions

#define FRAME_TYPE_TEST_ADV     3  // just for testing zero-message rx/tx_frame_iterator()

#define FRAME_TYPE_HELLO_ADV    4 // most-simple BMX-NG hello (nb-discovery) advertisements

#define FRAME_TYPE_DEV_REQ      6
#define FRAME_TYPE_DEV_ADV      7
#define FRAME_TYPE_LINK_REQ_ADV     8
#define FRAME_TYPE_LINK_ADV     9

#define FRAME_TYPE_RP_ADV      11


#define FRAME_TYPE_DESC_REQ    14
#define FRAME_TYPE_DESC_ADV    15


#define FRAME_TYPE_HASH_REQ    18  // Hash-for-description-of-OG-ID requests
#define FRAME_TYPE_HASH_ADV    19  // Hash-for-description-of-OG-ID advertisements

//#define FRAME_TYPE_HELLO_REPS  21  // most-simple BMX-NG hello (nb-discovery) replies

#define FRAME_TYPE_OGM_ADV     22 // most simple BMX-NG (type 0) OGM advertisements
#define FRAME_TYPE_OGM_ACK     23 // most simple BMX-NG (type 0) OGM advertisements

#define FRAME_TYPE_NOP         24
#define FRAME_TYPE_MAX         (FRAME_TYPE_ARRSZ-1)


#define FRAME_TYPE_PROCESS_ALL    (255)
#define FRAME_TYPE_PROCESS_NONE   (254)


#define ARG_DESCRIPTIONS        "descriptions"
#define HLP_DESCRIPTIONS        "show node descriptions\n"

#define ARG_DESCRIPTION_NAME    "name"

#define ARG_DESCRIPTION_TYPE    "type"
#define DEF_DESCRIPTION_TYPE     FRAME_TYPE_PROCESS_ALL
#define MIN_DESCRIPTION_TYPE     0
#define MAX_DESCRIPTION_TYPE     FRAME_TYPE_PROCESS_ALL
#define HLP_DESCRIPTION_TYPE     "show description extension(s) of given type (0..253=type 254=none 255=all) \n"



struct frame_header_short { // 2 bytes

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int type : FRAME_TYPE_BIT_SIZE;
	unsigned int is_relevant : FRAME_RELEVANCE_BIT_SIZE;
	unsigned int is_short : FRAME_ISSHORT_BIT_SIZE;

#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int is_short : FRAME_ISSHORT_BIT_SIZE;
	unsigned int is_relevant : FRAME_RELEVANCE_BIT_SIZE;
	unsigned int type : FRAME_TYPE_BIT_SIZE;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t length_TLV_DATA_STEPS; // lenght of frame in TLV_DATA_STEPS Byte steps, including frame_header and variable data field
//	uint8_t  data[];   // frame-type specific data consisting of 0-1 data headers and 1-n data messages
} __attribute__((packed));


struct frame_header_long { // 4 bytes
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int type : FRAME_TYPE_BIT_SIZE;
	unsigned int is_relevant : FRAME_RELEVANCE_BIT_SIZE;
	unsigned int is_short : FRAME_ISSHORT_BIT_SIZE;

#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int is_short : FRAME_ISSHORT_BIT_SIZE;
	unsigned int is_relevant : FRAME_RELEVANCE_BIT_SIZE;
	unsigned int type : FRAME_TYPE_BIT_SIZE;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t  reserved;
	uint16_t length;  // lenght of frame in 1-Byte steps, including frame_header and variable data field
//	uint8_t  data[];  // frame-type specific data consisting of 0-1 data headers and 1-n data messages
} __attribute__((packed));





#define SHORT_FRAME_DATA_MAX (MIN( 500, ((int)((((sizeof( ((struct frame_header_short*)NULL)->length_TLV_DATA_STEPS ))<<8)-1)*TLV_DATA_STEPS))))

/*
// iterator return codes:
#define TLV_RX_DATA_BLOCKED    (-3) // blocked due to DAD

#define TLV_TX_DATA_FULL       (-2) // nothing done! Frame finished or not enough remining data area to write
                                 // only returns from tx-iterations, rx- will return FAILURE
#define TLV_RX_DATA_FAILURE    (-1) // syntax error: exit or blacklist
#define TLV_TX_DATA_FAILURE    (-1) // syntax error: will fail assertion()

#define TLV_RX_DATA_DONE        (0) // done, nothing more to do
#define TLV_TX_DATA_DONE        (0) // done, nothing more to do

#define TLV_RX_DATA_IGNORED     (1) // unknown, filtered, nothing to send, or ignored due to bad link...
#define TLV_TX_DATA_IGNORED     (1) // unknown, filtered, nothing to send, or ignored due to bad link...

#define TLV_RX_DATA_PROCESSED   (2) // >= means succesfully processed returned amount of data
#define TLV_TX_DATA_PROCESSED   (2) // >= means succesfully processed returned amount of data
#define TLV_DATA_STEPS          (2) // legal data-size steps, never returns
                                    // the smalles legal frame must be:
                                    // - a multiple of two
                                    // - have lenght of frame_header_short plus 2 bytes frame_data
*/

// iterator return codes:
#define TLV_RX_DATA_BLOCKED    (-5) // blocked due to DAD

#define TLV_TX_DATA_FULL       (-4) // nothing done! Frame finished or not enough remining data area to write
                                 // only returns from tx-iterations, rx- will return FAILURE
#define TLV_RX_DATA_FAILURE    (-3) // syntax error: exit or blacklist
#define TLV_TX_DATA_FAILURE    (-3) // syntax error: will fail assertion()

#define TLV_RX_DATA_DONE        (-2) // done, nothing more to do
#define TLV_TX_DATA_DONE        (-2) // done, nothing more to do

#define TLV_RX_DATA_IGNORED     (-1) // unknown, filtered, nothing to send, or ignored due to bad link...
#define TLV_TX_DATA_IGNORED     (-1) // unknown, filtered, nothing to send, or ignored due to bad link...

#define TLV_RX_DATA_PROCESSED   (0) // >= means succesfully processed returned amount of data
#define TLV_TX_DATA_PROCESSED   (0) // >= means succesfully processed returned amount of data
#define TLV_DATA_STEPS          (1) // legal data-size steps, never returns
                                    // the smalles legal frame must be:
                                    // - a multiple of two
                                    // - have lenght of frame_header_short plus 2 bytes frame_data



// rx_frame_iterator operation codes:
enum {
	TLV_OP_DEL = 0,
	TLV_OP_TEST = 1,
	TLV_OP_ADD = 2,
	TLV_OP_DEBUG = 3,

	TLV_OP_CUSTOM_MIN = 20,
        TLV_OP_CUSTOM_MAX = 99,
        TLV_OP_PLUGIN_MIN = 100,
        TLV_OP_PLUGIN_MAX = 199
};

char *tlv_op_str(uint8_t op);

/*
 * this iterator is given the beginning of a frame area (e.g. the end of the packet_header)
 * then it iterates over the frames in that area */
struct rx_frame_iterator {
	// MUST be initialized:
	// remains unchanged:
	const char         *caller;
	struct packet_buff *pb;
	struct orig_node   *on;
	struct ctrl_node   *cn;
	uint8_t            *frames_in;
	struct frame_handl *handls;
	uint8_t             op;
	uint8_t             process_filter;
	uint8_t             handl_max;
	int32_t             frames_length;

	// updated by rx..iterate():
	int32_t             frames_pos;

	// set by rx..iterate(), and consumed by handl[].rx_tlv_handler
	uint8_t             is_short_header;
	uint8_t             frame_type;
	int32_t             frame_data_length;
	int32_t             frame_msgs_length;
	uint8_t            *frame_data;
	uint8_t            *msg;
};


/*
 * this iterator is given a fr_type and a set of handlers,
 * then the handlers are supposed to figure out what needs to be done.
 * finally the iterator writes ready-to-send frame_header and frame data to *fs_data */
struct tx_frame_iterator {
	// MUST be initialized:
	// remains unchanged:
	const char          *caller;
	struct list_head    *tx_task_list;
	struct tx_task_node *ttn;

	uint8_t             *cache_data_array;
	uint8_t             *frames_out;
	struct frame_handl  *handls;
	uint8_t              handl_max;
	int32_t              frames_out_max;

        // updated by fs_caller():
	uint8_t              frame_type;

	// updated by tx..iterate():
	int32_t              frames_out_pos;
	int32_t              cache_msgs_size;

//#define tx_iterator_cache_data_space( it ) (((it)->frames_out_max) - ((it)->frames_out_pos + (it)->cache_msg_pos + ((int)(sizeof (struct frame_header_long)))))
//#define tx_iterator_cache_hdr_ptr( it ) ((it)->cache_data_array)
//#define tx_iterator_cache_msg_ptr( it ) ((it)->cache_data_array + (it)->cache_msg_pos)
};


struct frame_handl {
        uint8_t is_advertisement;              // NO link information required for tx_frame_...(), dev is enough
	uint8_t is_destination_specific_frame; // particularly: is NO advertisement AND individual frames are created for each destination
	uint8_t is_relevant; // if set to ONE specifies: frame MUST BE processed or in case of unknown frame type, the
	                     // whole super_frame MUST be dropped. If set to ZERO the frame can be ignored.
	                     // if frame->is_relevant==1 and unknown and super_frame->is_relevant==1, then
	                     // the whole super_frame MUST BE dropped as well.
	                     // If irrelevant and unknown frames are rebroadcasted depends on the super_frame logic.
	                     // i.e.: * unknown packet_frames MUST BE dropped.
	                     //       * unknown and irrelevant description_tlv_frames MUST BE propagated
	uint8_t rx_requires_described_neigh;
        uint16_t data_header_size;
        uint16_t min_msg_size;
        uint16_t fixed_msg_size;
        uint16_t tx_task_interval_min;
        int32_t *tx_iterations;
        UMETRIC_T *tx_tp_min;
        UMETRIC_T *tx_rp_min;
        UMETRIC_T *rx_tp_min;
        UMETRIC_T *rx_rp_min;
        char *name;

	int32_t (*rx_frame_handler) (struct rx_frame_iterator *); // returns: TLV_RX_DATA_code or rcvd frame_msgs_len (without data_header_size)
	int32_t (*rx_msg_handler)   (struct rx_frame_iterator *); // returns: TLV_RX_DATA_code or rcvd frame_msg_len  (without data_header_size)
	int32_t (*tx_frame_handler) (struct tx_frame_iterator *); // returns: TLV_TX_DATA_code or send frame_msgs_len (without data_header_size)
	int32_t (*tx_msg_handler)   (struct tx_frame_iterator *); // returns: TLV_TX_DATA_code or send frame_msg_len  (without data_header_size)
	
	const struct field_format *msg_format;
};


static inline uint8_t * tx_iterator_cache_hdr_ptr(struct tx_frame_iterator *it)
{
	return it->cache_data_array;
}

static inline uint8_t * tx_iterator_cache_msg_ptr(struct tx_frame_iterator *it)
{
	return it->cache_data_array + it->handls[it->frame_type].data_header_size + it->cache_msgs_size;
}

static inline int32_t tx_iterator_cache_data_space(struct tx_frame_iterator *it)
{
	return it->frames_out_max - (
		it->frames_out_pos +
		it->handls[it->frame_type].data_header_size +
		it->cache_msgs_size +
		(int) sizeof(struct frame_header_long));
}








#define FRAME_TYPE_PROBLEM_CODE_MIN          0x01
#define FRAME_TYPE_PROBLEM_CODE_DUP_LINK_ID  0x01
#define FRAME_TYPE_PROBLEM_CODE_MAX          0x01

//struct msg_test_adv { // 1 byte
//	uint8_t adv_test;
//} __attribute__((packed));
//
//struct hdr_test_adv { // 1 byte
//	uint8_t hdr_test;
//	struct msg_test_adv msg[];
//} __attribute__((packed));




struct msg_problem_adv { // 4 bytes
	uint8_t code;
	uint8_t reserved;
	LOCAL_ID_T local_id;
} __attribute__((packed));






struct msg_hello_adv { // 2 bytes
	HELLO_SQN_T hello_sqn;
//	uint8_t reserved; !!!!!!!!!!!!!!!!!!!!!!!!!!
} __attribute__((packed));



#define DEVADV_MSG_IGNORED -1


struct msg_dev_adv { // 26 byte

	DEVADV_IDX_T dev_idx;        // 1 byte
	uint8_t channel;             // 1 byte
	FMETRIC_U8_T tx_bitrate_min; // 1 byte
	FMETRIC_U8_T tx_bitrate_max; // 1 byte

	IPX_T llip;                  // 16 byte
	MAC_T mac;                   // 6 byte
} __attribute__((packed));

struct hdr_dev_adv { // 2 byte
	DEVADV_SQN_T dev_sqn;
	struct msg_dev_adv msg[];
} __attribute__((packed));

struct msg_dev_req { // 4 byte
	LOCAL_ID_T destination_local_id;
} __attribute__((packed));



#define LINKADV_INTERVAL_REMOVED 10000
#define LINKADV_INTERVAL_NEW 2000
#define LINKADV_CHANGES_NONE     0
#define LINKADV_CHANGES_REMOVED  1
#define LINKADV_CHANGES_NEW      1000
#define LINKADV_CHANGES_CRITICAL 1000000
#define LINKADV_MSG_IGNORED -1
#define LINKADV_ADD_RP_4DIF 4
#define LINKADV_ADD_RP_4MIN 2
#define LINKADV_ADD_RP_4MAX 3

struct msg_link_adv { // 6 byte
	DEVADV_IDX_T transmitter_dev_idx; // to be combined with dev_id from packet header to resolve transmitters dev_id of reported link
	DEVADV_IDX_T peer_dev_idx;
	LOCAL_ID_T peer_local_id;
} __attribute__((packed));

struct hdr_link_adv { // 2 byte
	//LINK_SQN_T link_sqn; as given in packet_header
	DEVADV_SQN_T dev_sqn_ref;
	struct msg_link_adv msg[];
} __attribute__((packed));

struct msg_link_req { // 4 byte
	LOCAL_ID_T destination_local_id;
} __attribute__((packed));




struct msg_rp_adv { // 1 byte
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int rp_127range : 7;
	unsigned int ogm_request : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ogm_request : 1;
	unsigned int rp_127range : 7;
#else
# error "Please fix <bits/endian.h>"
#endif

//	uint8_t rp_255range;
} __attribute__((packed));




/* Why knowledge about prev-hop (z) bandwidth is important:
 * x,y,z transmit time via link x,y,z
 *
 *  ->-x=3--              x: MAX(x,z) <  y+z
 * A        B        C
 *  ---y=2-- ---z=2--
 *
 *
 *  ---x=3--
 * A        B        C
 *  ->-y=2-- ---z=1--     y: MAX(x,z) >= y+z
 *
 *  */


/* 
 * Why 2-hops channel knowledge is important for directional links:
 *
 *  (------)--..  ..--(-------)--..
 * A        B        C         D
 *       ..--(------)--..
 *
 * Why 3-hops channel knowledge is important for omnidirectional links:
 *
 * *||||||||*)))))))) (((((((((*||||||||*))))))))))
 * A        B                           E
 *  ((((((((*||||||||*)))))))))
 *                   C         D
 *           ((((((((*|||||||||*)))))))))
 *  */




struct msg_dhash_request { // 2 bytes
	IID_T receiverIID4x;
} __attribute__((packed));

struct hdr_dhash_request { // 4 bytes
	LOCAL_ID_T destination_local_id;
	struct msg_dhash_request msg[];
} __attribute__((packed));


struct msg_dhash_adv { // 2 + X bytes
	IID_T transmitterIID4x;
	struct description_hash dhash;
} __attribute__((packed));


#define msg_description_request msg_dhash_request
#define hdr_description_request hdr_dhash_request



struct description { // 48 bytes
	GLOBAL_ID_T globalId; // 32 bytes

        uint16_t codeVersion; // 2 bytes
	uint16_t capabilities;// 2 bytes

        DESC_SQN_T descSqn;   // 2 bytes

	OGM_SQN_T ogmSqnMin;  // 2 bytes
	OGM_SQN_T ogmSqnRange;// 2 bytes

	uint16_t txInterval;  // 2 bytes

	uint8_t reservedTtl;  // 1 byte
        uint8_t reserved;     // 1 byte

        uint16_t extensionLen;// 2 bytes
//	uint8_t extensionData[];
} __attribute__((packed));


#define MSG_DESCRIPTION0_ADV_UNHASHED_SIZE  2
#define MSG_DESCRIPTION0_ADV_HASHED_SIZE   (sizeof( GLOBAL_ID_T) + (4 * sizeof(uint32_t)))
#define MSG_DESCRIPTION0_ADV_SIZE  (MSG_DESCRIPTION0_ADV_UNHASHED_SIZE + MSG_DESCRIPTION0_ADV_HASHED_SIZE)

struct msg_description_adv { // IPv6: >= 92 bytes
	
	// the unhashed part:
	IID_T    transmitterIID4x; // 2 bytes

	// the hashed pard:
	struct description desc;   // 48 bytes + extension frames (>= (metric-algo:2+16 bytes + hna6: 2+(x*22) bytes  ))

} __attribute__((packed));


#define DESCRIPTION_MSG_FORMAT { \
{FIELD_TYPE_UINT,             -1, (8*sizeof(IID_T)),       0, FIELD_RELEVANCE_MEDI, "transmitterIid4x"}, \
{FIELD_TYPE_GLOBAL_ID,        -1, (8*sizeof(GLOBAL_ID_T)), 1, FIELD_RELEVANCE_HIGH, "globalId"},  \
{FIELD_TYPE_UINT,             -1, 16,                      0, FIELD_RELEVANCE_MEDI, "codeVersion" }, \
{FIELD_TYPE_HEX,              -1, 16,                      0, FIELD_RELEVANCE_MEDI, "capabilities" }, \
{FIELD_TYPE_UINT,             -1, 16,                      0, FIELD_RELEVANCE_MEDI, "descSqn" }, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(OGM_SQN_T)),   0, FIELD_RELEVANCE_MEDI, "ogmSqnMin" }, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(OGM_SQN_T)),   0, FIELD_RELEVANCE_MEDI, ARG_OGM_SQN_RANGE }, \
{FIELD_TYPE_UINT,             -1, 16,                      0, FIELD_RELEVANCE_HIGH, ARG_TX_INTERVAL }, \
{FIELD_TYPE_UINT,             -1, 8,                       1, FIELD_RELEVANCE_LOW,  "reservedTtl" }, \
{FIELD_TYPE_UINT,             -1, 8,                       1, FIELD_RELEVANCE_LOW,  "reserved" }, \
{FIELD_TYPE_STRING_SIZE,      -1, 16,                      0, FIELD_RELEVANCE_LOW,  "extensionLen" }, \
{FIELD_TYPE_STRING_BINARY,    -1, 0,                       1, FIELD_RELEVANCE_LOW,  "extensionData" }, \
FIELD_FORMAT_END}



#define OGM_JUMPS_PER_AGGREGATION 10

#define OGMS_PER_AGGREG_MAX                                                                                         \
              ( (pref_udpd_size -                                                                                   \
                  (sizeof(struct packet_header) + sizeof(struct frame_header_long) + sizeof(struct hdr_ogm_adv) +   \
                    (OGM_JUMPS_PER_AGGREGATION * sizeof(struct msg_ogm_adv)) ) ) /                              \
                (sizeof(struct msg_ogm_adv)) )

#define OGMS_PER_AGGREG_PREF ( OGMS_PER_AGGREG_MAX  / 2 )




#define OGM_IID_RSVD_JUMP  (OGM_IIDOFFST_MASK) // 63 //255 // resulting from ((2^transmitterIIDoffset_bit_range)-1)



struct msg_ogm_adv // 4 bytes
{
	OGM_MIX_T mix; //uint16_t mix of transmitterIIDoffset, metric_mant, metric_exp

	union {
		OGM_SQN_T ogm_sqn;
		IID_T transmitterIIDabsolute;
	} u;

} __attribute__((packed));



struct hdr_ogm_adv { // 2 bytes
	AGGREG_SQN_T aggregation_sqn;
	uint8_t ogm_destination_array;

	struct msg_ogm_adv msg[];
} __attribute__((packed));

/*
 * reception triggers:
 * - (if link <-> neigh <-... is known and orig_sid is NOT known) msg_dhash0_request[ ... orig_did = orig_sid ]
 * - else update_orig(orig_sid, orig_sqn)
 */

struct msg_ogm_ack {
//	IID_T transmitterIID4x;
	OGM_DEST_T ogm_destination;   // 1 byte
	AGGREG_SQN_T aggregation_sqn; // 1 byte
} __attribute__((packed));
/*
 * reception triggers:
 * - (if link <-> neigh <-... is known and orig_sid is NOT known) msg_dhash0_request[ ... orig_did = orig_sid ]
 * - else update_orig(orig_sid, orig_sqn)
 */


#define BMX_DSC_TLV_METRIC     0x00
#define BMX_DSC_TLV_UHNA4      0x01
#define BMX_DSC_TLV_UHNA6      0x02
#define BMX_DSC_TLV_TUNNEL     0x03
#define BMX_DSC_TLV_GW         0x04
#define BMX_DSC_TLV_JSON_SMS   0x10
#define BMX_DSC_TLV_MAX        (FRAME_TYPE_ARRSZ-1)
#define BMX_DSC_TLV_ARRSZ      (FRAME_TYPE_ARRSZ)





struct description_cache_node {
	struct description_hash dhash;
        TIME_T timestamp;
        struct description *description;
};

extern uint32_t ogm_aggreg_pending;
extern IID_T myIID4me;
extern TIME_T myIID4me_timestamp;

//extern IDM_T my_dev_adv_changed;


extern struct frame_handl packet_frame_handler[FRAME_TYPE_ARRSZ];
extern struct frame_handl description_tlv_handl[BMX_DSC_TLV_ARRSZ];


/***********************************************************
  The core frame/message structures and handlers
************************************************************/


OGM_SQN_T set_ogmSqn_toBeSend_and_aggregated(struct orig_node *on, UMETRIC_T um, OGM_SQN_T to_be_send, OGM_SQN_T aggregated);
void update_my_description_adv( void );
void update_my_dev_adv(void);
void update_my_link_adv(uint32_t changes);

struct dhash_node * process_description(struct packet_buff *pb, struct description *desc, struct description_hash *dhash);
IDM_T process_description_tlvs(struct packet_buff *pb, struct orig_node *on, struct description *desc, uint8_t op,
        uint8_t filter, struct ctrl_node *cn);
void purge_tx_task_list(struct list_head *tx_tasks_list, struct link_node *only_link, struct dev_node *only_dev);

void tx_packets( void *unused );
IDM_T rx_frames(struct packet_buff *pb);
int32_t rx_frame_iterate(struct rx_frame_iterator* it);


#define SCHEDULE_UNKNOWN_MSGS_SIZE 0
#define SCHEDULE_MIN_MSG_SIZE -1

void schedule_tx_task(struct link_dev_node *lndev_out, uint16_t type, int16_t msgs_len,
	uint16_t u16, uint32_t u32, IID_T myIID4x, IID_T neighIID4x);

void register_frame_handler(struct frame_handl *array, int pos, struct frame_handl *handl);

struct plugin *msg_get_plugin( void );
