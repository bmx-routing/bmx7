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



#define DEF_DROP_ALL_FRAMES 0
#define MIN_DROP_ALL_FRAMES 0
#define MAX_DROP_ALL_FRAMES 1
#define ARG_DROP_ALL_FRAMES "dropAllFrames"

#define DEF_DROP_ALL_PACKETS 0
#define MIN_DROP_ALL_PACKETS 0
#define MAX_DROP_ALL_PACKETS 1
#define ARG_DROP_ALL_PACKETS "dropAllPackets"


#define ARG_UDPD_SIZE "prefUdpSize"
#define HLP_UDPD_SIZE "set preferred udp-data size for send packets"
#define MIN_UDPD_SIZE 128 //(6+4+(22+8)+32)+184=72+56=128
#define MAX_UDPD_SIZE (1280 /*min IPv6 MTU*/ - sizeof(struct ip6_hdr) - sizeof(struct udphdr))
#define DEF_UDPD_SIZE MAX_UDPD_SIZE
extern int32_t pref_udpd_size;

#define DEF_OVERLAPPING_BURSTS 100
#define MIN_OVERLAPPING_BURSTS 1
#define MAX_OVERLAPPING_BURSTS 1000
#define ARG_OVERLAPPING_BURSTS "overlappingBursts"


#define MAX_TX_CASUAL_INTERVAL 5000
#define MIN_TX_CASUAL_INTERVAL 100
#define DEF_TX_CASUAL_INTERVAL 800
#define ARG_TX_CASUAL_INTERVAL "avgTxInterval"
extern int32_t txCasualInterval;


#define BUCKET_COIN_SCALE 100000
extern uint32_t txBucket;
extern int32_t txBucketSize;

#define DEF_TX_BUCKET_DRAIN 70

#define DEF_TX_BUCKET_SIZE 50
#define MIN_TX_BUCKET_SIZE 1
#define MAX_TX_BUCKET_SIZE 100000
#define ARG_TX_BUCKET_SIZE "txBucketSize"

#define MIN_TX_MIN_INTERVAL 35
#define MAX_TX_MIN_INTERVAL 10000  // < U16_MAX due to metricalgo->ogm_interval field
#define DEF_TX_MIN_INTERVAL 100
#define ARG_TX_MIN_INTERVAL "minTxInterval"



#define PKT_FRAMES_SIZE_PREF     (pref_udpd_size - sizeof(struct packet_header))
#define PKT_FRAMES_SIZE_MAX     ( MAX_UDPD_SIZE - sizeof(struct packet_header))

#define FRM_SIGN_VERS_SIZE_MIN (sizeof(struct tlv_hdr) + sizeof(struct frame_msg_signature) + \
                                sizeof(struct tlv_hdr) + sizeof(struct msg_ogm_aggreg_sqn_adv))

#define FRM_SIGN_VERS_SIZE_MAX (FRM_SIGN_VERS_SIZE_MIN + (MAX_LINK_SIGN_LEN/8))

#define SIGNED_FRAMES_SIZE_PREF (PKT_FRAMES_SIZE_PREF - FRM_SIGN_VERS_SIZE_MAX)
#define SIGNED_FRAMES_SIZE_MAX (PKT_FRAMES_SIZE_MAX - FRM_SIGN_VERS_SIZE_MAX)

#define ARG_FZIP     "descCompression"
#define MIN_FZIP      0
#define TYP_FZIP_DFLT 0
#define TYP_FZIP_DONT 1
#define TYP_FZIP_DO   2
#define MAX_FZIP      2
#define DEF_FZIP      TYP_FZIP_DO
#define HLP_FZIP      "use compressed description 0:dflt, 1:disabled, 2:gzip"

#define ARG_FREF      "descReferencing"
#define MIN_FREF      0
#define TYP_FREF_DONT 0
#define TYP_FREF_DO1  1
#define TYP_FREF_DO2  2
#define TYP_FREF_DO3  3
#define TYP_FREF_DFLT 4
#define MAX_FREF      4
#define DEF_FREF      TYP_FREF_DO2
#define HLP_FREF      "use referenced description 4:dflt, 0:disabled, 1-level-nesting, 2-level-nesting, 3-level-nesting"


#define MIN_TX_TREE_SIZE_MAX 1
#define MAX_TX_TREE_SIZE_MAX 1000
#define DEF_TX_TREE_SIZE_MAX 150
#define ARG_TX_TREE_SIZE_MAX "maxTxTaskTreeSize"
extern int32_t txTaskTreeSizeMax;


#define FRAME_TYPE_RSVD0            0

#define FRAME_TYPE_DESC_ADVS        2
#define FRAME_TYPE_CONTENT_ADV      4

#define FRAME_TYPE_SIGN_MUST_MIN    8
#define FRAME_TYPE_SIGNATURE_ADV    8
#define FRAME_TYPE_OGM_AGG_SQN_ADV  9
#define FRAME_TYPE_SIGN_MUST_MAX    9

#define FRAME_TYPE_HELLO_ADV        12 // most-simple BMX-NG hello (nb-discovery) advertisements
#define FRAME_TYPE_HELLO_REPLY_DHASH  13
#define FRAME_TYPE_HELLO_REPLY_IID  14

#define FRAME_TYPE_DHASH_ADV        19  // Hash-for-description-of-OG-ID advertisements

#define FRAME_TYPE_OGM_DHASH_ADV    21
#define FRAME_TYPE_OGM_IID_ADV      22

#define FRAME_TYPE_OGM_REQ          27
#define FRAME_TYPE_DHASH_REQ        28  // Hash-for-description-of-OG-ID requests
#define FRAME_TYPE_DESC_REQ         29
#define FRAME_TYPE_CONTENT_REQ      30


#define FRAME_TYPE_NOP           31
#define FRAME_TYPE_MAX_KNOWN    31
#define FRAME_TYPE_MAX         (FRAME_TYPE_ARRSZ-1)


#define FRAME_TYPE_PROCESS_ALL    (255)
#define FRAME_TYPE_PROCESS_NONE   (254)


#define ARG_DBG_FRAME_TYPES "dbgFrameTypes"
#define MAX_DBG_FRAME_TYPES I32_MAX
#define MIN_DBG_FRAME_TYPES 0
#define DEF_DBG_FRAME_TYPES ( \
	 (1 << FRAME_TYPE_CONTENT_ADV) | (1 << FRAME_TYPE_CONTENT_REQ) | \
	 (1 << FRAME_TYPE_DESC_ADVS) | (1 << FRAME_TYPE_DESC_REQ) | \
	 (1 << FRAME_TYPE_DHASH_ADV) | (1 << FRAME_TYPE_DHASH_REQ) | \
/*       (1 << FRAME_TYPE_OGM_DHASH_ADV) | (1 << FRAME_TYPE_OGM_IID_ADV) |*/ \
	 (1 << FRAME_TYPE_OGM_REQ) \
	 )



extern BURST_SQN_T myBurstSqn;





struct tlv_hdr_virtual { // 6 bytes
	uint8_t type;
	uint8_t mbz;
	uint32_t length; // lenght of (always uncompressed and resolved) frame in 1-Byte steps, including frame_header and variable data field
	uint8_t data[]; // frame-type specific data consisting of 0-1 data headers and 1-n data messages
} __attribute__((packed));

struct tlv_hdr { // 2 bytes

	union {

		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			unsigned int length : 11; //<2048
			unsigned int type : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
			unsigned int type : 5;
			unsigned int length : 11;
#else
#error "Please fix <bits/endian.h>"
#endif
		} __attribute__((packed)) tlv;
		uint16_t u16;
	} u;
	//    uint8_t  data[];  // frame-type specific data consisting of 0-1 data headers and 1-n data messages
} __attribute__((packed));


#define TLV_FORMAT { \
{FIELD_TYPE_UINT,          -1,  5,  0, FIELD_RELEVANCE_HIGH, "type"},  \
{FIELD_TYPE_UINT,          -1, 11,  0, FIELD_RELEVANCE_HIGH, "length"},\
{FIELD_TYPE_STRING_BINARY, -1,  0,  1, FIELD_RELEVANCE_HIGH, "data" }, \
FIELD_FORMAT_END }



// iterator return codes:

#define TLV_RX_DATA_FAILURE     (-5) // syntax error: exit or badlist. Transmitter should NOT have send this!
#define TLV_RX_DATA_REJECTED    (-4) // incompatible version, outdated sqn, unsupported feature. Marked as invalid to avoid further requests
#define TLV_RX_DATA_REBOOTED    (-3) // changed runtimeKey
#define TLV_RX_DATA_DONE        (-2) // done, nothing more to do
#define TLV_RX_DATA_BLOCKED     (-1) // blocked due to DAD.
#define TLV_RX_DATA_PROCESSED   (0)  // > means succesfully processed returned amount of data

char *tlv_rx_result_str(int32_t r);

#define TLV_TX_DATA_FULL        (-5) // nothing done! Frame finished or not enough remining data area to write
#define TLV_TX_DATA_FAILURE     (-4) // syntax error: will fail assertion()
#define TLV_TX_DATA_DONE        (-3) // done, nothing more to do
#define TLV_TX_DATA_IGNORED     (-1) // unknown, filtered, nothing to send, or ignored due to bad link...
#define TLV_TX_DATA_PROCESSED   (0) // >= means succesfully processed returned amount of data

char *tlv_tx_result_str(int32_t r);

// rx_frame_iterator operation codes:

enum {
	TLV_OP_DEL = 0,
	TLV_OP_TEST = 1,
	//	TLV_OP_ADD = 2,
	TLV_OP_NEW = 2,
	TLV_OP_DEBUG = 3,

	TLV_OP_CUSTOM_MIN = 20,
	TLV_OP_CUSTOM_MAX = 99,
	TLV_OP_PLUGIN_MIN = 100,
	TLV_OP_PLUGIN_MAX = 199
};

char *tlv_op_str(uint8_t op);


struct tlv_hdr tlvSetBigEndian(int16_t type, int16_t length);


#define BMX_DSC_TLV_CONTENT_HASH    0x00
#define BMX_DSC_TLV_NODE_PUBKEY     0x01
#define BMX_DSC_TLV_DSC_SIGNATURE   0x02
#define BMX_DSC_TLV_VERSION         0x03
#define BMX_DSC_TLV_LINK_PUBKEY     0x05

#define BMX_DSC_TLV_NAMES           0x07

#define BMX_DSC_TLV_BOYCOTS         0x08
#define BMX_DSC_TLV_SUPPORTS        0x09
#define BMX_DSC_TLV_TRUSTS          0x0A
#define BMX_DSC_TLV_DISTRUSTS       0x0B

#define BMX_DSC_TLV_METRIC          0x0D

#define BMX_DSC_TLV_LLIP            0x0E

#define BMX_DSC_TLV_HNA6            0x0F

#define BMX_DSC_TLV_TUN6_MIN        0x10
#define BMX_DSC_TLV_TUN6            0x11
#define BMX_DSC_TLV_TUN4IN6_INGRESS 0x12
#define BMX_DSC_TLV_TUN6IN6_INGRESS 0x13
#define BMX_DSC_TLV_TUN4IN6_SRC     0x14
#define BMX_DSC_TLV_TUN6IN6_SRC     0x15
#define BMX_DSC_TLV_TUN4IN6_NET     0x16
#define BMX_DSC_TLV_TUN6IN6_NET     0x17
#define BMX_DSC_TLV_TUN6_MAX        0x17

#define BMX_DSC_TLV_SMS             0x1A

#define BMX_DSC_TLV_SIGNATURE_DUMMY 0x1F

#define FRAME_MSG_SIGNATURE_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint8_t),                   1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "signature" }, \
FIELD_FORMAT_END }

struct frame_msg_signature {
	uint8_t type;
	uint8_t signature[];
} __attribute__((packed));

struct frame_hdr_signature {

	union {

		struct {
			DESC_SQN_T descSqn;
			BURST_SQN_T burstSqn;
		} u32;
		uint64_t u64;
	} sqn;
	DEVIDX_T devIdx;
} __attribute__((packed));





/*
 * this iterator is given the beginning of a frame area (e.g. the end of the packet_header)
 * then it iterates over the frames in that area */
struct rx_frame_iterator {
	// MUST be initialized:
	// remains unchanged:
	const char *caller;
	struct packet_buff *pb;
	struct frame_db *db;
	struct orig_node *on;
	struct desc_content *dcOld;
	struct desc_content *dcNew;

	uint8_t *frames_in;
	int32_t frames_length;
	uint8_t op;
	uint8_t process_filter;
	uint32_t dbgl;

	// MUST be initialized, updated by rx_frame_iterate(), and consumed by handl->rx_tlv_handler
	int32_t _f_pos_next;
	int8_t f_type; //init to -1 !!
	int8_t f_type_expanded; //init to -1 !!

	// set by rx_frame_iterate(), and consumed by handl->rx_tlv_handler
	struct frame_handl *f_handl;
	int32_t _f_len;
	int32_t f_dlen;
	int32_t f_msgs_len;
	int32_t f_msgs_fixed;
	uint8_t *f_data;
	uint8_t *f_msg;

	// allocated by handl[].rx_tlv_handler and freed by calling function of rx_frame_iterate() (e.g. process_description_tlvs())
};

/*
 * this iterator is given a fr_type and a set of handlers,
 * then the handlers are supposed to figure out what needs to be done.
 * finally the iterator writes ready-to-send frame_header and frame data to *fs_data */
struct tx_frame_iterator {
	// MUST be initialized:
	// remains unchanged:
	const char *caller;
	struct list_head *tx_task_list;
	struct tx_task_node *ttn;
	//	struct desc_contents *descContents;
	struct frame_db *db;

	uint8_t *frames_out_ptr;
	int32_t frames_out_pref;
	int32_t frames_out_max;
	uint8_t *frame_cache_array;
	int32_t frame_cache_size;

	// updated by tx_frame_iterate() caller():
	uint8_t frame_type;
	int8_t prev_out_type;

	// updated by tx_frame_iterate():
	struct frame_handl *handl;
	int32_t frames_out_pos;
	int32_t frame_cache_msgs_size;


	//#define tx_iterator_cache_data_space( it ) (((it)->frames_out_max) - ((it)->frames_out_pos + (it)->cache_msg_pos + ((int)(sizeof (struct frame_header_long)))))
	//#define tx_iterator_cache_hdr_ptr( it ) ((it)->cache_data_array)
	//#define tx_iterator_cache_msg_ptr( it ) ((it)->cache_data_array + (it)->cache_msg_pos)
};

struct frame_handl {
	uint8_t alwaysMandatory;
	uint8_t positionMandatory;
	int32_t *dextCompression;
	int32_t *dextReferencing;
	uint8_t rx_processUnVerifiedLink;
	int8_t rx_minNeighCol;
	uint16_t data_header_size;
	uint16_t min_msg_size;
	uint16_t fixed_msg_size;
	int32_t *tx_task_interval_min;
	int32_t *tx_iterations;
	char *name;
	void (*tx_packet_prepare_casuals) (void);
	void (*tx_packet_prepare_always) (void);
	int32_t(*rx_frame_handler) (struct rx_frame_iterator *); // returns: TLV_RX_DATA_code or rcvd frame_msgs_len (without data_header_size)
	int32_t(*rx_msg_handler) (struct rx_frame_iterator *); // returns: TLV_RX_DATA_code or rcvd frame_msg_len  (without data_header_size)
	int32_t(*tx_frame_handler) (struct tx_frame_iterator *); // returns: TLV_TX_DATA_code or send frame_msgs_len (without data_header_size)
	int32_t(*tx_msg_handler) (struct tx_frame_iterator *); // returns: TLV_TX_DATA_code or send frame_msg_len  (without data_header_size)

	const struct field_format *msg_format;
};

struct frame_db {
	uint8_t handl_max;
	uint8_t rx_processUnVerifiedLink;
	int8_t double_frame_types;
	char *name;
	struct frame_handl handls[];
};

#define TX_TASK_MAX_KEY_DATA_LEN 24

struct tx_task_key {

	struct {

		struct {
			uint8_t sign; //ensure unsigned tx_tasks are queued first
			struct dev_node *dev; // the outgoing interface to be used for transmitting
		} p; // ensure individual packets for each (in order of pref): sing, dev, type, id
		uint8_t type;
		CRYPTSHA1_T groupId;
	} f;
	uint8_t data[TX_TASK_MAX_KEY_DATA_LEN];
	//TODO: remove these:
} __attribute__((packed));

struct tx_task_node {
	struct tx_task_key key;

	struct neigh_node *neigh;
	uint16_t frame_msgs_length;
	int16_t tx_iterations;
	TIME_T send_ts;
};


extern const int32_t fref_always_l1;
extern const int32_t fref_always_l2;
extern const int32_t fref_never;
extern const int32_t fref_dflt;

extern const int32_t never_fzip;
extern const int32_t dflt_fzip;




extern struct frame_db *packet_frame_db;
extern struct frame_db *description_tlv_db;

static inline uint8_t * tx_iterator_cache_hdr_ptr(struct tx_frame_iterator *it)
{
	return it->frame_cache_array;
}

static inline uint8_t * tx_iterator_cache_msg_ptr(struct tx_frame_iterator *it)
{
	return it->frame_cache_array + it->db->handls[it->frame_type].data_header_size + it->frame_cache_msgs_size;
}

int32_t _tx_iterator_cache_data_space(struct tx_frame_iterator *it, IDM_T max, int32_t len, int32_t rsvd);

#define tx_iterator_cache_data_space_max( it, len, rsvd )  _tx_iterator_cache_data_space(it, 1, len, rsvd)
#define tx_iterator_cache_data_space_pref( it, len, rsvd ) _tx_iterator_cache_data_space(it, 0, len, rsvd)


IDM_T purge_tx_task_tree(struct neigh_node *onlyNeigh, struct dev_node *onlyDev, struct tx_task_node *onlyTtn, IDM_T force);
void tx_packets(void *unused);
int32_t tx_frame_iterate(IDM_T iterate_msg, struct tx_frame_iterator *it);
int32_t rx_frame_iterate(struct rx_frame_iterator* it);

void rx_packet(struct packet_buff *pb);

#define SCHEDULE_UNKNOWN_MSGS_SIZE 0
#define SCHEDULE_MIN_MSG_SIZE -1

void schedule_tx_task(uint8_t f_type, CRYPTSHA1_T *someId, struct neigh_node *neighId, struct dev_node *dev, int16_t f_msgs_len, void *keyData, uint32_t keyLen);

void register_frame_handler(struct frame_db *db, int pos, struct frame_handl *handl);

void init_msg(void);
void cleanup_msg(void);

uint8_t use_compression(struct frame_handl *handl);
uint8_t use_refLevel(struct frame_handl *handl);

