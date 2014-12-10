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

/*
 * from iid.h:
 */
typedef uint16_t IID_T;
typedef struct neigh_node IID_NEIGH_T;
typedef struct dhash_node IID_NODE_T;


#define IID_REPOS_SIZE_BLOCK 32

#define IID_REPOS_SIZE_MAX  ((IID_T)(-1))
#define IID_REPOS_SIZE_WARN 1024

#define IID_RSVD_UNUSED 0
#define IID_RSVD_MAX    0
#define IID_MIN_USED    1

#define IID_SPREAD_FK   1  /*default=2 , 1 means no spreading    #define IID_REPOS_USAGE_WARNING 10 */


struct iid_ref {
	IID_T myIID4x;
	uint16_t referred_by_neigh_timestamp_sec;
};

struct iid_repos {
	IID_T arr_size; // the number of allocated array fields
	IID_T min_free; // the first unused array field from the beginning of the array (might be outside of allocated space)
	IID_T max_free; // the first unused array field after the last used field in the array (might be outside of allocated space)
	IID_T tot_used; // the total number of used fields in the array
	union {
		uint8_t *u8;
		IID_NODE_T **node;
		struct iid_ref *ref;
	} arr;
};



/*
 * from metrics.h:
 */

// to be used:
typedef uint64_t UMETRIC_T;


#define OGM_MANTISSA_BIT_SIZE  5
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
	}val;
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


	uint8_t window_size;                // MUST be given as multiple of sqn_steps
        uint8_t lounge_size;                // MUST be given as multiple of sqn_steps e.g. 6
        uint8_t regression;             // e.g. 16
//        uint8_t fast_regression;             // e.g. 2
//        uint8_t fast_regression_impact;             // e.g. 8
	uint8_t hystere;
	uint8_t hop_penalty;
	uint8_t late_penalty;
};

struct lndev_probe_record {
	HELLO_SQN_T hello_sqn_max; // SQN which has been applied (if equals wa_pos) then wa_unscaled MUST NOT be set again!

	uint8_t hello_array[MAX_HELLO_SQN_WINDOW/8];
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


#define DEF_LINK_PURGE_TO  100000
#define MIN_LINK_PURGE_TO  (MAX_TX_INTERVAL*2)
#define MAX_LINK_PURGE_TO  864000000 /*10 days*/
#define ARG_LINK_PURGE_TO  "linkPurgeTimeout"

#define MIN_OGM_PURGE_TO  (MAX_OGM_INTERVAL + MAX_TX_INTERVAL)
#define MAX_OGM_PURGE_TO  864000000 /*10 days*/
#define DEF_OGM_PURGE_TO  100000
#define ARG_OGM_PURGE_TO  "purgeTimeout"


typedef CRYPTSHA1_T GLOBAL_ID_T;

typedef CRYPTSHA1_T LOCAL_ID_T;

typedef struct {
	DEVADV_IDX_T dev_idx;
	LOCAL_ID_T local_id;
} __attribute__((packed)) LinkDevKey;

typedef struct {

	LinkDevKey key;

	IPX_T link_ip;

	TIME_T pkt_time_max;
	TIME_T hello_time_max;

	HELLO_SQN_T hello_sqn_max;

	struct neigh_node *local; // set immediately

	struct list_head link_list; // list with one link_node_dev element per link
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

	struct list_head tx_task_lists[FRAME_TYPE_ARRSZ]; // scheduled frames and messages
	int16_t myLinkId;
	TIME_T pkt_time_max;
} LinkNode;


struct neigh_node {

	LOCAL_ID_T local_id;
	struct avl_tree linkDev_tree;
	LinkNode *best_rp_link;
	LinkNode *best_tp_link;
	LinkNode *best_link;

	TIME_T packet_time;
	LINKADV_SQN_T packet_link_sqn_ref; //indicating the maximum existing link_adv_sqn

	// the latest received link_adv:
	LINKADV_SQN_T link_adv_sqn;
	TIME_T link_adv_time;
	uint16_t link_adv_msgs;
	int16_t neighLinkId;
	int16_t myLinkId;
        OGM_DEST_T internalNeighId;
        
	struct msg_link_adv *link_adv;
	DEVADV_SQN_T link_adv_dev_sqn_ref;

	// the latest received dev_adv:
	DEVADV_SQN_T dev_adv_sqn;
	uint16_t dev_adv_msgs;
	struct msg_dev_adv *dev_adv;

	// the latest received rp_adv:
	TIME_T rp_adv_time;
	IDM_T rp_ogm_request_rcvd;
	int32_t orig_routes;
        
        
        struct orig_node *on;
        // the old neigh_node:
	struct dhash_node *dhn; //TODO remove and use on;
        CRYPTKEY_T *pktKey;

	IID_T neighIID4me;

	struct iid_repos neighIID4x_repos;

        TIME_T ogm_new_aggregation_rcvd;
	AGGREG_SQN_T ogm_aggregation_cleard_max;
	uint8_t ogm_aggregations_not_acked[AGGREG_ARRAY_BYTE_SIZE];
	uint8_t ogm_aggregations_rcvd[AGGREG_ARRAY_BYTE_SIZE];
        
};




struct router_node {

//	struct link_dev_key key_2BRemoved;

	struct neigh_node *local_key;

	struct metric_record mr;
	OGM_SQN_T ogm_sqn_last;
	UMETRIC_T ogm_umetric_last;

	UMETRIC_T best_path_metric; //TODO removed
	LinkNode *best_path_link;
};







struct dext_tree_key {
    struct desc_extension *dext;
} __attribute__((packed));

struct dext_tree_node {
    struct dext_tree_key dext_key;
    uint8_t rf_types[(BMX_DSC_TLV_ARRSZ/8) + (BMX_DSC_TLV_ARRSZ%8)];
};

#define MAX_DESC_LEN (INT32_MAX-1)
#define MAX_REF_NESTING 2

struct ref_node {
        SHA1_T rhash;
        //struct frame_header_long *frame_hdr;
	uint8_t *f_body;
	uint32_t f_body_len;
	uint8_t nested;
	uint8_t compression;
	uint8_t reserved;
        uint32_t last_usage;
        uint32_t usage_counter;
	struct avl_tree dext_tree;
};



struct refnl_node {
    	struct list_node list;
	struct ref_node *refn;
};

struct dext_type_data {
    uint32_t len;
    uint32_t pos;
};

struct desc_extension {
	struct list_head refnl_list;
	struct dhash_node *dhn;
        uint8_t max_nesting;
        uint8_t *data;
        uint32_t dlen;
        struct dext_type_data dtd[BMX_DSC_TLV_ARRSZ];
};

void *dext_dptr( struct desc_extension *dext, uint8_t type);


struct orig_node {
	// filled in by validate_new_link_desc0():

	GLOBAL_ID_T nodeId;

	struct dhash_node *dhn;

	TIME_T updated_timestamp; // last time this on's desc was succesfully updated

	OGM_SQN_T ogmSqn_rangeMin;
	OGM_SQN_T ogmSqn_rangeSize;



	// filled in by process_desc0_tlvs()->
	IPX_T primary_ip;
	char primary_ip_str[IPX_STR_LEN];
	uint8_t blocked; // blocked description
        uint8_t added;   // added description


	struct host_metricalgo *path_metricalgo;
        
        char *hostname;
        
        uint32_t *trustedNeighsBitArray;

	// calculated by update_path_metric()

	OGM_SQN_T ogmSqn_maxRcvd;

	OGM_SQN_T ogmSqn_next;
	UMETRIC_T ogmMetric_next;

	OGM_SQN_T ogmSqn_send;
//	UMETRIC_T ogmMetric_send;

	UMETRIC_T *metricSqnMaxArr;          // TODO: remove

	struct avl_tree rt_tree;

	struct router_node *curr_rt_local;   // the currently used local neighbor for routing
	LinkNode *curr_rt_link; // the configured route in the kernel!

	//size of plugin data is defined during intialization and depends on registered PLUGIN_DATA_ORIG hooks
	void *plugin_data[];

};



struct dhash_node {

	DHASH_T dhash;

	TIME_T referred_by_me_timestamp; // last time this dhn was referred

        struct neigh_node *local; //TODO: remove and use on!
	IID_T myIID4orig;


	struct orig_node *on;

	uint8_t *desc_frame;
        uint16_t desc_frame_len;
	struct desc_extension *dext;
        
        struct deprecated_globalId_node *deprecated_globalId;
};

struct deprecated_globalId_node {
    GLOBAL_ID_T globalId;
    struct avl_tree deprecated_dhash_tree;
};



struct packet_header
{
	uint8_t    comp_version;
	uint8_t    reserved;
        
} __attribute__((packed,__may_alias__));



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
                
                struct dhash_node *verifiedLinkDhn;
                LinkNode *verifiedLink;
//              LinkDevNode *linkDev;
//		IID_T transmittersIID;
//		uint32_t rx_counter;
                
	} i;

	union {
		struct packet_header hdr;
		unsigned char data[MAX_UDPD_SIZE + 1];
	} p;

};




extern struct orig_node *self;

extern struct iid_repos my_iid_repos;


//extern struct avl_tree dhash_tree;
extern struct avl_tree deprecated_dhash_tree;
extern struct avl_tree deprecated_globalId_tree;
extern struct avl_tree local_tree;
extern struct avl_tree link_dev_tree;
extern struct avl_tree link_tree;
extern struct avl_tree orig_tree;


/***********************************************************
 Data Infrastructure
 ************************************************************/

void iid_purge_repos( struct iid_repos *rep );
void iid_free(struct iid_repos *rep, IID_T iid);
void iid_free_neighIID4x_by_myIID4x( struct iid_repos *rep, IID_T myIID4x);
IDM_T iid_set_neighIID4x(struct iid_repos *neigh_rep, IID_T neighIID4x, IID_T myIID4x);
IID_T iid_new_myIID4x( IID_NODE_T *dhn );
IID_NODE_T* iid_get_node_by_neighIID4x(IID_NEIGH_T *nn, IID_T neighIID4x, IDM_T verbose);
IID_NODE_T* iid_get_node_by_myIID4x( IID_T myIID4x );


LinkNode *getLinkNode(struct dev_node *dev, IPX_T *llip, LINKADV_SQN_T link_sqn, struct dhash_node *verifiedLinkDhn, DEVADV_IDX_T dev_idx);

void badlist_neighbor_if_verified(struct packet_buff *pb);

IDM_T badlist_neighbor(struct packet_buff *pb, DHASH_T *dhash);


void purge_deprecated_globalId_tree( GLOBAL_ID_T *globalId );
//void purge_deprecated_dhash_tree( struct dhash_node *onlyDhn, IDM_T onlyExpired );
void deprecate_dhash_iid( struct dhash_node *dhn, DHASH_T *dhash, GLOBAL_ID_T *globalId );
void purge_orig_router(struct orig_node *onlyOrig, struct neigh_node *onlyNeigh, LinkNode *onlyLink, IDM_T only_useless);
void purge_link_route_orig_nodes(struct dev_node *only_dev, IDM_T only_expired, struct orig_node *except_on);
void block_orig_node(IDM_T block, struct orig_node *on);
void free_orig_node(struct orig_node *on);
struct orig_node *init_orig_node(GLOBAL_ID_T *id);
void init_self(void);

SHA1_T *nodeIdFromDescAdv( uint8_t *desc_adv );
char *nodeIdAsStringFromDescAdv( uint8_t *desc_adv );

void purge_local_node(struct neigh_node *local);
void purge_linkDevs(LinkDevKey *onlyLinkDev, struct dev_node *only_dev, IDM_T only_expired);

struct dhash_node *get_dhash_tree_node(DHASH_T *dhash);
void update_orig_dhash(struct orig_node *on, struct dhash_node *dhn);
struct dhash_node* create_dext_dhash(uint8_t *desc_frame, uint32_t desc_frame_len, struct desc_extension* dext, DHASH_T *dhash);

LOCAL_ID_T new_local_id(struct dev_node *dev);


void node_tasks(void);

void cleanup_node(void);
void init_node(void);