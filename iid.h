


typedef struct neigh_node IID_NEIGH_T;
typedef struct desc_content IID_NODE_T__;



#define IID_REPOS_SIZE_BLOCK 32

#define IID_REPOS_SIZE_MAX  ((IID_T)(-1))
#define IID_REPOS_SIZE_WARN 1024

#define IID_RSVD_UNUSED 0
#define IID_RSVD_MAX    0
#define IID_MIN_USED    1

#define IID_SPREAD_FK   1  /*default=2 , 1 means no spreading    #define IID_REPOS_USAGE_WARNING 10 */


#define OGMS_IID_PER_AGGREG_MAX  (SIGNED_FRAMES_SIZE_MAX - (\
                              sizeof(struct tlv_hdr) + \
                              sizeof (struct hdr_ogm_adv)  + \
                              (OGM_JUMPS_PER_AGGREGATION * sizeof(struct msg_ogm_iid_adv)))) \
                              / sizeof(struct msg_ogm_iid_adv)

#define OGMS_IID_PER_AGGREG_PREF (SIGNED_FRAMES_SIZE_PREF - (\
                              sizeof(struct tlv_hdr) + \
                              sizeof (struct hdr_ogm_adv)  + \
                              (OGM_JUMPS_PER_AGGREGATION * sizeof(struct msg_ogm_iid_adv)))) \
                              / sizeof(struct msg_ogm_iid_adv)

#define MIN_OGM_IID 0
#define MAX_OGM_IID 1
#define DEF_OGM_IID 0
#define ARG_OGM_IID "iidOgms"
extern int32_t ogmIid;
struct msg_ogm_iid_adv // 4 bytes
{

	union {

		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			unsigned int sqn : 16;
			unsigned int mtcMantissa : 5;
			unsigned int mtcExponent : 5;
			unsigned int iidOffset : 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			unsigned int iidOffset : 6;
			unsigned int mtcExponent : 5;
			unsigned int mtcMantissa : 5;
			unsigned int sqn : 16;
#else
#error "Please fix <bits/endian.h>"
#endif
		} o;

		struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			unsigned int iid : 16;
			unsigned int mtcU10 : 10;
			unsigned int iidOffset : 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
			unsigned int iidOffset : 6;
			unsigned int mtcU10 : 10;
			unsigned int iid : 16;
#else
#error "Please fix <bits/endian.h>"
#endif
		} j;
		uint32_t u32;
	} u;
} __attribute__((packed));

struct ogm_aggreg_node {
	IID_T *iidsArr;
	uint16_t iidsNum;
	uint16_t iidJumps;

	AGGREG_SQN_T sqn;
	uint8_t tx_round;
};

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
		IID_NODE_T__ **node;
		struct iid_ref *ref;
	} arr;
};


extern struct iid_repos my_iid_repos;


int8_t iid_extend_repos(struct iid_repos *rep);
void iid_purge_repos(struct iid_repos *rep);
void iid_free(struct iid_repos *rep, IID_T iid);
void iid_free_neighIID4x_by_myIID4x(struct iid_repos *rep, IID_T myIID4x);
IDM_T iid_set_neighIID4x(struct iid_repos *neigh_rep, IID_T neighIID4x, IID_T myIID4x);
IID_T iid_new_myIID4x(IID_NODE_T__ *dhn);

IID_NODE_T__* iid_get_node_by_neighIID4x(IID_NEIGH_T *nn, IID_T neighIID4x);
IID_NODE_T__* iid_get_node_by_myIID4x(IID_T myIID4x);

void iid_purge_dhash(IID_T myIID4orig);