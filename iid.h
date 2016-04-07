
/*
 * from iid.h:
 */
typedef uint16_t IID_T;
#define IID_BIT_SIZE (15)
#define IID_MASK     ((1<<IID_BIT_SIZE)-1)


typedef struct orig_node MIID_T;
typedef struct NeighRef_node NIID_T;


#define NB_IID_TIMEOUT ((MAX_OGM_INTERVAL * 120) / 100)


#define IID_REPOS_SIZE_BLOCK 64

#define IID_REPOS_SIZE_MAX  (IID_MASK - 1)
#define IID_REPOS_SIZE_WARN 1024

#define IID_RSVD_MAX    0
#define IID_MIN_USED_FOR_SELF 1

struct iid_ref {
	void *iidn;
	TIME_T referred_timestamp;
};

struct iid_repos {
	IID_T arr_size; // the number of allocated array fields
	IID_T min_free; // the first unused array field from the beginning of the array (might be outside of allocated space)
	IID_T max_free; // the first unused array field after the last used field in the array (might be outside of allocated space)
	IID_T tot_used; // the total number of used fields in the array

	union {
		uint8_t *u8;
		struct iid_ref *r;
	} arr;
};


extern struct iid_repos my_iid_repos;


void iid_extend_repos(struct iid_repos *rep);
void iid_purge_repos(struct iid_repos *rep);
void iid_free(struct iid_repos *rep, IID_T iid);
void iid_set_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, NIID_T *niidn);
IID_T iid_new_myIID4x(MIID_T *on);

IID_T iid_get_neighIID4x_by_node(NIID_T *niidn);
IID_T iid_get_neighIID4x_timeout_by_node(NIID_T *niidn);
NIID_T* iid_get_node_by_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, IDM_T update);
IID_T iid_get_myIID4x_by_node(MIID_T* miidn);

MIID_T* iid_get_node_by_myIID4x(IID_T myIID4x);
