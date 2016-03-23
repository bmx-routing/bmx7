
/*
 * from iid.h:
 */
typedef uint16_t IID_T;



typedef struct orig_node MIID_T;
typedef struct NeighRef_node NIID_T;


#define MY_IID_TIMEOUT 80000
#define NB_IID_TIMEOUT 60000


#define IID_REPOS_SIZE_BLOCK 32

#define IID_REPOS_SIZE_MAX  ((IID_T)(-1))
#define IID_REPOS_SIZE_WARN 1024

#define IID_RSVD_UNUSED 0
#define IID_RSVD_MAX    0
#define IID_MIN_USED    1

#define IID_SPREAD_FK   1  /*default=2 , 1 means no spreading    #define IID_REPOS_USAGE_WARNING 10 */

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


int8_t iid_extend_repos(struct iid_repos *rep);
void iid_purge_repos(struct iid_repos *rep);
void iid_free(struct iid_repos *rep, IID_T iid, IDM_T force);
void iid_set_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, NIID_T *niidn);
IID_T iid_new_myIID4x(MIID_T *dhn);

IID_T iid_get_neighIID4x_by_node(NIID_T *niidn, IDM_T update);
IID_T iid_get_neighIID4x_timeout_by_node(NIID_T *niidn);
NIID_T* iid_get_node_by_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, IDM_T update, void (*destroy) (NIID_T *niidn));
IID_T iid_get_myIID4x_by_node(MIID_T* miidn);

MIID_T* iid_get_node_by_myIID4x(IID_T myIID4x);
