
#define DEF_LINK_METRIC_FLAGS     (0x0)
#define ARG_LINK_METRIC_FLAGS     "linkMetricFlags"

#define ARG_LINKS "links"



struct dsc_msg_llip {
	IP6_T ip6;
} __attribute__((packed));

#define DESCRIPTION_MSG_LLIP_FORMAT { \
{FIELD_TYPE_IPX6, -1, 128, 1, FIELD_RELEVANCE_HIGH, "address" },  \
FIELD_FORMAT_END }

struct msg_hello_adv { // 2 bytes
	HELLO_SQN_T hello_sqn;
} __attribute__((packed));

struct msg_hello_reply_data {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int rxLq_63range : 6;
	unsigned int receiverDevIdx : DEVIDX_BITS;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int receiverDevIdx : DEVIDX_BITS;
	unsigned int rxLq_63range : 6;
#else
#error "Please fix <bits/endian.h>"
#endif
} __attribute__((packed));

struct msg_hello_reply_dhash {
	DHASH_T dest_dhash;

	union {
		struct msg_hello_reply_data d;
		uint16_t u16;
	} u;
} __attribute__((packed));



//IDM_T updateNeighDevId(struct neigh_node *nn, struct desc_content *contents);
LinkNode *getLinkNode(struct dev_node *dev, IPX_T *llip, DEVIDX_T idx, struct neigh_node *verifiedNeigh);
void purge_linkDevs(LinkDevKey *onlyLinkDev, struct dev_node *only_dev, IDM_T purgeLocal);

struct plugin *link_get_plugin(void);