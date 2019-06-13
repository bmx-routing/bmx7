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


#define DEF_LINK_METRIC_FLAGS     (0x0)
#define ARG_LINK_METRIC_FLAGS     "linkMetricFlags"

#define ARG_LINKS "links"

#define MIN_LINK_PURGE_TO  MAX_TX_MIN_INTERVAL
#define MAX_LINK_PURGE_TO  864000000 /*10 days*/
#define DEF_LINK_PURGE_TO  20000
#define ARG_LINK_PURGE_TO  "linkTimeout"
extern int32_t link_purge_to;

#define MIN_TIMEAWARE_LQ_MIN 1
#define MAX_TIMEAWARE_LQ_MIN LQ_MAX
#define DEF_TIMEAWARE_LQ_MIN (LQ_MAX / 10)
#define ARG_TIMEAWARE_LQ_MIN "minLinkQuality"

#define MAX_LINK_KEYS_SIZE 30

struct dsc_msg_llip {
	IP6_T ip6;
} __attribute__((packed));

#define DESCRIPTION_MSG_LLIP_FORMAT { \
{FIELD_TYPE_IPX6, -1, 128, 1, FIELD_RELEVANCE_HIGH, "address" },  \
FIELD_FORMAT_END }

struct msg_hello_adv { // 2 bytes
	HELLO_SQN_T hello_sqn;
} __attribute__((packed));

struct msg_hello_reply_dhash {
	DHASH_T dest_dhash;
	LQ_T rxLq;
	DEVIDX_T receiverDevIdx;
} __attribute__((packed));



//IDM_T updateNeighDevId(struct neigh_node *nn, struct desc_content *contents);
IDM_T min_lq_probe(LinkNode *link);
LinkNode *getLinkNode(struct dev_node *dev, IPX_T *llip, DEVIDX_T idx, struct neigh_node *verifiedNeigh);
uint16_t purge_linkDevs(LinkDevNode *onlyLinkDev, struct dev_node *onlyDev, LinkNode *onlyLink, IDM_T onlyExpired, IDM_T purgeLocal);
char * getLinkKeysAsString(struct orig_node *on);

struct plugin *link_get_plugin(void);
