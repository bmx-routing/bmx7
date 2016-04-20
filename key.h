/*
 * Copyright (c) 2014  Axel Neumann
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





#define DEF_LINK_PURGE_TO  20000
#define MIN_LINK_PURGE_TO  (MAX_TX_MIN_INTERVAL*2)
#define MAX_LINK_PURGE_TO  864000000 /*10 days*/
#define ARG_LINK_PURGE_TO  "linkPurgeTimeout"

extern int32_t link_purge_to;
extern int32_t tracked_timeout;
extern int32_t neigh_qualifying_to;


// Key Weight:
#define KCNull (-1)

enum KColumns {
	KCListed,
	KCTracked,
	KCCertified,
	KCPromoted,
	KCNeighbor,
	KCSize,
};

// Key Credits:
enum KRows {
	KRQualifying,
	KRFriend,
	KRRecommended,
	KRAlien,
	KRSize,
};

extern struct KeyState keyMatrix[KCSize][KRSize];
extern uint32_t key_tree_deletions_chk, key_tree_deletions_cntr;

void keyNode_schedLowerWeight(struct key_node *kn, int8_t weight);

struct key_node *keyNode_updCredits(GLOBAL_ID_T *kHash, struct key_node *kn, struct key_credits *kc);

#define keyNode_delCredits( a, b, c ) keyNode_delCredits_(__FUNCTION__, (a), (b), (c) )
void keyNode_delCredits_(const char *f, GLOBAL_ID_T *kHash, struct key_node *kn, struct key_credits *kc);
#define KEYNODES_BLOCKING_ID 10

#define keyNodes_block_and_sync( id, force ) keyNodes_block_and_sync_( __FUNCTION__, (id), (force) )
uint32_t keyNodes_block_and_sync_(const char *f, uint32_t id, IDM_T force);
void keyNode_fixTimeouts(void);
struct key_node *keyNode_get(GLOBAL_ID_T *kHask);
void keyNodes_cleanup(int8_t keyStateColumn, struct key_node *except);
void init_key(void);
