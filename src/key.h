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






extern int32_t tracked_timeout;
extern int32_t neigh_qualifying_to;


#define MIN_ID_PURGE_TO 0
#define MAX_ID_PURGE_TO 864000000 /*10 days*/
#define DEF_ID_PURGE_TO 20000
#define ARG_ID_PURGE_TO "idTimeout"

#define ARG_SET_CREDITS "setCredits"
#define ARG_SET_CREDITS_MAX "maxNodes"
#define HLP_SET_CREDITS "parametrize given state section"
#define MIN_SET_CREDITS_MAX 1
#define MAX_SET_CREDITS_MAX 100000
#define HLP_SET_CREDITS_MAX "set maximum number of nodes of state section"
#define ARG_SET_CREDITS_PREF "preference"
#define MIN_SET_CREDITS_PREF 0
#define MAX_SET_CREDITS_PREF 9999
#define HLP_SET_CREDITS_PREF "set preference for nodes of given state section"


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

int16_t kPref_neighbor_metric(struct key_node *kn);

extern struct KeyState keyMatrix[KCSize][KRSize];
extern uint32_t key_tree_deletions_chk, key_tree_deletions_cntr;

void keyNode_schedLowerWeight(struct key_node *kn, int8_t weight);

struct key_node *keyNode_updCredits(GLOBAL_ID_T *kHash, struct key_node *kn, struct key_credits *kc);

#define keyNode_delCredits( a, b, c, d ) keyNode_delCredits_(__func__, (a), (b), (c), (d) )
void keyNode_delCredits_(const char *f, GLOBAL_ID_T *kHash, struct key_node *kn, struct key_credits *kc, IDM_T reAssessState);
#define KEYNODES_BLOCKING_ID 10

#define keyNodes_block_and_sync( id, force ) keyNodes_block_and_sync_( __func__, (id), (force) )
uint32_t keyNodes_block_and_sync_(const char *f, uint32_t id, IDM_T force);
void keyNode_fixTimeouts(void);
struct key_node *keyNode_get(GLOBAL_ID_T *kHask);
void keyNodes_cleanup(int8_t keyStateColumn, struct key_node *except);
void init_key(void);
