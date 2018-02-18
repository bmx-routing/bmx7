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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "allocate.h"
#include "tools.h"
#include "prof.h"
#include "schedule.h"

#define CODE_CATEGORY_NAME "profiling"

static AVL_TREE(prof_tree, struct prof_ctx, k);

void prof_init( struct prof_ctx *sp)
{
	assertion(-502112, (!sp->initialized));
	assertion(-502113, (sp && sp->k.func && sp->name && strlen(sp->name)< 100));
	assertion(-502114, (!(sp->k.orig && sp->k.neigh)));
	assertion(-502115, (!avl_find_item(&prof_tree, &sp->k)));

	if (sp->parent_func) {
		struct prof_ctx_key pk = {.func=sp->parent_func};
		struct prof_ctx *pp = avl_find_item(&prof_tree, &pk);

		assertion(-502116, (pp));

		avl_insert(&pp->childs_tree, sp, -300644);
		sp->parent = pp;
	}

	AVL_INIT_TREE(sp->childs_tree, struct prof_ctx, k);

	avl_insert(&prof_tree, sp, -300645);
	sp->initialized = 1;

}

void prof_free( struct prof_ctx *p)
{
	assertion(-502117, (p));
	assertion(-502118, (p->initialized));
	assertion(-502119, (!(p->childs_tree.items)));
	assertion(-502120, (avl_find_item(&prof_tree, &p->k)));
//	assertion(-502121, !((*p)->timeBefore));

	p->initialized = 0;
	
	avl_remove(&prof_tree, &p->k, -300646);

	if (p->parent)
		avl_remove(&(p->parent->childs_tree), &p->k, -300647);

}

static uint8_t prof_check_disabled = 0;

STATIC_FUNC
int prof_check(struct prof_ctx *p, int childs)
{
	if (prof_check_disabled ||
		!p || (p->active_prof && !!p->active_childs == childs && prof_check(p->parent, 1) == SUCCESS))
		return SUCCESS;

	dbgf_sys(DBGT_ERR, "func=%d name=%s parent_func=%d neigh=%p orig=%p parent_active_childs=%d childs=%d",
		!!p->k.func, p->name, !!p->parent_func, (void*)p->k.neigh, (void*)p->k.orig, p->active_childs, childs);

	return FAILURE;
}

void prof_start_( struct prof_ctx *p)
{
	assertion_dbg(-502122, (!p->active_prof && !p->clockBeforePStart && !p->active_childs),
		"func=%s %d %ju %d", p->name, p->active_prof, (uintmax_t)p->clockBeforePStart, p->active_childs);

	if (!p->initialized)
		prof_init(p);

	p->clockBeforePStart = (TIME_T)clock();
	p->active_prof = 1;

	if (p->parent)
		p->parent->active_childs++;

	ASSERTION(-502125, (prof_check(p, 0) == SUCCESS));
}



void prof_stop_( struct prof_ctx *p)
{
	TIME_T clockAfter = clock();
	TIME_T clockPeriod = (clockAfter - p->clockBeforePStart);

	assertion_dbg(-502126, (p->active_prof && !p->active_childs),
		"func=%s %d %d %ju %d %d", p->name, p->active_prof, p->active_childs, (uintmax_t)p->clockBeforePStart, clockAfter, clockPeriod);

	ASSERTION(-502127, (prof_check(p, 0) == SUCCESS));

//	IDM_T TODO_Fix_this_for_critical_system_time_drifts;
//	assertion(-502128, (clockPeriod < ((~((TIME_T)0))>>1)) ); //this wraps around some time..

	if (clockPeriod < ((~((TIME_T)0))>>1))
		p->clockRunningPeriod += clockPeriod;

	p->clockBeforePStart = 0;
	p->active_prof = 0;

	if (p->parent)
		p->parent->active_childs--;
}

static uint64_t durationPrevPeriod = 0;
static uint64_t timeAfterPrevPeriod = 0;

STATIC_FUNC
void prof_update_all( void *unused) {

	struct avl_node *an=NULL;
	struct prof_ctx *pn;

	struct timeval tvAfterRunningPeriod;
	upd_time(&tvAfterRunningPeriod);
	uint64_t timeAfterRunningPeriod = (((uint64_t)tvAfterRunningPeriod.tv_sec) * 1000000) + tvAfterRunningPeriod.tv_usec;

	durationPrevPeriod = (timeAfterRunningPeriod - timeAfterPrevPeriod);

	assertion(-502129, (durationPrevPeriod > 0));
	assertion(-502130, (durationPrevPeriod < 10*1000000));

	prof_check_disabled = YES;

	while ((pn = avl_iterate_item(&prof_tree, &an))) {

		uint8_t active = pn->active_prof;

		dbgf_all(DBGT_INFO, "updating %s active=%d", pn->name, active);

		if (active)
			prof_stop_(pn);

		pn->clockPrevPeriod = pn->clockRunningPeriod;
		pn->clockPrevTotal += pn->clockRunningPeriod;

		pn->clockRunningPeriod = 0;

		if (active)
			prof_start_(pn);
	}

	prof_check_disabled = NO;

	timeAfterPrevPeriod = timeAfterRunningPeriod;

	task_register(5000, prof_update_all, NULL, -300648);
}


struct prof_status {
        GLOBAL_ID_T *neighId;
        GLOBAL_ID_T *origId;
	const char* parent;
        const char* name;
//	uint32_t total;
	char sysCurrCpu[10];
	char relCurrCpu[10];
	char sysAvgCpu[10];
	char relAvgCpu[10];

};

static const struct field_format prof_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  prof_status, neighId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, prof_status, origId,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      prof_status, parent,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      prof_status, name,          1, FIELD_RELEVANCE_HIGH),
//      FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              prof_status, total,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, sysCurrCpu,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, relCurrCpu,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, sysAvgCpu,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       prof_status, relAvgCpu,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

STATIC_FUNC
struct prof_status *prof_status_iterate(struct prof_ctx *pn, struct prof_status *status)
{
	dbgf_all(DBGT_INFO, "dbg pn=%s status=%p", pn->name, (void*)status);

	status->neighId = pn->k.neigh ? &pn->k.neigh->local_id: NULL;
	status->origId = pn->k.orig ? &pn->k.orig->k.nodeId : NULL;
	status->parent = pn->parent ? pn->parent->name : NULL;
	status->name = pn->name;
	sprintf(status->sysCurrCpu, DBG_NIL);
	sprintf(status->relCurrCpu, DBG_NIL);
	sprintf(status->sysAvgCpu, DBG_NIL);
	sprintf(status->relAvgCpu, DBG_NIL);

	if (!durationPrevPeriod || !timeAfterPrevPeriod)
		goto prof_status_iterate_childs;

	uint32_t loadPrevPeriod = (((uint64_t) pn->clockPrevPeriod)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		durationPrevPeriod;

	snprintf(status->sysCurrCpu, sizeof(status->sysCurrCpu), "%8.4f", ((float) loadPrevPeriod) / 1000);

	uint32_t loadPrevTotal = (((uint64_t) pn->clockPrevTotal)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		timeAfterPrevPeriod;

	snprintf(status->sysAvgCpu, sizeof(status->sysAvgCpu), "%8.4f", ((float) loadPrevTotal) / 1000);

	if (!pn->parent)
		goto prof_status_iterate_childs;

	uint32_t loadParentPrevPeriod = (((uint64_t) pn->parent->clockPrevPeriod)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		durationPrevPeriod;

	if (loadParentPrevPeriod)
		snprintf(status->relCurrCpu, sizeof(status->relCurrCpu), "%8.4f", ((((float) loadPrevPeriod)*100) / ((float) loadParentPrevPeriod)));
	else if (!loadParentPrevPeriod && loadPrevPeriod)
		sprintf(status->relCurrCpu, "ERR");

	uint32_t loadParentPrevTotal = (((uint64_t) pn->parent->clockPrevTotal)*
		((((uint64_t) 100)*1000 * 1000000) / ((uint64_t) CLOCKS_PER_SEC))) /
		timeAfterPrevPeriod;

	if (loadParentPrevTotal)
		snprintf(status->relAvgCpu, sizeof(status->relAvgCpu), "%8.4f", ((((float) loadPrevTotal)*100) / ((float) loadParentPrevTotal)));
	else if (!loadParentPrevTotal && loadPrevTotal)
		sprintf(status->relAvgCpu, "ERR");


prof_status_iterate_childs: {

	status = &(status[1]);

	struct avl_node *an = NULL;
	struct prof_ctx *cn;
	while ((cn=avl_iterate_item(&pn->childs_tree, &an))) {
		status = prof_status_iterate(cn, status);
	}
}
	return status;
}

STATIC_FUNC
int32_t prof_status_creator(struct status_handl *handl, void *data)
{
        struct avl_node *it = NULL;
        struct prof_ctx *pn;
        uint32_t status_size = (prof_tree.items) * sizeof (struct prof_status);
        struct prof_status *status = ((struct prof_status*) (handl->data = debugRealloc(handl->data, status_size, -300366)));
        memset(status, 0, status_size);

	while ((pn = avl_iterate_item(&prof_tree, &it))) {

		if (!pn->parent) {
			status = prof_status_iterate(pn, status);
		}
        }

        return status_size;
}


static struct opt_type prof_options[]=
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	{ODI,0,ARG_CPU_PROFILING,        0,  9,1,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show cpu usage of relevant functions\n"}
};


void init_prof( void )
{
	register_status_handl(sizeof (struct prof_status), 1, prof_status_format, ARG_CPU_PROFILING, prof_status_creator);
	register_options_array(prof_options, sizeof( prof_options), CODE_CATEGORY_NAME);

	task_register(5000, prof_update_all, NULL, -300649);

}

void cleanup_prof(void)
{

        struct avl_node *it = NULL;
        struct prof_ctx *pn;

	for (it = NULL; (pn = avl_iterate_item(&prof_tree, &it));) {
		pn->parent = NULL;
		while ((avl_remove_first_item(&(pn->childs_tree), -300650)));
        }

	while ((avl_remove_first_item(&prof_tree, -300651)));
}
