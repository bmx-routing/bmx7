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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/rtnetlink.h>
#include <time.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "msg.h"
#include "ip.h"
#include "hna.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"
#include "z.h"

#define CODE_CATEGORY_NAME "iid"



/***********************************************************
 IID Infrastructure
 ************************************************************/


struct iid_repos my_iid_repos = {0, 0, 0, 0,
	{NULL}};

int8_t iid_extend_repos(struct iid_repos *rep)
{
	TRACE_FUNCTION_CALL;

	assertion(-500217, (rep != &my_iid_repos || IID_SPREAD_FK != 1 || rep->tot_used == rep->arr_size));

	if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_WARN) {

		dbgf_sys(DBGT_WARN, "%d", rep->arr_size);

		if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_MAX)
			return FAILURE;
	}

	if (rep->arr_size) {

		rep->arr.u8 = debugRealloc(rep->arr.u8, (rep->arr_size + IID_REPOS_SIZE_BLOCK) * sizeof(struct iid_ref), -300035);

	} else {

		rep->arr.u8 = debugMalloc(IID_REPOS_SIZE_BLOCK * sizeof(struct iid_ref), -300085);
		rep->tot_used = IID_RSVD_MAX + 1;
		rep->min_free = IID_RSVD_MAX + 1;
		rep->max_free = IID_RSVD_MAX + 1;
	}

	memset(&(rep->arr.u8[rep->arr_size * sizeof(struct iid_ref)]), 0, IID_REPOS_SIZE_BLOCK * sizeof(struct iid_ref));

	rep->arr_size += IID_REPOS_SIZE_BLOCK;

	return SUCCESS;
}

void iid_purge_repos(struct iid_repos *rep)
{
	TRACE_FUNCTION_CALL;

	if (rep->arr.u8)
		debugFree(rep->arr.u8, -300135);

	memset(rep, 0, sizeof( struct iid_repos));

}

void iid_free(struct iid_repos *rep, IID_T iid, IDM_T force)
{
	TRACE_FUNCTION_CALL;
	rep = rep ? rep : &my_iid_repos;

	assertion(-500330, (iid > IID_RSVD_MAX));
	assertion(-500228, (iid < rep->arr_size && iid < rep->max_free && rep->tot_used > IID_RSVD_MAX));

	struct iid_ref *ref = &rep->arr.r[iid];
	assertion(-500229, (ref->referred_timestamp));

	if (rep == &my_iid_repos)
		((MIID_T*)(ref->iidn))->__myIID4x = 0;
	else
		((NIID_T*)(ref->iidn))->__neighIID4x = 0;

	ref->iidn = NULL;

	if (rep == &my_iid_repos && !(force || (((TIME_T) (bmx_time - ref->referred_timestamp)) > MY_IID_TIMEOUT)))
		return;

	ref->referred_timestamp = 0;

	rep->min_free = XMIN(rep->min_free, iid);

	if (rep->max_free == iid + 1) {

		IID_T i;

		for (i = iid; i > IID_MIN_USED; i--) {

			if (rep->arr.r[i-1].referred_timestamp)
				break;
		}

		rep->max_free = i;
	}

	rep->tot_used--;

	dbgf_all(DBGT_INFO, "mine=%d, iid=%d tot_used=%d, min_free=%d max_free=%d",
		(rep == &my_iid_repos), iid, rep->tot_used, rep->min_free, rep->max_free);

	if (rep->tot_used > 0 && rep->tot_used <= IID_MIN_USED) {

		assertion(-500362, (rep->tot_used == IID_MIN_USED && rep->max_free == IID_MIN_USED && rep->min_free == IID_MIN_USED));

		iid_purge_repos(rep);
	}

}

IID_T iid_get_myIID4x_by_node(MIID_T* miidn)
{
	assertion(-500000, (miidn));
	IID_T iid;

	if (!miidn->__myIID4x) {
		iid = iid_new_myIID4x(miidn);
	} else {
		iid = miidn->__myIID4x;
	}
	assertion(-500000, (my_iid_repos.max_free > iid));
	assertion(-500000, (my_iid_repos.arr.r[iid].iidn == miidn));

	my_iid_repos.arr.r[iid].referred_timestamp = bmx_time;

	return iid;
}

MIID_T* iid_get_node_by_myIID4x(IID_T myIID4x)
{
	TRACE_FUNCTION_CALL;

	if (my_iid_repos.max_free <= myIID4x)
		return NULL;

	MIID_T *ref = my_iid_repos.arr.r[myIID4x].iidn;

	if (ref) {
		assertion(-500000, (ref->__myIID4x == myIID4x));
		my_iid_repos.arr.r[myIID4x].referred_timestamp = bmx_time;
	}
	
	return ref;
}



IID_T iid_get_neighIID4x_timeout_by_node(NIID_T *niidn)
{
	assertion(-500000, (niidn));
	assertion(-500000, (niidn && niidn->__neighIID4x));
	assertion(-500000, (niidn->nn));
	assertion(-500000, (niidn->nn->neighIID4x_repos.max_free > niidn->__neighIID4x));
	assertion(-500000, (niidn->nn->neighIID4x_repos.arr.r[niidn->__neighIID4x].iidn == niidn));

	TIME_T to = ((TIME_T) ((bmx_time - niidn->nn->neighIID4x_repos.arr.r[niidn->__neighIID4x].referred_timestamp)));

	if (to <= NB_IID_TIMEOUT)
		return to;
	else
		return 0;
}

IID_T iid_get_neighIID4x_by_node(NIID_T *niidn, IDM_T update)
{

	if (!iid_get_neighIID4x_timeout_by_node(niidn)) {
		
		return 0;

	} else {
		if (update)
			niidn->nn->neighIID4x_repos.arr.r[niidn->__neighIID4x].referred_timestamp = bmx_time;

		return niidn->__neighIID4x;
	}
}

NIID_T* iid_get_node_by_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, IDM_T update, void (*destroy) (NIID_T *niidn) )
{
	TRACE_FUNCTION_CALL;
	struct iid_ref *ref = NULL;


	if (!rep || rep->max_free <= neighIID4x || !(ref = &(rep->arr.r[neighIID4x])) || !ref->iidn) {

		return NULL;

	} else if (((TIME_T) (bmx_time - ref->referred_timestamp)) > NB_IID_TIMEOUT) {

		dbgf_track(DBGT_WARN, "neighIID4x=%d outdated in neighIID4x_repos, now_sec=%d, ref=%d",
			neighIID4x, bmx_time_sec, ref->referred_timestamp);

		if (destroy)
			(*destroy)((NIID_T*)(ref->iidn));

	} else {

		assertion(-500000, (((NIID_T*)(ref->iidn))->__neighIID4x == neighIID4x));
		if (update)
			ref->referred_timestamp = bmx_time;
		return ((NIID_T*)(ref->iidn));
	}

	return NULL;
}

STATIC_FUNC
void _iid_set(struct iid_repos *rep, IID_T IIDpos, NIID_T *nbn, MIID_T *myn)
{
	TRACE_FUNCTION_CALL;
	assertion(-500530, (rep));
	assertion(-500535, (IIDpos >= IID_MIN_USED));
	assertion(-500000, (XOR(nbn, myn))); // eihter the one ore the other !!
	assertion(-500531, IMPLIES(myn, rep == &my_iid_repos));

	rep->tot_used++;
	rep->max_free = XMAX(rep->max_free, IIDpos + 1);

	IID_T min = rep->min_free;

	if (min == IIDpos) {
		for (min++; min < rep->arr_size; min++) {

			if (!(rep->arr.r[min].referred_timestamp))
				break;
		}
	}

	assertion(-500244, (min <= rep->max_free));

	rep->min_free = min;

	assertion(-500000, (!rep->arr.r[IIDpos].iidn));
	assertion(-500000, (!rep->arr.r[IIDpos].referred_timestamp));

	if (nbn) {
		assertion(-500000, (!nbn->__neighIID4x));
		rep->arr.r[IIDpos].iidn = nbn;
		nbn->__neighIID4x = IIDpos;
	} else {
		assertion(-500000, (!myn->__myIID4x));
		rep->arr.r[IIDpos].iidn = myn;
		myn->__myIID4x = IIDpos;
	}

	rep->arr.r[IIDpos].referred_timestamp = bmx_time;


}

IID_T iid_new_myIID4x(MIID_T *on)
{
	TRACE_FUNCTION_CALL;
	IID_T mid;
#ifndef NO_ASSERTIONS
	IDM_T warn = 0;
#endif

	assertion(-500216, (my_iid_repos.tot_used <= my_iid_repos.arr_size));

	while (my_iid_repos.arr_size <= my_iid_repos.tot_used * IID_SPREAD_FK)
		iid_extend_repos(&my_iid_repos);

	if (IID_SPREAD_FK > 1) {

		uint32_t random = rand_num(my_iid_repos.arr_size);

		// Never put random function intro MAX()! It would be called twice
		mid = XMAX(IID_MIN_USED, random);

		while (my_iid_repos.arr.r[mid].referred_timestamp) {

			mid++;
			if (mid >= my_iid_repos.arr_size) {
				mid = IID_MIN_USED;
				assertion(-500533, (!(warn++)));
			}
		}

	} else {

		mid = my_iid_repos.min_free;
	}

	_iid_set(&my_iid_repos, mid, 0, on);

	return mid;

}

void iid_set_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, NIID_T *niidn)
{
	TRACE_FUNCTION_CALL;
	assertion(-500326, (neighIID4x > IID_RSVD_MAX));
	assertion(-500327, (niidn));
	assertion(-500384, (rep && rep != &my_iid_repos));


	if (rep->max_free > neighIID4x) {

		struct iid_ref *ref = &(rep->arr.r[neighIID4x]);

		if (ref->iidn) {
			ref->iidn = niidn;
			ref->referred_timestamp = bmx_time;
			return;
		}
	}

	while (rep->arr_size <= neighIID4x) {

		if (
			rep->arr_size > IID_REPOS_SIZE_BLOCK &&
			rep->arr_size > my_iid_repos.arr_size &&
			rep->tot_used < rep->arr_size / (2 * IID_SPREAD_FK)) {

			dbgf_track(DBGT_WARN, "IID_REPOS USAGE WARNING neighIID4x=%d  arr_size=%d used=%d",
				neighIID4x, rep->arr_size, rep->tot_used);
		}

		iid_extend_repos(rep);
	}

	assertion(-500243, (rep->arr_size > neighIID4x &&
		(rep->max_free <= neighIID4x || rep->arr.r[neighIID4x].iidn == NULL)));

	_iid_set(rep, neighIID4x, niidn, NULL);
}


