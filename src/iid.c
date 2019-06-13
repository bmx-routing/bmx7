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
#include "ogm.h"
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


struct iid_repos my_iid_repos = {0, 0, 0, 0, {NULL}};

void iid_extend_repos(struct iid_repos *rep)
{
	assertion(-500217, (rep != &my_iid_repos || rep->tot_used == rep->arr_size));

	if (rep->arr_size + IID_REPOS_SIZE_BLOCK >= IID_REPOS_SIZE_WARN) {

		dbgf_sys(DBGT_WARN, "%d", rep->arr_size);

		assertion(-502538, (rep->arr_size + IID_REPOS_SIZE_BLOCK <= IID_REPOS_SIZE_MAX));
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
}

void iid_purge_repos(struct iid_repos *rep)
{
	if (rep->arr.u8)
		debugFree(rep->arr.u8, -300135);

	memset(rep, 0, sizeof( struct iid_repos));

}

void iid_free(struct iid_repos *rep, IID_T iid)
{
	rep = rep ? rep : &my_iid_repos;

	assertion(-500330, (iid > IID_RSVD_MAX));
	assertion(-500228, (iid < rep->arr_size && iid < rep->max_free && rep->tot_used > IID_RSVD_MAX));

	struct iid_ref *ref = &rep->arr.r[iid];
	assertion(-500229, (ref->referred_timestamp));

	if (rep == &my_iid_repos)
		((MIID_T*) (ref->iidn))->__myIID4x = 0;
	else
		((NIID_T*) (ref->iidn))->__neighIID4x = 0;

	ref->iidn = NULL;
	ref->referred_timestamp = 0;

	rep->min_free = XMIN(rep->min_free, iid);

	if (rep->max_free == iid + 1) {

		IID_T i;

		for (i = iid; i > IID_MIN_USED_FOR_SELF; i--) {

			if (rep->arr.r[i - 1].referred_timestamp)
				break;
		}

		rep->max_free = i;
	}

	rep->tot_used--;

	dbgf_all(DBGT_INFO, "mine=%d, iid=%d tot_used=%d, min_free=%d max_free=%d",
		(rep == &my_iid_repos), iid, rep->tot_used, rep->min_free, rep->max_free);

	if (rep->tot_used > 0 && rep->tot_used <= IID_MIN_USED_FOR_SELF) {

		assertion(-500362, (rep->tot_used == IID_MIN_USED_FOR_SELF && rep->max_free == IID_MIN_USED_FOR_SELF && rep->min_free == IID_MIN_USED_FOR_SELF));

		iid_purge_repos(rep);
	}

}

IID_T iid_get_myIID4x_by_node(MIID_T* miidn)
{
	assertion(-502539, (miidn));
	IID_T iid = miidn->__myIID4x;

	assertion(-502540, (iid));
	assertion(-502541, (my_iid_repos.max_free > iid));
	assertion(-502542, (my_iid_repos.arr.r[iid].iidn == miidn));

	my_iid_repos.arr.r[iid].referred_timestamp = bmx_time;

	return iid;
}

MIID_T* iid_get_node_by_myIID4x(IID_T myIID4x)
{
	if (my_iid_repos.max_free <= myIID4x)
		return NULL;

	MIID_T *ref = my_iid_repos.arr.r[myIID4x].iidn;

	if (ref) {
		assertion(-502543, (ref->__myIID4x == myIID4x));
		my_iid_repos.arr.r[myIID4x].referred_timestamp = bmx_time;
	}

	return ref;
}

IID_T iid_get_neighIID4x_timeout_by_node(NIID_T *niidn)
{
	assertion(-502544, (niidn));
	assertion(-502545, (niidn && niidn->__neighIID4x));
	assertion(-502546, (niidn->nn));
	assertion(-502547, (niidn->nn->neighIID4x_repos.max_free > niidn->__neighIID4x));
	assertion(-502548, (niidn->nn->neighIID4x_repos.arr.r[niidn->__neighIID4x].iidn == niidn));

	TIME_T to = ((TIME_T) ((bmx_time - niidn->nn->neighIID4x_repos.arr.r[niidn->__neighIID4x].referred_timestamp)));

	if (to < NB_IID_TIMEOUT)
		return(NB_IID_TIMEOUT - to);
	else
		return 0;
}

IID_T iid_get_neighIID4x_by_node(NIID_T *niidn)
{
	return niidn ? niidn->__neighIID4x : IID_RSVD_MAX;
}

NIID_T* iid_get_node_by_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, IDM_T update)
{
	struct iid_ref *ref = NULL;


	if (!rep || rep->max_free <= neighIID4x || !(ref = &(rep->arr.r[neighIID4x])) || !ref->iidn) {

		return NULL;

	} else {

		assertion(-502549, (((NIID_T*) (ref->iidn))->__neighIID4x == neighIID4x));
		if (update)
			ref->referred_timestamp = bmx_time;
		return((NIID_T*) (ref->iidn));
	}

	return NULL;
}

STATIC_FUNC
void _iid_set(struct iid_repos *rep, IID_T IIDpos, NIID_T *nbn, MIID_T *myn)
{
	assertion(-500530, (rep));
	assertion(-500535, (IIDpos >= IID_MIN_USED_FOR_SELF));
	assertion(-502550, (XOR(nbn, myn))); // eihter the one ore the other !!
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

	assertion(-502551, (!rep->arr.r[IIDpos].iidn));
	assertion(-502552, (!rep->arr.r[IIDpos].referred_timestamp));

	if (nbn) {
		assertion(-502553, (!nbn->__neighIID4x));
		rep->arr.r[IIDpos].iidn = nbn;
		nbn->__neighIID4x = IIDpos;
	} else {
		assertion(-502554, (!myn->__myIID4x));
		rep->arr.r[IIDpos].iidn = myn;
		myn->__myIID4x = IIDpos;
	}

	rep->arr.r[IIDpos].referred_timestamp = bmx_time;


}

IID_T iid_new_myIID4x(MIID_T *on)
{
	IID_T mid;

	assertion(-500216, (my_iid_repos.tot_used <= my_iid_repos.arr_size));

	while (my_iid_repos.arr_size <= my_iid_repos.tot_used)
		iid_extend_repos(&my_iid_repos);

	mid = my_iid_repos.min_free;

	_iid_set(&my_iid_repos, mid, 0, on);

	return mid;

}

void iid_set_neighIID4x(struct iid_repos *rep, IID_T neighIID4x, NIID_T *niidn)
{
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
			rep->tot_used < rep->arr_size / 2) {

			dbgf_track(DBGT_WARN, "IID_REPOS USAGE WARNING neighIID4x=%d  arr_size=%d used=%d",
				neighIID4x, rep->arr_size, rep->tot_used);
		}

		iid_extend_repos(rep);
	}

	assertion(-500243, (rep->arr_size > neighIID4x &&
		(rep->max_free <= neighIID4x || rep->arr.r[neighIID4x].iidn == NULL)));

	_iid_set(rep, neighIID4x, niidn, NULL);
}
