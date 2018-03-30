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
#define ARG_CPU_PROFILING "cpu"

struct prof_ctx_key {
	struct neigh_node *neigh;
	struct orig_node *orig;
	void (* func) (void);
} __attribute__((packed));

struct prof_ctx {
	// must be initialized:
	struct prof_ctx_key k;
	const char *name;
	void (* parent_func) (void);
	// updated by first prof_start() -> prof_init():
	struct prof_ctx *parent;
	struct avl_tree childs_tree;
	int8_t initialized;

	int8_t active_childs;
	int8_t active_prof;

	clock_t clockBeforePStart;

	// updated by prof_stop():
	clock_t clockRunningPeriod;
	clock_t clockPrevPeriod;
	uint64_t clockPrevTotal;
};

//void prof_init( struct prof_ctx *sp);

void prof_free(struct prof_ctx *p);

void prof_start_(struct prof_ctx *p);
void prof_stop_(struct prof_ctx *p);

#define prof_start( thisFunc, parentFunc ) \
	extern int main(int argc, char *argv[]); \
	static struct prof_ctx prof_ctx_ = {.k = { .func = (void(*)(void))thisFunc}, .name = __func__, .parent_func = (void (*) (void))parentFunc}; \
	prof_start_(&prof_ctx_)

#define prof_stop() prof_stop_( &prof_ctx_ )




void init_prof(void);
void cleanup_prof(void);
