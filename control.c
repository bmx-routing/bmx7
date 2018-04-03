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
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "link.h"
#include "msg.h"
#include "sec.h"
#include "content.h"
#include "desc.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "allocate.h"
#include "hna.h"
#include "dump.h"
#include "prof.h"

#define CODE_CATEGORY_NAME "control"


char run_dir[MAX_PATH_SIZE] = DEF_RUN_DIR;

static int32_t debug_level = -1;
static int32_t dbg_mute_to;

#define MIN_LOOP_INTERVAL 100
#define MAX_LOOP_INTERVAL 10000
#define DEF_LOOP_INTERVAL 1000
static int32_t loop_interval = DEF_LOOP_INTERVAL;

static int32_t loop_mode;



int unix_sock = 0;
uint32_t My_pid = 0;

LIST_SIMPEL(ctrl_list, struct ctrl_node, list, list);

struct list_head dbgl_clients[DBGL_MAX + 1];
static struct dbg_histogram dbgl_history[2][DBG_HIST_SIZE];

static uint8_t debug_system_active = NO;



static char *init_string = NULL;

static int32_t Testing = NO;
int32_t Load_config;

static int32_t dbg_syslog = DEF_DBG_SYSLOG;

char *prog_name;

struct opt_type Patch_opt;

LIST_SIMPEL(opt_list, struct opt_data, list, list); // global opt_list


int32_t Client_mode = NO; //this one must be initialized manually!

STATIC_FUNC
void remove_dbgl_node(struct ctrl_node *cn)
{

	int8_t i;
	struct dbgl_node *dn;
	struct list_node *list_pos, *list_tmp, *list_prev;

	for (i = DBGL_MIN; i <= DBGL_MAX; i++) {

		list_prev = (struct list_node *) &dbgl_clients[i];

		list_for_each_safe(list_pos, list_tmp, /*(struct list_node *)*/(&dbgl_clients[i]))
		{

			dn = list_entry(list_pos, struct dbgl_node, list);

			if (dn->cn == cn) {
				list_del_next(&dbgl_clients[i], list_prev);
				debugFree(list_pos, -300049);
			} else {
				list_prev = &dn->list;
			}
		}
	}

	cn->dbgl = -1;
}

STATIC_FUNC
void add_dbgl_node(struct ctrl_node *cn, int dbgl)
{

	if (!cn || dbgl < DBGL_MIN || dbgl > DBGL_MAX)
		return;

	struct dbgl_node *dn = debugMallocReset(sizeof( struct dbgl_node), -300009);

	dn->cn = cn;
	cn->dbgl = dbgl;
	list_add_tail(&dbgl_clients[dbgl], &dn->list);

	if (dbgl == DBGL_SYS || dbgl == DBGL_CHANGES) {
		dbgf_all(DBGT_INFO, "resetting muted dbg history");
		memset(dbgl_history, 0, sizeof( dbgl_history));
	}

}

static int daemonize(void)
{

	int fd;

	switch (fork()) {

	case -1:
		return -1;

	case 0:
		break;

	default:
		exit(EXIT_SUCCESS);

	}

	if (setsid() == -1)
		return -1;

	/* Ensure we are no session leader */
	if (fork())
		exit(EXIT_SUCCESS);


	errno = 0;
	if (chdir("/") < 0) {
		dbg_sys(DBGT_ERR, "could not chdir to /: %s", strerror(errno));
	}

	if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {

		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if (fd > 2)
			close(fd);

	}

	return 0;

}

STATIC_FUNC
int update_pid_file(void)
{

	char tmp_path[MAX_PATH_SIZE + 20] = "";
	int tmp_fd = 0;

	My_pid = getpid();

	sprintf(tmp_path, "%s/%s", run_dir, BMX_PID_FILE);

	if ((tmp_fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) { //check permissions of generated file

		dbgf_sys(DBGT_ERR, "could not open %s - %s", tmp_path, strerror(errno));
		return FAILURE;
	}

	dprintf(tmp_fd, "%d\n", My_pid);

	close(tmp_fd);
	return SUCCESS;
}

STATIC_FUNC
void activate_debug_system(void)
{

	if (!debug_system_active) {

		/* daemonize */
		if (debug_level == -1) {

			if (daemonize() < 0) {
				dbg_sys(DBGT_ERR, "can't fork to background: %s", strerror(errno));
				cleanup_all(-500093);
			}

			// fork will result in a new pid
			if (update_pid_file() == FAILURE)
				cleanup_all(-500132);


		} else {

			struct ctrl_node *cn = create_ctrl_node(STDOUT_FILENO, NULL, NO/*admin rights not necessary*/);

			add_dbgl_node(cn, debug_level);

		}

		//dbg( DBGL_CHANGES, DBGT_INFO, "resetting muted dbg history" );
		memset(dbgl_history, 0, sizeof( dbgl_history));

		debug_system_active = YES;

		dbgf_all(DBGT_INFO, "activated debug_level=%d", debug_level);

	}
}

struct ctrl_node *create_ctrl_node(int fd, void (*cn_fd_handler) (struct ctrl_node *), uint8_t authorized)
{
	struct ctrl_node *cn = debugMallocReset(sizeof(struct ctrl_node), -300010);

	list_add_tail(&ctrl_list, &cn->list);

	cn->fd = fd;
	cn->cn_fd_handler = cn_fd_handler;
	cn->dbgl = -1;
	cn->authorized = authorized;

	return cn;
}

void close_ctrl_node(uint8_t cmd, struct ctrl_node *cn)
{

	struct list_node* list_pos, *list_prev, *list_tmp;

	list_prev = (struct list_node *) &ctrl_list;

	list_for_each_safe(list_pos, list_tmp, &ctrl_list)
	{

		struct ctrl_node *cn_tmp = list_entry(list_pos, struct ctrl_node, list);

		if ((cmd == CTRL_CLOSE_ERROR || cmd == CTRL_CLOSE_SUCCESS || cmd == CTRL_CLOSE_DELAY) && cn_tmp == cn) {

			if (cn_tmp->fd > 0 && cn_tmp->fd != STDOUT_FILENO) {

				cn_tmp->closing_stamp = XMAX(bmx_time, 1);
				remove_dbgl_node(cn_tmp);

				//leaving this after remove_dbgl_node() prevents debugging via broken -d4 pipe
				dbgf_all(DBGT_INFO, "closed ctrl node fd %d with cmd %d", cn_tmp->fd, cmd);


				if (cmd == CTRL_CLOSE_SUCCESS) {
					if (write(cn_tmp->fd, CONNECTION_END_STR, strlen(CONNECTION_END_STR)) < 0) {
						dbgf_track(DBGT_WARN, "%s", strerror(errno));
					}
				}

				if (cmd != CTRL_CLOSE_DELAY) {
					close(cn_tmp->fd);
					cn_tmp->fd = 0;
					change_selects();
				}

			}

			return;

		} else if ((cmd == CTRL_CLOSE_STRAIGHT && cn_tmp == cn) ||
			(cmd == CTRL_PURGE_ALL) ||
			(cmd == CTRL_CLEANUP && cn_tmp->closing_stamp && /* cn_tmp->fd <= 0  && */
			U32_GT(bmx_time, cn_tmp->closing_stamp + CTRL_CLOSING_TIMEOUT))) {

			if (cn_tmp->fd > 0 && cn_tmp->fd != STDOUT_FILENO) {
				remove_dbgl_node(cn_tmp);
				//leaving this after remove_dbgl_node() prevents debugging via broken -d4 pipe
				dbgf_all(DBGT_INFO, "closed ctrl node fd %d", cn_tmp->fd);

				close(cn_tmp->fd);
				cn_tmp->fd = 0;
				change_selects();
			}

			list_del_next(&ctrl_list, list_prev);
			debugFree(cn_tmp, -300050);

		} else {

			list_prev = (struct list_node *) &cn_tmp->list;

		}
	}
}

void accept_ctrl_node(void)
{


	struct sockaddr addr;
	socklen_t addr_size = sizeof(struct sockaddr);


	int fd = accept(unix_sock, (struct sockaddr *) &addr, &addr_size);

	if (fd < 0) {
		dbg_sys(DBGT_ERR, "can't accept unix client: %s", strerror(errno));
		return;
	}

	// make unix socket non blocking:
	// int32_t unix_opts = fcntl(fd, F_GETFL, 0);
	// fcntl( fd, F_SETFL, unix_opts | O_NONBLOCK );

	create_ctrl_node(fd, NULL, YES);

	change_selects();

	dbgf_all(DBGT_INFO, "got unix control connection via fd=%d", fd);

}

void handle_ctrl_node(struct ctrl_node *cn)
{
	char buff[MAX_UNIX_MSG_SIZE + 1];

	if (cn->cn_fd_handler) {
		(cn->cn_fd_handler) (cn);
		return;
	}

	errno = 0;
	int input = read(cn->fd, buff, MAX_UNIX_MSG_SIZE);

	buff[input] = '\0';

	if (input > 0 && input < MAX_UNIX_MSG_SIZE) {

		dbgf_all(DBGT_INFO, "rcvd ctrl stream via fd %d, %d bytes, auth %d: %s",
			cn->fd, input, cn->authorized, buff);

		if (validate_char_string(buff, input) != SUCCESS ||
			(apply_stream_opts(buff, OPT_CHECK, NO/*no cfg by default*/, cn) == FAILURE) ||
			(apply_stream_opts(buff, OPT_APPLY, NO/*no cfg by default*/, cn) == FAILURE)) {

			dbg_sys(DBGT_ERR, "invalid ctrl stream via fd %d, %d bytes, auth %d: %s",
				cn->fd, input, cn->authorized, buff);

			close_ctrl_node(CTRL_CLOSE_ERROR, cn);
			return;
		}

		respect_opt_order(OPT_APPLY, 0, 99, NULL, NO/*load_cofig*/, OPT_POST, 0/*probably closed*/);

		cb_plugin_hooks(PLUGIN_CB_CONF, NULL);

	} else {

		close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);

		//leaving this after close_ctrl_node() -> remove_dbgl_node() prevents debugging via broken -d4 pipe
		dbgf_all(DBGT_INFO, "closed fd %d, rcvd %d bytes, auth %d: %s",
			cn->fd, input, cn->authorized, buff);

	}

	return;
}


#ifndef TEST_DEBUG

// returns DBG_HIST_NEW, DBG_HIST_MUTING, or  DBG_HIST_MUTED

STATIC_FUNC
uint8_t check_dbg_history(int8_t dbgl, char *s, uint16_t check_len)
{

	static int r = 0;
	int i, unused_i, h;

	check_len = XMIN(check_len, DBG_HIST_TEXT_SIZE);

	if (!strlen(s) || !dbg_mute_to || !check_len)
		return DBG_HIST_NEW;

	if (dbgl == DBGL_SYS)
		h = 0;

	else if (dbgl == DBGL_CHANGES)
		h = 1;

	else
		return DBG_HIST_NEW;


	unused_i = -1;
	i = r = (r + 1) % DBG_HIST_SIZE;

	do {

		if (dbgl_history[h][i].check_len == check_len &&
			dbgl_history[h][i].expire == dbg_mute_to &&
			!memcmp(s, dbgl_history[h][i].text, XMIN(check_len, strlen(s)))) {

			if (U32_LT(bmx_time, dbgl_history[h][i].print_stamp + dbg_mute_to) &&
				U32_GE(bmx_time, dbgl_history[h][i].print_stamp)) {

				dbgl_history[h][i].catched++;

				if (dbgl_history[h][i].catched == 2)
					return DBG_HIST_MUTING;

				else
					return DBG_HIST_MUTED;

			}

			dbgl_history[h][i].print_stamp = bmx_time;
			dbgl_history[h][i].catched = 1;
			return DBG_HIST_NEW;

		}

		if (unused_i == -1 &&
			(dbgl_history[h][i].catched == 0 ||
			!(U32_LT(bmx_time, dbgl_history[h][i].print_stamp + dbg_mute_to) &&
			U32_GE(bmx_time, dbgl_history[h][i].print_stamp)))) {

			unused_i = i;
		}


		i = ((i + 1) % DBG_HIST_SIZE);

	} while (i != r);

	if (unused_i == -1)
		unused_i = r;

	dbgl_history[h][unused_i].expire = dbg_mute_to;
	dbgl_history[h][unused_i].check_len = check_len;
	dbgl_history[h][unused_i].print_stamp = bmx_time;
	dbgl_history[h][unused_i].catched = 1;
	memcpy(dbgl_history[h][unused_i].text, s, XMIN(check_len, strlen(s)));

	return DBG_HIST_NEW;
}

STATIC_FUNC
void debug_output(uint32_t check_len, struct ctrl_node *cn, int8_t dbgl, int8_t dbgt, const char *f, char *s)
{

	static uint16_t dbgl_all_msg_num = 0;
	static char *dbgt2str[] = { "", "INFO  ", "WARN  ", "ERROR " };

	struct list_node *list_pos;
	int16_t dbgl_out[DBGL_MAX + 1];
	int i = 0, j;

	uint8_t mute_dbgl_sys = DBG_HIST_NEW;
	uint8_t mute_dbgl_changes = DBG_HIST_NEW;


	if (cn && cn->fd != STDOUT_FILENO)
		dbg_printf(cn, "%s%s: %s\n", dbgt2str[dbgt], f ? f : "", s);


	if (!debug_system_active) {

		if (dbgl == DBGL_SYS || debug_level == DBGL_ALL || debug_level == dbgl)
			printf("[%d %8u] %s%s: %s\n", My_pid, bmx_time, dbgt2str[dbgt], f ? f : "", s);

		if ((dbg_syslog || initializing || terminating) && dbgl == DBGL_SYS)
			syslog(LOG_ERR, "%s%s: %s\n", dbgt2str[dbgt], f ? f : "", s);

		return;
	}


	if (dbgl == DBGL_ALL) {

		if (!LIST_EMPTY(&dbgl_clients[DBGL_ALL ])) dbgl_out[i++] = DBGL_ALL;

	} else if (dbgl == DBGL_CHANGES) {

		if (!LIST_EMPTY(&dbgl_clients[DBGL_CHANGES ])) dbgl_out[i++] = DBGL_CHANGES;
		if (!LIST_EMPTY(&dbgl_clients[DBGL_ALL ])) dbgl_out[i++] = DBGL_ALL;

	} else if (dbgl == DBGL_TEST) {

		if (!LIST_EMPTY(&dbgl_clients[DBGL_TEST ])) dbgl_out[i++] = DBGL_TEST;
		if (!LIST_EMPTY(&dbgl_clients[DBGL_ALL ])) dbgl_out[i++] = DBGL_ALL;

	} else if (dbgl == DBGL_DUMP) {

		if (!LIST_EMPTY(&dbgl_clients[DBGL_DUMP ])) dbgl_out[i++] = DBGL_DUMP;
		if (!LIST_EMPTY(&dbgl_clients[DBGL_ALL ])) dbgl_out[i++] = DBGL_ALL;

	} else if (dbgl == DBGL_PROFILE) {

		if (!LIST_EMPTY(&dbgl_clients[DBGL_PROFILE ])) dbgl_out[i++] = DBGL_PROFILE;

	} else if (dbgl == DBGL_SYS) {

		if (!LIST_EMPTY(&dbgl_clients[DBGL_SYS ])) dbgl_out[i++] = DBGL_SYS;
		if (!LIST_EMPTY(&dbgl_clients[DBGL_CHANGES ])) dbgl_out[i++] = DBGL_CHANGES;
		if (!LIST_EMPTY(&dbgl_clients[DBGL_ALL ])) dbgl_out[i++] = DBGL_ALL;

		if (check_len)
			mute_dbgl_sys = check_dbg_history(DBGL_SYS, s, check_len);

		if (dbg_syslog || initializing || terminating) {
			if (mute_dbgl_sys != DBG_HIST_MUTED)
				syslog(LOG_ERR, "%s%s%s%s\n", dbgt2str[dbgt], f ? f : "", f ? "(): " : "", s);

			if (mute_dbgl_sys == DBG_HIST_MUTING)
				syslog(LOG_ERR, "%smuting further messages (with equal first %d bytes) for at most %d seconds\n",
				dbgt2str[DBGT_WARN], check_len, dbg_mute_to / 1000);
		}
	}

	dbgl_all_msg_num++;

	for (j = 0; j < i; j++) {

		int level = dbgl_out[j];

		/*// enable to mute in DBLG_CHANGES...
		if ( level == DBGL_CHANGES  &&  check_len  && 
		     (mute_dbgl_changes = check_dbg_history( DBGL_CHANGES, s, check_len )) == DBG_HIST_MUTED )
			continue;
		 */
		if (level == DBGL_SYS && mute_dbgl_sys == DBG_HIST_MUTED)
			continue;

		list_for_each(list_pos, /*(struct list_head *)*/&(dbgl_clients[level]))
		{

			struct dbgl_node *dn = list_entry(list_pos, struct dbgl_node, list);

			if (!dn->cn || dn->cn->fd <= 0)
				continue;

			if (level == DBGL_CHANGES ||
				level == DBGL_TEST ||
				level == DBGL_DUMP ||
				level == DBGL_PROFILE ||
				level == DBGL_SYS ||
				level == DBGL_ALL)
				dbg_printf(dn->cn, "[%d %8u %5u] ", My_pid, bmx_time, dbgl_all_msg_num);


			dbg_printf(dn->cn, "%s%s: %s\n", dbgt2str[dbgt], f ? f : "", s);

			if ((level == DBGL_SYS && mute_dbgl_sys == DBG_HIST_MUTING) ||
				(level == DBGL_CHANGES && mute_dbgl_changes == DBG_HIST_MUTING))
				dbg_printf(dn->cn,
				"[%d %8u] %smuting further messages (with equal first %d bytes) for at most %d seconds\n",
				My_pid, bmx_time, dbgt2str[DBGT_WARN], check_len, dbg_mute_to / 1000);

		}
	}
}



// this static array of char is used by all following dbg functions.
static char dbg_string_out[ MAX_DBG_STR_SIZE + 1 ];

void dbg(int8_t dbgl, int8_t dbgt, char *last, ...)
{
	va_list ap;
	va_start(ap, last);
	vsnprintf(dbg_string_out, MAX_DBG_STR_SIZE, last, ap);
	va_end(ap);
	debug_output(0, 0, dbgl, dbgt, 0, dbg_string_out);
}

void _dbgf(int8_t dbgl, int8_t dbgt, const char *f, char *last, ...)
{
	va_list ap;
	va_start(ap, last);
	vsnprintf(dbg_string_out, MAX_DBG_STR_SIZE, last, ap);
	va_end(ap);
	debug_output(0, 0, dbgl, dbgt, f, dbg_string_out);
}

void dbg_cn(struct ctrl_node *cn, int8_t dbgl, int8_t dbgt, char *last, ...)
{
	va_list ap;
	va_start(ap, last);
	vsnprintf(dbg_string_out, MAX_DBG_STR_SIZE, last, ap);
	va_end(ap);
	debug_output(0, cn, dbgl, dbgt, 0, dbg_string_out);
}

void _dbgf_cn(struct ctrl_node *cn, int8_t dbgl, int8_t dbgt, const char *f, char *last, ...)
{
	va_list ap;
	va_start(ap, last);
	vsnprintf(dbg_string_out, MAX_DBG_STR_SIZE, last, ap);
	va_end(ap);
	debug_output(0, cn, dbgl, dbgt, f, dbg_string_out);
}

void dbg_mute(uint32_t check_len, int8_t dbgl, int8_t dbgt, char *last, ...)
{
	va_list ap;
	va_start(ap, last);
	vsnprintf(dbg_string_out, MAX_DBG_STR_SIZE, last, ap);
	va_end(ap);
	debug_output(check_len, 0, dbgl, dbgt, 0, dbg_string_out);
}

void _dbgf_mute(uint32_t check_len, int8_t dbgl, int8_t dbgt, const char *f, char *last, ...)
{
	va_list ap;
	va_start(ap, last);
	vsnprintf(dbg_string_out, MAX_DBG_STR_SIZE, last, ap);
	va_end(ap);
	debug_output(check_len, 0, dbgl, dbgt, f, dbg_string_out);
}

void _dbgf_all(int8_t dbgt, const char *f, char *last, ...)
{
	va_list ap;
	va_start(ap, last);
	vsnprintf(dbg_string_out, MAX_DBG_STR_SIZE, last, ap);
	va_end(ap);
	debug_output(0, 0, DBGL_ALL, dbgt, f, dbg_string_out);
}

void dbg_spaces(struct ctrl_node *cn, uint16_t spaces)
{
	uint16_t i;
	for (i = 0; i < spaces; i++)
		dbg_printf(cn, " ");

}

void dbg_printf(struct ctrl_node *cn, char *last, ...)
{
#define MAX_DBG_WRITES 4

	if (!cn || cn->fd <= 0)
		return;

	/*
	static char s[ MAX_DBG_STR_SIZE + 1 ];
	ssize_t w, out = 0;
	int tries = 1;

	 */

	errno = 0;

	va_list ap;
	va_start(ap, last);
	//        vsnprintf(s, MAX_DBG_STR_SIZE, last, ap);

	if (vdprintf(cn->fd, last, ap) < 0) {
		int err = errno;
		wait_sec_usec(0, 100000);
		dprintf(cn->fd, "\nERROR: %s !\n", strerror(err));
	}

	va_end(ap);

	/*

	// CONNECTION_END_CHR is reserved for signaling connection end
	assertion(-500146, (!strchr(s, CONNECTION_END_CHR)));

	errno = 0;

	while ((w = write(cn->fd, s + out, strlen(s + out))) != (ssize_t) strlen(s + out)) {

		if (errno == EPIPE || tries >= MAX_DBG_WRITES || cn->dbgl == DBGL_ALL) {

			if (cn->dbgl != DBGL_ALL) {
				syslog(LOG_ERR, "failed %d times writing %d instead of %d/%d bytes (%s)! Giving up: %s\n",
					tries, (int) w, (int) strlen(s + out), (int) strlen(s), strerror(errno), s + out);
			}

			break;
		}
		tries++;

		wait_sec_msec(0, 10000);

		if (w > 0)
			out += w;

		errno = 0;
	}
	 */
}

#endif

uint8_t __dbgf_all(void)
{

	if (debug_level != DBGL_ALL && LIST_EMPTY(&dbgl_clients[DBGL_ALL]))
		return NO;

	return YES;
}

uint8_t __dbgf_track(void)
{

	if (debug_level != DBGL_CHANGES && LIST_EMPTY(&dbgl_clients[DBGL_CHANGES]) &&
		debug_level != DBGL_ALL && LIST_EMPTY(&dbgl_clients[DBGL_ALL]))
		return NO;

	return YES;
}

uint8_t __dbgf(uint8_t level)
{

	switch (level) {
	case DBGL_SYS:
		return YES;
	case DBGL_CHANGES:
	{
		if (debug_level == DBGL_CHANGES || !LIST_EMPTY(&dbgl_clients[DBGL_CHANGES]))
			return YES;
		break;
	}
	case DBGL_DUMP:
	{
		if (debug_level == DBGL_DUMP || !LIST_EMPTY(&dbgl_clients[DBGL_DUMP]))
			return YES;
		break;
	}
	case DBGL_ALL:
		if (debug_level == DBGL_ALL || !LIST_EMPTY(&dbgl_clients[DBGL_ALL]))
			return YES;
	}

	return NO;
}





int (*load_config_cb) (uint8_t test, struct opt_type *opt, struct ctrl_node *cn) = NULL;

int (*save_config_cb) (uint8_t del, struct opt_type *opt, char *parent, char *val, struct ctrl_node *cn) = NULL;

int (*derive_config) (char *reference, char *derivation, struct ctrl_node *cn) = NULL;

void get_init_string(int g_argc, char **g_argv)
{

	uint32_t size = 1, dbg_init_out = 0;
	int i;
	char *dbg_init_str;

	for (i = 0; i < g_argc; i++)
		size += (1 + strlen(g_argv[i]));

	dbg_init_str = debugMalloc(size, -300012);

	for (i = 0; i < g_argc; i++)
		dbg_init_out = dbg_init_out + sprintf((dbg_init_str + dbg_init_out), "%s ", g_argv[i]);

	init_string = dbg_init_str;
}

STATIC_FUNC
void free_init_string(void)
{

	if (init_string)
		debugFree(init_string, -300052);

	init_string = NULL;
}

STATIC_FUNC
char* nextword(char *s)
{

	uint32_t i = 0;
	uint8_t found_gap = NO;

	if (!s)
		return NULL;

	for (i = 0; i < strlen(s); i++) {

		if (s[i] == '\0' || s[i] == '\n')
			return NULL;

		if (!found_gap && (s[i] == ' ' || s[i] == '\t'))
			found_gap = YES;

		if (found_gap && (s[i] != ' ' && s[i] != '\t'))
			return &(s[i]);

	}

	return NULL;

}

STATIC_FUNC
char *debugWordDup(char* word, int32_t tag)
{

	if (!word)
		return NULL;

	char *ret = debugMalloc(wordlen(word) + 1, tag);
	snprintf(ret, wordlen(word) + 1, "%s", word);
	return ret;
}

STATIC_FUNC
void strchange(char *s, char i, char o)
{

	char *p;
	while (s && (p = strchr(s, i)))
		p[0] = o;

}

STATIC_FUNC
int32_t is_end_of_cmd_stream(struct opt_type *opt, char *s)
{

	char test[MAX_ARG_SIZE] = "";
	snprintf(test, wordlen(s) + 1, "%s", s);
	strchange(test, '-', '_');

	if (opt->opt_t != A_PS0)
		s = nextword(s);
	else if (wordlen(s) > 1 && !strncasecmp(test, opt->name, wordlen(opt->name)))
		s = nextword(s);
	else if (wordlen(s) > 1)
		s = s + 1;
	else
		s = nextword(s);

	if (s && (s[0] != CHR_QUIT || wordlen(s) > 1))
		return NO;

	return YES;

}

STATIC_FUNC
int8_t is_valid_opt_ival(struct opt_type *opt, char *s, struct ctrl_node *cn)
{

	if (opt->imin == opt->imax)
		return SUCCESS;

	char* invalids = NULL;

	errno = 0;
	int ival = strtol(s, &invalids, 10);
	int err = errno;

	if (wordlen(s) < 1 ||
		ival < opt->imin || ival > opt->imax ||
		invalids != (s + wordlen(s)) ||
		err == ERANGE || err == EINVAL) {

		dbg_cn(cn, DBGL_SYS, DBGT_ERR, "--%s value %d is invalid! Must be %d <= <value> <= %d !",
			opt->name, ival, opt->imin, opt->imax);

		return FAILURE;
	}

	return SUCCESS;
}

STATIC_FUNC
void register_option(struct opt_type *opt, const char * category_name)
{

	dbgf_all(DBGT_INFO, "%s", (opt && opt->name) ? opt->name : "");

	struct opt_type *tmp_opt = NULL;
	struct list_node *tmp_pos;

	assertion(-501227, (opt->name));

	assertion_dbg(-501267,
		!get_option((opt->parent_name ? get_option(NULL, NO, opt->parent_name) : NULL), NO, opt->name),
		"%s", opt->name);
	assertion_dbg(-501268, IMPLIES(opt->short_name,
		!get_option((opt->parent_name ? get_option(NULL, NO, opt->parent_name) : NULL), YES, &opt->short_name)),
		"%s", opt->name);

	// arg_t A_PS0 with no function can only be YES/NO:
	assertion(-500111, IMPLIES(opt->opt_t == A_PS0 && opt->ival, opt->imin == NO && opt->imax == YES && opt->idef == NO));
	assertion(-501228, IMPLIES(opt->opt_t == A_PS0N, !opt->ival && !opt->imin && !opt->imax && !opt->idef));

	// arg_t A_PS0 can not be stored
	assertion(-500112, IMPLIES(opt->opt_t == A_PS0 || opt->opt_t == A_PS0N, opt->cfg_t == A_ARG));

	assertion(-500113, (opt->order >= 0 || opt->order <= 99));

	assertion(-501229, IMPLIES(opt->parent_name, !strchr(opt->parent_name, '-')));
	assertion(-501230, IMPLIES(opt->name, !strchr(opt->name, '-')));

	//        assertion(-501367, (opt->order != 5));


	// these are the valid combinations:
	if (!(
		//ival is validated and if valid assigned by call_option()
		((opt->ival) && (opt->call_custom_option) && (opt->name)) ||
		//ival is validated and if valid assigned
		((opt->ival) && !(opt->call_custom_option) && (opt->name)) ||
		//call_option() is called
		(!(opt->ival) && (opt->call_custom_option) && (opt->name)) ||
		//
		(!(opt->ival) && !(opt->call_custom_option) && !(opt->name) && opt->help)
		))
		goto failure;


	memset(&(opt->d), 0, sizeof( struct opt_data));

	opt->d.category_name = category_name;

	if (opt->ival)
		*opt->ival = opt->idef;

	if (opt->parent_name) {

		list_for_each(tmp_pos, &opt_list)
		{
			tmp_opt = (struct opt_type *) list_entry(tmp_pos, struct opt_data, list);

			if (tmp_opt->name == opt->parent_name)
				break;
			else
				tmp_opt = NULL;
		}

		if (opt->opt_t != A_CS1 || !tmp_opt || (tmp_opt->opt_t != A_PS0N && tmp_opt->opt_t != A_PS1N && tmp_opt->opt_t != A_PM1N))
			goto failure;

		opt->d.parent_opt = tmp_opt;

		list_add_tail(&tmp_opt->d.childs_type_list, &opt->d.list);

	} else {

		LIST_INIT_HEAD(opt->d.childs_type_list, struct opt_data, list, list);
		LIST_INIT_HEAD(opt->d.parents_instance_list, struct opt_parent, list, list);

		if (opt->order) {

			struct list_node *prev_pos = (struct list_node *) &opt_list;

			list_for_each(tmp_pos, &opt_list)
			{

				tmp_opt = (struct opt_type *) list_entry(tmp_pos, struct opt_data, list);

				if (tmp_opt->order > opt->order) {
					list_add_after(&opt_list, prev_pos, &opt->d.list);
					break;
				} else {
					prev_pos = &tmp_opt->d.list;
					tmp_opt = NULL;
				}
			}
		}

		if (!tmp_opt)
			list_add_tail(&opt_list, &opt->d.list);

	}

	if (opt->call_custom_option && ((opt->call_custom_option)(OPT_REGISTER, 0, opt, 0, 0)) == FAILURE) {

		dbgf_sys(DBGT_ERR, "%s failed!", opt->name);
		goto failure;
	}


	return;

failure:

	dbgf_sys(DBGT_ERR, "invalid data,  tmp_opt: %c %s  - option %c %s",
		(tmp_opt && tmp_opt->short_name) ? tmp_opt->short_name : '?',
		(tmp_opt && tmp_opt->name) ? tmp_opt->name : "??",
		(opt && opt->short_name) ? opt->short_name : '?', (opt && opt->name) ? opt->name : "??");

	assertion(-500091, NO);
}

STATIC_FUNC
void remove_option(struct opt_type *opt)
{

	struct list_node *tmp_pos, *list_pos, *prev_pos;

	del_opt_parent(opt, NULL);

	prev_pos = (struct list_node *) &opt_list;

	list_for_each_safe(list_pos, tmp_pos, &opt_list)
	{

		struct opt_type *tmp_opt = (struct opt_type *) list_entry(list_pos, struct opt_data, list);

		if (opt == tmp_opt) {

			if (!opt->parent_name && opt->call_custom_option &&
				((opt->call_custom_option)(OPT_UNREGISTER, 0, opt, 0, 0)) == FAILURE) {
				dbgf_sys(DBGT_ERR, "%s failed!", opt->name);
			}

			list_del_next(&opt_list, prev_pos);
			return;

		} else {

			prev_pos = &tmp_opt->d.list;

		}

	}

	dbgf_sys(DBGT_ERR, "%s no matching opt found", opt->name);
}

void register_options_array(struct opt_type *fixed_options, int size, const char *category_name)
{

	int i = 0;
	int i_max = size / sizeof( struct opt_type);

	assertion(-500149, ((size % sizeof( struct opt_type)) == 0));

	while (i < i_max && (fixed_options[i].name || fixed_options[i].help))
		register_option(&(fixed_options[i++]), category_name);

}

struct opt_type *get_option(struct opt_type *parent_opt, uint8_t short_opt, char *sin)
{

	struct list_node *list_pos;
	int32_t len = 0;
	struct list_head *list;
	struct opt_type *opt = NULL;
	char *equalp = NULL;
	char s[MAX_ARG_SIZE] = "";

	if (parent_opt && short_opt)
		goto get_option_failure;

	if (!sin || wordlen(sin) + 1 >= MAX_ARG_SIZE)
		goto get_option_failure;

	snprintf(s, wordlen(sin) + 1, "%s", sin);
	strchange(s, '-', '_');

	if (short_opt)
		len = 1;
	else if ((equalp = index(s, '=')) && equalp < s + wordlen(s))
		len = equalp - s;
	else
		len = wordlen(s);


	if (parent_opt == NULL)
		list = &opt_list;
	else
		list = &parent_opt->d.childs_type_list;

	dbgf_all(DBGT_INFO, "searching %s", s);

	list_for_each(list_pos, list)
	{

		opt = (struct opt_type *) list_entry(list_pos, struct opt_data, list);

		if (!opt->name)
			continue;

		else if (!short_opt && len == (int) strlen(opt->name) && !strncasecmp(s, opt->name, len))
			break;

		else if (!short_opt && len == 1 && s[0] == opt->short_name)
			break;

		else if (short_opt && s[0] == opt->short_name)
			break;

		opt = NULL;
	}

	if (opt && opt->name) {
		dbgf_all(DBGT_INFO,
			"Success! short_opt %d, opt: %s %c, type %d, dyn %d, ival %d, imin %d, imax %d, idef %d",
			short_opt, opt->name ? opt->name : "-", opt->short_name ? opt->short_name : '-',
			opt->opt_t, opt->dyn_t,
			opt->ival ? *opt->ival : 0, opt->imin, opt->imax, opt->idef);

		return opt;
	}


get_option_failure:

	dbgf_all(DBGT_WARN, "Failed! called with parent %s, opt %c %s, len %d",
		parent_opt ? "YES" : "NO", (short_opt ? s[0] : '-'), (!short_opt ? s : "-"), len);

	return NULL;

}

struct opt_child *get_opt_child(struct opt_type *opt, struct opt_parent *p)
{

	struct list_node *pos;

	assertion(-500026, (opt->opt_t == A_CS1));
	assertion(-500119, (p));

	list_for_each(pos, &(p->childs_instance_list))
	{

		struct opt_child *c = list_entry(pos, struct opt_child, list);

		if (c->opt == opt)
			return c;

	}

	return NULL;
}

int32_t get_opt_child_val_int(struct opt_type *parentOpt, struct opt_parent *patch, char *optName, int32_t dflt)
{
	struct opt_child *c = NULL;
	struct list_node *pos;

	while (patch->diff != DEL && (c = list_iterate(&patch->childs_instance_list, c))) {

		if ((!strcmp(c->opt->name, optName)) && c->val)
			return strtol(c->val, NULL, 10);
	}

	list_for_each(pos, &parentOpt->d.childs_type_list)
	{

		struct opt_type *c_opt = (struct opt_type *) list_entry(pos, struct opt_data, list);

		if (!strcmp(c_opt->name, optName))
			return c_opt->idef;
	}
	assertion(-502772, (dflt > FAILURE));
	return dflt;
}

char * get_opt_child_val_str(struct opt_type *parentOpt, struct opt_parent *patch, char *optName, char *dflt)
{
	struct opt_child *c = NULL;
	struct list_node *pos;

	while (patch->diff != DEL && (c = list_iterate(&patch->childs_instance_list, c))) {

		if ((!strcmp(c->opt->name, optName)) && c->val)
			return c->val;
	}

	list_for_each(pos, &parentOpt->d.childs_type_list)
	{

		struct opt_type *c_opt = (struct opt_type *) list_entry(pos, struct opt_data, list);

		if (!strcmp(c_opt->name, optName))
			return c_opt->sdef;
	}

	assertion(-502773, (dflt != FAILURE_PTR));
	return dflt;
}

void set_opt_child_val(struct opt_child *c, char *val)
{

	if (val && c->val && wordsEqual(c->val, val))
		return;

	if (c->val)
		debugFree(c->val, -300053);

	c->val = NULL;

	if (val)
		c->val = debugWordDup(val, -300013);
}

STATIC_FUNC
void set_opt_child_ref(struct opt_child *c, char *ref)
{

	if (ref && c->ref && wordsEqual(c->ref, ref))
		return;

	if (c->ref)
		debugFree(c->ref, -300054);

	c->ref = NULL;

	if (ref)
		c->ref = debugWordDup(ref, -300014);
}

STATIC_FUNC
void del_opt_child_save(struct list_node *prev, struct list_node *pos, struct opt_parent *p)
{

	struct opt_child *c = list_entry(pos, struct opt_child, list);

	list_del_next(&p->childs_instance_list, prev);

	set_opt_child_val(c, NULL);
	set_opt_child_ref(c, NULL);

	debugFree(pos, -300055);
	return;
}

STATIC_FUNC
void del_opt_child(struct opt_parent *p, struct opt_type *opt)
{

	struct list_node *pos, *tmp, *prev;

	prev = (struct list_node*) &p->childs_instance_list;

	list_for_each_safe(pos, tmp, &(p->childs_instance_list))
	{

		struct opt_child *c = list_entry(pos, struct opt_child, list);

		if (!opt || c->opt == opt)
			del_opt_child_save(prev, pos, p);
		else
			prev = pos;
	}
}

STATIC_FUNC
struct opt_child *add_opt_child(struct opt_type *opt, struct opt_parent *p)
{

	struct opt_child *c = debugMallocReset(sizeof( struct opt_child), -300017);

	c->opt = opt;
	c->parent_instance = p;
	list_add_tail(&p->childs_instance_list, &c->list);

	return c;
}

void set_opt_parent_val(struct opt_parent *p, char *val)
{

	if (val && p->val && wordsEqual(p->val, val))
		return;

	if (p->val)
		debugFree(p->val, -300056);

	p->val = NULL;

	if (val)
		p->val = debugWordDup(val, -300015);
}

void set_opt_parent_ref(struct opt_parent *p, char *ref)
{

	if (ref && p->ref && wordsEqual(p->ref, ref))
		return;

	if (p->ref)
		debugFree(p->ref, -300057);

	p->ref = NULL;

	if (ref)
		p->ref = debugWordDup(ref, -300016);
}

struct opt_parent *add_opt_parent(struct opt_type *opt)
{

	struct opt_parent *p = debugMallocReset(sizeof( struct opt_parent), -300018);

	LIST_INIT_HEAD(p->childs_instance_list, struct opt_child, list, list);

	list_add_tail(&opt->d.parents_instance_list, &p->list);

	return p;
}

STATIC_FUNC
void del_opt_parent_save(struct opt_type *opt, struct list_node *prev, struct list_node *pos)
{

	struct opt_parent *p = list_entry(pos, struct opt_parent, list);

	list_del_next(&opt->d.parents_instance_list, prev);

	del_opt_child(p, NULL);

	set_opt_parent_val(p, NULL);
	set_opt_parent_ref(p, NULL);

	debugFree(p, -300058);
}

void del_opt_parent(struct opt_type *opt, struct opt_parent *parent)
{

	struct list_node *pos, *tmp, *prev = (struct list_node*) &(opt->d.parents_instance_list);

	list_for_each_safe(pos, tmp, &(opt->d.parents_instance_list))
	{

		struct opt_parent *p = list_entry(pos, struct opt_parent, list);

		if (!parent || p == parent)
			del_opt_parent_save(opt, prev, pos);
		else
			prev = pos;
	}
}

struct opt_parent *get_opt_parent_val(struct opt_type *opt, char *val)
{

	struct opt_parent *p = NULL;
	struct list_node *pos;

	assertion(-500118, (opt->cfg_t != A_ARG));
	assertion(-500117, ((opt->opt_t != A_PS0 && opt->opt_t != A_PS1) || opt->d.parents_instance_list.items <= 1));

	list_for_each(pos, &(opt->d.parents_instance_list))
	{

		p = list_entry(pos, struct opt_parent, list);

		if (!val || wordsEqual(p->val, val))
			return p;

	}

	return NULL;
}

struct opt_parent *get_opt_parent_ref(struct opt_type *opt, char *ref)
{

	struct opt_parent *p = NULL;
	struct list_node *pos;

	assertion(-500124, (opt->cfg_t != A_ARG));
	assertion(-500116, ((opt->opt_t != A_PS0 && opt->opt_t != A_PS1) || opt->d.parents_instance_list.items <= 1));

	list_for_each(pos, &(opt->d.parents_instance_list))
	{
		p = list_entry(pos, struct opt_parent, list);

		if (ref && wordsEqual(p->ref, ref))
			return p;
	}

	return NULL;
}

STATIC_FUNC
struct opt_parent *dup_opt_parent(struct opt_type *opt, struct opt_parent *p)
{

	struct opt_parent *dup_p = add_opt_parent(opt);
	set_opt_parent_val(dup_p, p->val);
	set_opt_parent_ref(dup_p, p->ref);

	dup_p->diff = p->diff;

	struct list_node *pos;

	list_for_each(pos, &(p->childs_instance_list))
	{

		struct opt_child *c = list_entry(pos, struct opt_child, list);

		struct opt_child *dup_c = add_opt_child(c->opt, dup_p);
		set_opt_child_val(dup_c, c->val);
		set_opt_child_ref(dup_c, c->ref);
	}

	return dup_p;
}




char *opt_cmd2str[] = {
	"OPT_REGISTER",
	"OPT_PATCH",
	"OPT_ADJUST",
	"OPT_CHECK",
	"OPT_APPLY",
	"OPT_SET_POST",
	"OPT_POST",
	"OPT_UNREGISTER"
};

int32_t check_apply_parent_option(uint8_t del, uint8_t cmd, uint8_t _save, struct opt_type *opt, char *in, struct ctrl_node *cn)
{

	int32_t ret;

	assertion(-500102, !IMPLIES((cmd == OPT_CHECK || cmd == OPT_APPLY), opt && opt->parent_name));

	struct opt_parent *p = add_opt_parent(&Patch_opt);

	if ((ret = call_option(del, OPT_PATCH, _save, opt, p, in, cn)) == FAILURE ||
		call_option(del, OPT_ADJUST, _save, opt, p, in, cn) == FAILURE ||
		call_option(del, cmd, _save, opt, p, in, cn) == FAILURE)
		ret = FAILURE;

	del_opt_parent(&Patch_opt, p);

	dbgf_all(DBGT_INFO, "del:%d, %s, save:%d, %s %s returns: %d",
		del, opt_cmd2str[cmd], _save, opt->name, in, ret);

	return ret;
}

STATIC_FUNC
int32_t call_opt_patch(uint8_t ad, struct opt_type *opt, struct opt_parent *patch, char *strm, struct ctrl_node *cn)
{

	dbgf_all(DBGT_INFO, "ad:%d opt:%s val:%s strm:%s",
		ad, opt->name, patch->val, strm);

	if (opt->opt_t == A_PS0 || opt->opt_t == A_PS0N) {

		patch->diff = ((ad == ADD) ? ADD : DEL);

	} else if (opt->opt_t == A_PS1 || opt->opt_t == A_PS1N || opt->opt_t == A_PM1N || opt->opt_t == A_CS1) {

		char *ref = NULL;
		char tmp[MAX_ARG_SIZE];

		// assign one or more values
		if (ad == ADD || opt->opt_t == A_PS1N || opt->opt_t == A_PM1N) {

			if (!strm || !wordlen(strm) || strm[0] == CHR_QUIT)
				return FAILURE;

			if (strm && wordlen(strm) > strlen(REFERENCE_KEY_WORD) &&
				!strncmp(strm, REFERENCE_KEY_WORD, strlen(REFERENCE_KEY_WORD))) {
				ref = strm;

				if (ad == ADD) {

					if (!derive_config || derive_config(ref, tmp, cn) == FAILURE || !wordlen(strm)) {
						dbg_cn(cn, DBGL_SYS, DBGT_ERR,
							"%s. Could not derive reference %s",
							derive_config ? "invalid config" : "undefined callback", strm);
						return FAILURE;
					}

					strm = tmp;

				} else if (ad == DEL) {

					struct opt_parent *p_track = get_opt_parent_ref(opt, strm);

					if (!p_track || !p_track->val) {
						dbg_cn(cn, DBGL_SYS, DBGT_ERR,
							"Could not derive reference %s from tracked options", strm);
						return FAILURE;
					}

					strm = p_track->val;
				}
			}

			if (is_valid_opt_ival(opt, strm, cn) == FAILURE)
				return FAILURE;

		}

		if (opt->opt_t == A_PS1 || opt->opt_t == A_PS1N || opt->opt_t == A_PM1N) {

			set_opt_parent_val(patch, strm);
			set_opt_parent_ref(patch, ref);

			patch->diff = ((ad == ADD) ? ADD : DEL);

		} else if (opt->opt_t == A_CS1) {

			struct opt_child *c = add_opt_child(opt, patch);

			if (ad == ADD)
				set_opt_child_val(c, strm);

			set_opt_child_ref(c, ref);
		}
	}

	return SUCCESS;
}

STATIC_FUNC
int32_t cleanup_patch(struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	uint8_t del = patch->diff;
	char *val = patch->val;

	dbgf_all(DBGT_INFO, "del %d  opt %s  val %s", del, opt->name, val);

	if (opt->cfg_t == A_ARG)
		return SUCCESS;

	if (opt->opt_t == A_PS0) {

		if ((del && !opt->d.parents_instance_list.items) || (!del && opt->d.parents_instance_list.items))
			patch->diff = NOP;


	} else if (opt->opt_t == A_PS1) {

		if ((del && !opt->d.parents_instance_list.items) || (!del && get_opt_parent_val(opt, val)))
			patch->diff = NOP;


	} else if (opt->opt_t == A_PS0N || opt->opt_t == A_PS1N || opt->opt_t == A_PM1N) {

		struct opt_parent *p_track = NULL;
		struct list_node *c_pos, *c_tmp;
		struct list_node *c_prev = (struct list_node*) &patch->childs_instance_list;

		list_for_each_safe(c_pos, c_tmp, &patch->childs_instance_list)
		{

			struct opt_child *c = list_entry(c_pos, struct opt_child, list);
			struct opt_child *c_track = NULL;
			uint8_t c_del = c->val ? ADD : DEL;

			p_track = NULL;

			dbgf_all(DBGT_INFO, "p_val:%s", patch->val);

			if ((p_track = get_opt_parent_val(opt, val)))
				c_track = get_opt_child(c->opt, p_track);

			if ((c_del && !c_track) ||
				(!c_del && c_track && wordsEqual(c_track->val, c->val))) {
				del_opt_child_save(c_prev, c_pos, patch);
			} else {
				c_prev = c_pos;
			}
		}


		p_track = get_opt_parent_val(opt, val);

		if ((del && !p_track) || (!del && p_track))
			patch->diff = NOP;

	} else {
		return FAILURE;
	}

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_connect_client_to_daemon(uint8_t cmd, struct opt_type *opt, struct ctrl_node *cn, char *curr_strm_pos)
{

	char tmp_path[MAX_PATH_SIZE + 20] = "";
	char unix_buff[MAX_UNIX_MSG_SIZE + 1] = "";

	dbgf_all(DBGT_INFO, "cmd %s, opt_name %s, stream %s",
		opt_cmd2str[cmd], opt->name, curr_strm_pos);

	if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

		if (!curr_strm_pos)
			cleanup_all(-500141);

		sprintf(tmp_path, "%s/%s", run_dir, BMX_UNIX_SOCK_FILE);

		struct sockaddr_un unix_addr;

		memset(&unix_addr, 0, sizeof(struct sockaddr_un));
		unix_addr.sun_family = AF_LOCAL;
		strcpy(unix_addr.sun_path, tmp_path);


		if (strlen(curr_strm_pos) + 4 + strlen(ARG_TEST) > sizeof( unix_buff)) {

			dbg_sys(DBGT_ERR, "message too long: %s", curr_strm_pos);
			cleanup_all(CLEANUP_FAILURE);
		}

		if (cmd == OPT_CHECK)
			return SUCCESS;

		Client_mode = YES;

		do {

			dbgf_all(DBGT_INFO, "called with %s", curr_strm_pos);

			if (strlen(curr_strm_pos) > strlen(ARG_CONNECT) &&
				!strncmp(curr_strm_pos, ARG_CONNECT, strlen(ARG_CONNECT)) &&
				(curr_strm_pos + strlen(ARG_CONNECT))[0] == ' ') {

				sprintf(unix_buff, "%s %c", nextword(curr_strm_pos), CHR_QUIT);

			} else if (strlen(curr_strm_pos) > strlen(ARG_CONNECT) &&
				!strncmp(curr_strm_pos, ARG_CONNECT, strlen(ARG_CONNECT)) &&
				(curr_strm_pos + strlen(ARG_CONNECT))[0] == '=') {

				sprintf(unix_buff, "%s %c", curr_strm_pos + strlen(ARG_CONNECT) + 1, CHR_QUIT);

			} else if (strlen(curr_strm_pos) > 1 && curr_strm_pos[0] == opt->short_name && curr_strm_pos[1] == ' ') {

				sprintf(unix_buff, "%s %c", nextword(curr_strm_pos), CHR_QUIT);

			} else if (strlen(curr_strm_pos) > 1 && curr_strm_pos[0] == opt->short_name && curr_strm_pos[1] != ' ') {

				sprintf(unix_buff, "-%s %c", curr_strm_pos + 1, CHR_QUIT);

			} else {
				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid connect stream %s", curr_strm_pos);
				return FAILURE;
			}

			unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);

			/* make unix_sock socket non blocking */
			int sock_opts = fcntl(unix_sock, F_GETFL, 0);
			fcntl(unix_sock, F_SETFL, sock_opts | O_NONBLOCK);


			if (connect(unix_sock, (struct sockaddr *) &unix_addr, sizeof(struct sockaddr_un)) < 0) {

				dbg_sys(DBGT_ERR, "can't connect to unix socket '%s': %s ! Is bmx7 running on this host ?",
					tmp_path, strerror(errno));

				cleanup_all(CLEANUP_FAILURE);
			}

			if (write(unix_sock, unix_buff, strlen(unix_buff)) < 0) {
				dbg_sys(DBGT_ERR, "can't write to unix socket: %s", strerror(errno));
				cleanup_all(CLEANUP_FAILURE);
			}

			if (loop_mode) {
				if (system("clear") < 0) {
					dbgf_track(DBGT_WARN, "%s", strerror(errno));
				}
			}

			int32_t recv_buff_len = 0;

			while (!terminating) {

				recv_buff_len = 0;

				fd_set unix_wait_set;

				FD_ZERO(&unix_wait_set);
				FD_SET(unix_sock, &unix_wait_set);

				struct timeval to = { 0, 100000 };

				select(unix_sock + 1, &unix_wait_set, NULL, NULL, &to);

				if (!FD_ISSET(unix_sock, &unix_wait_set))
					continue;

				int err = 0;
				do {
					errno = 0;
					recv_buff_len = read(unix_sock, unix_buff, MAX_UNIX_MSG_SIZE);
					err = errno;

					if (recv_buff_len > 0) {
						char *p;
						unix_buff[recv_buff_len] = '\0';

						if ((p = strchr(unix_buff, CONNECTION_END_CHR))) {
							*p = '\0';

							//printf( "%s", unix_buff );
							if (write(STDOUT_FILENO, unix_buff, strlen(unix_buff)) < 0) {
								dbgf_track(DBGT_WARN, "%s", strerror(err));
							}
							break;

						}
						//printf( "%s", unix_buff );
						if (write(STDOUT_FILENO, unix_buff, strlen(unix_buff)) < 0) {
							dbgf_track(DBGT_WARN, "%s", strerror(err));
						}
					}

				} while (recv_buff_len > 0);

				if (recv_buff_len < 0 && (err == EWOULDBLOCK || err == EAGAIN))
					continue;

				if (recv_buff_len < 0) {
					dbgf_sys(DBGT_INFO, "sock returned %d errno %d: %s",
						recv_buff_len, err, strerror(err));
				}

				if (recv_buff_len <= 0)
					cleanup_all(CLEANUP_FAILURE);

				break;
			}

			close(unix_sock);
			unix_sock = 0;

			if (loop_mode && !terminating)
				wait_sec_usec(loop_interval / 1000, (loop_interval * 1000) % 1000000);


		} while (loop_mode && !terminating);

		cleanup_all(CLEANUP_SUCCESS);


	}

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_connect_daemon_to_unix_sock(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	char tmp_path[MAX_PATH_SIZE + 20] = "";

	if (cmd == OPT_SET_POST && initializing) {

		// create unix sock:

		struct sockaddr_un unix_addr;

		sprintf(tmp_path, "%s/%s", run_dir, BMX_UNIX_SOCK_FILE);


		memset(&unix_addr, 0, sizeof(struct sockaddr_un));
		unix_addr.sun_family = AF_LOCAL;
		strcpy(unix_addr.sun_path, tmp_path);

		// Testing for open and used unix socket

		unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);

		if (connect(unix_sock, (struct sockaddr *) &unix_addr, sizeof(struct sockaddr_un)) < 0) {

			dbgf_all(DBGT_INFO, "found unbound %s, going to unlink and reuse!", tmp_path);

			close(unix_sock);
			unlink(tmp_path);
			unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);

		} else {

			dbg_sys(DBGT_ERR,
				"%s busy! Probably bmx7 is already running! Use [--%s %s] -c ... to connect to a running bmx7",
				tmp_path, ARG_RUN_DIR, run_dir);
			cleanup_all(CLEANUP_FAILURE);

		}

		dbgf_all(DBGT_INFO, "opened control socket %d", unix_sock);

		if (bind(unix_sock, (struct sockaddr *) &unix_addr, sizeof(struct sockaddr_un)) < 0) {

			dbg_sys(DBGT_ERR, "can't bind unix socket '%s': %s", tmp_path, strerror(errno));
			cleanup_all(CLEANUP_FAILURE);

		}

		if (listen(unix_sock, 10) < 0) {

			dbg_sys(DBGT_ERR, "can't listen unix socket '%s': %s", tmp_path, strerror(errno));
			cleanup_all(CLEANUP_FAILURE);

		}

		if (update_pid_file() == FAILURE)
			return FAILURE;

	}

	return SUCCESS;
}

STATIC_FUNC
int32_t call_opt_apply(uint8_t cmd, uint8_t save, struct opt_type *opt, struct opt_parent *_patch, char *in, struct ctrl_node *cn)
{

	assertion(-500154, (cmd == OPT_CHECK || cmd == OPT_APPLY));

	//cleanup_patch will change the patch, so we'll work with a duplicate and destroy it afterwards
	struct opt_parent *patch = dup_opt_parent(&Patch_opt, _patch);

	dbgf_all(DBGT_INFO, "%s save=%d %s p_diff=%d p_val:%s p_ref:%s strm:%s",
		opt_cmd2str[cmd], save, opt->name, patch->diff, patch->val, patch->ref, in);

	if (cleanup_patch(opt, patch, cn) == FAILURE)
		goto call_opt_apply_error;

	if (patch->diff == NOP && LIST_EMPTY(&(patch->childs_instance_list))) {
		del_opt_parent(&Patch_opt, patch);
		return SUCCESS;
	}

	// keep this check after cleanup_patch  and  p_diff==NOP and list_empty check to let config_reload 
	// apply all unchanged options

	if ((initializing && opt->dyn_t == A_DYN) || (!initializing && opt->dyn_t == A_INI)) {

		dbg_cn(cn, DBGL_SYS, DBGT_ERR, "--%s%s%c can %s be applied at startup",
			opt->name, opt->short_name ? ", -" : "", opt->short_name ? opt->short_name : ' ',
			initializing ? "NOT" : "ONLY");

		goto call_opt_apply_error;
	}


	if (opt->call_custom_option == opt_connect_daemon_to_unix_sock) {
		// this is necessary because we dont have the "*in" argument for the opt_something(...) prototype
		if (opt_connect_client_to_daemon(cmd, opt, cn, in) == FAILURE)
			goto call_opt_apply_error;


	} else if (cmd == OPT_CHECK) {

		if (opt->call_custom_option &&
			(opt->call_custom_option)(OPT_CHECK, save, opt, patch, cn) == FAILURE) {

			goto call_opt_apply_error;
		}



	} else if (cmd == OPT_APPLY) {

		if (opt->auth_t == A_ADM) {

			dbgf_all(DBGT_INFO, "--%-22s  %-30s  (%s order %d)",
				opt->name, patch->val, opt_cmd2str[ cmd ], opt->order);
		}

		if (opt->ival && patch->diff == DEL)
			*(opt->ival) = opt->idef;

		else if (opt->opt_t == A_PS0 && opt->ival && patch->diff == ADD)
			*(opt->ival) = opt->imax;

		else if (opt->opt_t != A_PS0 && opt->ival && patch->diff == ADD)
			*(opt->ival) = strtol(patch->val, NULL, 10);

		if (opt->call_custom_option &&
			(opt->call_custom_option)(OPT_APPLY, save, opt, patch, cn) == FAILURE) {

			dbg_cn(cn, DBGL_SYS, DBGT_ERR,
				"failed setting the already succesfully tested option %s to %s",
				opt->name, patch->val);

			// this may happen when:
			// - overwriting a config-file option with a startup-option (pain in the ass!)
			// - configuring the same PMN option twice in one command-line
			goto call_opt_apply_error;
		}


	}

	del_opt_parent(&Patch_opt, patch);
	return SUCCESS;

call_opt_apply_error:

	del_opt_parent(&Patch_opt, patch);
	return FAILURE;
}

/* this table lists what could happen and how its' handled in track_opt_parent():

patch	tracked		patch	tracked		config-
p_val	t_val		p_ref	t_ref	->	file		track
						value:		value:	ref:

DEL/0	x		x	x		DEL		DEL	DEL	| if      ( !p_val && t_val )

DEL/0	NULL		x	x		NOP		NOP	NOP	| else if ( !p_val && !t_val )

A	A		A	A		NOP		NOP	NOP	| else if (  p_val  &&  p_val == t_val  &&  p_ref == t_ref )
A	A		0	0		NOP		NOP	NOP	|

										| else [if (  p_val  && (p_val != t_val  ||  p_ref != t_ref )]
										|
A	A		A	B		ref		value	ref	|	| if ( p_ref )
A	A		A	0		ref		value	ref	|	|
A	B/NULL		A	A	(*)	ref		value	ref	|	|
A	B/NULL		A	B	(-)	ref		value	ref	|	|
A	B/NULL		A	0	(-)	ref		value	ref	|	|
										|
A	A		0	B		value		value	0	|	| else [if( !p_ref)] 
A	B/NULL		0	0		value		NOP	0	|	| 
A	B/NULL		0	A	(*)	value		value	0	|	|

(*) in these cases, when configuring parent-options 
we have to reset the old (currently active) tracked t_val option 
before configuring the new patched p_val parent value
This has already been done during call_option( cmd==CHECK || cmd==APPLY )

(-) impossible to configue in one step for parent-options

 */

STATIC_FUNC
int32_t track_opt_parent(uint8_t cmd, uint8_t save, struct opt_type *p_opt, struct opt_parent *p_patch, struct ctrl_node *cn)
{

	struct list_node *pos;
	struct opt_parent *p_reftr = get_opt_parent_ref(p_opt, (p_opt->opt_t == A_PS1N || p_opt->opt_t == A_PM1N) ? p_patch->ref : NULL);
	struct opt_parent *p_track = get_opt_parent_val(p_opt, (p_opt->opt_t == A_PS1N || p_opt->opt_t == A_PM1N) ? p_patch->val : NULL);

	assertion(-500125, !(p_reftr && p_track && p_reftr != p_track));

	p_track = p_track ? p_track : p_reftr;

	dbgf_all(DBGT_INFO, "%s %s save=%d patch_diff:%d patch_val:%s patch_ref:%s track_val:%s track_ref:%s",
		opt_cmd2str[cmd], p_opt->name, save, p_patch->diff,
		p_patch->val, p_patch->ref, p_track ? p_track->val : "-", p_track ? p_track->ref : "-");

	if (p_patch->diff == DEL && p_track) {

		if (cmd == OPT_APPLY) {

			if (save && save_config_cb)
				save_config_cb(DEL, p_opt, p_track->ref ? p_track->ref : p_track->val, NULL, cn);

			del_opt_parent(p_opt, p_track);

			dbg_cn(cn, DBGL_CHANGES, DBGT_INFO, "--%-22s -", p_opt->name);
		}

	} else {

		uint8_t changed = NO;

		if (p_patch->diff == DEL && !p_track) {

			/*
			if ( save ) {
				dbg_cn( cn, DBGL_SYS, DBGT_ERR, "--%s %s does not exist", p_opt->long_name, p_patch->p_val );
				return FAILURE;
			}
			 */

			return SUCCESS;

		} else if ((p_patch->diff == ADD && p_patch->val && p_track && wordsEqual(p_patch->val, p_track->val)) &&
			((p_patch->ref && p_track->ref && wordsEqual(p_patch->ref, p_track->ref)) ||
			(!p_patch->ref && !p_track->ref))) {

		} else if (p_patch->val /*&&  (patch_c->c_ref || !patch_c->c_ref)*/) {

			if (cmd == OPT_APPLY) {

				if (!p_track) {
					p_track = add_opt_parent(p_opt);
					set_opt_parent_val(p_track, p_patch->val);
					set_opt_parent_ref(p_track, p_patch->ref);
				}

				if (save && save_config_cb)
					save_config_cb(ADD, p_opt,
					p_track->ref ? p_track->ref : p_track->val,
					p_patch->ref ? p_patch->ref : p_patch->val, cn);

				set_opt_parent_val(p_track, p_patch->val);
				set_opt_parent_ref(p_track, p_patch->ref);
			}
			changed = YES;

		} else {
			assertion(-500121, NO);
		}

		if (cmd == OPT_APPLY && changed && p_opt->auth_t == A_ADM)
			dbg_cn(cn, DBGL_CHANGES, DBGT_INFO, "--%-22s %c%-30s",
			p_opt->name, p_patch->diff == DEL ? '-' : ' ', p_patch->val);

		if (p_track) {

			list_for_each(pos, &p_patch->childs_instance_list)
			{

				uint8_t changed_child = NO;
				char *save_val = p_track->ref ? p_track->ref : p_track->val;
				struct opt_child *c_patch = list_entry(pos, struct opt_child, list);
				struct opt_child *c_track = get_opt_child(c_patch->opt, p_track);


				if (!c_patch->val && c_track) {

					if (cmd == OPT_APPLY) {
						if (save && save_config_cb && c_track->opt->cfg_t != A_ARG)
							save_config_cb(DEL, c_track->opt, save_val, c_track->ref ? c_track->ref : c_track->val, cn);

						del_opt_child(p_track, c_track->opt);
					}
					changed_child = changed = YES;

				} else if (!c_patch->val && !c_track) {

					if (save) {
						dbg_cn(cn, DBGL_SYS, DBGT_ERR, "--%s %s %s%s does not exist",
							p_opt->name, p_patch->val, LONG_OPT_ARG_DELIMITER_STR, c_patch->opt->name);
						return FAILURE;
					}

				} else if ((c_patch->val && c_track && wordsEqual(c_patch->val, c_track->val)) &&
					((c_patch->ref && c_track->ref && wordsEqual(c_patch->ref, c_track->ref)) ||
					(!c_patch->ref && !c_track->ref))) {

					dbgf_all(DBGT_INFO, "--%s %s %s%s %s already configured",
						p_opt->name, p_patch->val, LONG_OPT_ARG_DELIMITER_STR, c_patch->opt->name, c_patch->val);

				} else if (c_patch->val) {

					if (cmd == OPT_APPLY) {
						if (save && save_config_cb && c_patch->opt->cfg_t != A_ARG)
							save_config_cb(ADD, c_patch->opt, save_val, c_patch->ref ? c_patch->ref : c_patch->val, cn);

						if (!c_track)
							c_track = add_opt_child(c_patch->opt, p_track);

						set_opt_child_val(c_track, c_patch->val);
						set_opt_child_ref(c_track, c_patch->ref);
					}

					changed_child = changed = YES;

				} else {

					assertion(-500122, NO);
				}

				if (cmd == OPT_APPLY && changed_child && c_patch->opt->auth_t == A_ADM)
					dbg_cn(cn, DBGL_CHANGES, DBGT_INFO, "--%-22s  %-30s  %s%-22s %c%-30s",
					p_opt->name, p_patch->val, LONG_OPT_ARG_DELIMITER_STR,
					c_patch->opt->name, c_patch->val ? ' ' : '-', c_patch->val);

			}
		}
		/*
		// be pedantic only after startup (!on_the_fly) and not reload-config (!save)
		if (!changed && !initializing && save) {

			dbg_cn( cn, DBGL_SYS, DBGT_ERR, "--%s %s already configured", 
				p_opt->long_name, p_patch->p_val );

			// actually here we can be pedantic or not because cleanup_patch()
			// have already checked for double applied options
			return FAILURE;
		}
		 */
	}

	return SUCCESS;
}

int32_t call_option(uint8_t ad, uint8_t cmd, uint8_t save, struct opt_type *opt, struct opt_parent *patch, char *in, struct ctrl_node *cn)
{

	dbgf_all(DBGT_INFO, "%s (cmd %s  del %d  save %d  parent_name %s order %d) p_val: %s in: %s",
		opt->name, opt_cmd2str[ cmd ], ad, save, opt->parent_name, opt->order, patch ? patch->val : "-", in);

	if (!opt) // might be NULL when referring to disabled plugin functionality
		return SUCCESS;

	assertion(-500104, (ad == ADD || ad == DEL));
	assertion(-500103, IMPLIES(cmd == OPT_PATCH || cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY, patch));
	//        assertion(-500147, IMPLIES(cmd == OPT_PATCH || cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY, cn));

	if ((cmd == OPT_PATCH || cmd == OPT_ADJUST || cmd == OPT_CHECK || cmd == OPT_APPLY) &&
		cn && !cn->authorized && opt->auth_t == A_ADM) {
		dbg_cn(cn, DBGL_SYS, DBGT_ERR, "insufficient permissions to use command %s", opt->name);
		return FAILURE;
	}

	if (ad == DEL && (/*!on_the_fly this is what concurrent -r and -g configurations do || */
		/* opt->dyn_t == A_INI this is what conf-reload tries   ||*/ opt->cfg_t == A_ARG &&
		opt->opt_t != A_PM1N)) {
		dbg_sys(DBGT_ERR, "option %s can not be resetted during startup!", opt->name);
		return FAILURE;
	}


	if ((opt->pos_t == A_END) && in && !is_end_of_cmd_stream(opt, in)) {

		dbg_cn(cn, DBGL_SYS, DBGT_ERR, "--%s%s%c MUST be last option before line feed",
			opt->name, opt->short_name ? ", -" : "", opt->short_name ? opt->short_name : ' ');

		goto call_option_failure;
	}


	if (cmd == OPT_PATCH) {

		if ((call_opt_patch(ad, opt, patch, in, cn)) == FAILURE)
			goto call_option_failure;

		if (opt->pos_t == A_EAT && in) {
			return strlen(in);
		} else if (opt->pos_t == A_ETE && in && is_end_of_cmd_stream(opt, in)) {
			return strlen(in);
		} else {
			return SUCCESS;
		}


	} else if (cmd == OPT_ADJUST) {

		if (opt->call_custom_option &&
			((opt->call_custom_option)(OPT_ADJUST, 0, opt, patch, cn)) == FAILURE)
			goto call_option_failure;
		else
			return SUCCESS;


	} else if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

		assertion(-500105, (!opt->parent_name));

		assertion(-500128, (opt->cfg_t == A_ARG || patch->val ||
			(patch->diff == DEL && opt->opt_t != A_PS1N && opt->opt_t != A_PM1N)));

		if (opt->cfg_t != A_ARG && (opt->opt_t == A_PS1N || opt->opt_t == A_PM1N)) {

			struct opt_parent *p_reftr = get_opt_parent_ref(opt, patch->ref);
			struct opt_parent *p_track = get_opt_parent_val(opt, patch->val);

			assertion(-500129, IMPLIES((p_reftr && p_track), p_reftr == p_track));

			p_track = p_track ? p_track : p_reftr;

			if ((patch->diff == ADD && patch->val && p_track &&
				!wordsEqual(patch->val, p_track->val)) && (patch->ref || p_track->ref)) {

				check_apply_parent_option(DEL, cmd, save, opt, p_track->val, cn);
			}
		}

		//TODO: this is not nice! But needed to avoid having multiple tracked instances of a PS1N option!

		if (cmd == OPT_APPLY && opt->opt_t == A_PS1N && opt->dyn_t != A_INI && patch->diff == ADD && patch->val && opt->d.parents_instance_list.items >= 1) {

			assertion(-501313, (opt->d.parents_instance_list.items == 1));

			struct opt_parent *p_tmp = list_get_first(&opt->d.parents_instance_list);

			if (check_apply_parent_option(DEL, OPT_APPLY, save, opt, p_tmp->val, cn) == FAILURE) {

				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "calling %s %s failed", opt->name, p_tmp->val);

				return FAILURE;
			}
		}



		if ((call_opt_apply(cmd, save, opt, patch, in, cn)) == FAILURE)
			goto call_option_failure;

		if (opt->cfg_t != A_ARG && track_opt_parent(cmd, save, opt, patch, cn) == FAILURE)
			goto call_option_failure;

		return SUCCESS;


	} else if (cmd == OPT_SET_POST || cmd == OPT_POST) {

		if (opt->call_custom_option && ((opt->call_custom_option)(cmd, 0, opt, 0, cn)) == FAILURE)
			goto call_option_failure;

		return SUCCESS;
	}


call_option_failure:

	dbg_cn(cn, DBGL_SYS, DBGT_ERR,
		"--%s  %s  Failed ! ( diff:%d ad:%d val:%d min:%d max:%d def:%d  %s %d %d %d )",
		opt->name ? opt->name : "-", in ? in : "-",
		patch ? patch->diff : -1,
		ad, opt->ival ? *(opt->ival) : 0, opt->imin, opt->imax, opt->idef,
		opt_cmd2str[cmd], opt->opt_t, !initializing, wordlen(in));

	return FAILURE;
}

int respect_opt_order(uint8_t test, int8_t last, int8_t next, struct opt_type *on, uint8_t load, uint8_t cmd, struct ctrl_node *cn)
{

	struct list_node *list_pos;
	struct opt_type *opt;

	dbgf_all(DBGT_INFO, "test=%s, cmd=%s, last=%d, next=%d, opt_name=%s  load=%d load_config_cb=%d",
		opt_cmd2str[ test ], opt_cmd2str[ cmd ], last, next, on ? on->name : "???", load, !!load_config_cb);

	assertion(-500002, (test == OPT_CHECK || test == OPT_APPLY));
	assertion(-500107, (cmd != OPT_CHECK && cmd != OPT_APPLY));


	if (next == 0)
		return last;

	if (last > next) {

		// debug which option caused the problems !
		dbg_cn(cn, DBGL_SYS, DBGT_ERR,
			"--%s%s%c (order=%d option) MUST appear earlier in command sequence!",
			on ? on->name : "???", on && on->short_name ? ", " : "", on && on->short_name ? on->short_name : ' ', next);

		return FAILURE;
	}

	if (last == next)
		return next;

	list_for_each(list_pos, &opt_list)
	{

		opt = (struct opt_type *) list_entry(list_pos, struct opt_data, list);

		if (load && opt->order >= last + 1 && opt->order <= next) {

			if (load_config_cb && load_config_cb(test, opt, cn) == FAILURE) {

				dbgf_all(DBGT_ERR, "load_config_cb() %s failed",
					opt->name);

				return FAILURE;
			}
		}

		if (test == OPT_APPLY && opt->order >= last && opt->order <= next - 1) {

			if (call_option(ADD, cmd, 0/*save*/, opt, 0, 0, cn) == FAILURE) {

				dbg_cn(cn, DBGL_SYS, DBGT_ERR, "call_option() %s cmd %s failed",
					opt->name, opt_cmd2str[cmd]);

				return FAILURE;
			}
		}
	}

	return next;
}


// if returns SUCCESS then fd might be closed ( called remove_ctrl_node( fd ) ) or not.
// if returns FAILURE then fd IS open and must be closed

int8_t apply_stream_opts(char *s, uint8_t cmd, uint8_t load_cfg, struct ctrl_node *cn)
{

	enum {
		NEXT_OPT, // 0
		NEW_OPT, // 1
		SHORT_OPT, // 2
		LONG_OPT, // 3
		LONG_OPT_VAL, // 4
		LONG_OPT_WHAT, // 5
		LONG_OPT_ARG, // 6
		LONG_OPT_ARG_VAL, // 7
	};

#if defined(DEBUG_ALL) || defined(TEST_DEBUG)
	char *state2str[] = { "NEXT_OPT", "NEW_OPT", "SHORT_OPT", "LONG_OPT", "LONG_OPT_VAL", "LONG_OPT_WHAT", "LONG_OPT_ARG", "LONG_OPT_ARG_VAL" };
#endif

	int8_t state = NEW_OPT;
	struct opt_type *opt = NULL;
	struct opt_type *opt_arg = NULL;
	char* equalp = NULL;
	char* pmn_s = NULL;
	int8_t order = 0;
	int32_t pb;
	char argument[MAX_ARG_SIZE];
	struct opt_parent *patch = NULL;

	if (cmd != OPT_CHECK && cmd != OPT_APPLY)
		return FAILURE;

	uint8_t del;

	Load_config = load_cfg;
	Testing = 0;


	while (s && strlen(s) >= 1) {

		dbgf_all(DBGT_INFO, "cmd: %-10s, state: %s opt: %s, wordlen: %d rest: %s",
			opt_cmd2str[cmd], state2str[state], opt ? opt->name : "null", wordlen(s), s);

		if (Testing) {
			Testing = 0;
			close_ctrl_node(CTRL_CLOSE_SUCCESS, cn);
			return SUCCESS;
		}


		if (state == NEXT_OPT) {
			// assumes s points to last successfully processed word or its following gap
			s = nextword(s);
			state = NEW_OPT;

		} else if (state == NEW_OPT && wordlen(s) >= 2 && s[0] == '-' && s[1] != '-') {

			s++;
			state = SHORT_OPT;

		} else if (state == NEW_OPT && wordlen(s) >= 3 && s[0] == '-' && s[1] == '-') {

			s += 2;
			state = LONG_OPT;

		} else if (state == NEW_OPT && wordlen(s) >= 1 && s[0] != '-' && s[0] != LONG_OPT_ARG_DELIMITER_CHAR) {

			state = LONG_OPT;

		} else if (state == SHORT_OPT && wordlen(s) >= 1) {

			if (!(opt = get_option(NULL, YES, s)))
				goto apply_args_error;

			if ((order = respect_opt_order(cmd, order, opt->order, opt, Load_config, OPT_SET_POST, cn)) < 0)
				goto apply_args_error;

			if (opt->opt_t == A_PS0) {

				if ((pb = check_apply_parent_option(ADD, cmd, 0/*save*/, opt, s, cn)) == FAILURE)
					goto apply_args_error;

				if (pb) {
					s += pb;
					state = NEXT_OPT;
				} else if (wordlen(s + 1) >= 1) {
					s++;
					state = SHORT_OPT;
				} else if (wordlen(s + 1) == 0) {
					s++;
					state = NEXT_OPT;
				} else {
					goto apply_args_error;
				}

			} else if (opt->opt_t == A_PS0N) {

				patch = add_opt_parent(&Patch_opt);

				if ((pb = call_option(ADD, OPT_PATCH, 0/*save*/, opt, patch, s, cn)) == FAILURE)
					goto apply_args_error;

				pmn_s = s;
				s += pb;
				state = LONG_OPT_WHAT;


			} else if (opt->opt_t == A_PS1 || opt->opt_t == A_PS1N || opt->opt_t == A_PM1N) {

				s++;

				if (wordlen(s) > 1 && s[0] == '=')
					s++;

				if (wordlen(s) == 0 && !(s = nextword(s)))
					goto apply_args_error;

				state = LONG_OPT_VAL;
			}


		} else if (state == LONG_OPT && wordlen(s) >= 1) {

			opt = get_option(NULL, NO, s);

			if (opt) {

				if ((order = respect_opt_order(cmd, order, opt->order, opt, Load_config, OPT_SET_POST, cn)) < 0)
					goto apply_args_error;

				if (opt->opt_t == A_PS0) {

					if ((pb = check_apply_parent_option(ADD, cmd, 0/*save*/, opt, s, cn)) == FAILURE)
						goto apply_args_error;

					s += pb ? pb : (int32_t) wordlen(s);

					state = NEXT_OPT;

				} else if (opt->opt_t == A_PS0N) {

					patch = add_opt_parent(&Patch_opt);

					if ((pb = call_option(ADD, OPT_PATCH, 0/*save*/, opt, patch, s, cn)) == FAILURE)
						goto apply_args_error;

					pmn_s = s;
					s += pb;
					state = LONG_OPT_WHAT;

				} else if (opt->opt_t == A_PS1 || opt->opt_t == A_PS1N || opt->opt_t == A_PM1N) {

					equalp = index(s, '=');

					if (equalp && equalp < s + wordlen(s)) {

						s = equalp + 1;

					} else {

						if ((s = nextword(s)) == NULL)
							goto apply_args_error;
					}

					state = LONG_OPT_VAL;

				} else {
					goto apply_args_error;
				}

			} else {
				goto apply_args_error;
			}


		} else if (state == LONG_OPT_VAL && wordlen(s) >= 1) {

			if (opt->opt_t == A_PS1) {

				s = s + (del = ((s[0] == ARG_RESET_CHAR) ? 1 : 0));

				if ((pb = check_apply_parent_option(del, cmd, (initializing ? NO : YES)/*save*/, opt, s, cn)) == FAILURE)
					goto apply_args_error;

				s += pb;
				state = NEXT_OPT;

			} else if (opt->opt_t == A_PS1N || opt->opt_t == A_PM1N) {

				s = s + (del = ((s[0] == ARG_RESET_CHAR) ? 1 : 0));

				patch = add_opt_parent(&Patch_opt);

				if ((pb = call_option(del, OPT_PATCH, 0/*save*/, opt, patch, s, cn)) == FAILURE)
					goto apply_args_error;

				pmn_s = s;
				s += pb;
				state = LONG_OPT_WHAT;

			} else {
				goto apply_args_error;
			}

		} else if (state == LONG_OPT_WHAT) {

			if (opt->opt_t != A_PS0N && opt->opt_t != A_PS1N && opt->opt_t != A_PM1N)
				goto apply_args_error;


			char* nextword_ptr = nextword(s);
			char* delimiter_ptr = nextword_ptr ? index(nextword_ptr, LONG_OPT_ARG_DELIMITER_CHAR) : NULL;

			if (delimiter_ptr && delimiter_ptr == nextword(s) && patch->diff == DEL) {

				wordCopy(argument, delimiter_ptr + 1);

				dbg_cn(cn, DBGL_SYS, DBGT_ERR,
					"--%s %s can not be resetted and refined at the same time. Just omit %s%s!",
					opt->name, patch->val, LONG_OPT_ARG_DELIMITER_STR, argument);

				goto apply_args_error;

			} else if (delimiter_ptr && delimiter_ptr == nextword(s)) {

				//nextword starts with slashp 
				s = delimiter_ptr + 1;
				state = LONG_OPT_ARG;

			} else {

				if ((call_option(ADD, OPT_ADJUST, 0/*save*/, opt, patch, pmn_s, cn)) == FAILURE)
					goto apply_args_error;

				//indicate end of LONG_OPT_ARGs
				if ((call_option(ADD, cmd, (initializing ? NO : YES)/*save*/, opt, patch, pmn_s, cn)) == FAILURE)
					goto apply_args_error;

				del_opt_parent(&Patch_opt, patch);
				patch = NULL;
				state = NEXT_OPT;
			}


		} else if (state == LONG_OPT_ARG && wordlen(s) >= 1) {

			opt_arg = get_option(opt, NO, s);

			if (!opt_arg || opt_arg->opt_t != A_CS1 || opt_arg->order != opt->order)
				goto apply_args_error;

			equalp = index(s, '=');

			if (equalp && equalp < s + wordlen(s)) {

				s = equalp + 1;

			} else {

				if ((s = nextword(s)) == NULL)
					goto apply_args_error;
			}

			state = LONG_OPT_ARG_VAL;


		} else if (state == LONG_OPT_ARG_VAL && wordlen(s) >= 1) {

			s = s + (del = ((s[0] == ARG_RESET_CHAR) ? 1 : 0));

			if ((pb = call_option(del, OPT_PATCH, 0/*save*/, opt_arg, patch, s, cn)) == FAILURE)
				goto apply_args_error;

			s += pb;

			state = LONG_OPT_WHAT;


		} else {
			goto apply_args_error;
		}

		continue;
	}


	if (state != LONG_OPT_ARG && state != NEW_OPT && state != NEXT_OPT)
		goto apply_args_error;


	dbgf_all(DBGT_INFO, "all opts and args succesfully called with %s", opt_cmd2str[cmd]);

	if ((order = respect_opt_order(cmd, order, 99, NULL, Load_config, OPT_SET_POST, cn)) < 0)
		goto apply_args_error;


	return SUCCESS;

apply_args_error:

	if (patch)
		del_opt_parent(&Patch_opt, patch);

	snprintf(argument, XMIN(sizeof(argument), wordlen(s) + 1), "%s", s);

	//otherwise invalid sysntax identified only by apply_stream_opts is not printed;
	dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "invalid argument: %s", argument);

	return FAILURE;
}

void apply_init_args(int argc, char *argv[])
{

	prog_name = argv[0];

	get_init_string(argc, argv);

	char *stream_opts = nextword(init_string);

	struct ctrl_node *cn = create_ctrl_node(STDOUT_FILENO, NULL, (getuid() | getgid())/*are we root*/ ? NO : YES);

	if ((apply_stream_opts(stream_opts, OPT_CHECK, YES/*load cfg*/, cn) == FAILURE) ||
		(apply_stream_opts(stream_opts, OPT_APPLY, YES/*load cfg*/, cn) == FAILURE))
		cleanup_all(CLEANUP_FAILURE);

	respect_opt_order(OPT_APPLY, 0, 99, NULL, NO/*load_cofig*/, OPT_POST, 0/*probably closed*/);

	close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);

	cb_plugin_hooks(PLUGIN_CB_CONF, NULL);

	free_init_string();
}

STATIC_FUNC
int32_t opt_show_parameter(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd == OPT_APPLY) {

		struct opt_type *opt = NULL;

		dbg_printf(cn, "PARAMETERS:\n");

		while ((opt = list_iterate(&opt_list, opt))) {
			struct opt_parent *p = NULL;


			while ((p = list_iterate(&opt->d.parents_instance_list, p))) {
				struct opt_child *c = NULL;

				assertion(-501231, (opt->name && opt->cfg_t != A_ARG));

				char pdef[14];
				sprintf(pdef, "%d", opt->idef);

				dbg_printf(cn, " %-22s %-20s (%s) %s%s\n", opt->name, p->val, (opt->sdef ? opt->sdef : pdef),
					(p->ref ? "resolved from " : ""), (p->ref ? p->ref : ""));

				while ((c = list_iterate(&p->childs_instance_list, c))) {
					char cdef[14];
					sprintf(cdef, "%d", c->opt->idef);
					dbg_printf(cn, "    %s%-18s %-20s (%s) %s%s\n",
						LONG_OPT_ARG_DELIMITER_STR, c->opt->name, c->val, (c->opt->sdef ? c->opt->sdef : cdef),
						(c->ref ? "resolved from " : ""), (c->ref ? c->ref : ""));
				}
			}
		}

		if (initializing)
			cleanup_all(CLEANUP_SUCCESS);
	}

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_debug(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (initializing && cmd == OPT_POST) {

		activate_debug_system();

	} else if (initializing && cmd == OPT_APPLY) {

		debug_level = strtol(patch->val, NULL, 10);

		activate_debug_system();

	} else if (!initializing && cmd == OPT_APPLY) {

		int ival = strtol(patch->val, NULL, 10);


		if (ival == DBGL_SYS ||
			ival == DBGL_CHANGES ||
			ival == DBGL_TEST ||
			ival == DBGL_DUMP ||
			ival == DBGL_ALL) {

			remove_dbgl_node(cn);
			add_dbgl_node(cn, ival);
			return SUCCESS;

		} else if (ival == DBGL_SILCT) {

			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_STATUS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_CREDITS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_INTERFACES, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_DUMP), ARG_DUMP_DEV, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_LINKS, cn);

		} else if (ival == DBGL_SILCO) {

			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_STATUS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_CREDITS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_INTERFACES, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_LINKS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_ORIGINATORS, cn);

		} else if (ival == DBGL_DETAILS) {

			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_STATUS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_INTERFACES, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_LINKS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_ORIGINATORS, cn);
			if (get_option(0, 0, ARG_TUNS))
				check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_TUNS, cn);

		} else if (ival == DBGL_ALLDETAILS) {

			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_STATUS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_CREDITS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_CPU_PROFILING, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_INTERFACES, cn);
#ifdef TRAFFIC_DUMP
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_DUMP), ARG_DUMP_DEV, cn);
#endif
#if defined MEMORY_USAGE
			debugMemory(cn);
#endif
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_LINKS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_ORIGINATORS, cn);
			if (get_option(0, 0, ARG_TUNS))
				check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_TUNS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_DESCREFS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_SHOW), ARG_CONTENTS, cn);
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_DESCRIPTIONS), NULL, cn);

		} else if (ival == DBGL_PROFILE) {

#if defined MEMORY_USAGE
			debugMemory(cn);
#endif
		}
		close_ctrl_node(CTRL_CLOSE_SUCCESS, cn);
	}

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_help(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd != OPT_APPLY)
		return SUCCESS;

	if (!cn)
		return FAILURE;

	uint8_t verbose = !strcmp(opt->name, ARG_VERBOSE_HELP);
	int32_t relevance = get_opt_child_val_int(opt, patch, ARG_RELEVANCE, FAILURE);

	struct list_node *list_pos;
	const char *category = NULL;

	dbg_printf(cn, "\n");
	dbg_printf(cn, "Usage: %s [LONGOPT=[%c]VAL] | -[SHORTOPT[SHORTOPT...] [%c]VAL] ...\n",
		prog_name, ARG_RESET_CHAR, ARG_RESET_CHAR);
	dbg_printf(cn, "  e.g. %s %s=eth1 %s=wlan0 d=3\n", prog_name, ARG_DEV, ARG_DEV);
	dbg_printf(cn, "  e.g. %s -c %s=%s %s=%s %s=%s %s=%s %s=%s\n",
		prog_name, ARG_SHOW, ARG_STATUS, ARG_SHOW, ARG_INTERFACES, ARG_SHOW, ARG_LINKS, ARG_SHOW, ARG_ORIGINATORS, ARG_SHOW, ARG_CREDITS);
	dbg_printf(cn, "  e.g. %s -c %s=%cwlan0 %s=%s \n", prog_name, ARG_DEV, ARG_RESET_CHAR, ARG_SHOW, ARG_INTERFACES);
	dbg_printf(cn, "\n");

	list_for_each(list_pos, &opt_list)
	{

		struct list_node *pos;
		struct opt_type *opt = (struct opt_type *) list_entry(list_pos, struct opt_data, list);
		char sn[5], st[3 * MAX_ARG_SIZE];

		if (relevance > opt->relevance)
			continue;

		if (category != opt->d.category_name) {
			category = opt->d.category_name;
			dbg_printf(cn, "\n\n%s options  (order=%d):\n", category, opt->order);
		}

		if (opt->name && opt->help && !opt->parent_name) {


			if (opt->short_name)
				snprintf(sn, 5, ", -%c", opt->short_name);
			else
				*sn = '\0';

			sprintf(st, "--%s%s %s ", opt->name, sn, opt->syntax ? opt->syntax : "");


			dbg_printf(cn, "\n%-40s ", st);

			if (opt->opt_t != A_PS0 && opt->imin != opt->imax) {
				dbg_printf(cn, "def: %-6d  range: [ %d %s %d ]",
					opt->idef, opt->imin, opt->imin + 1 == opt->imax ? "," : "...", opt->imax);
			} else if (opt->sdef) {
				dbg_printf(cn, "def: %s", opt->sdef);
			}

			dbg_printf(cn, "\n");


			if (verbose)
				dbg_printf(cn, "	%s\n", opt->help);

		}

		list_for_each(pos, &opt->d.childs_type_list)
		{

			struct opt_type *c_opt = (struct opt_type *) list_entry(pos, struct opt_data, list);

			if (relevance > c_opt->relevance || !c_opt->parent_name || !c_opt->help)
				continue;


			if (c_opt->short_name)
				snprintf(sn, 5, ", %s%c", LONG_OPT_ARG_DELIMITER_STR, c_opt->short_name);
			else
				*sn = '\0';

			sprintf(st, "  %s%s%s %s ",
				LONG_OPT_ARG_DELIMITER_STR, c_opt->name, sn, c_opt->syntax ? c_opt->syntax : "");


			dbg_printf(cn, "%-40s ", st);

			if (c_opt->opt_t != A_PS0 && c_opt->imin != c_opt->imax) {
				dbg_printf(cn, "def: %-6d  range: [ %d %s %d ]",
					c_opt->idef, c_opt->imin, c_opt->imin + 1 == c_opt->imax ? "," : "...", c_opt->imax);
			} else if (c_opt->sdef) {
				dbg_printf(cn, "def: %s", c_opt->sdef);
			}

			dbg_printf(cn, "\n");

			if (verbose)
				dbg_printf(cn, "	        %s\n", c_opt->help);

		}
	}

	dbg_printf(cn, "\n");

	if (relevance != MAX_RELEVANCE) {
		dbg_printf(cn, "Environment variables (e.g. sudo %s=/usr/src/bmx7/lib %s -d3 dev=eth0 ):\n",
			BMX_ENV_LIB_PATH, prog_name);

		dbg_printf(cn, "\t%s\n", BMX_ENV_LIB_PATH);
		dbg_printf(cn, "\t%s\n", BMX_ENV_DEBUG);
	}

	dbg_printf(cn, "\n");

	if (initializing)
		cleanup_all(CLEANUP_SUCCESS);

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_quit_connection(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if (cmd == OPT_APPLY)
		close_ctrl_node(CTRL_CLOSE_SUCCESS, cn);

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_run_dir(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	char tmp_dir[MAX_PATH_SIZE] = "";

	if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

		if (wordlen(patch->val) + 1 >= MAX_PATH_SIZE || patch->val[0] != '/')
			return FAILURE;

		snprintf(tmp_dir, wordlen(patch->val) + 1, "%s", patch->val);

		if (check_dir(tmp_dir, YES/*create*/, YES/*writable*/, NO) == FAILURE)
			return FAILURE;

		strcpy(run_dir, tmp_dir);

	} else if (cmd == OPT_SET_POST && initializing) {

		if (check_dir(run_dir, YES/*create*/, YES/*writable*/, NO) == FAILURE)
			return FAILURE;

	}

	return SUCCESS;
}









static struct opt_type control_options[] ={
	//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	//		                            v order of ARG_HELP should be higher than ARG_CONFIG_FILE order and less or equal to ARG_CONNECT order !!!
	{ODI,0,ARG_HELP,		'h',3,2,A_PS0N,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_help,
			0,		"summarize help"},
	{ODI,ARG_HELP,ARG_RELEVANCE,    'r',3,2,A_CS1,A_USR,A_DYI,A_ARG,A_ANY,	0,	       MIN_RELEVANCE,   MAX_RELEVANCE,  DEF_RELEVANCE,0, opt_help,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
	,
	{ODI,0,ARG_VERBOSE_HELP,	'H',3,2,A_PS0N,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_help,
			0,		"show verbose help"},
	{ODI,ARG_VERBOSE_HELP,ARG_RELEVANCE,'r',3,2,A_CS1,A_USR,A_DYI,A_ARG,A_ANY,0,	       MIN_RELEVANCE,   MAX_RELEVANCE,  DEF_RELEVANCE,0, opt_help,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
	,

	{ODI,0,ARG_TEST,		0,  0,1,A_PS0,A_ADM,A_DYI,A_ARG,A_ANY,	&Testing,	0, 		1,		0,0, 		0,
			0,		"test remaining args and provide feedback about projected success (without applying them)"},

	{ODI,0,ARG_DEBUG,		'd',0,2,A_PS1,A_ADM,A_DYI,A_ARG,A_ETE,	0,		DBGL_MIN, 	DBGL_MAX,	-1,0, 		opt_debug,
			ARG_VALUE_FORM,	"show debug information:\n"
		"	 0  : system\n"
//		"	 1  : routes\n"
//		"	 2  : gateways\n"
		"	 3  : changes\n"
		"	 4  : verbose changes (depends on -DDEBUG_ALL)\n"
		"	 5  : profiling (depends on -DDEBUG_MALLOC and -DMEMORY_USAGE)\n"
//		"	 7  : services\n"
		"	 8  : details\n"
//		"	 9  : announced networks and interfaces\n"
//		"	10  : links\n"
		"	11  : testing"
		"	12  : traffic dump"},

	{ODI,0,ARG_RUN_DIR,		0,  2,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_RUN_DIR,	opt_run_dir,
			ARG_DIR_FORM,	"set runtime DIR of "BMX_PID_FILE", "BMX_UNIX_SOCK_FILE", ... - default: " DEF_RUN_DIR " (must be defined before --" ARG_CONNECT ")."},

	{ODI,0,ARG_DBG_SYSLOG,          0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&dbg_syslog,	MIN_DBG_SYSLOG,	MAX_DBG_SYSLOG,	DEF_DBG_SYSLOG,0,0,
			ARG_VALUE_FORM,"Disable/Enable syslog warnings"},


	{ODI,0,"loopMode",		'l',3,1,A_PS0,A_ADM,A_INI,A_ARG,A_ANY,	&loop_mode,	0, 		1,		0,0, 		0,
			0,		"put client daemon in loop mode to periodically refresh debug information"},

#ifndef LESS_OPTIONS
	{ODI,0,"loopInterval",		0,  3,1,A_PS1,A_ADM,A_INI,A_ARG,A_ANY,	&loop_interval,	MIN_LOOP_INTERVAL,MAX_LOOP_INTERVAL,DEF_LOOP_INTERVAL,0,0,
			ARG_VALUE_FORM,	"periodicity in ms with which client daemon in loop-mode refreshes debug information"},
#endif


	{ODI,0,ARG_CONNECT,		'c',3,2,A_PS0,A_ADM,A_INI,A_ARG,A_EAT,	0,		0, 		0,		0,0, 		opt_connect_daemon_to_unix_sock,
			0,		"set client mode. Connect and forward remaining args to main routing daemon"},

	//order=5: so when used during startup it also shows the config-file options	
	{ODI,0,ARG_SHOW_PARAMETER,	'p',9,2,A_PS0,A_ADM,A_DYI,A_ARG,A_ANY,	0,		0,		0,		0,0, 		opt_show_parameter,
			0,		"show configured parameters"}
	,

        {ODI,0,"dbgMuteTimeout",	0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&dbg_mute_to,	0,		10000000,	100000,0,	0,
			ARG_VALUE_FORM,	"set timeout in ms for muting frequent messages"},


	{ODI,0,ARG_QUIT,CHR_QUIT,    9,0,A_PS0,A_USR,A_DYN,A_ARG,A_END,	        0,		0, 		0,		0,0, 		opt_quit_connection,0,0}
};

void init_control(void)
{

	int i;

	char *d = getenv(BMX_ENV_DEBUG);
	if (d && strtol(d, NULL, 10) >= DBGL_MIN && strtol(d, NULL, 10) <= DBGL_MAX)
		debug_level = strtol(d, NULL, 10);

	for (i = DBGL_MIN; i <= DBGL_MAX; i++)
		LIST_INIT_HEAD(dbgl_clients[i], struct dbgl_node, list, list);

	openlog("bmx7", LOG_PID, LOG_DAEMON);

	memset(&Patch_opt, 0, sizeof( struct opt_type));

	LIST_INIT_HEAD(Patch_opt.d.childs_type_list, struct opt_data, list, list);
	LIST_INIT_HEAD(Patch_opt.d.parents_instance_list, struct opt_parent, list, list);

	register_options_array(control_options, sizeof( control_options), CODE_CATEGORY_NAME);

}

void cleanup_config(void)
{

	del_opt_parent(&Patch_opt, NULL);

	while (!LIST_EMPTY(&opt_list))
		remove_option((struct opt_type*) list_entry((&opt_list)->next, struct opt_data, list));

	free_init_string();

}

void cleanup_control(void)
{

	int8_t i;

	debug_system_active = NO;
	closelog();

	if (unix_sock)
		close(unix_sock);

	unix_sock = 0;

	close_ctrl_node(CTRL_PURGE_ALL, NULL);

	for (i = DBGL_MIN; i <= DBGL_MAX; i++) {

		while (!LIST_EMPTY(&dbgl_clients[i]))
			remove_dbgl_node((list_entry((&dbgl_clients[i])->next, struct dbgl_node, list))->cn);

	}
}
