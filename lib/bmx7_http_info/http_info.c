/*
 * Copyright (C) 2006 BATMAN contributors:
 * Axel Neumann
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>



#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "ip.h"

#define CODE_CATEGORY_NAME "http_info"

#define MAX_TCP_REQ_LEN  MAX_UNIX_MSG_SIZE
#define HTTP_PREAMBLE   "GET /"
#define HTTP_PREAMBLE_LEN strlen(HTTP_PREAMBLE)

#define HTTP_INFO_PORT  "http_info_port"
static int32_t http_info_port;

#define HTTP_INFO_GLOB_ACCESS "http_info_global_access"
static int32_t http_access;

#define HTTP_INFO_LISTEN_QUEUE 5


static int http_info_tcp_sock_in = 0;

static void http_info_rcv_tcp_data(struct ctrl_node *cn)
{

	char tcp_req_data[MAX_TCP_REQ_LEN + 1];
	int tcp_req_len;

	memset(&tcp_req_data, 0, MAX_TCP_REQ_LEN + 1);

	errno = 0;
	tcp_req_len = read(cn->fd, &tcp_req_data, MAX_TCP_REQ_LEN);

	if (tcp_req_len > 5 &&
		!memcmp(HTTP_PREAMBLE, tcp_req_data, HTTP_PREAMBLE_LEN) &&
		tcp_req_len <= MAX_TCP_REQ_LEN) {

		tcp_req_data[tcp_req_len] = 0;

		struct opt_type *opt;
		char *request = &(tcp_req_data[HTTP_PREAMBLE_LEN]);

		dbg_printf(cn, "Content-type: text/plain\n\n");
		dbg_printf(cn, "\n");


		if (wordlen(request) <= MAX_ARG_SIZE &&
			(opt = get_option(0, 0, request)) &&
			opt->auth_t == A_USR &&
			opt->opt_t == A_PS0 &&
			opt->dyn_t != A_INI &&
			opt->cfg_t == A_ARG) {

			dbgf(DBGL_CHANGES, DBGT_INFO, "rcvd %d bytes long HTTP request via fd %d: %s",
				tcp_req_len, cn->fd, opt->name);

			check_apply_parent_option(ADD, OPT_APPLY, 0, opt, 0, cn);

		} else {

			/*
			dbg_cn( cn, DBGL_ALL, DBGT_INFO, "rcvd illegal %d bytes long HTTP request via fd %d:\n%s\n", 
				tcp_req_len, cn->fd, tcp_req_data);
			 */
			check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_STATUS), 0, cn);

			dbg_printf(cn, "\nillegal HTTP request! Valid requests are:\n\n");

			struct list_node *list_pos;

			list_for_each(list_pos, &opt_list)
			{

				struct opt_type *opt = (struct opt_type *) list_entry(list_pos, struct opt_data, list);

				if (opt->auth_t == A_USR &&
					opt->opt_t == A_PS0 &&
					opt->dyn_t != A_INI &&
					opt->cfg_t == A_ARG) {
					dbg_printf(cn, "/%s\n\n", opt->name);

				}
			}

		}

	} else {

		dbgf(DBGL_SYS, DBGT_ERR, "illegal request via cn->fd %d: %s", cn->fd, strerror(errno));
	}

	close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);

}

static void http_info_rcv_tcp_connect(int32_t fd_in)
{

	int tmp_tcp_sock;

	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	if (!fd_in)
		return;

	assertion(-500155, (fd_in == http_info_tcp_sock_in));

	if (fd_in != http_info_tcp_sock_in) {
		dbgf(DBGL_SYS, DBGT_ERR, "rcvd invalid fd %d - should be %d", fd_in, http_info_tcp_sock_in);
		set_fd_hook(fd_in, http_info_rcv_tcp_connect, YES /*unregister*/);
		close(fd_in);
	}

	errno = 0;
	if ((tmp_tcp_sock = accept(http_info_tcp_sock_in, (struct sockaddr *) &addr, &addrlen)) < 0) {
		dbgf(DBGL_SYS, DBGT_ERR, "accept failed: %s", strerror(errno));
		return;
	}


	if (!http_access && addr.sin_addr.s_addr != 0x100007f /*127.0.0.1*/) {

		dbg_mute(35, DBGL_SYS, DBGT_WARN, "rcvd illegal info request from %12s %x",
			ip4AsStr(addr.sin_addr.s_addr), addr.sin_addr.s_addr);
		close(tmp_tcp_sock);
		return;
	}

	/*
	int32_t sock_opts;
	sock_opts = fcntl( tmp_tcp_sock, F_GETFL, 0 );
	fcntl( tmp_tcp_sock, F_SETFL, sock_opts | O_NONBLOCK );
	 */

	dbgf(DBGL_CHANGES, DBGT_INFO, "rcvd connect via fd %d from %s", tmp_tcp_sock, ip4AsStr(addr.sin_addr.s_addr));

	struct ctrl_node *cn = create_ctrl_node(tmp_tcp_sock, http_info_rcv_tcp_data, NO /*admin rights*/);
	close_ctrl_node(CTRL_CLOSE_DELAY, cn);
	change_selects();
}

static int32_t opt_http_port(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{


	if (cmd == OPT_APPLY) {

		if (http_info_tcp_sock_in) {

			set_fd_hook(http_info_tcp_sock_in, http_info_rcv_tcp_connect, YES /*unregister*/);
			close(http_info_tcp_sock_in);
			http_info_tcp_sock_in = 0;
		}


		if (http_info_port > 0) {

			int32_t tmp_tcp_sock_in;
			struct sockaddr_in http_info_addr;

			errno = 0;
			if ((tmp_tcp_sock_in = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "requesting socket failed: %s", strerror(errno));
				return SUCCESS;
			}

			int sock_opts = 1;
			if (setsockopt(tmp_tcp_sock_in, SOL_SOCKET, SO_REUSEADDR, &sock_opts, sizeof(sock_opts)) < 0) {
				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "can't set SO_REUSEADDR option: %s\n", strerror(errno));
				close(tmp_tcp_sock_in);
				return SUCCESS;
			}

			memset(&http_info_addr, 0, sizeof(http_info_addr));
			http_info_addr.sin_family = AF_INET;
			http_info_addr.sin_addr.s_addr = htonl(INADDR_ANY);
			http_info_addr.sin_port = htons(http_info_port);

			errno = 0;
			if (bind(tmp_tcp_sock_in, (struct sockaddr *) &http_info_addr, sizeof(http_info_addr)) < 0) {
				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "binding socket failed: %s", strerror(errno));
				close(tmp_tcp_sock_in);
				return SUCCESS;
			}

			errno = 0;
			if (listen(tmp_tcp_sock_in, HTTP_INFO_LISTEN_QUEUE) < 0) {
				dbgf_cn(cn, DBGL_SYS, DBGT_ERR, "listening on socket failed: %s", strerror(errno));
				close(tmp_tcp_sock_in);
				return SUCCESS;
			}

			http_info_tcp_sock_in = tmp_tcp_sock_in;

			set_fd_hook(http_info_tcp_sock_in, http_info_rcv_tcp_connect, NO /*unregister*/);


		}


	} else if (cmd == OPT_UNREGISTER) {

		if (http_info_tcp_sock_in) {

			set_fd_hook(http_info_tcp_sock_in, http_info_rcv_tcp_connect, YES /*unregister*/);
			close(http_info_tcp_sock_in);
			http_info_tcp_sock_in = 0;
		}

	}

	return SUCCESS;
}


static struct opt_type http_info_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,HTTP_INFO_PORT,	        0,9,2, A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&http_info_port,0, 		64000,		0,0, 		opt_http_port,
			ARG_PORT_FORM,	"set tcp port for http_info plugin" },
		
	{ODI,0,HTTP_INFO_GLOB_ACCESS,	0,9,2, A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&http_access,	0, 		1,		0,0, 		0,
			ARG_VALUE_FORM,	"disable/enable global accessibility of http_info plugin via configured tcp port" }
	
};
static void http_info_cleanup(void)
{

	//	remove_options_array( http_info_options );

}

static int32_t http_info_init(void)
{

	register_options_array(http_info_options, sizeof( http_info_options), CODE_CATEGORY_NAME);

	return SUCCESS;

}

struct plugin* get_plugin(void)
{

	static struct plugin http_info_plugin;

	memset(&http_info_plugin, 0, sizeof( struct plugin));


	http_info_plugin.plugin_name = "bmx7_http_info_plugin";
	http_info_plugin.plugin_size = sizeof( struct plugin);
	http_info_plugin.cb_init = http_info_init;
	http_info_plugin.cb_cleanup = http_info_cleanup;

	return &http_info_plugin;

}
