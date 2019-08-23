/*
 * Copyright (c) 2019 Harry Pantazis
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


#include "wireguard.h"

/* Set default names */
#define ARG_WG_TUN_NAME_PREFIX "wg_dev"
#define MAX_WG_TUN_NAME_PREFIX_LEN 5
#define ARG_WG_TUN_STATUS "wg_status"

#define ARG_WG_TUN_DEV  "wgDev"

struct dsc_msg_wg_tun {
	wg_key public_key;
	IP6_T wg_tun_addr;
	uint8_t wg_tun_addr_prefix_len;
	uint16_t udp_port;

} __attribute__((packed));

#define DESCRIPTION_MSG_WG_TUN_ADV_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, sizeof(wg_key)*8, 0, FIELD_RELEVANCE_HIGH, "public_key" }, \
{FIELD_TYPE_IPX6, -1, 128, 0, FIELD_RELEVANCE_HIGH, "wg_tun_addr" }, \
{FIELD_TYPE_UINT, -1, 8, 0, FIELD_RELEVANCE_HIGH, "wg_tun_addr_prefix_len"}, \
{FIELD_TYPE_UINT, -1, 16, 0, FIELD_RELEVANCE_HIGH, "udp_port"}, \
FIELD_FORMAT_END }


